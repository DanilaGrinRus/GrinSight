//! The header chain from a starting point: real points and headers of both
//! networks, and chains mined in the test on the automated-testing network.
//! Run with `cargo test --features testkit`.
use fly_chain_headers::chain::{HeaderChain, OpenError, Opened, Outcome, FILE_NAME, MAX_BATCH};
use fly_chain_headers::checkpoint::{self, CheckError};
use fly_chain_headers::peaks::{Peaks, PeaksError};
use fly_chain_headers::rules::{self, Reject};
use fly_chain_headers::testkit::TestChain;
use fly_chain_headers::origin::{Kind, Origin};
use fly_chain_headers::{baked_point, hash_bytes, read_header, write_header, Net};
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::pmmr::{self, ReadablePMMR, VecBackend, PMMR};
use grin_core::core::BlockHeader;
use grin_core::pow::Difficulty;
use serde_json::{json, Value};
use std::path::PathBuf;

const FAR: u64 = u64::MAX / 2;

struct Temp(PathBuf);
impl Temp {
    fn new(tag: &str) -> Temp {
        let mut r = [0u8; 8];
        getrandom::getrandom(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!("fly-headers-{tag}-{}", u64::from_le_bytes(r)));
        std::fs::create_dir_all(&p).unwrap();
        Temp(p)
    }
    fn file(&self) -> PathBuf {
        self.0.join(FILE_NAME)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn without_base(mut value: Value) -> Value {
    if let Some(map) = value.as_object_mut() {
        map.remove("base");
    }
    value
}

fn point(name: &str) -> Vec<u8> {
    std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("points").join(name)).unwrap()
}
fn next_headers(name: &str) -> Vec<BlockHeader> {
    Net::Main.enter();
    String::from_utf8(point(name))
        .unwrap()
        .lines()
        .map(|line| {
            let raw: Vec<u8> = (0..line.len()).step_by(2).map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap()).collect();
            read_header(&raw).unwrap()
        })
        .collect()
}

/// The peaks kept here are the peaks of the full range the Grin code
/// builds, for every size; and the proof of the last leaf gives them back.
#[test]
fn peaks_are_those_of_the_full_range() {
    Net::Automated.enter();
    let chain = TestChain::new();
    let mut leaves: Vec<BlockHeader> = Vec::new();
    for i in 0..300u64 {
        let mut h = chain.headers[1].clone();
        h.pow.proof.nonces = (0..8).map(|k| i * 100 + k).collect();
        leaves.push(h);
    }
    let mut backend = VecBackend::<BlockHeader>::new();
    let mut mmr = PMMR::new(&mut backend);
    let mut peaks = Peaks::empty();
    assert_eq!(peaks.root(), mmr.root().unwrap());
    for (i, leaf) in leaves.iter().enumerate() {
        let n = i as u64 + 1;
        mmr.push(leaf).unwrap();
        peaks.append(leaf).unwrap();
        let root = mmr.root().unwrap();
        assert_eq!((peaks.leaves(), peaks.size()), (n, mmr.unpruned_size()), "{n} leaves");
        assert_eq!(peaks.root(), root, "{n} leaves");
        assert_eq!(peaks.hashes(), mmr.peaks().as_slice(), "{n} leaves");
        // the proof of the last leaf determines every peak
        let pos = pmmr::insertion_to_pmmr_index(i as u64);
        let proof = mmr.merkle_proof(pos).unwrap();
        proof.verify(root, leaf, pos).unwrap();
        assert_eq!(Peaks::from_last_leaf(n, leaf, &proof.path, root).unwrap(), peaks, "{n} leaves");
        // and nothing else passes for it
        for k in 0..proof.path.len() {
            let mut path = proof.path.clone();
            path[k] = Hash::from_vec(&[k as u8; 32]);
            assert_eq!(Peaks::from_last_leaf(n, leaf, &path, root), Err(PeaksError::Root));
        }
        if i > 0 {
            assert_eq!(Peaks::from_last_leaf(n, &leaves[i - 1], &proof.path, root), Err(PeaksError::Root), "another leaf");
            assert!(Peaks::from_last_leaf(n - 1, leaf, &proof.path, root).is_err(), "another size");
        }
        let mut long = proof.path.clone();
        long.push(root);
        assert_eq!(Peaks::from_last_leaf(n, leaf, &long, root), Err(PeaksError::Shape));
        if !proof.path.is_empty() {
            assert_eq!(Peaks::from_last_leaf(n, leaf, &proof.path[1..], root), Err(PeaksError::Shape));
        }
        assert_eq!(Peaks::from_parts(n, peaks.hashes().to_vec()).unwrap(), peaks);
        assert_eq!(Peaks::from_parts(n + 1, peaks.hashes().to_vec()).is_ok(), (n + 1).count_ones() == n.count_ones());
    }
    assert_eq!(Peaks::from_last_leaf(0, &leaves[0], &[], peaks.root()), Err(PeaksError::Shape));
}

/// K202: a leaf followed through a growing range has, at every size, the
/// Merkle proof the full range of the Grin code gives for it; the path is
/// taken up again from the peaks, and a path whose upper part is not what
/// the peaks give is refused.
#[test]
fn a_followed_leaf_has_the_proof_of_the_full_range() {
    use fly_chain_headers::peaks::Track;
    Net::Automated.enter();
    let chain = TestChain::new();
    let leaves: Vec<BlockHeader> = (0..160u64)
        .map(|i| {
            let mut h = chain.headers[1].clone();
            h.pow.proof.nonces = (0..8).map(|k| i * 100 + k).collect();
            h
        })
        .collect();
    for target in [0usize, 1, 2, 3, 6, 7, 8, 21, 63, 64, 100] {
        let mut backend = VecBackend::<BlockHeader>::new();
        let mut mmr = PMMR::new(&mut backend);
        let mut before = Peaks::empty();
        for leaf in &leaves[..target] {
            mmr.push(leaf).unwrap();
            before.append(leaf).unwrap();
        }
        mmr.push(&leaves[target]).unwrap();
        let mut track = Track::begin(&before, &leaves[target]).unwrap();
        let pos = pmmr::insertion_to_pmmr_index(target as u64);
        for n in target + 1..=leaves.len() {
            let root = mmr.root().unwrap();
            assert_eq!(track.peaks().root(), root, "{target} in {n}");
            let path = track.path().unwrap();
            let full = mmr.merkle_proof(pos).unwrap();
            assert_eq!(path, full.path, "{target} in {n}");
            full.verify(root, &leaves[target], pos).unwrap();
            assert_eq!(Track::from_path(track.peaks(), target as u64, &path).unwrap(), track, "{target} in {n}");
            if !path.is_empty() {
                let mut cut = path.clone();
                cut.pop();
                assert!(Track::from_path(track.peaks(), target as u64, &cut).is_err());
            }
            let mut long = path.clone();
            long.push(root);
            assert!(Track::from_path(track.peaks(), target as u64, &long).is_err());
            assert!(Track::from_path(track.peaks(), n as u64, &path).is_err(), "a leaf the range does not have");
            if let Some(next) = leaves.get(n) {
                mmr.push(next).unwrap();
                track.append(next).unwrap();
            }
        }
    }
}

/// The points prepared from real nodes pass, on both networks, and the real
/// headers that follow them are accepted; a point is refused for another
/// network.
#[test]
fn real_points_and_real_headers() {
    let floonet = checkpoint::check(&point("floonet-3331315.json"), Net::Test).unwrap();
    assert_eq!((floonet.height(), floonet.net, floonet.release_time), (3_331_315, Net::Test, 1_795_046_400));
    assert_eq!(floonet.peaks.leaves(), 3_331_316);
    assert_eq!(checkpoint::check(&point("floonet-3331315.json"), Net::Main).err(), Some(CheckError::Network));
    assert_eq!(checkpoint::check(&point("mainnet-4113930.json"), Net::Test).err(), Some(CheckError::Network));

    for height in [4_110_480u64, 4_111_200, 4_113_930] {
        let record = point(&format!("mainnet-{height}.json"));
        let start = checkpoint::check(&record, Net::Main).unwrap();
        assert_eq!(start.height(), height);
        let next = next_headers(&format!("mainnet-{height}.next"));
        assert_eq!(next.len(), 2);
        let t = Temp::new("real");
        let (mut chain, opened) = HeaderChain::open(&t.0, Net::Main, &record).unwrap();
        assert_eq!(opened, Opened { kept: 0, cut_bytes: 0 });
        assert_eq!(chain.tip().height, height);
        // the second without the first hangs in the air
        assert_eq!(chain.offer(&next[1..], FAR).unwrap().outcome, Outcome::Detached);
        let offered = chain.offer(&next, FAR).unwrap();
        assert_eq!((offered.outcome, offered.bad, offered.held), (Outcome::Extended { added: 2 }, None, false));
        assert_eq!(chain.tip().hash, hash_bytes(&next[1]));
        assert_eq!(chain.tip().total_work, next[1].total_difficulty().to_num());
        drop(chain);
        let (chain, opened) = HeaderChain::open(&t.0, Net::Main, &record).unwrap();
        assert_eq!(opened, Opened { kept: 2, cut_bytes: 0 });
        assert_eq!(chain.tip().height, height + 2);
        assert_eq!(chain.header_at(height + 1).unwrap().unwrap().hash(), next[0].hash());

        // a real header with one bit of its proof changed is no header
        let t = Temp::new("real-bad");
        let (mut chain, _) = HeaderChain::open(&t.0, Net::Main, &record).unwrap();
        let mut bent = next[0].clone();
        bent.pow.proof.nonces[5] ^= 1;
        // its hash changed with the proof, so the one after it no longer names it
        let offered = chain.offer(&[bent], FAR).unwrap();
        assert_eq!((offered.outcome, offered.bad), (Outcome::Nothing, Some(Reject::Pow)));
        // one whose claimed work is a little higher
        let mut greedy = next[0].clone();
        greedy.pow.total_difficulty = greedy.pow.total_difficulty + Difficulty::from_num(1);
        let offered = chain.offer(&[greedy], FAR).unwrap();
        assert_eq!((offered.outcome, offered.bad), (Outcome::Nothing, Some(Reject::Pow)), "the work is part of what the proof covers");
        assert_eq!(chain.tip().height, height);
    }
}

/// The points compiled in pass the check of a record, and what the build
/// says about each is about that very header. A build that calls its point
/// a release point has to carry the two confirmations that make it one.
#[test]
fn the_points_compiled_in_are_what_the_build_says() {
    for net in [Net::Main, Net::Test] {
        let baked = baked_point(net).unwrap();
        let start = checkpoint::check(baked.record, net).unwrap();
        let origin = Origin::read(baked.origin).unwrap();
        assert!(origin.names(&start), "the origin is about another header");
        assert_eq!(origin.vouches_for(&start), origin.kind == Kind::Release, "a release point without its confirmations");
        // the other network's origin is about another header
        let other = baked_point(if net == Net::Main { Net::Test } else { Net::Main }).unwrap();
        assert!(!Origin::read(other.origin).unwrap().names(&start));
    }
    assert!(baked_point(Net::Automated).is_none());
}

/// An origin vouches only for the header it names, only as a release
/// point, and only with two operators on two networks behind it.
#[test]
fn what_an_origin_vouches_for() {
    use fly_chain_headers::origin::Confirmed;
    let start = checkpoint::check(&point("mainnet-4113930.json"), Net::Main).unwrap();
    let node = |group: &str, asn: u32| Confirmed {
        group: group.to_string(),
        host: format!("{}.example", group.to_lowercase()),
        asn,
    };
    let good = Origin::of(Kind::Release, &start, 1_795_000_000, "the maker's own node", vec![node("One", 1), node("Two", 2)]);
    assert!(good.names(&start) && good.vouches_for(&start));
    assert_eq!((good.network, good.height, good.made), (1, 4_113_930, 1_795_000_000));
    assert_eq!(good.hash, "0000626fab0beb4fa57bae98a16c7a27842e6af8c447a25030ce92cdad190ee1");
    // written and read back, it still does
    assert!(Origin::read(&good.write().unwrap()).unwrap().vouches_for(&start));

    let development = Origin::of(Kind::Development, &start, 1, "a node", vec![node("One", 1), node("Two", 2)]);
    assert!(development.names(&start) && !development.vouches_for(&start), "a development point is vouched for by nobody");
    let alone = Origin::of(Kind::Release, &start, 1, "a node", vec![node("One", 1)]);
    assert!(!alone.vouches_for(&start));
    let one_network = Origin::of(Kind::Release, &start, 1, "a node", vec![node("One", 1), node("Two", 1)]);
    assert!(!one_network.vouches_for(&start));
    let one_operator = Origin::of(Kind::Release, &start, 1, "a node", vec![node("One", 1), node("One", 2)]);
    assert!(!one_operator.vouches_for(&start));

    // about another header: one above, another hash, another network
    for change in [0usize, 1, 2] {
        let mut other = good.clone();
        match change {
            0 => other.height += 1,
            1 => other.hash = other.hash.replace("626f", "626e"),
            _ => other.network = 2,
        }
        assert!(!other.names(&start) && !other.vouches_for(&start), "{change}");
    }
    // the origin of one real point says nothing about another
    let earlier = checkpoint::check(&point("mainnet-4111200.json"), Net::Main).unwrap();
    assert!(!good.vouches_for(&earlier));
}

/// A point made from the chain is the record the full range of the Grin
/// code gives for that header, at every height the chain can make one of;
/// and a chain started from it goes on as the first one did.
#[test]
fn a_point_is_written_from_the_chain() {
    let mut main = TestChain::new();
    main.mine(70, 60);
    let tip = main.tip().height;
    let t = Temp::new("write");
    let (mut chain, _) = open(&t, &main, 20);
    chain.offer(main.after(20), FAR).unwrap();
    assert_eq!(chain.tip().height, tip);
    // below: the two headers before the point, and what they were added
    // to, have to be in the chain; above: there is no such header
    for height in [0, 19, 20, 21, 22, tip + 1, u64::MAX] {
        assert_eq!(chain.record_at(height, 1_700_000_000).unwrap(), None, "{height}");
    }
    for height in 23..=tip {
        let record = chain.record_at(height, 1_700_000_000).unwrap().unwrap();
        let written: Value = serde_json::from_slice(&record).unwrap();
        // K202: the point the chain began at (20) is followed into the record
        assert_eq!(written["base"]["height"], json!(20), "{height}");
        assert_eq!(without_base(written), main.record_value(height), "{height}");
        let start = checkpoint::check(&record, Net::Automated).unwrap();
        assert_eq!((start.height(), start.hash()), (height, hash_bytes(&main.headers[height as usize])));
    }
    // the time is carried as given and changes nothing else
    let mut later = without_base(serde_json::from_slice(&chain.record_at(40, 7).unwrap().unwrap()).unwrap());
    assert_eq!(later["release_time"], json!(7));
    later["release_time"] = json!(1_700_000_000u64);
    assert_eq!(later, main.record_value(40));

    // from the new point the same chain is followed to the same tip
    let record = chain.record_at(40, 1).unwrap().unwrap();
    let t2 = Temp::new("write-on");
    let (mut second, _) = HeaderChain::open(&t2.0, Net::Automated, &record).unwrap();
    assert_eq!(second.offer(main.after(40), FAR).unwrap().outcome, Outcome::Extended { added: tip - 40 });
    assert_eq!(second.tip(), chain.tip());
    // and a point can be made from that chain in its turn
    assert_eq!(second.record_at(50, 1_700_000_000).unwrap().unwrap(), chain.record_at(50, 1_700_000_000).unwrap().unwrap());

    // after a change of branch the point is of the branch
    let mut fork = main.fork_at(tip - 5);
    fork.mine_salted(8, 60, 9);
    assert!(matches!(chain.offer(fork.after(tip - 5), FAR).unwrap().outcome, Outcome::Switched { .. }));
    let on_fork = without_base(serde_json::from_slice(&chain.record_at(tip - 2, 1_700_000_000).unwrap().unwrap()).unwrap());
    assert_eq!(on_fork, fork.record_value(tip - 2));
    assert_ne!(on_fork, main.record_value(tip - 2));
}

/// The same on real headers: a point made three headers above a real
/// Mainnet point is a record the check takes, and the real headers that
/// follow it are accepted from it.
#[test]
fn a_point_is_written_from_real_headers() {
    let record = point("mainnet-4113930.json");
    let next = next_headers("mainnet-4113930.next8");
    assert_eq!(next.len(), 8);
    let t = Temp::new("real-write");
    let (mut chain, _) = HeaderChain::open(&t.0, Net::Main, &record).unwrap();
    assert_eq!(chain.offer(&next, FAR).unwrap().outcome, Outcome::Extended { added: 8 });
    assert_eq!(chain.record_at(4_113_932, 1).unwrap(), None);
    for (index, height) in (4_113_933u64..=4_113_938).enumerate() {
        let made = chain.record_at(height, 1_795_300_000).unwrap().unwrap();
        let start = checkpoint::check(&made, Net::Main).unwrap();
        assert_eq!((start.height(), start.release_time), (height, 1_795_300_000));
        assert_eq!(start.hash(), hash_bytes(&next[index + 2]));
        assert_eq!(start.peaks.leaves(), height + 1);
        // made for the other network it is no record at all
        assert_eq!(checkpoint::check(&made, Net::Test).err(), Some(CheckError::Network));
        let t = Temp::new("real-write-on");
        let (mut second, _) = HeaderChain::open(&t.0, Net::Main, &made).unwrap();
        let rest = &next[index + 3..];
        if rest.is_empty() {
            continue;
        }
        assert_eq!(second.offer(rest, FAR).unwrap().outcome, Outcome::Extended { added: rest.len() as u64 }, "{height}");
        assert_eq!(second.tip(), chain.tip());
    }
}

/// A record is written only from parts that fit together: headers in
/// their order and the peaks they were added to.
#[test]
fn a_record_is_written_only_from_what_fits() {
    use fly_chain_headers::checkpoint::Parts;
    Net::Automated.enter();
    let mut main = TestChain::new();
    main.mine(30, 60);
    let peaks_before = |height: usize| {
        let mut peaks = Peaks::empty();
        for header in &main.headers[..height] {
            peaks.append(header).unwrap();
        }
        peaks
    };
    let h = &main.headers;
    let (before_prev, before_older) = (peaks_before(29), peaks_before(28));
    let good = Parts {
        net: Net::Automated,
        anchor: &h[30],
        prev: &h[29],
        older: &h[28],
        before_prev: &before_prev,
        before_older: &before_older,
        release_time: 1_700_000_000,
        base: None,
    };
    let written: Value = serde_json::from_slice(&checkpoint::write(&good).unwrap()).unwrap();
    assert_eq!(written, main.record_value(30));

    let (one_less, one_more) = (peaks_before(27), peaks_before(30));
    let none = |parts: Parts<'_>| assert_eq!(checkpoint::write(&parts), None);
    none(Parts { anchor: &h[31], ..good });
    none(Parts { prev: &h[28], ..good });
    none(Parts { older: &h[27], ..good });
    none(Parts { before_prev: &before_older, ..good });
    none(Parts { before_prev: &one_more, ..good });
    none(Parts { before_older: &one_less, ..good });
    none(Parts { before_older: &before_prev, ..good });
    none(Parts { net: Net::Main, ..good });
    // peaks of the right size from another chain
    let mut other = TestChain::new();
    other.mine_salted(30, 60, 3);
    let mut foreign = Peaks::empty();
    for header in &other.headers[..29] {
        foreign.append(header).unwrap();
    }
    none(Parts { before_prev: &foreign, ..good });
    let mut foreign_older = Peaks::empty();
    for header in &other.headers[..28] {
        foreign_older.append(header).unwrap();
    }
    none(Parts { before_older: &foreign_older, ..good });
}

/// Everything in a record hangs on it: change any byte of any header, hash
/// or path, or any number, and the record is refused. Only the release time
/// is carried unchecked.
#[test]
fn nothing_in_a_record_can_be_changed() {
    let good: Value = serde_json::from_slice(&point("mainnet-4110480.json")).unwrap();
    let check = |v: &Value| checkpoint::check(&serde_json::to_vec(v).unwrap(), Net::Main);
    assert!(check(&good).is_ok());
    let mut tried = 0;
    let bump = |n: &mut Value| *n = json!((n.as_u64().unwrap() + 1) % 256);
    for field in ["genesis", "header_hash"] {
        for i in 0..32 {
            let mut v = good.clone();
            bump(&mut v[field][i]);
            assert!(check(&v).is_err(), "{field}[{i}]");
            tried += 1;
        }
    }
    for field in ["context", "peaks", "previous_path", "older_context_path"] {
        for row in 0..good[field].as_array().unwrap().len() {
            for i in 0..good[field][row].as_array().unwrap().len() {
                let mut v = good.clone();
                bump(&mut v[field][row][i]);
                assert!(check(&v).is_err(), "{field}[{row}][{i}]");
                tried += 1;
            }
        }
    }
    assert!(tried > 2000, "{tried}");
    for (field, value) in [
        ("version", json!(2)),
        ("network", json!(2)),
        ("height", json!(4_110_481u64)),
        ("total_work", json!(1)),
        ("mmr_size", json!(8_220_951u64)),
    ] {
        let mut v = good.clone();
        v[field] = value;
        assert!(check(&v).is_err(), "{field}");
    }
    // rows taken away, added, swapped
    for field in ["context", "peaks", "previous_path", "older_context_path"] {
        let mut v = good.clone();
        v[field].as_array_mut().unwrap().pop();
        assert!(check(&v).is_err(), "{field} shorter");
        let mut v = good.clone();
        let row = v[field][0].clone();
        v[field].as_array_mut().unwrap().push(row);
        assert!(check(&v).is_err(), "{field} longer");
        let mut v = good.clone();
        v[field].as_array_mut().unwrap().swap(0, 1);
        assert!(check(&v).is_err(), "{field} swapped");
    }
    let mut v = good.clone();
    v["extra"] = json!(1);
    assert_eq!(check(&v).err(), Some(CheckError::Format), "a field this format does not have");
    for bytes in [&b""[..], b"{}", b"[]", b"null", &[b' '; 70_000][..]] {
        assert_eq!(checkpoint::check(bytes, Net::Main).err(), Some(CheckError::Format));
    }
    // the proof of the header before the one before is optional ...
    let mut v = good.clone();
    v.as_object_mut().unwrap().remove("older_context_path");
    assert!(check(&v).is_ok());
    // ... and the release time is only carried
    let mut v = good.clone();
    v["release_time"] = json!(42);
    assert_eq!(check(&v).unwrap().release_time, 42);
}

/// A record names three headers of one chain, in order, after the fourth
/// hard fork; headers of another branch in their places are refused even
/// though each is a valid header.
#[test]
fn a_record_holds_one_chain() {
    let mut main = TestChain::new();
    main.mine(20, 60); // to height 29
    let check = |v: &Value| checkpoint::check(&serde_json::to_vec(v).unwrap(), Net::Automated);
    let good = main.record_value(20);
    let start = check(&good).unwrap();
    assert_eq!((start.height(), start.hash()), (20, hash_bytes(&main.headers[20])));
    assert_eq!(start.peaks.leaves(), 21);
    for height in 14..=29 {
        assert!(checkpoint::check(&main.record(height), Net::Automated).is_ok(), "{height}");
    }
    assert_eq!(checkpoint::check(&main.record(20), Net::Main).err(), Some(CheckError::Network));
    let raw = |h: &BlockHeader| json!(write_header(h).unwrap());
    // the header before, from another branch
    let mut other = main.fork_at(18);
    other.mine_salted(2, 60, 7);
    let mut v = good.clone();
    v["context"][1] = raw(&other.headers[19]);
    assert_eq!(check(&v).err(), Some(CheckError::Headers(Reject::Link)));
    // the one before that, from another branch
    let mut other = main.fork_at(17);
    other.mine_salted(1, 60, 8);
    let mut v = good.clone();
    v["context"][2] = raw(&other.headers[18]);
    assert_eq!(check(&v).err(), Some(CheckError::Headers(Reject::Link)));
    // the right headers in the wrong places
    let mut v = good.clone();
    v["context"] = json!([raw(&main.headers[20]), raw(&main.headers[18]), raw(&main.headers[19])]);
    assert_eq!(check(&v).err(), Some(CheckError::Headers(Reject::Height)));
    let mut v = good.clone();
    v["context"] = json!([raw(&main.headers[20]), raw(&main.headers[19]), raw(&main.headers[19])]);
    assert_eq!(check(&v).err(), Some(CheckError::Headers(Reject::Height)));
    // a whole other branch under the hash of this one
    let mut other = main.fork_at(17);
    other.mine_salted(3, 60, 9);
    let mut v = other.record_value(20);
    v["header_hash"] = good["header_hash"].clone();
    assert_eq!(check(&v).err(), Some(CheckError::Format));
    // the peaks of another branch
    let mut v = good.clone();
    v["peaks"] = other.record_value(20)["peaks"].clone();
    assert_eq!(check(&v).err(), Some(CheckError::Peaks));
    let mut v = good.clone();
    v["previous_path"] = other.record_value(20)["previous_path"].clone();
    assert_eq!(check(&v).err(), Some(CheckError::Peaks));
    // a point from before the fourth hard fork cannot be continued from
    let mut v = good.clone();
    v["context"] = json!([raw(&main.headers[13]), raw(&main.headers[12]), raw(&main.headers[11])]);
    v["height"] = json!(13);
    v["header_hash"] = json!(hash_bytes(&main.headers[13]).to_vec());
    v["total_work"] = json!(main.headers[13].total_difficulty().to_num());
    assert_eq!(check(&v).err(), Some(CheckError::Headers(Reject::Unsupported)));
}

fn open(t: &Temp, chain: &TestChain, start: u64) -> (HeaderChain, Opened) {
    HeaderChain::open(&t.0, Net::Automated, &chain.record(start)).unwrap()
}

/// A mined chain is followed from its starting point in any pieces, kept
/// across restarts, and described to a node by a locator.
#[test]
fn a_chain_is_followed_and_kept() {
    let mut main = TestChain::new();
    main.mine(60, 60);
    let tip = main.tip().height;
    let t = Temp::new("follow");
    let (mut chain, opened) = open(&t, &main, 20);
    assert_eq!(opened, Opened { kept: 0, cut_bytes: 0 });
    assert_eq!((chain.start().height(), chain.tip().height, chain.locator()), (20, 20, vec![hash_bytes(&main.headers[20])]));
    assert_eq!(chain.hash_at(19), None, "nothing is known below the starting point");
    assert_eq!(chain.offer(&[], FAR).unwrap().outcome, Outcome::Nothing);

    // in pieces, with overlap, and again
    assert_eq!(chain.offer(&main.headers[21..=25], FAR).unwrap().outcome, Outcome::Extended { added: 5 });
    assert_eq!(chain.offer(&main.headers[21..=25], FAR).unwrap().outcome, Outcome::Nothing);
    assert_eq!(chain.offer(&main.headers[23..=30], FAR).unwrap().outcome, Outcome::Extended { added: 5 });
    // headers at and below the starting point are known or hang in the air
    assert_eq!(chain.offer(&main.headers[20..=31], FAR).unwrap().outcome, Outcome::Extended { added: 1 });
    assert_eq!(chain.offer(&main.headers[15..=18], FAR).unwrap().outcome, Outcome::Detached);
    assert_eq!(chain.offer(&main.headers[40..=41], FAR).unwrap().outcome, Outcome::Detached, "a gap");
    assert_eq!(chain.offer(main.after(31), FAR).unwrap().outcome, Outcome::Extended { added: tip - 31 });
    assert_eq!(chain.tip().hash, hash_bytes(main.tip()));
    for h in 20..=tip {
        assert_eq!(chain.hash_at(h), Some(hash_bytes(&main.headers[h as usize])));
        assert_eq!(chain.header_at(h).unwrap().unwrap(), main.headers[h as usize]);
    }
    assert_eq!((chain.hash_at(tip + 1), chain.header_at(tip + 1).unwrap()), (None, None));
    // the locator: the tip, then 1, 2, 4, 8 ... back, the starting point last
    let heights: Vec<u64> = chain
        .locator()
        .iter()
        .map(|hash| main.headers.iter().find(|h| hash_bytes(h) == *hash).unwrap().height)
        .collect();
    assert_eq!(heights, [tip, tip - 1, tip - 3, tip - 7, tip - 15, tip - 31, 20]);

    // a second process cannot have the file
    assert_eq!(HeaderChain::open(&t.0, Net::Automated, &main.record(20)).err(), Some(OpenError::Busy));
    drop(chain);
    let (chain, opened) = open(&t, &main, 20);
    assert_eq!(opened, Opened { kept: tip - 20, cut_bytes: 0 });
    assert_eq!(chain.tip().hash, hash_bytes(main.tip()));
    drop(chain);
    // the file of a network is not used for another, and is left alone
    let before = std::fs::read(t.file()).unwrap();
    assert_eq!(
        HeaderChain::open(&t.0, Net::Main, &point("mainnet-4113930.json")).err(),
        Some(OpenError::OtherStart)
    );
    assert_eq!(std::fs::read(t.file()).unwrap(), before);
    assert_eq!(
        HeaderChain::open(&t.0, Net::Automated, b"not a record").err(),
        Some(OpenError::Start(CheckError::Format))
    );
    assert_eq!(std::fs::read(t.file()).unwrap(), before);
}

/// The file of another starting point of the same network gives way to a
/// chain from the new one: the headers above the new point are kept if
/// they follow from it, and nothing else is.
#[test]
fn the_file_of_another_point_gives_way() {
    let mut main = TestChain::new();
    main.mine(60, 60);
    let tip = main.tip().height;
    let t = Temp::new("other-point");
    let (mut chain, _) = open(&t, &main, 20);
    chain.offer(main.after(20), FAR).unwrap();
    assert_eq!(chain.replaced(), None);
    drop(chain);

    // a higher point on the same chain: what is above it is kept
    let (chain, opened) = open(&t, &main, 40);
    assert_eq!((chain.replaced(), chain.start().height(), chain.tip()), (Some(20), 40, {
        let (whole, _) = HeaderChain::open(&Temp::new("whole").0, Net::Automated, &main.record(20)).unwrap();
        let mut whole = whole;
        whole.offer(main.after(20), FAR).unwrap();
        whole.tip()
    }));
    assert_eq!(opened, Opened { kept: tip - 40, cut_bytes: 0 });
    assert!(!t.0.join(fly_chain_headers::chain::NEXT_FILE_NAME).exists());
    drop(chain);
    // opened again it is the file of its own point
    let (chain, opened) = open(&t, &main, 40);
    assert_eq!((chain.replaced(), opened.kept), (None, tip - 40));
    drop(chain);

    // a lower point: the file holds nothing above the old point that
    // starts right after the new one, so it starts empty
    // (and a long file left by an interrupted attempt leaves nothing behind)
    std::fs::write(t.0.join(fly_chain_headers::chain::NEXT_FILE_NAME), vec![7u8; 300]).unwrap();
    let (chain, opened) = open(&t, &main, 30);
    assert_eq!((chain.replaced(), opened, chain.tip().height), (Some(40), Opened { kept: 0, cut_bytes: 0 }, 30));
    drop(chain);

    // a point on another branch: the headers of the old one do not follow
    let (mut chain, _) = open(&t, &main, 20);
    chain.offer(main.after(20), FAR).unwrap();
    drop(chain);
    let mut fork = main.fork_at(35);
    fork.mine_salted(30, 60, 5);
    let (mut chain, opened) = open(&t, &fork, 45);
    assert_eq!((chain.replaced(), opened.kept, chain.tip().height), (Some(20), 0, 45));
    assert_eq!(chain.offer(fork.after(45), FAR).unwrap().outcome, Outcome::Extended { added: fork.tip().height - 45 });
    drop(chain);

    // a file with a header that breaks the rules part way: kept up to it
    let (mut chain, _) = open(&t, &main, 20);
    chain.offer(main.after(20), FAR).unwrap();
    drop(chain);
    let mut bytes = std::fs::read(t.file()).unwrap();
    let len = bytes.len();
    // the last header's proof, one bit changed
    bytes[len - 20] ^= 1;
    std::fs::write(t.file(), &bytes).unwrap();
    let (chain, opened) = open(&t, &main, 40);
    assert_eq!((chain.replaced(), opened.kept), (Some(20), tip - 41));

    // a second process cannot replace what the first holds
    let busy = HeaderChain::open(&t.0, Net::Automated, &main.record(50)).err();
    assert_eq!(busy, Some(OpenError::Busy));
    drop(chain);

    // what an interrupted replacement left behind is no obstacle
    std::fs::write(t.0.join(fly_chain_headers::chain::NEXT_FILE_NAME), b"half a file").unwrap();
    let (chain, opened) = open(&t, &main, 50);
    assert_eq!((chain.replaced(), opened.kept), (Some(40), tip - 51));
}

/// A header that breaks a rule is not written, whatever came with it; the
/// valid headers before it are.
#[test]
fn a_header_that_breaks_a_rule_is_refused() {
    let mut main = TestChain::new();
    main.mine(30, 60);
    let tip = main.tip().height as usize;
    let work = main.headers[tip].total_difficulty() - main.headers[tip - 1].total_difficulty();
    let honest = main.next_after(tip, 60, 0);
    let remined = |change: &dyn Fn(&mut BlockHeader)| {
        let mut h = honest.clone();
        change(&mut h);
        TestChain::remine(&mut h, work);
        h
    };
    let cases: Vec<(&str, BlockHeader, Reject)> = vec![
        ("the proof does not fit the header", { let mut h = honest.clone(); h.output_mmr_size += 1; h }, Reject::Pow),
        ("no commitment to the headers before", remined(&|h| h.prev_root = h.prev_hash), Reject::Root),
        ("time stands still", remined(&|h| h.timestamp = main.headers[tip].timestamp), Reject::Time),
        ("time runs backwards", remined(&|h| h.timestamp = main.headers[tip - 1].timestamp), Reject::Time),
        (
            "more work claimed than the rule gives, and paid for",
            {
                let mut h = honest.clone();
                h.pow.total_difficulty = h.pow.total_difficulty + Difficulty::from_num(1);
                TestChain::remine(&mut h, work + Difficulty::from_num(1));
                h
            },
            Reject::Difficulty,
        ),
        (
            "work claimed that the proof does not pay for",
            {
                let mut h = honest.clone();
                h.pow.total_difficulty = h.pow.total_difficulty + Difficulty::from_num(100_000_000);
                TestChain::remine(&mut h, work);
                h
            },
            Reject::Work,
        ),
        ("less work claimed than the rule gives", remined(&|h| h.pow.total_difficulty = h.pow.total_difficulty - Difficulty::from_num(1)), Reject::Difficulty),
        ("no work claimed", remined(&|h| h.pow.total_difficulty = main.headers[tip].pow.total_difficulty), Reject::Work),
        ("no new output", remined(&|h| h.output_mmr_size = main.headers[tip].output_mmr_size), Reject::Sizes),
        ("no new kernel", remined(&|h| h.kernel_mmr_size = main.headers[tip].kernel_mmr_size), Reject::Sizes),
        (
            "a block heavier than any",
            remined(&|h| h.output_mmr_size = pmmr::insertion_to_pmmr_index(main.headers[tip].output_mmr_count() + 12)),
            Reject::Weight,
        ),
        ("a chain heavier than all its blocks", remined(&|h| h.output_mmr_size = pmmr::insertion_to_pmmr_index(1_000_000)), Reject::Weight),
        ("a version from the past", remined(&|h| h.version = grin_core::core::block::HeaderVersion(4)), Reject::Version),
        ("a version from the future", remined(&|h| h.version = grin_core::core::block::HeaderVersion(6)), Reject::Version),
    ];
    for (what, bad, reject) in cases {
        let t = Temp::new("rule");
        let (mut chain, _) = open(&t, &main, 20);
        // after valid ones: those are kept, it is not
        let mut batch = main.after(20).to_vec();
        batch.push(bad.clone());
        let offered = chain.offer(&batch, FAR).unwrap();
        assert_eq!((offered.outcome, offered.bad), (Outcome::Extended { added: 19 }, Some(reject)), "{what}");
        assert_eq!(chain.tip().hash, hash_bytes(main.tip()), "{what}");
        // alone
        let offered = chain.offer(std::slice::from_ref(&bad), FAR).unwrap();
        assert_eq!((offered.outcome, offered.bad), (Outcome::Nothing, Some(reject)), "{what}");
        assert_eq!(chain.tip().hash, hash_bytes(main.tip()), "{what}");
        drop(chain);
        let (mut chain, opened) = open(&t, &main, 20);
        assert_eq!(opened, Opened { kept: 19, cut_bytes: 0 }, "{what}");
        // and the honest header still fits
        assert_eq!(chain.offer(std::slice::from_ref(&honest), FAR).unwrap().outcome, Outcome::Extended { added: 1 }, "{what}");
    }
    // the rules, asked directly
    Net::Automated.enter();
    let (older, prev) = (&main.headers[tip - 1], &main.headers[tip]);
    assert_eq!(rules::check_step(older, prev, &honest), Ok(()));
    assert_eq!(rules::check_step(prev, older, &honest), Err(Reject::Height));
    assert_eq!(rules::check_step(&main.headers[tip - 2], prev, &honest), Err(Reject::Height));
    let mut stranger = main.fork_at(tip as u64 - 1);
    stranger.mine_salted(1, 60, 9);
    assert_eq!(rules::check_step(older, stranger.tip(), &honest), Err(Reject::Link));
    assert_eq!(rules::check_alone(&main.headers[11]), Err(Reject::Unsupported), "before the fourth hard fork");
    // one header by itself: the bound on the whole chain's counts
    let mut bloated = honest.clone();
    bloated.output_mmr_size = pmmr::insertion_to_pmmr_index(1_000_000);
    TestChain::remine(&mut bloated, work);
    assert_eq!(rules::check_alone(&bloated), Err(Reject::Weight));
    let mut within = honest.clone();
    within.output_mmr_size = pmmr::insertion_to_pmmr_index(400);
    TestChain::remine(&mut within, work);
    assert_eq!(rules::check_alone(&within), Ok(()), "many outputs in the chain, not in one block");
    assert_eq!(rules::check_alone(&main.headers[12]), Ok(()));

    // a header from the future is neither applied nor called invalid
    let t = Temp::new("clock");
    let (mut chain, _) = open(&t, &main, 20);
    let time = |h: u64| main.headers[h as usize].timestamp.timestamp() as u64;
    let limit = grin_core::global::get_future_time_limit();
    let offered = chain.offer(main.after(20), time(25) - limit).unwrap();
    assert_eq!((offered.outcome, offered.bad, offered.held), (Outcome::Extended { added: 5 }, None, true));
    let offered = chain.offer(main.after(20), time(25) - limit).unwrap();
    assert_eq!((offered.outcome, offered.held), (Outcome::Nothing, true));
    let offered = chain.offer(&main.headers[21..=30], time(30) - limit).unwrap();
    assert_eq!((offered.outcome, offered.held), (Outcome::Extended { added: 5 }, false), "its time has come");
    assert!(!rules::ahead_of(&main.headers[30], time(30) - limit) && rules::ahead_of(&main.headers[30], time(30) - limit - 1));
    // more than a node sends at once is not taken at once
    let mut long = TestChain::new();
    long.mine(MAX_BATCH + 20, 60);
    let t = Temp::new("batch");
    let (mut chain, _) = open(&t, &long, 14);
    assert_eq!(chain.offer(long.after(14), FAR).unwrap().outcome, Outcome::Extended { added: MAX_BATCH as u64 });
}

/// The chain changes branch for more work and for nothing else, and what
/// the file holds afterwards is the new branch.
#[test]
fn a_branch_wins_only_by_work() {
    let mut main = TestChain::new();
    main.mine(30, 60); // to height 39
    let top = main.tip().height;
    let mut side = main.fork_at(30);
    side.mine_salted((top - 30) as usize, 60, 100);
    assert_eq!(side.tip().total_difficulty(), main.tip().total_difficulty(), "same pace, same work");
    assert_ne!(side.tip().hash(), main.tip().hash());

    let t = Temp::new("fork");
    let (mut chain, _) = open(&t, &main, 20);
    chain.offer(main.after(20), FAR).unwrap();
    // a branch with less work, then with the same: it waits
    assert_eq!(chain.offer(&side.headers[31..=35], FAR).unwrap().outcome, Outcome::Side { height: 35 });
    assert_eq!(chain.tip().hash, hash_bytes(main.tip()));
    assert_eq!(chain.locator()[0], hash_bytes(&side.headers[35]), "whoever is on the branch is asked to continue it");
    assert_eq!(chain.offer(&side.headers[36..=top as usize], FAR).unwrap().outcome, Outcome::Side { height: top });
    assert_eq!(chain.tip().hash, hash_bytes(main.tip()), "the first seen stays at equal work");
    // one more header: more work
    side.mine_salted(1, 60, 200);
    assert_eq!(
        chain.offer(&side.headers[top as usize + 1..], FAR).unwrap().outcome,
        Outcome::Switched { from: 30, removed: top - 30, added: top - 30 + 1 }
    );
    assert_eq!(chain.tip().hash, hash_bytes(side.tip()));
    for h in 20..=top + 1 {
        assert_eq!(chain.hash_at(h), Some(hash_bytes(&side.headers[h as usize])));
        assert_eq!(chain.header_at(h).unwrap().unwrap(), side.headers[h as usize]);
    }
    drop(chain);
    let (mut chain, opened) = open(&t, &main, 20);
    assert_eq!(opened, Opened { kept: top + 1 - 20, cut_bytes: 0 });
    assert_eq!(chain.tip().hash, hash_bytes(side.tip()));
    // the old branch is now the lighter one; it wins back with more work
    assert_eq!(chain.offer(main.after(30), FAR).unwrap().outcome, Outcome::Side { height: top });
    main.mine(2, 60);
    assert_eq!(
        chain.offer(main.after(top), FAR).unwrap().outcome,
        Outcome::Switched { from: 30, removed: top + 1 - 30, added: top + 2 - 30 }
    );
    assert_eq!(chain.tip().hash, hash_bytes(main.tip()));

    // an invalid header does not help a branch
    let mut cheat = main.fork_at(38);
    let mut bad = cheat.next_after(38, 60, 400);
    bad.pow.total_difficulty = bad.pow.total_difficulty + Difficulty::from_num(1_000_000);
    TestChain::remine(&mut bad, Difficulty::from_num(1));
    let offered = chain.offer(&[bad], FAR).unwrap();
    assert_eq!((offered.outcome, offered.bad), (Outcome::Nothing, Some(Reject::Work)));
    cheat.mine_salted(1, 60, 500);
    assert_eq!(chain.offer(cheat.after(38), FAR).unwrap().outcome, Outcome::Side { height: 39 });
    assert_eq!(chain.tip().hash, hash_bytes(main.tip()));

    // a branch that leaves the chain too far back is reported, not followed
    chain.set_max_reorg(3);
    let mut deep = main.fork_at(37);
    deep.mine_salted(8, 60, 600);
    assert!(deep.tip().total_difficulty() > main.tip().total_difficulty());
    assert_eq!(chain.offer(deep.after(37), FAR).unwrap().outcome, Outcome::TooDeep { depth: 4 });
    assert_eq!(chain.tip().hash, hash_bytes(main.tip()));
    // a branch from the starting point itself
    chain.set_max_reorg(u64::MAX);
    let mut root = main.fork_at(20);
    root.mine_salted(30, 60, 700);
    assert!(root.tip().total_difficulty() > main.tip().total_difficulty());
    assert_eq!(
        chain.offer(root.after(20), FAR).unwrap().outcome,
        Outcome::Switched { from: 20, removed: main.tip().height - 20, added: 30 }
    );
    drop(chain);
    let (chain, opened) = open(&t, &main, 20);
    assert_eq!((opened.kept, chain.tip().hash), (30, hash_bytes(root.tip())));
}

/// The difficulty follows the pace of the blocks, and with it the work of a
/// branch: of two branches of the same length the one whose blocks came
/// faster is the heavier. A header that claims another difficulty than the
/// rule gives is refused whichever way it errs.
#[test]
fn work_follows_the_pace_of_the_blocks() {
    // high enough for the rule's rounding to move it
    let mut main = TestChain::with_work(280);
    main.mine(12, 60); // to height 21
    let step = |c: &TestChain, h: usize| (c.headers[h].total_difficulty() - c.headers[h - 1].total_difficulty()).to_num();
    assert_eq!((step(&main, 14), step(&main, 21)), (280, 280), "one block a minute: unchanged");
    let mut slow = main.fork_at(18);
    slow.mine_salted(3, 600, 1);
    let mut fast = main.fork_at(18);
    fast.mine_salted(3, 5, 2);
    assert!(step(&slow, 21) < 280 && step(&fast, 21) > 280, "{} {}", step(&slow, 21), step(&fast, 21));

    let t = Temp::new("pace");
    let (mut chain, _) = open(&t, &main, 14);
    assert_eq!(chain.offer(main.after(14), FAR).unwrap().outcome, Outcome::Extended { added: 7 });
    assert_eq!(chain.offer(slow.after(18), FAR).unwrap().outcome, Outcome::Side { height: 21 });
    assert_eq!(
        chain.offer(fast.after(18), FAR).unwrap().outcome,
        Outcome::Switched { from: 18, removed: 3, added: 3 }
    );
    assert_eq!(chain.tip().total_work, fast.tip().total_difficulty().to_num());
    // after fast blocks the next header must carry the raised difficulty
    let honest = fast.next_after(21, 60, 3);
    let due = honest.total_difficulty() - fast.tip().total_difficulty();
    assert!(due.to_num() > step(&fast, 21), "the last block came after five seconds");
    for (claimed, reject) in [(due.to_num() - 1, Reject::Difficulty), (step(&fast, 21), Reject::Difficulty), (due.to_num() + 1, Reject::Difficulty)] {
        let mut h = honest.clone();
        h.pow.total_difficulty = fast.tip().total_difficulty() + Difficulty::from_num(claimed);
        // with proof of work to spare, so that only the rule can refuse it
        TestChain::remine(&mut h, Difficulty::from_num(due.to_num() + 1));
        let offered = chain.offer(&[h], FAR).unwrap();
        assert_eq!((offered.outcome, offered.bad), (Outcome::Nothing, Some(reject)), "claimed {claimed}, due {}", due.to_num());
    }
    assert_eq!(chain.offer(std::slice::from_ref(&honest), FAR).unwrap().outcome, Outcome::Extended { added: 1 });
    drop(chain);
    let (mut chain, opened) = open(&t, &main, 14);
    assert_eq!(opened.kept, 8, "the file holds the heavier branch and it verifies again");

    // work decides, not length: a long branch of slow blocks loses to a
    // shorter branch of fast ones
    fast.headers.push(honest);
    let mut long = fast.fork_at(22);
    long.mine_salted(40, 600, 10);
    assert_eq!(chain.offer(long.after(22), FAR).unwrap().outcome, Outcome::Extended { added: 40 });
    let mut short = fast.fork_at(22);
    short.mine_salted(25, 5, 20);
    assert!(short.tip().total_difficulty() > long.tip().total_difficulty(), "25 fast blocks outweigh 40 slow ones");
    assert_eq!(chain.offer(&short.headers[23..=40], FAR).unwrap().outcome, Outcome::Side { height: 40 });
    assert_eq!(
        chain.offer(&short.headers[41..], FAR).unwrap().outcome,
        Outcome::Switched { from: 22, removed: 40, added: 25 }
    );
    assert_eq!((chain.tip().height, chain.tip().hash), (47, hash_bytes(short.tip())));
    assert_eq!(chain.hash_at(48), None);
    drop(chain);
    // nothing of the longer branch is left in the file
    let record_len = 2 + write_header(short.tip()).unwrap().len();
    assert_eq!(std::fs::read(t.file()).unwrap().len(), 49 + 33 * record_len);
    let (chain, opened) = open(&t, &main, 14);
    assert_eq!((opened, chain.tip().hash), (Opened { kept: 33, cut_bytes: 0 }, hash_bytes(short.tip())));
}

/// Whatever happened to the file, what is used after opening it is a chain
/// that verified: a torn end and changed bytes are cut off and fetched again.
#[test]
fn the_file_is_verified_whenever_it_is_opened() {
    let mut main = TestChain::new();
    main.mine(1100, 60);
    let tip = main.tip().height;
    let t = Temp::new("file");
    let (mut chain, _) = open(&t, &main, 20);
    for batch in main.after(20).chunks(MAX_BATCH) {
        chain.offer(batch, FAR).unwrap();
    }
    assert_eq!(chain.tip().height, tip);
    // a branch from above the first remembered peaks, and one from below
    let mut high = main.fork_at(tip - 40);
    high.mine_salted(41, 5, 800);
    assert_eq!(chain.offer(high.after(tip - 40), FAR).unwrap().outcome, Outcome::Switched { from: tip - 40, removed: 40, added: 41 });
    let mut low = high.fork_at(tip - 300);
    low.mine_salted(400, 5, 900);
    assert_eq!(
        chain.offer(low.after(tip - 300), FAR).unwrap().outcome,
        Outcome::Switched { from: tip - 300, removed: 301, added: 400 }
    );
    let top = low.tip().height;
    assert_eq!(chain.tip().hash, hash_bytes(low.tip()));
    drop(chain);
    let whole = std::fs::read(t.file()).unwrap();
    let record_len = 2 + write_header(low.tip()).unwrap().len();

    // a torn last record
    std::fs::write(t.file(), &whole[..whole.len() - 7]).unwrap();
    let (mut chain, opened) = open(&t, &low, 20);
    assert_eq!(opened, Opened { kept: top - 21, cut_bytes: record_len as u64 - 7 });
    assert_eq!(chain.tip().height, top - 1);
    assert_eq!(chain.offer(low.after(top - 1), FAR).unwrap().outcome, Outcome::Extended { added: 1 });
    drop(chain);
    assert_eq!(std::fs::read(t.file()).unwrap(), whole, "the same bytes again");

    // rubbish after the end
    let mut longer = whole.clone();
    longer.extend_from_slice(&[0xAB; 1000]);
    std::fs::write(t.file(), &longer).unwrap();
    let (chain, opened) = open(&t, &low, 20);
    assert_eq!(opened, Opened { kept: top - 20, cut_bytes: 1000 });
    drop(chain);
    assert_eq!(std::fs::read(t.file()).unwrap(), whole);

    // one changed byte in the 500th header: the chain ends before it
    let mut bent = whole.clone();
    let at = 49 + 499 * record_len + 100;
    bent[at] ^= 0x40;
    std::fs::write(t.file(), &bent).unwrap();
    let (mut chain, opened) = open(&t, &low, 20);
    assert_eq!(opened.kept, 499);
    assert_eq!(opened.cut_bytes as usize, whole.len() - 49 - 499 * record_len);
    assert_eq!(chain.tip().hash, hash_bytes(&low.headers[20 + 499]));
    for batch in low.after(20 + 499).chunks(MAX_BATCH) {
        chain.offer(batch, FAR).unwrap();
    }
    assert_eq!(chain.tip().hash, hash_bytes(low.tip()));
    drop(chain);
    assert_eq!(std::fs::read(t.file()).unwrap(), whole);

    // a valid header of another chain spliced in: it does not follow
    let mut spliced = whole[..49 + 10 * record_len].to_vec();
    let foreign = main.fork_at(29).mine_salted(2, 60, 1000).tip().clone();
    assert_eq!(foreign.height, 31);
    let raw = write_header(&foreign).unwrap();
    spliced.extend_from_slice(&(raw.len() as u16).to_le_bytes());
    spliced.extend_from_slice(&raw);
    spliced.extend_from_slice(&whole[49 + 11 * record_len..]);
    std::fs::write(t.file(), &spliced).unwrap();
    let (_, opened) = open(&t, &low, 20);
    assert_eq!(opened.kept, 10);

    // a file that is no header file at all is not touched
    std::fs::write(t.file(), b"something else entirely, long enough to hold a head of forty-nine bytes").unwrap();
    assert_eq!(HeaderChain::open(&t.0, Net::Automated, &low.record(20)).err(), Some(OpenError::OtherStart));
    assert!(std::fs::read(t.file()).unwrap().starts_with(b"something else"));
}

#[test]
fn pending_branch_reports_the_current_depth_limit() {
    let mut main = TestChain::new();
    main.mine(12, 60);
    let mut side = main.fork_at(18);
    side.mine_salted(3, 60, 1);
    let dir = Temp::new("pending-depth-limit");
    let (mut chain, _) = open(&dir, &main, 15);
    chain.offer(main.after(15), FAR).unwrap();
    let candidates = side.after(18);
    let (first, rest) = candidates.split_first().unwrap();
    assert!(matches!(chain.offer(std::slice::from_ref(first), FAR).unwrap().outcome, Outcome::Side { .. }));
    chain.set_max_reorg(2);
    assert_eq!(chain.offer(rest, FAR).unwrap().outcome, Outcome::TooDeep { depth: 3 });
    assert_eq!(chain.tip().hash, hash_bytes(main.tip()));
}

/// K202: a point a wallet makes from a chain that began at the program's
/// point carries that point in its history - through any number of such
/// points - and the proof of the program's point is checked for it as for
/// the point itself; a point without that path, or with a spoiled one, is
/// refused as another point. (The filler headers of a test chain have no
/// proof of work, so the proof itself fails here at the same place each
/// time; that it passes for a later point of mainnet is the test in
/// `baked.rs`.)
#[test]
fn a_point_made_later_carries_the_proof_of_the_programs_point() {
    use fly_chain_headers::proof::{self, History, Refused};
    Net::Automated.enter();
    let mut main = TestChain::new();
    main.mine(160, 60);
    let all = main.headers.clone();
    let at = |h: u64| all.get(h as usize).cloned();
    let made = proof::build(&at, 60, Net::Automated, proof::POINTS).unwrap();
    let raw = proof::write(&made, Net::Automated).unwrap();
    let record = main.record(60);
    let start = checkpoint::check(&record, Net::Automated).unwrap();
    assert_eq!(start.track.target(), 60, "a point that names none follows itself");
    let as_itself = proof::check_for(&start, &raw);
    assert!(matches!(as_itself, History::Refused(Refused::Sample(..))), "{as_itself:?}");

    let t = Temp::new("k202");
    let (mut chain, _) = HeaderChain::open(&t.0, Net::Automated, &record).unwrap();
    chain.offer(main.after(60), FAR).unwrap();
    assert_eq!(chain.tip().height, main.tip().height);
    let later = chain.record_at(120, 1).unwrap().unwrap();
    let second = checkpoint::check(&later, Net::Automated).unwrap();
    assert_eq!(second.track.target(), 60);
    assert_eq!(proof::check_for(&second, &raw), as_itself, "checked as the point itself");

    // a point made from a chain that began at the later point still carries it
    let t2 = Temp::new("k202-on");
    let (mut on, _) = HeaderChain::open(&t2.0, Net::Automated, &later).unwrap();
    on.offer(main.after(120), FAR).unwrap();
    let third = checkpoint::check(&on.record_at(150, 1).unwrap().unwrap(), Net::Automated).unwrap();
    assert_eq!(third.track.target(), 60);
    assert_eq!(proof::check_for(&third, &raw), as_itself);

    // the same header without the path is a point of its own
    let plain = checkpoint::check(&main.record(120), Net::Automated).unwrap();
    assert_eq!(plain.track.target(), 120);
    assert_eq!(proof::check_for(&plain, &raw), History::Refused(Refused::Point));
    // a spoiled path, and a path that names another height, are not taken
    for k in 0..serde_json::from_slice::<Value>(&later).unwrap()["base"]["path"].as_array().unwrap().len() {
        let mut value: Value = serde_json::from_slice(&later).unwrap();
        value["base"]["path"][k] = json!(vec![7u8; 32]);
        if let Ok(spoiled) = checkpoint::check(&serde_json::to_vec(&value).unwrap(), Net::Automated) {
            assert_eq!(proof::check_for(&spoiled, &raw), History::Refused(Refused::Point), "{k}");
        }
    }
    for height in [59u64, 61, 119] {
        let mut value: Value = serde_json::from_slice(&later).unwrap();
        value["base"]["height"] = json!(height);
        if let Ok(moved) = checkpoint::check(&serde_json::to_vec(&value).unwrap(), Net::Automated) {
            assert_eq!(proof::check_for(&moved, &raw), History::Refused(Refused::Point), "{height}");
        }
    }
    // a path longer than any range has, or a height not below the point, is refused with the record
    let mut value: Value = serde_json::from_slice(&later).unwrap();
    value["base"]["path"] = json!(vec![vec![1u8; 32]; 65]);
    assert!(checkpoint::check(&serde_json::to_vec(&value).unwrap(), Net::Automated).is_err());
    let mut value: Value = serde_json::from_slice(&later).unwrap();
    value["base"]["height"] = json!(120);
    assert!(checkpoint::check(&serde_json::to_vec(&value).unwrap(), Net::Automated).is_err());
    // an unknown field in it is refused
    let mut value: Value = serde_json::from_slice(&later).unwrap();
    value["base"]["more"] = json!(1);
    assert!(checkpoint::check(&serde_json::to_vec(&value).unwrap(), Net::Automated).is_err());
}
