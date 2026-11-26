//! What a build knows of the history before its starting point: nothing
//! without the proof, and with it (feature `history-proof`) that the
//! history answered for every point of its work.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::panic)]
use fly_chain_headers::proof::{self, History, Refused};
use fly_chain_headers::{baked_point, checkpoint, Net};

#[test]
fn the_starting_point_of_mainnet_and_its_history() {
    let start = checkpoint::check(baked_point(Net::Main).unwrap().record, Net::Main).unwrap();
    let history = proof::history_of(&start);
    if cfg!(feature = "history-proof") {
        let History::Sampled(passed) = history else { panic!("{history:?}") };
        assert_eq!((passed.height, passed.hash, passed.points), (start.height(), start.hash(), proof::POINTS));
        // the work before the point is all of its own but the last header's and the first block's
        assert!(passed.work < start.anchor.total_difficulty().to_num());
        assert_eq!(passed.work, start.prev.total_difficulty().to_num() - proof::first_work(Net::Main));
        assert!(passed.early > 200 && passed.early < proof::POINTS, "{}", passed.early);
        // the proof is for this header and no other
        let raw = proof::baked_history(Net::Main).unwrap();
        let mut other = start.clone();
        other.anchor = start.prev.clone();
        assert_eq!(proof::check_for(&other, raw), History::Refused(Refused::Point));
        // spoiled, it is refused and the point is on trust again - never taken for proved
        let mut spoiled = raw.to_vec();
        let middle = spoiled.len() / 2;
        spoiled[middle] ^= 1;
        assert!(matches!(proof::check_for(&start, &spoiled), History::Refused(_)));
        assert_eq!(proof::check_for(&start, &raw[..raw.len() - 1]), History::Refused(Refused::Form));
        assert_eq!(proof::check_for(&start, b""), History::Refused(Refused::Form));
    } else {
        assert_eq!(history, History::Unproved);
        assert!(proof::baked_history(Net::Main).is_none());
    }
    // the test network has no proof in any build
    let test = checkpoint::check(baked_point(Net::Test).unwrap().record, Net::Test).unwrap();
    assert_eq!(proof::history_of(&test), History::Unproved);
}

/// K202 on mainnet: a point the wallet makes from a chain that began at the
/// program's point carries that point, and the proof of history holds for
/// it; the real headers 4,115,500-4,115,600 were read from a synced node on
/// 26.11.2026 (`after-point.sh`).
#[test]
fn a_point_made_above_the_starting_point_of_mainnet_keeps_its_proof() {
    use fly_chain_headers::chain::HeaderChain;
    use fly_chain_headers::read_header;
    Net::Main.enter();
    let raw = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("mainnet").join("after-main-point.bin")).unwrap();
    let mut headers = Vec::new();
    let mut at = 0usize;
    while at < raw.len() {
        let size = usize::from(u16::from_be_bytes([raw[at], raw[at + 1]]));
        headers.push(read_header(&raw[at + 2..at + 2 + size]).unwrap());
        at += 2 + size;
    }
    assert_eq!((headers.first().unwrap().height, headers.last().unwrap().height), (4_115_500, 4_115_600));
    let record = baked_point(Net::Main).unwrap().record;
    let start = checkpoint::check(record, Net::Main).unwrap();
    assert_eq!(fly_chain_headers::hash_bytes(&headers[20]), start.hash(), "the file has the very point");
    let dir = std::env::temp_dir().join(format!("fly-k202-main-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut chain, _) = HeaderChain::open(&dir, Net::Main, record).unwrap();
    chain.offer(&headers[21..], u64::MAX / 2).unwrap();
    assert_eq!(chain.tip().height, 4_115_600);
    let own = checkpoint::check(&chain.record_at(4_115_590, 1).unwrap().unwrap(), Net::Main).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(own.track.target(), start.height());
    let history = proof::history_of(&own);
    if cfg!(feature = "history-proof") {
        let History::Extended(passed) = history else { panic!("{history:?}") };
        assert_eq!((passed.height, passed.hash), (start.height(), start.hash()));
    } else {
        assert_eq!(history, History::Unproved);
    }
}
