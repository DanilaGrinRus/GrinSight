//! An independent check of this crate on real headers: the 14,734 mainnet
//! headers of a colleague's research package ("FlyClient for Grin - audit
//! package", draft 0.1 of 26.11.2026; heights 4,099,166-4,113,899), with
//! the header MMR peaks and the two context headers that package starts
//! from. The data were gathered and first verified by code that shares
//! nothing with this crate (Python, and a Cuckatoo verifier of its own).
//!
//! Here every one of those headers must pass what a header passes on its
//! way into the wallet: it commits to all headers before it (`prev_root`
//! against the peaks), its proof of work is valid, and it follows the two
//! before it by the difficulty rule. The starting peaks are the package's
//! and are taken on trust here - what is checked is that the chain built
//! on them is consistent with them, header by header.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::panic)]
use fly_chain_headers::peaks::Peaks;
use fly_chain_headers::{read_header, rules, write_header, Net};
use grin_core::core::hash::Hash;

const HEADER: usize = 415;

fn bytes_of(value: &serde_json::Value) -> Vec<u8> {
    value.as_array().unwrap().iter().map(|b| u8::try_from(b.as_u64().unwrap()).unwrap()).collect()
}

#[test]
fn the_colleagues_mainnet_headers_pass_header_by_header() {
    Net::Main.enter();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("colleague");
    let root: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join("research-root.json")).unwrap()).unwrap();
    let start = root["height"].as_u64().unwrap();
    let hashes: Vec<Hash> = root["peaks"].as_array().unwrap().iter().map(|p| Hash::from_vec(&bytes_of(p))).collect();
    // the package names the size of the range, not the number of its leaves
    let size = root["mmr_size"].as_u64().unwrap();
    let leaves = [start, start + 1].into_iter().find(|n| Peaks::from_parts(*n, hashes.clone()).is_ok_and(|p| p.size() == size)).expect("the peaks are of the start");
    let mut peaks = Peaks::from_parts(leaves, hashes).unwrap();
    let context: Vec<_> = root["context"].as_array().unwrap().iter().map(|c| read_header(&bytes_of(c)).unwrap()).collect();
    assert_eq!(context.len(), 2);
    // the package lists the context newest first
    let (mut older, mut prev) = (context[1].clone(), context[0].clone());
    assert_eq!((older.height, prev.height), (start - 1, start));

    let raw = std::fs::read(dir.join("headers.bin")).unwrap();
    assert_eq!(raw.len() % HEADER, 0);
    let mut count = 0u64;
    for one in raw.chunks(HEADER) {
        let header = read_header(one).unwrap_or_else(|| panic!("header {count} of the file is not read"));
        assert_eq!(write_header(&header).unwrap(), one, "height {}: read and written back the same", header.height);
        // the peaks hold every header before this one, as its prev_root says
        if peaks.leaves() < header.height {
            peaks.append(&prev).unwrap();
        }
        assert_eq!(peaks.leaves(), header.height);
        assert_eq!(header.prev_root, peaks.root(), "height {}: the commitment to all headers before it", header.height);
        rules::check_step(&older, &prev, &header).unwrap_or_else(|why| panic!("height {}: {why:?}", header.height));
        older = prev;
        prev = header;
        count += 1;
    }
    assert_eq!(count, 14_734);
    assert_eq!((prev.height, start + count), (4_113_899, 4_113_899));
}

fn fixture() -> (Vec<grin_core::core::BlockHeader>, u64) {
    Net::Main.enter();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("colleague");
    let root: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join("research-root.json")).unwrap()).unwrap();
    let mut headers: Vec<_> = root["context"].as_array().unwrap().iter().rev().map(|c| read_header(&bytes_of(c)).unwrap()).collect();
    let raw = std::fs::read(dir.join("headers.bin")).unwrap();
    headers.extend(raw.chunks(HEADER).map(|one| read_header(one).unwrap()));
    (headers, root["height"].as_u64().unwrap())
}

/// The work of the same headers, laid out as a line and sampled: the
/// tree of sums, the points drawn from a hash, and every point answered by
/// the header that covers it. The total over the stretch the colleague's
/// package compares (14,731 headers after height 4,099,168) is the number
/// that package states.
#[test]
fn the_work_of_those_headers_is_sampled() {
    use fly_chain_headers::sample::{check_leaf, covers, draw, leaf_of, seed, Leaf, Node, Path, Refused, Tree};
    let (headers, _) = fixture();
    // the stretch after the package's fork height: three headers of context, then the leaves
    let below = 4_099_168u64;
    let first = headers.iter().position(|h| h.height == below + 1).unwrap();
    let leaves: Vec<Leaf> = (first..headers.len()).map(|i| leaf_of(&headers[i - 1], &headers[i]).unwrap()).collect();
    assert_eq!(leaves.len(), 14_731);
    let tree = Tree::build(&leaves).unwrap();
    let root = tree.root().unwrap();
    assert_eq!(root.leaves, 14_731);
    assert_eq!(root.top.sum, 1_299_763_030_229, "the suffix work the package states");
    assert_eq!(root.top.sum, headers.last().unwrap().total_difficulty().to_num() - headers[first - 1].total_difficulty().to_num());

    let point_hash = fly_chain_headers::hash_bytes(headers.last().unwrap());
    let points = 420u32;
    let drawn = seed(0, &point_hash, below, &root, points);
    assert_ne!(drawn, seed(1, &point_hash, below, &root, points), "another network, other points");
    assert_ne!(drawn, seed(0, &point_hash, below + 1, &root, points));
    assert_ne!(drawn, seed(0, &point_hash, below, &root, points + 1));
    let mut other = root;
    other.top.sum += 1;
    assert_ne!(drawn, seed(0, &point_hash, below, &other, points), "another tree, other points");

    let mut seen = std::collections::BTreeSet::new();
    for number in 0..points {
        let point = draw(&drawn, number, root.top.sum).unwrap();
        assert!(point < root.top.sum);
        let index = tree.leaf_at(point).unwrap();
        let leaf = leaves[index];
        let path = tree.path(index).unwrap();
        covers(&root, point, index as u64, &leaf, &path).unwrap();
        let at = first + index;
        check_leaf(&leaf, &headers[at - 2], &headers[at - 1], &headers[at]).unwrap();
        seen.insert(index);
        if number == 0 {
            // the same leaf shown for a point it does not cover
            let begin = fly_chain_headers::sample::begins_at(&root, index as u64, &leaf, &path).unwrap();
            assert_eq!(covers(&root, begin + leaf.work, index as u64, &leaf, &path), Err(Refused::Point));
            if begin > 0 {
                assert_eq!(covers(&root, begin - 1, index as u64, &leaf, &path), Err(Refused::Point));
            }
            covers(&root, begin, index as u64, &leaf, &path).unwrap();
            covers(&root, begin + leaf.work - 1, index as u64, &leaf, &path).unwrap();
            // another leaf's work, another place, another path
            let more = Leaf { work: leaf.work + 1, ..leaf };
            assert_eq!(covers(&root, point, index as u64, &more, &path), Err(Refused::Path));
            assert_eq!(covers(&root, point, index as u64 ^ 1, &leaf, &path), Err(Refused::Path));
            let mut short = path.clone();
            short.beside.pop();
            assert_eq!(covers(&root, point, index as u64, &leaf, &short), Err(Refused::Path));
            let mut long = path.clone();
            long.beside.push(Node { hash: [0; 32], sum: 0 });
            assert_eq!(covers(&root, point, index as u64, &leaf, &long), Err(Refused::Path));
            // a node beside the way that claims more work than it has
            let mut fat = path.clone();
            fat.beside[0].sum += 1;
            assert_eq!(covers(&root, point, index as u64, &leaf, &fat), Err(Refused::Path));
            assert_eq!(covers(&root, point, root.leaves, &leaf, &path), Err(Refused::Shape));
            // the leaf tied to other headers
            assert_eq!(check_leaf(&leaf, &headers[at - 3], &headers[at - 2], &headers[at - 1]), Err(Refused::Leaf));
            assert!(matches!(check_leaf(&leaf, &headers[at - 3], &headers[at - 1], &headers[at]), Err(Refused::Header(_))));
        }
    }
    // the points fall where the work is: many different headers answer
    assert!(seen.len() > 400, "{}", seen.len());
    // drawn again, the same points
    assert_eq!(draw(&drawn, 7, root.top.sum), draw(&drawn, 7, root.top.sum));
    assert_eq!(draw(&drawn, 7, 0), None);
    let _ = Path { beside: Vec::new() };
}

/// Trees of every small size: each point of the line leads to the one
/// leaf that covers it, and a leaf begins where the work before it ends.
#[test]
fn every_point_of_a_small_line_has_its_leaf() {
    use fly_chain_headers::sample::{begins_at, covers, Leaf, Refused, Tree};
    assert!(Tree::build(&[]).is_none());
    for count in 1u64..=17 {
        let leaves: Vec<Leaf> = (0..count).map(|i| Leaf { height: 100 + i, hash: [i as u8; 32], work: 1 + (i * 7) % 5 }).collect();
        let tree = Tree::build(&leaves).unwrap();
        let root = tree.root().unwrap();
        assert_eq!(root.top.sum, leaves.iter().map(|l| l.work).sum::<u64>());
        let mut begin = 0u64;
        for (index, leaf) in leaves.iter().enumerate() {
            let path = tree.path(index).unwrap();
            assert_eq!(begins_at(&root, index as u64, leaf, &path), Ok(begin), "{count} leaves, leaf {index}");
            for point in begin..begin + leaf.work {
                assert_eq!(tree.leaf_at(point), Some(index));
                covers(&root, point, index as u64, leaf, &path).unwrap();
                // no other leaf answers for this point
                for (wrong, other) in leaves.iter().enumerate().filter(|(w, _)| *w != index) {
                    assert!(covers(&root, point, wrong as u64, other, &tree.path(wrong).unwrap()) == Err(Refused::Point));
                }
            }
            begin += leaf.work;
        }
        assert_eq!(tree.leaf_at(begin), None, "past the end of the line");
        assert!(tree.path(leaves.len()).is_none());
    }
    // heights with a gap, and a leaf without work, make no tree
    let leaf = |height: u64, work: u64| Leaf { height, hash: [1; 32], work };
    assert!(Tree::build(&[leaf(5, 1), leaf(7, 1)]).is_none());
    assert!(Tree::build(&[leaf(5, 1), leaf(6, 0)]).is_none());
    assert!(Tree::build(&[leaf(5, u64::MAX), leaf(6, 1)]).is_none(), "work that does not fit");
}
