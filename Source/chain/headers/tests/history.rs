//! The proof of history on the real beginning of the chain: the first
//! 4,100 headers of mainnet, as read from a synced node on 26.11.2026
//! (`dump_headers.py`). All of them are of the first era, where the
//! difficulty rule reads sixty-one headers and, near the first block, the
//! node's padding for the headers that never were.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::panic)]
use fly_chain_headers::proof::{self, Refused, Why};
use fly_chain_headers::{read_header, Net};
use grin_core::core::BlockHeader;

fn headers() -> Vec<BlockHeader> {
    Net::Main.enter();
    let raw = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("mainnet").join("first-4100-headers.bin")).unwrap();
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < raw.len() {
        let size = usize::from(u16::from_be_bytes([raw[at], raw[at + 1]]));
        out.push(read_header(&raw[at + 2..at + 2 + size]).unwrap());
        at += 2 + size;
    }
    assert_eq!(out.len(), 4100);
    assert_eq!(out[0].hash_bytes_for_test(), Net::Main.genesis_hash(), "the file begins with the first block of mainnet");
    out
}

trait HashBytes {
    fn hash_bytes_for_test(&self) -> [u8; 32];
}
impl HashBytes for BlockHeader {
    fn hash_bytes_for_test(&self) -> [u8; 32] {
        fly_chain_headers::hash_bytes(self)
    }
}

#[test]
fn a_proof_of_the_first_headers_passes_and_spoiled_ones_do_not() {
    let all = headers();
    let at = |h: u64| all.get(h as usize).cloned();
    let points = 60u32;
    let made = proof::build(&at, 4000, Net::Main, points).unwrap();
    let passed = proof::check(&made, Net::Main, points).unwrap();
    assert_eq!((passed.height, passed.points, passed.early), (4000, points, points));
    assert_eq!(passed.work, all[3999].total_difficulty().to_num() - all[0].total_difficulty().to_num());
    assert_eq!(passed.hash, fly_chain_headers::hash_bytes(&all[4000]));
    // written and read back, it is the same proof
    let bytes = proof::write(&made, Net::Main).unwrap();
    let read = proof::read(&bytes, Net::Main).unwrap();
    assert_eq!(proof::check(&read, Net::Main, points), Ok(passed));
    assert_eq!(proof::write(&read, Net::Main).unwrap(), bytes);
    assert!(proof::read(&bytes[..bytes.len() - 1], Net::Main).is_none(), "cut short");
    assert!(proof::read(&[bytes.as_slice(), &[0]].concat(), Net::Main).is_none(), "with a tail");
    assert!(proof::read(&bytes, Net::Test).is_none(), "of another network");

    // other points: the answers are for the wrong places
    assert!(matches!(proof::check(&made, Net::Main, points - 1), Err(Refused::Form)));
    let mut fewer = made.clone();
    fewer.answers.pop();
    assert!(matches!(proof::check(&fewer, Net::Main, points - 1), Err(Refused::Sample(_, Why::Work(_)))));
    // two answers changed places
    let mut swapped = made.clone();
    swapped.answers.swap(0, 1);
    assert!(matches!(proof::check(&swapped, Net::Main, points), Err(Refused::Sample(0, Why::Work(_)))));
    // a tree that claims more work than the history has
    let mut more = made.clone();
    more.root.top.sum += 1;
    assert_eq!(proof::check(&more, Net::Main, points), Err(Refused::Tree));
    // a run without its earliest header, and one with a header that is not the next
    let mut short = made.clone();
    short.answers[3].run.remove(0);
    assert_eq!(proof::check(&short, Net::Main, points), Err(Refused::Sample(3, Why::Run)));
    // a header of the run with a field changed: its proof of work no longer holds
    let mut touched = made.clone();
    let middle = touched.answers[5].run.len() / 2;
    touched.answers[5].run[middle].pow.secondary_scaling += 1;
    assert_eq!(proof::check(&touched, Net::Main, points), Err(Refused::Sample(5, Why::Pow)));
    // the header of the leaf placed elsewhere in the header tree
    let mut moved = made.clone();
    moved.answers[7].place = made.answers[8].place.clone();
    assert_eq!(proof::check(&moved, Net::Main, points), Err(Refused::Sample(7, Why::Place)));
    // another header before the point
    let mut other = made.clone();
    other.last = all[3998].clone();
    assert_eq!(proof::check(&other, Net::Main, points), Err(Refused::Point));
    // a point whose proof of work does not hold
    let mut point = made.clone();
    point.point.pow.nonce += 1;
    assert_eq!(proof::check(&point, Net::Main, points), Err(Refused::Point));
}

/// Next to the first block the rule has fewer headers than it reads, and
/// the node pads: the proof holds there too, and at every size of history.
#[test]
fn a_proof_holds_right_after_the_first_block() {
    let all = headers();
    let at = |h: u64| all.get(h as usize).cloned();
    for point in [3u64, 4, 5, 30, 61, 62, 63, 64, 65, 200, 1023, 1024, 1025] {
        let made = proof::build(&at, point, Net::Main, 16).unwrap_or_else(|| panic!("point {point}"));
        let passed = proof::check(&made, Net::Main, 16).unwrap_or_else(|e| panic!("point {point}: {e:?}"));
        assert_eq!(passed.height, point);
        assert!(made.answers.iter().all(|a| a.run.len() <= 63 && a.run[0].height == proof::run_from(a.index + 1)));
    }
    assert!(proof::build(&at, 2, Net::Main, 16).is_none(), "nothing to sample before the third header");
    assert!(proof::build(&at, 4100, Net::Main, 16).is_none(), "the point itself is not in the file");
    assert!(proof::build(&at, 100, Net::Main, 0).is_none());
}
