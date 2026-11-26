//! K202: a starting point of the owner's own is made only of a chain that
//! keeps the proof of the program's point; a chain that began at a point the
//! proof does not reach makes none. Real mainnet headers 4,115,500-4,115,600
//! (`chain/headers/tests/mainnet/after-main-point.bin`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::panic)]
use fly_chain_headers::chain::HeaderChain;
use fly_chain_headers::{baked_point, read_header, Net};
use grin_core::core::BlockHeader;

fn headers() -> Vec<BlockHeader> {
    Net::Main.enter();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../headers/tests/mainnet/after-main-point.bin");
    let raw = std::fs::read(path).unwrap();
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < raw.len() {
        let size = usize::from(u16::from_be_bytes([raw[at], raw[at + 1]]));
        out.push(read_header(&raw[at + 2..at + 2 + size]).unwrap());
        at += 2 + size;
    }
    out
}

#[test]
fn an_own_point_is_made_only_of_a_chain_that_keeps_the_proof() {
    let all = headers();
    let base = std::env::temp_dir().join(format!("fly-own-point-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    for d in ["a", "b"] {
        std::fs::create_dir_all(base.join(d)).unwrap();
    }
    let (mut chain, _) = HeaderChain::open(&base.join("a"), Net::Main, baked_point(Net::Main).unwrap().record).unwrap();
    chain.offer(&all[21..], u64::MAX / 2).unwrap();
    // from the program's point: refused only for being too near the tip
    let near = fly_chain::point_from(&chain, 1).unwrap_err();
    assert!(near.starts_with("no new starting point can be made yet"), "{near}");
    // a point of that chain without the path to the program's point
    let mut record: serde_json::Value = serde_json::from_slice(&chain.record_at(4_115_530, 1).unwrap().unwrap()).unwrap();
    assert!(record.as_object_mut().unwrap().remove("base").is_some());
    let (mut other, _) = HeaderChain::open(&base.join("b"), Net::Main, &serde_json::to_vec(&record).unwrap()).unwrap();
    other.offer(&all[31..], u64::MAX / 2).unwrap();
    let refused = fly_chain::point_from(&other, 1).unwrap_err();
    assert!(refused.starts_with("no starting point of your own is made from this chain"), "{refused}");
    let _ = std::fs::remove_dir_all(&base);
}
