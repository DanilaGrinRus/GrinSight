//! us-fixture DIR: a synthetic testnet chain for the C ABI test (feature
//! `testkit`). Writes the archive header and its PIBD segments, three blocks
//! with their headers, a block that hides a spend, a genesis checkpoint and a
//! header without valid PoW, plus expected.txt with what the Rust core says.
//! Never valid on a real network.

use grin_core::core::hash::Hashed;
use grin_core::core::{BlockHeader, OutputIdentifier};
use grin_core::global::{self, ChainTypes};
use grin_core::ser::{self, ProtocolVersion};
use grin_util::ToHex;
use std::fs;
use std::path::Path;
use grinsight_state::headers::Verifier;
use grinsight_state::outputs::{input_commits, output_ids, OutputState};
use grinsight_state::testkit::{block, id, reference};

fn w<T: ser::Writeable>(dir: &Path, name: &str, v: &T) {
    fs::write(dir.join(name), ser::ser_vec(v, ProtocolVersion::local()).unwrap()).unwrap();
}

fn main() {
    let dir = std::env::args().nth(1).expect("usage: us-fixture DIR");
    let dir = Path::new(&dir);
    fs::create_dir_all(dir).unwrap();
    global::set_local_chain_type(ChainTypes::Testnet);

    // Archive: 3000 outputs, every 4th spent; segments as a compacted node serves them.
    let mut r = reference(3000, 4);
    let archive = r.header();
    let (bm, out) = r.compacted_segments(5);
    w(dir, "archive_header.bin", &archive);
    for (i, s) in bm.iter().enumerate() {
        // Bitmap segments travel as BitmapSegment (the wire format).
        w(dir, &format!("bitmap_{i:03}.bin"), &grin_chain::txhashset::BitmapSegment::from(s.clone()));
    }
    for (i, s) in out.iter().enumerate() {
        w(dir, &format!("output_{i:03}.bin"), s);
    }
    let st0 = OutputState::from_segments(&archive, &bm, &out).unwrap();

    let watched = id(1);
    let script: Vec<(Vec<OutputIdentifier>, Vec<OutputIdentifier>)> = vec![
        (vec![id(5_000_001)], vec![id(2)]),
        (vec![id(5_000_002), id(5_000_003)], vec![watched, id(3)]),
        (vec![id(5_000_004)], vec![id(5_000_001)]),
    ];
    let mut headers = vec![archive.clone()];
    let mut st = st0.clone();
    for (k, (o, i)) in script.iter().enumerate() {
        let mut b = block(&BlockHeader::default(), o, i);
        let sorted: Vec<OutputIdentifier> = input_commits(&b).iter().map(|c| *i.iter().find(|x| x.commit == *c).unwrap()).collect();
        r.apply(&output_ids(&b), &sorted);
        let mut h = r.header();
        h.height = k as u64 + 1;
        h.pow.nonce = k as u64 + 1;
        b.header = h.clone();
        st = st.apply_block(&h, &b).unwrap();
        w(dir, &format!("header_{}.bin", k + 1), &h);
        w(dir, &format!("block_{}.bin", k + 1), &b);
        headers.push(h);
    }
    // Block 2 hiding the spend of `watched` (another unspent output instead).
    let mut lying = block(&headers[2], &script[1].0, &[id(5), id(3)]);
    lying.header = headers[2].clone();
    w(dir, "block_2_hides_spend.bin", &lying);

    // Header chain: genesis checkpoint, and a child without valid PoW.
    let v = Verifier::from_genesis();
    let g = &v.tip;
    let mut t = format!(
        "RWM1\nheight 0\nhash {}\nheader {}\nleaves {}\nsize {}\nroot {}\n",
        g.hash().to_hex(),
        ser::ser_vec(g, ProtocolVersion::local()).unwrap().to_hex(),
        v.mmr.leaves,
        v.mmr.size,
        v.mmr.root().to_hex()
    );
    for (pos, height, hash) in &v.mmr.peaks {
        t.push_str(&format!("peak {pos} {height} {}\n", hash.to_hex()));
    }
    fs::write(dir.join("genesis.rwm"), t).unwrap();
    let mut bad = g.clone();
    bad.height = 1;
    bad.prev_hash = g.hash();
    bad.prev_root = v.mmr.root();
    bad.timestamp = g.timestamp + chrono_secs(60);
    bad.output_mmr_size = g.output_mmr_size + 1;
    bad.kernel_mmr_size = g.kernel_mmr_size + 1;
    w(dir, "header_bad_pow.bin", &bad);

    let ex = format!(
        "segments_bitmap {}\nsegments_output {}\narchive_utxo {}\nfinal_utxo {}\nfinal_mmr_size {}\nfinal_output_root {}\nwatched {}\nnew_output {}\nnew_output_pos {}\ngenesis_hash {}\n",
        bm.len(),
        out.len(),
        st0.utxo_count(),
        st.utxo_count(),
        st.size,
        st.output_root().to_hex(),
        watched.commit.0.to_hex(),
        id(5_000_002).commit.0.to_hex(),
        st.position(&id(5_000_002).commit.0).unwrap(),
        g.hash().to_hex(),
    );
    fs::write(dir.join("expected.txt"), &ex).unwrap();
    print!("{ex}");
}

fn chrono_secs(s: i64) -> chrono::Duration {
    chrono::Duration::seconds(s)
}
