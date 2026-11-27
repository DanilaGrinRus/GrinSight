use super::*;
use fly_chain_headers::{peaks::Peaks, write_header};
use grin_core::consensus::{self, HeaderDifficultyInfo};
use grin_core::core::{hash::Hashed, pmmr, BlockHeader};
use grin_core::{global, pow};

/// Mine every block, including the early DAA epochs. No filler headers.
#[test]
fn full_generation_and_atomic_advance_on_mined_fixture() {
    let net = Net::Automated;
    net.enter();
    let dir = tempfile::tempdir().unwrap();
    let export = dir.path().join("history");
    let mut output = File::create(&export).unwrap();
    fn frame(f: &mut File, h: &BlockHeader) {
        let raw = write_header(h).unwrap();
        f.write_all(&(raw.len() as u16).to_be_bytes()).unwrap();
        f.write_all(&raw).unwrap();
    }

    let mut prev = grin_core::genesis::genesis_dev().header;
    frame(&mut output, &prev);
    let mut peaks = Peaks::empty();
    peaks.append(&prev).unwrap();
    let mut infos = vec![HeaderDifficultyInfo::new(
        None,
        prev.timestamp.timestamp() as u64,
        prev.total_difficulty(),
        prev.pow.secondary_scaling,
        prev.pow.is_secondary(),
    )];
    for height in 1..=18 {
        let next = consensus::next_difficulty(height, infos.iter().rev().cloned());
        let mut h = BlockHeader::default();
        h.height = height;
        h.version = consensus::header_version(height);
        h.prev_hash = prev.hash();
        h.prev_root = peaks.root();
        h.timestamp = prev.timestamp + chrono::Duration::seconds(60);
        h.output_mmr_size = pmmr::insertion_to_pmmr_index(prev.output_mmr_count() + 1);
        h.kernel_mmr_size = pmmr::insertion_to_pmmr_index(prev.kernel_mmr_count() + 1);
        h.pow.secondary_scaling = next.secondary_scaling;
        h.pow.total_difficulty = prev.total_difficulty() + next.difficulty;
        h.pow.proof.edge_bits = global::min_edge_bits();
        pow::pow_size(
            &mut h,
            next.difficulty,
            global::proofsize(),
            global::min_edge_bits(),
        )
        .unwrap();
        infos.push(HeaderDifficultyInfo::new(
            None,
            h.timestamp.timestamp() as u64,
            next.difficulty,
            h.pow.secondary_scaling,
            h.pow.is_secondary(),
        ));
        frame(&mut output, &h);
        peaks.append(&h).unwrap();
        prev = h;
    }
    drop(output);
    let root = dir.path().join("public");
    let (a, pa) = generate::from_dump(net, &export, 17).unwrap();
    let (b, pb) = generate::from_dump(net, &export, 18).unwrap();
    let old = publish(&root, net, &a, &pa).unwrap();
    let before = object_path(&root, &old);
    let new = publish(&root, net, &b, &pb).unwrap();
    assert!(before.join("checkpoint.json").is_file());
    assert_eq!(verify(&root, net).unwrap(), new);
    assert!(publish(&root, net, &a, &pa).is_err());
    assert_eq!(verify(&root, net).unwrap(), new);
}
