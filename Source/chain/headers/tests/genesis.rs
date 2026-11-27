//! Regression vectors for streaming verification, including the first WTEMA
//! blocks where both predecessors still belong to an older consensus era.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
use fly_chain_headers::genesis::{GenesisError, GenesisVerifier};
use fly_chain_headers::{checkpoint, hash_bytes, read_header, rules::Reject, Net};
use grin_core::core::hash::Hashed;
use grin_core::core::BlockHeader;

fn main_headers() -> impl Iterator<Item = BlockHeader> {
    Net::Main.enter();
    let mut input: &[u8] = include_bytes!("mainnet/first-4100-headers.bin");
    std::iter::from_fn(move || {
        if input.is_empty() {
            return None;
        }
        let n = u16::from_be_bytes([input[0], input[1]]) as usize;
        let header = read_header(&input[2..2 + n]).unwrap();
        input = &input[2 + n..];
        Some(header)
    })
}

#[test]
fn mainnet_first_4100_from_exact_genesis() {
    let mut chain = GenesisVerifier::new(Net::Main).unwrap();
    let mut raw = main_headers();
    chain.check_genesis(&raw.next().unwrap()).unwrap();
    for h in raw {
        chain.push(&h, 2_000_000_000).unwrap();
    }
    assert_eq!(chain.tip().height, 4099);
    assert_eq!(chain.peaks().leaves(), 4100);
    assert!(
        chain.record(0).is_none(),
        "the checkpoint reader needs post-HF4 context"
    );
}

#[test]
fn network_and_full_genesis_are_pinned() {
    let main = GenesisVerifier::new(Net::Main).unwrap();
    let other = GenesisVerifier::new(Net::Test).unwrap();
    other.check_genesis(other.tip()).unwrap();
    assert_eq!(
        other.check_genesis(main.tip()),
        Err(GenesisError::WrongGenesis)
    );
    let mut changed = main.tip().clone();
    changed.output_mmr_size += 1;
    assert_eq!(hash_bytes(&changed), hash_bytes(main.tip()));
    assert_eq!(
        main.check_genesis(&changed),
        Err(GenesisError::WrongGenesis)
    );
}

#[test]
fn failures_leave_the_entire_verified_prefix_usable() {
    let mut chain = GenesisVerifier::new(Net::Main).unwrap();
    let mut raw = main_headers();
    let first = raw.nth(1).unwrap();
    assert_eq!(chain.push(&first, 0), Err(GenesisError::Future));
    let mut bad = first.clone();
    bad.version.0 += 1;
    assert_eq!(
        chain.push(&bad, 2_000_000_000),
        Err(GenesisError::Header(Reject::Version))
    );
    bad = first.clone();
    bad.prev_root = grin_core::core::hash::ZERO_HASH;
    assert_eq!(
        chain.push(&bad, 2_000_000_000),
        Err(GenesisError::Header(Reject::Root))
    );
    bad = first.clone();
    bad.pow.nonce ^= 1;
    assert_eq!(
        chain.push(&bad, 2_000_000_000),
        Err(GenesisError::Header(Reject::Pow))
    );
    assert_eq!(chain.tip().height, 0);
    assert_eq!(chain.peaks().leaves(), 1);
    chain.push(&first, 2_000_000_000).unwrap();
    chain.push(&raw.next().unwrap(), 2_000_000_000).unwrap();
}

// Mine real low-cost proofs on Grin's automated-test network. Build the
// reference difficulty iterator from *all* preceding headers, independently
// of the verifier's bounded window.
#[cfg(feature = "testkit")]
mod fork {
    use super::*;
    use grin_core::{
        consensus::{self, HeaderDifficultyInfo},
        core::pmmr,
        global,
        pow::{self, Difficulty},
    };

    fn next(
        chain: &[BlockHeader],
        peaks: &fly_chain_headers::peaks::Peaks,
        extra: u64,
    ) -> BlockHeader {
        let prev = chain.last().unwrap();
        let mut h = BlockHeader::default();
        h.height = prev.height + 1;
        h.version = consensus::header_version(h.height);
        h.prev_hash = prev.hash();
        h.prev_root = peaks.root();
        h.timestamp = prev.timestamp + chrono::Duration::seconds(60);
        h.output_mmr_size = pmmr::insertion_to_pmmr_index(prev.output_mmr_count() + 1);
        h.kernel_mmr_size = pmmr::insertion_to_pmmr_index(prev.kernel_mmr_count() + 1);
        let iter = chain.iter().enumerate().rev().map(|(i, header)| {
            let before = i
                .checked_sub(1)
                .map_or(0, |at| chain[at].total_difficulty().to_num());
            HeaderDifficultyInfo::new(
                None,
                header.timestamp.timestamp() as u64,
                Difficulty::from_num(header.total_difficulty().to_num() - before),
                header.pow.secondary_scaling,
                header.pow.is_secondary(),
            )
        });
        let next = consensus::next_difficulty(h.height, iter);
        let work = Difficulty::from_num(next.difficulty.to_num() + extra);
        h.pow.secondary_scaling = next.secondary_scaling;
        h.pow.total_difficulty = prev.total_difficulty() + work;
        pow::pow_size(&mut h, work, global::proofsize(), global::min_edge_bits()).unwrap();
        h
    }

    #[test]
    fn all_eras_including_first_two_hf4_steps_and_checkpoint_round_trip() {
        let mut verify = GenesisVerifier::new(Net::Automated).unwrap();
        let mut history = vec![verify.tip().clone()];
        for height in 1..=18 {
            if matches!(height, 11..=13) {
                // Valid proof, incorrect target. Check both sides of the fork.
                let wrong = next(&history, verify.peaks(), 1);
                assert_eq!(
                    verify.push(&wrong, 2_000_000_000),
                    Err(GenesisError::Header(Reject::Difficulty))
                );
            }
            let h = next(&history, verify.peaks(), 0);
            verify.push(&h, 2_000_000_000).unwrap();
            history.push(h);
        }
        assert_eq!(history[11].version.0, 4);
        assert_eq!(history[12].version.0, 5);
        let record = verify.record(2_000_000_000).unwrap();
        let start = checkpoint::check(&record, Net::Automated).unwrap();
        assert_eq!(start.hash(), hash_bytes(verify.tip()));
        assert_eq!(start.peaks, *verify.peaks());
    }
}

// Deterministic bounded fuzz corpus: serialized first successor and every
// one-bit change to it. Alternate encodings of the same decoded header are
// immaterial. Every genuinely altered header must leave the prefix untouched.
#[test]
fn single_bit_mutations_of_first_mainnet_successor_preserve_verified_state() {
    let mut chain = GenesisVerifier::new(Net::Main).unwrap();
    let first = main_headers().nth(1).unwrap();
    let mut bytes = fly_chain_headers::write_header(&first).unwrap();
    for index in 0..bytes.len() {
        for bit in 0..8 {
            bytes[index] ^= 1u8 << bit;
            if let Some(other) = read_header(&bytes) {
                if other != first {
                    assert!(
                        chain.push(&other, 2_000_000_000).is_err(),
                        "byte {index}, bit {bit}"
                    );
                }
            }
            bytes[index] ^= 1u8 << bit;
        }
    }
    assert_eq!(chain.tip().height, 0);
    chain.push(&first, 2_000_000_000).unwrap();
}
