//! Offline differential fixture. Its anchor is the packaged sampled-history
//! statement. This test does not prove a genesis-to-fork execution.
use fly_chain_headers::{peaks::Peaks, proof, Net};
use grin_core::{
    consensus::{self, HeaderDifficultyInfo},
    core::{block::HeaderVersion, hash::Hashed, BlockHeader},
    global,
    pow::{self, Difficulty},
};

const FORK: u64 = 262_080;
const FIRST: u64 = 262_025;

fn full_hash(header: &BlockHeader) -> String {
    header
        .hash()
        .as_bytes()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}

fn using_graph_for_height(header: &BlockHeader, selecting_height: u64) -> bool {
    // Preserve the exact pre-PoW bytes, nonce and proof. Change only the
    // rules used to select the secondary graph implementation.
    let mut context = global::create_pow_context::<u64>(
        selecting_height,
        header.pow.edge_bits(),
        header.pow.proof.nonces.len(),
        1,
    )
    .unwrap();
    context
        .set_header_nonce(header.pre_pow(), None, false)
        .unwrap();
    context.verify(&header.pow.proof).is_ok()
}

fn check_window(run: &[BlockHeader], height: u64) -> Option<(u64, u32)> {
    // next_dma_difficulty drops row zero for both work and scaling, but reads
    // its timestamp. Fill its unused work explicitly. Every other row's delta
    // is derived from the preceding actual header.
    let end = usize::try_from(height.checked_sub(run.first()?.height)?).ok()?;
    let window = run.get(end.checked_sub(61)?..end)?;
    let newest_first = window.iter().enumerate().rev().map(|(i, h)| {
        let work = i
            .checked_sub(1)
            .map(|p| h.total_difficulty().to_num() - window[p].total_difficulty().to_num())
            .unwrap_or(1);
        HeaderDifficultyInfo::new(
            None,
            h.timestamp.timestamp() as u64,
            Difficulty::from_num(work),
            h.pow.secondary_scaling,
            h.pow.is_secondary(),
        )
    });
    let next = consensus::next_difficulty(height, newest_first);
    Some((next.difficulty.to_num(), next.secondary_scaling))
}

#[test]
fn first_mainnet_fork_checks_real_versioned_pow_frontier_and_available_dma() {
    Net::Main.enter();
    assert_eq!(consensus::HARD_FORK_INTERVAL, FORK);
    let saved = proof::read(include_bytes!("../points/main.history"), Net::Main).unwrap();
    assert_eq!(saved.point.height, 4_115_520);
    assert_eq!(
        full_hash(&saved.point),
        "000622ed34fb7c40c407c79d70b27bcf5841d1c2893da88c191779b7b4761482"
    );
    proof::check(&saved, Net::Main, saved.answers.len() as u32).unwrap();
    let answer = saved
        .answers
        .iter()
        .find(|a| {
            a.run.first().map(|h| h.height) == Some(FIRST)
                && a.run.last().map(|h| h.height) == Some(262_087)
        })
        .unwrap();
    let run = &answer.run;
    assert_eq!(run.len(), 63);
    for (i, h) in run.iter().enumerate() {
        assert_eq!(h.height, FIRST + i as u64);
        assert_eq!(h.version, consensus::header_version(h.height));
        pow::verify_size(h).unwrap();
        if let Some(prev) = i.checked_sub(1).map(|p| &run[p]) {
            assert_eq!(h.prev_hash, prev.hash());
            assert!(h.timestamp > prev.timestamp);
        }
    }
    let at = |height| &run[usize::try_from(height - FIRST).unwrap()];
    let before = at(FORK - 1);
    let after = at(FORK);
    assert_eq!(
        (before.version, after.version),
        (HeaderVersion(1), HeaderVersion(2))
    );
    assert_eq!((before.pow.edge_bits(), after.pow.edge_bits()), (29, 29));
    assert_eq!(
        full_hash(after),
        "000003b905723fc31902ce704d4416c3c40ec1c91b443f64d77d0b6956b3d8cb"
    );
    assert!(using_graph_for_height(before, FORK - 1));
    assert!(!using_graph_for_height(before, FORK));
    assert!(using_graph_for_height(after, FORK));
    assert!(!using_graph_for_height(after, FORK - 1));

    // The inclusion path for h262087 lies in the first mountain at the
    // packaged point. At each set bit of the earlier leaf count, its left
    // sibling covers one complete mountain of the prefix before the fork.
    let peaks = (0..64)
        .rev()
        .filter(|level| (FORK >> level) & 1 == 1)
        .map(|level| answer.place.path[level])
        .collect::<Vec<_>>();
    assert_eq!(peaks.len(), 12);
    let mut frontier = Peaks::from_parts(FORK, peaks).unwrap();
    assert_eq!(frontier.size(), 524_148);
    assert_eq!(frontier.root(), after.prev_root);
    for height in FORK..=262_087 {
        let h = at(height);
        assert_eq!(frontier.root(), h.prev_root);
        frontier.append(h).unwrap();
        match check_window(run, height) {
            None => assert!(height < 262_086),
            Some((work, scaling)) => {
                assert!(height >= 262_086);
                assert_eq!(
                    h.total_difficulty().to_num() - at(height - 1).total_difficulty().to_num(),
                    work
                );
                assert_eq!(h.pow.secondary_scaling, scaling);
                assert!(h.pow.to_difficulty(height).to_num() >= work);
            }
        }
    }
}
