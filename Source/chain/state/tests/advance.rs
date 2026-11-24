//! The collected state carried forward by the blocks of a real chain of
//! the Grin node's own code, and back. Run with
//! `cargo test --features testkit`.
#![cfg(feature = "testkit")]
use fly_chain_state::advance::{Applied, Check, Live, Rejected};
use fly_chain_state::blocks::{AddError, Blocks, BlocksError, Reopened, FILE_NAME};
use fly_chain_state::testkit::Temp;
use fly_chain_state::testkit::Source;
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::{Block, BlockHeader, Inputs, OutputFeatures};
use grin_core::global::{self, ChainTypes};

/// The chain of 236 blocks the state tests use: the archive header is 210.
fn shared() -> &'static Source {
    static SOURCE: std::sync::OnceLock<Source> = std::sync::OnceLock::new();
    let source = SOURCE.get_or_init(|| Source::mine(236));
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    source
}

fn live_at(source: &Source, height: u64) -> Live {
    let mut live = Live::new(source.collect()).unwrap();
    for b in &source.blocks[211..=height as usize] {
        live.apply(b, &b.header, Check::Kept, None).unwrap();
    }
    live
}

/// Everything about a state that can be compared.
fn picture(live: &Live, source: &Source) -> (Hash, (Hash, Hash, Hash), usize, Vec<Option<u64>>) {
    let known: Vec<Option<u64>> = source
        .blocks
        .iter()
        .flat_map(|b| b.outputs().iter().map(|o| live.unspent(&o.commitment().0).map(|u| u.pos)).collect::<Vec<_>>())
        .collect();
    (live.header().hash(), live.roots(), live.unspent_count(), known)
}

/// Block after block from the archive header to the tip: each one passes
/// the node's block check and gives the roots its header commits to, and
/// at the end the unspent outputs are the chain's.
#[test]
fn blocks_carry_the_state_forward() {
    let source = shared();
    let mut live = Live::new(source.collect()).unwrap();
    assert_eq!((live.header().height, live.depth()), (210, 0));
    for b in &source.blocks[211..] {
        let before = live.unspent_count();
        // a coinbase output is spendable three blocks on: the size of the
        // output MMR three blocks back is where the mature ones end
        let mature_below = source.blocks[b.header.height as usize - 3].header.output_mmr_size;
        let applied = live.apply(b, &b.header, Check::Arrived, Some(mature_below)).unwrap();
        let inputs: Vec<grin_core::core::CommitWrapper> = b.inputs().into();
        assert_eq!(applied, Applied { spent: inputs.len(), created: b.outputs().len(), maturity_checked: true });
        assert_eq!(live.unspent_count(), before + applied.created - applied.spent);
        assert_eq!(live.roots(), (b.header.output_root, b.header.range_proof_root, b.header.kernel_root));
    }
    assert_eq!((live.header().height, live.depth()), (236, 26));
    let expected = source.unspent_at(236);
    assert_eq!(live.unspent_count(), expected.len());
    for (commitment, id) in &expected {
        let found = live.unspent(commitment.as_slice().try_into().unwrap()).unwrap();
        assert!(found.features == id.features);
    }
    // an output that was spent on the way is not there
    let spent: Vec<grin_core::core::CommitWrapper> = source.blocks[230].inputs().into();
    assert!(live.unspent(&spent[0].commitment().0).is_none());
}

/// Taking blocks back gives exactly the state there was, and going forward
/// again exactly the state there would have been.
#[test]
fn blocks_are_taken_back() {
    let source = shared();
    let at_220 = picture(&live_at(source, 220), source);
    let at_236 = picture(&live_at(source, 236), source);
    assert_ne!(at_220, at_236);
    let mut live = live_at(source, 236);
    for _ in 0..16 {
        assert!(live.undo());
    }
    assert_eq!(picture(&live, source), at_220);
    for b in &source.blocks[221..] {
        live.apply(b, &b.header, Check::Arrived, None).unwrap();
    }
    assert_eq!(picture(&live, source), at_236);
    // back to the archive header and no further
    let at_210 = picture(&Live::new(source.collect()).unwrap(), source);
    for _ in 0..26 {
        assert!(live.undo());
    }
    assert_eq!(picture(&live, source), at_210);
    assert!(!live.undo());
    assert_eq!(picture(&live, source), at_210);
    // The bitmap as it was at any height on the way - without taking
    // anything back.
    let live = live_at(source, 236);
    for height in [210u64, 211, 220, 235, 236] {
        assert_eq!(live.bitmap_at(height).as_ref(), Some(live_at(source, height).bitmap()), "at {height}");
    }
    assert!(live.bitmap_at(209).is_none() && live.bitmap_at(237).is_none());
    assert_eq!(picture(&live, source), at_236, "asking changes nothing");
    let by_position = live.unspent_between(0, u64::MAX);
    assert_eq!(by_position.len(), live.unspent_count());
    assert!(by_position.windows(2).all(|pair| pair[0].0 < pair[1].0));
    // a stretch of positions: those in it, both ends included
    let (first, last) = (by_position[10].0, by_position[40].0);
    assert_eq!(live.unspent_between(first, last), by_position[10..=40].to_vec());
    assert_eq!(live.unspent_between(first + 1, last - 1), by_position[11..40].to_vec());
    // what is forgotten cannot be taken back
    let mut live = live_at(source, 236);
    live.forget_before(3);
    assert_eq!(live.depth(), 3);
    assert!(live.bitmap_at(232).is_none() && live.bitmap_at(233).is_some());
    assert!(live.undo() && live.undo() && live.undo() && !live.undo());
    assert_eq!(live.header().height, 233);
}

fn with_inputs(block: &Block, change: impl FnOnce(&mut Vec<grin_core::core::CommitWrapper>)) -> Block {
    let mut inputs: Vec<grin_core::core::CommitWrapper> = block.inputs().into();
    change(&mut inputs);
    let mut other = block.clone();
    other.body.inputs = Inputs::CommitOnly(inputs);
    other
}

/// A block is applied only if it is the next one, comes with the verified
/// header itself, spends what is unspent, and gives the roots the header
/// commits to. Whatever is refused leaves the state as it was.
#[test]
fn a_block_that_does_not_fit_is_refused() {
    let source = shared();
    let mut live = live_at(source, 229);
    let before = picture(&live, source);
    let good = &source.blocks[230];
    let header: &BlockHeader = &good.header;
    let refused = |live: &mut Live, block: &Block, verified: &BlockHeader, check: Check, mature: Option<u64>, why: Rejected| {
        assert_eq!(live.apply(block, verified, check, mature), Err(why));
        assert_eq!(picture(live, source), before, "after {why:?}");
    };

    // not the next block: the one after it, and the one already applied
    refused(&mut live, &source.blocks[231], &source.blocks[231].header, Check::Kept, None, Rejected::NotNext);
    refused(&mut live, &source.blocks[229], &source.blocks[229].header, Check::Kept, None, Rejected::NotNext);

    // The right contents under a header that has the verified header's
    // hash and says something else: the hash of a header is the hash of its
    // proof of work alone.
    let mut other = good.clone();
    other.header.total_kernel_offset = source.blocks[229].header.total_kernel_offset.clone();
    assert_eq!(other.header.hash(), header.hash());
    refused(&mut live, &other, header, Check::Arrived, None, Rejected::Header);
    // and another block's contents with the verified header put on top
    let mut other = source.blocks[231].clone();
    other.header = header.clone();
    refused(&mut live, &other, header, Check::Kept, None, Rejected::Roots);

    // an input that spends what is not there: never made, and spent before
    let never = source.forged_next().outputs()[0].commitment();
    let fake = with_inputs(good, |inputs| inputs[0] = grin_core::core::CommitWrapper::from(never));
    refused(&mut live, &fake, header, Check::Kept, None, Rejected::Input);
    let gone: Vec<grin_core::core::CommitWrapper> = source.blocks[229].inputs().into();
    let again = with_inputs(good, |inputs| inputs[0] = gone[0]);
    refused(&mut live, &again, header, Check::Kept, None, Rejected::Input);
    // the same output spent twice in one block
    let twice = with_inputs(good, |inputs| inputs.push(inputs[0]));
    refused(&mut live, &twice, header, Check::Kept, None, Rejected::Input);
    // an input left out, one more spent: the bitmap would not be the header's
    let fewer = with_inputs(good, |inputs| {
        inputs.pop();
    });
    refused(&mut live, &fewer, header, Check::Kept, None, Rejected::Roots);
    let unspent_other = source.blocks[229].outputs()[0].commitment();
    assert!(live.unspent(&unspent_other.0).is_some());
    let more = with_inputs(good, |inputs| inputs.push(grin_core::core::CommitWrapper::from(unspent_other)));
    refused(&mut live, &more, header, Check::Kept, None, Rejected::Roots);

    // one thing in the contents changed: an output, a range proof, a
    // kernel; an output or a kernel left out
    let mut bent = good.clone();
    bent.body.outputs[0].identifier.commit.0[4] ^= 1;
    refused(&mut live, &bent, header, Check::Kept, None, Rejected::Roots);
    refused(&mut live, &bent, header, Check::Arrived, None, Rejected::Body);
    let mut bent = good.clone();
    bent.body.outputs[1].proof.proof[40] ^= 1;
    refused(&mut live, &bent, header, Check::Kept, None, Rejected::Roots);
    let mut bent = good.clone();
    bent.body.kernels[0].excess_sig = source.blocks[229].kernels()[0].excess_sig;
    refused(&mut live, &bent, header, Check::Kept, None, Rejected::Roots);
    let mut bent = good.clone();
    bent.body.outputs.pop();
    refused(&mut live, &bent, header, Check::Kept, None, Rejected::Roots);
    let mut bent = good.clone();
    bent.body.kernels.pop();
    refused(&mut live, &bent, header, Check::Kept, None, Rejected::Roots);

    // an output with the commitment of one that is unspent already
    let mut bent = good.clone();
    bent.body.outputs[0] = source.blocks[229].outputs()[0];
    refused(&mut live, &bent, header, Check::Kept, None, Rejected::Duplicate);

    // A coinbase output spent too young. Block 230 spends the reward of
    // block 226; were the mature ones to end with block 225, it would be
    // too young. Where they end is the caller's to say; if the caller
    // cannot, it is not checked, and that is said.
    let reward = good.inputs();
    let reward: Vec<grin_core::core::CommitWrapper> = reward.into();
    assert!(reward.iter().any(|input| live.unspent(&input.commitment().0).unwrap().features == OutputFeatures::Coinbase));
    let ends_225 = source.blocks[225].header.output_mmr_size;
    refused(&mut live, good, header, Check::Kept, Some(ends_225), Rejected::Immature);

    // after all that, the block itself goes in
    let ends_227 = source.blocks[227].header.output_mmr_size;
    assert!(live.apply(good, header, Check::Arrived, Some(ends_227)).unwrap().maturity_checked);
    let mut again = live_at(source, 229);
    assert!(!again.apply(good, header, Check::Arrived, None).unwrap().maturity_checked);
}

/// The roots tell that a block is the one its header is about - not that
/// it is a valid block. A block that pays its miner more than a block may
/// has a header in perfect order; only the node's block check finds it.
#[test]
fn a_block_no_node_would_take_is_refused_when_it_arrives() {
    let source = shared();
    let forged = source.forged_next();
    assert_eq!(forged.header.height, 237);
    let mut live = live_at(source, 236);
    assert_eq!(live.apply(&forged, &forged.header, Check::Arrived, None), Err(Rejected::Body));
    assert_eq!(live.header().height, 236);
    // the roots alone would have let it through
    assert!(live.apply(&forged, &forged.header, Check::Kept, None).is_ok());
}

/// The blocks are kept in a file, and the file is believed no more than a
/// peer: at every opening its blocks are applied again under the verified
/// headers, and it ends where one does not fit.
#[test]
fn the_blocks_are_kept_and_checked_again() {
    let source = shared();
    let dir = Temp::new("blocks");
    let path = dir.0.join(FILE_NAME);
    let verified = |height: u64| source.blocks.get(height as usize).map(|b| b.header.clone());
    let at_236 = picture(&live_at(source, 236), source);

    let (mut blocks, reopened) = Blocks::open(&dir.0, source.collect(), false, verified).unwrap();
    assert_eq!(reopened, Reopened { kept: 0, cut_bytes: 0 });
    assert!(matches!(Blocks::open(&dir.0, source.collect(), false, verified), Err(BlocksError::Busy)));
    // a block that is refused is not written
    let forged_early = &source.blocks[212];
    assert!(matches!(blocks.add(forged_early, &forged_early.header, None), Err(AddError::Rejected(Rejected::NotNext))));
    assert_eq!(blocks.file_len(), 48);
    let mut ends = vec![48u64];
    for b in &source.blocks[211..] {
        blocks.add(b, &b.header, None).unwrap();
        ends.push(blocks.file_len());
    }
    let forged = source.forged_next();
    assert!(matches!(blocks.add(&forged, &forged.header, None), Err(AddError::Rejected(Rejected::Body))));
    assert_eq!(blocks.file_len(), ends[26]);
    assert_eq!(picture(blocks.live(), source), at_236);
    drop(blocks);
    let full = std::fs::read(&path).unwrap();
    assert_eq!(full.len() as u64, ends[26]);

    // the next process has the state from the file, and can go back
    let (mut blocks, reopened) = Blocks::open(&dir.0, source.collect(), false, verified).unwrap();
    assert_eq!(reopened, Reopened { kept: 26, cut_bytes: 0 });
    assert_eq!(picture(blocks.live(), source), at_236);
    assert_eq!(blocks.live().depth(), 26);
    // any of them can be read back; nothing below or above them
    assert_eq!(blocks.base().height, 210);
    for height in [211u64, 220, 236] {
        let block = blocks.read(height).unwrap().unwrap();
        assert_eq!(block.header, source.blocks[height as usize].header);
        assert_eq!(block.outputs(), source.blocks[height as usize].outputs());
    }
    assert!(blocks.read(210).unwrap().is_none() && blocks.read(237).unwrap().is_none() && blocks.read(0).unwrap().is_none());
    for _ in 0..6 {
        assert!(blocks.back().unwrap());
    }
    assert_eq!(picture(blocks.live(), source), picture(&live_at(source, 230), source));
    drop(blocks);
    assert_eq!(std::fs::read(&path).unwrap(), &full[..ends[20] as usize], "the file went back with the state");
    let (mut blocks, reopened) = Blocks::open(&dir.0, source.collect(), false, verified).unwrap();
    assert_eq!(reopened, Reopened { kept: 20, cut_bytes: 0 });
    for b in &source.blocks[231..] {
        blocks.add(b, &b.header, None).unwrap();
    }
    drop(blocks);
    assert_eq!(std::fs::read(&path).unwrap(), full);

    // a torn end; one byte of a block in the middle changed; a block and
    // one byte more: the file ends before it, and the rest is added again
    let mut longer = full[..ends[9] as usize].to_vec();
    longer.push(0);
    longer.extend_from_slice(&full[ends[9] as usize..]);
    let length = u32::from_be_bytes(longer[ends[8] as usize..ends[8] as usize + 4].try_into().unwrap()) + 1;
    longer[ends[8] as usize..ends[8] as usize + 4].copy_from_slice(&length.to_be_bytes());
    let mut bent = full.clone();
    bent[ends[12] as usize + 150] ^= 1;
    for (bytes, kept) in [(full[..full.len() - 9].to_vec(), 25usize), (bent, 12), (longer, 8)] {
        std::fs::write(&path, &bytes).unwrap();
        let (mut blocks, reopened) = Blocks::open(&dir.0, source.collect(), false, verified).unwrap();
        assert_eq!(reopened, Reopened { kept: kept as u64, cut_bytes: bytes.len() as u64 - ends[kept] }, "{kept} kept");
        assert_eq!(blocks.live().header().height, 210 + kept as u64);
        for b in &source.blocks[211 + kept..] {
            blocks.add(b, &b.header, None).unwrap();
        }
        drop(blocks);
        assert_eq!(std::fs::read(&path).unwrap(), full);
    }

    // The verified chain has changed while the program was not running:
    // from 231 on it has other headers, or none. The file ends at 230.
    let other = source.forged_next().header;
    for changed in [Some(other), None] {
        std::fs::write(&path, &full).unwrap();
        let moved = |height: u64| if height >= 231 { changed.clone() } else { verified(height) };
        let (blocks, reopened) = Blocks::open(&dir.0, source.collect(), false, moved).unwrap();
        assert_eq!(reopened, Reopened { kept: 20, cut_bytes: ends[26] - ends[20] });
        assert_eq!(picture(blocks.live(), source), picture(&live_at(source, 230), source));
    }

    // a file that is not a file of blocks is never written over; a file
    // for another archive header only when told to start over
    std::fs::write(&path, b"somebody else's notes, longer than a start of ours would be").unwrap();
    assert!(matches!(Blocks::open(&dir.0, source.collect(), true, verified), Err(BlocksError::NotOurs)));
    std::fs::write(&path, &full).unwrap();
    let mut elsewhere = source.collect();
    elsewhere.header = source.blocks[209].header.clone();
    match Blocks::open(&dir.0, elsewhere, false, verified) {
        Err(BlocksError::Other(height, hash)) => assert_eq!((height, hash), (210, source.blocks[210].header.hash())),
        _ => panic!("the file is for another archive header"),
    }
    assert_eq!(std::fs::read(&path).unwrap(), full);
    let mut elsewhere = source.collect();
    elsewhere.header = source.blocks[209].header.clone();
    let (blocks, reopened) = Blocks::open(&dir.0, elsewhere, true, verified).unwrap();
    assert_eq!((reopened, blocks.file_len()), (Reopened { kept: 0, cut_bytes: 0 }, 48));
}

/// The range proofs of the unspent outputs, segment by segment, under the
/// root of the rangeproof MMR in the header: every unspent output has its
/// proof, no spent one has, and a segment with a proof changed is refused.
/// The bitmap they are checked with may be one carried forward by blocks
/// and looked back at, not only one collected.
#[test]
fn the_range_proofs_of_unspent_outputs_are_given_out() {
    use fly_chain_state::archive::{rangeproof_segments, rangeproofs_of, Refused};
    use grin_core::core::SegmentIdentifier;
    let source = shared();
    let archive = source.archive();
    let segmenter = source.chain.segmenter().unwrap();
    // the bitmap at the archive header, from a state that has moved on
    let live = live_at(source, 236);
    let bitmap = live.bitmap_at(210).unwrap();
    let segments = rangeproof_segments(&archive);
    assert!(segments >= 2);
    let cut = |idx| segmenter.rangeproof_segment(SegmentIdentifier { height: 11, idx }).unwrap();
    let mut found = std::collections::BTreeMap::new();
    for idx in 0..segments {
        for (pos, proof) in rangeproofs_of(cut(idx), &archive, &bitmap).unwrap() {
            assert!(found.insert(pos, proof).is_none());
        }
    }
    // exactly the outputs unspent at the archive header, each with the
    // proof it has in its block
    let at_210 = live_at(source, 210);
    let expected = at_210.unspent_between(0, u64::MAX);
    assert_eq!(found.keys().copied().collect::<Vec<u64>>(), expected.iter().map(|(pos, _, _)| *pos).collect::<Vec<u64>>());
    let in_blocks: std::collections::HashMap<[u8; 33], _> = source.blocks.iter().flat_map(|b| b.outputs().iter().map(|o| (o.commitment().0, o.proof()))).collect();
    for (pos, commitment, _) in &expected {
        assert!(found[pos] == in_blocks[commitment], "the proof at {pos}");
    }
    // one proof changed; the bitmap of another height; a segment there is not
    let (id, hash_pos, hashes, leaf_pos, mut leaves, proof) = cut(1).parts();
    let last = leaves.len() - 1;
    leaves[last].proof[9] ^= 1;
    let bent = grin_core::core::Segment::from_parts(id, hash_pos, hashes, leaf_pos, leaves, proof);
    assert_eq!(rangeproofs_of(bent, &archive, &bitmap).err(), Some(Refused::Invalid));
    // With another bitmap - the tip's - the check reads other leaves. This
    // node has pruned nothing and sent them all, so the segment passes; and
    // whatever is given out is still the proof at that position, bound to
    // the header's root. (A node that has pruned sends what the bitmap of
    // its archive header calls for, and only that bitmap fits.)
    let by_position: std::collections::HashMap<u64, [u8; 33]> = live.unspent_between(0, u64::MAX).into_iter().map(|(pos, commitment, _)| (pos, commitment)).collect();
    assert!(!rangeproofs_of(cut(1), &archive, live.bitmap()).unwrap().is_empty());
    for (pos, proof) in rangeproofs_of(cut(1), &archive, live.bitmap()).unwrap() {
        assert!(proof == in_blocks[&by_position[&pos]], "the proof at {pos}");
    }
    let beyond = grin_core::core::Segment::from_parts(SegmentIdentifier { height: 11, idx: segments }, vec![], vec![], vec![], Vec::new(), cut(1).parts().5);
    assert_eq!(rangeproofs_of(beyond, &archive, &bitmap).err(), Some(Refused::NotWanted));
    // a segment of another height is not one of the pieces
    let (_, hash_pos, hashes, leaf_pos, leaves, proof) = cut(0).parts();
    let short = grin_core::core::Segment::from_parts(SegmentIdentifier { height: 10, idx: 0 }, hash_pos, hashes, leaf_pos, leaves, proof);
    assert_eq!(rangeproofs_of(short, &archive, &bitmap).err(), Some(Refused::NotWanted));
    // A segment that carries, after its own leaves, a leaf of the next
    // segment - an unspent output's position, with a proof that is not
    // that output's. The check does not read it. Whatever becomes of the
    // segment, that leaf is not given out.
    let (first_of_next, _) = cut(1).segment_pos_range(archive.output_mmr_size);
    let (foreign_pos, _, _) = at_210.unspent_between(first_of_next, u64::MAX)[0];
    let (id, hash_pos, hashes, mut leaf_pos, mut leaves, proof) = cut(0).parts();
    leaf_pos.push(foreign_pos);
    leaves.push(leaves[0]);
    let padded = grin_core::core::Segment::from_parts(id, hash_pos, hashes, leaf_pos, leaves, proof);
    match rangeproofs_of(padded, &archive, &bitmap) {
        Ok(given) => {
            assert!(given.iter().all(|(pos, _)| *pos != foreign_pos), "a leaf the check did not bind was given out");
            assert_eq!(given, rangeproofs_of(cut(0), &archive, &bitmap).unwrap());
        }
        Err(refused) => assert_eq!(refused, Refused::Invalid),
    }
}

/// The state transition checks the sizes of its reconstructed trees even
/// when both copies of the header carry the same inconsistent metadata.
#[test]
fn reconstructed_kernel_size_is_checked_before_publication() -> Result<(), &'static str> {
    let source = shared();
    let mut live = Live::new(source.collect()).ok_or("fixture archive")?;
    let height = live.header().height;
    let mut next = source.blocks.iter()
        .find(|block| height.checked_add(1) == Some(block.header.height))
        .cloned().ok_or("fixture successor")?;
    next.header.kernel_mmr_size = next.header.kernel_mmr_size.checked_add(1).ok_or("fixture size")?;
    let before = picture(&live, source);
    assert_eq!(live.apply(&next, &next.header, Check::Arrived, None), Err(Rejected::Roots));
    assert_eq!(picture(&live, source), before);
    Ok(())
}
