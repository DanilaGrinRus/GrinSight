//! The state collected from segments. The source in these tests is a real
//! chain of the Grin node's own code (`grin_chain::Chain`), mined in the
//! test kit with spending transactions; the segments are built by the
//! node's segmenter. Run with `cargo test --features testkit`.
#![cfg(feature = "testkit")]
use croaring::Bitmap;
use fly_chain_state::archive::{tail_peaks, Collector, Refused, State, Wanted, LARGE_OUTPUT_HEIGHT, SMALL_OUTPUT_HEIGHT};
use fly_chain_state::mmr::{Builder, MmrError};
use fly_chain_state::store::{AddError, Opened, Store, StoreError, FILE_NAME};
use fly_chain_state::testkit::{Source, Temp};
use grin_chain::txhashset::{BitmapAccumulator, BitmapChunk};
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::pmmr::{self, ReadablePMMR, ReadonlyPMMR, VecBackend, PMMR};
use grin_core::core::{BlockHeader, KernelFeatures, OutputIdentifier, Segment, SegmentIdentifier, TxKernel};
use grin_core::global::{self, ChainTypes};
use grin_core::ser::PMMRIndexHashable;
use std::collections::BTreeMap;
/// The chain most tests read: mined once.
fn shared() -> &'static Source {
    static SOURCE: std::sync::OnceLock<Source> = std::sync::OnceLock::new();
    let source = SOURCE.get_or_init(|| Source::mine(236));
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    source
}

/// The peaks-only builder gives the root of the full MMR of the Grin code,
/// whichever subtrees are handed to it as one hash instead of leaf by leaf.
#[test]
fn the_builder_agrees_with_the_full_range() {
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    let leaf = |i: u64| TxKernel::with_features(KernelFeatures::Plain { fee: ((i + 1) as u32).into() });
    let mut backend = VecBackend::<TxKernel>::new();
    let mut plain = Builder::new();
    assert_eq!(plain.root(), PMMR::new(&mut backend).root().unwrap());
    for n in 1..=200u64 {
        let size = {
            let mut mmr = PMMR::at(&mut backend, pmmr::insertion_to_pmmr_index(n - 1));
            mmr.push(&leaf(n - 1)).unwrap();
            mmr.unpruned_size()
        };
        plain.push_leaf(&leaf(n - 1)).unwrap();
        let mmr = PMMR::at(&mut backend, size);
        let root = mmr.root().unwrap();
        assert_eq!((plain.size(), plain.root(), plain.hashes()), (size, root, mmr.peaks()), "{n} leaves");
        assert_eq!(Builder::from_peaks(size, &plain.hashes()).unwrap().root(), root);
        assert!(Builder::from_peaks(size + 1, &plain.hashes()).is_none() || pmmr::peaks(size + 1).len() == plain.hashes().len());
        // the same range with whole subtrees given as one hash each: every
        // way of cutting it at one height, from several starting points
        for height in 1..=4u64 {
            for skip in 0..3u64 {
                let mut b = Builder::new();
                let mut i = 0u64;
                while i < n {
                    let span = 1u64 << height;
                    let aligned = i.is_multiple_of(span) && i + span <= n && (i / span) % 3 == skip;
                    if aligned {
                        // the root of the subtree over leaves i..i+span
                        let last_leaf = pmmr::insertion_to_pmmr_index(i + span - 1);
                        let top = last_leaf + height;
                        assert_eq!(pmmr::bintree_leftmost(top), pmmr::insertion_to_pmmr_index(i));
                        b.push_subtree(top, mmr.get_from_file(top).unwrap()).unwrap();
                        i += span;
                    } else {
                        assert_eq!(b.push_leaf(&leaf(i)).unwrap(), pmmr::insertion_to_pmmr_index(i));
                        i += 1;
                    }
                }
                assert_eq!((b.size(), b.root(), b.hashes()), (size, root, mmr.peaks()), "{n} leaves, height {height}, skip {skip}");
            }
        }
    }
    // pieces out of place are refused and change nothing
    let mut b = Builder::new();
    b.push_leaf(&leaf(0)).unwrap();
    let before = b.clone();
    assert_eq!(b.push_subtree(2, Hash::from_vec(&[1; 32])), Err(MmrError::Order), "its leftmost leaf is already there");
    assert_eq!(b.push_subtree(6, Hash::from_vec(&[1; 32])), Err(MmrError::Order));
    assert_eq!(b.push_subtree(9, Hash::from_vec(&[1; 32])), Err(MmrError::Order), "a gap");
    assert_eq!(b.push_subtree(u64::MAX - 5, Hash::from_vec(&[1; 32])), Err(MmrError::Position));
    assert_eq!(b, before);
    b.push_leaf(&leaf(1)).unwrap();
    assert_eq!(b.push_leaf(&leaf(2)).unwrap(), 3);
}

/// The peaks of a whole MMR come out of its one last segment and that
/// segment's proof - for every size, so for every shape of the last segment.
#[test]
fn the_last_segment_gives_the_peaks() {
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    let leaf = |i: u64| TxKernel::with_features(KernelFeatures::Plain { fee: ((i + 1) as u32).into() });
    for height in [1u8, 2, 3, 5] {
        let mut backend = VecBackend::<TxKernel>::new();
        let mut plain = Builder::new();
        for n in 1..=140u64 {
            let size = {
                let mut mmr = PMMR::at(&mut backend, pmmr::insertion_to_pmmr_index(n - 1));
                mmr.push(&leaf(n - 1)).unwrap();
                mmr.unpruned_size()
            };
            plain.push_leaf(&leaf(n - 1)).unwrap();
            let mmr = ReadonlyPMMR::at(&backend, size);
            let root = mmr.root().unwrap();
            let last = SegmentIdentifier { height, idx: SegmentIdentifier::count_segments_required(size, height) as u64 - 1 };
            let segment = Segment::from_pmmr(last, &mmr, false).unwrap();
            segment.validate(size, None, root).unwrap();
            let peaks = tail_peaks(segment.clone(), size, None, root).unwrap();
            assert_eq!(peaks, plain, "{n} leaves, segments of height {height}");
            // against another root, or as the tail of another size: nothing
            assert_eq!(tail_peaks(segment.clone(), size, None, Hash::from_vec(&[3; 32])).err(), Some(Refused::Unreadable));
            assert!(tail_peaks(segment.clone(), size + 1, None, root).is_err());
            // a segment that is not the last one is not a tail
            if last.idx > 0 {
                let earlier = Segment::from_pmmr(SegmentIdentifier { height, idx: 0 }, &mmr, false).unwrap();
                assert_eq!(tail_peaks(earlier, size, None, root).err(), Some(Refused::NotWanted));
            }
        }
    }
}

/// The whole road on a real chain: every segment the node's segmenter gives
/// is taken, the unspent outputs are exactly those the blocks leave, and
/// the collected state is enough to recompute the roots of the next blocks'
/// headers - which is what verifying a block's contents will need.
#[test]
fn the_state_of_a_real_chain_is_collected() {
    let source = shared();
    let archive = source.archive();
    assert_eq!(archive.height, 210);
    assert!(archive.output_mmr_count() > 2048, "more than one output segment: {}", archive.output_mmr_count());
    let state = source.collect();
    assert_eq!(state.header.hash(), archive.hash());

    // the unspent outputs: exactly the set the blocks leave, in MMR order
    let expected = source.unspent_at(archive.height);
    assert_eq!(state.unspent.len(), expected.len());
    assert!(expected.len() > 1000 && (expected.len() as u64) < archive.output_mmr_count() / 2 + 700);
    for pair in state.unspent.windows(2) {
        assert!(pair[0].0 < pair[1].0);
    }
    for (pos, id) in &state.unspent {
        assert_eq!(expected.get(id.commit.0.as_slice()), Some(id));
        assert!(pmmr::is_leaf(*pos) && *pos < archive.output_mmr_size);
        // where the node itself says the output is, if it is still unspent at its head
        if let Ok(Some((_, at))) = source.chain.get_unspent(id.commit) {
            assert_eq!(at.pos - 1, *pos);
        }
    }
    let bitmap = state.bitmap.as_bitmap().unwrap();
    assert_eq!(bitmap.cardinality(), expected.len() as u64);
    // the three sets of peaks, against the header
    assert_eq!(state.outputs.size(), archive.output_mmr_size);
    assert_eq!((state.outputs.root(), state.bitmap.root()).hash_with_index(archive.output_mmr_size), archive.output_root);
    assert_eq!((state.rangeproofs.size(), state.rangeproofs.root()), (archive.output_mmr_size, archive.range_proof_root));
    assert_eq!((state.kernels.size(), state.kernels.root()), (archive.kernel_mmr_size, archive.kernel_root));

    // ... and forward: apply the next blocks to the collected state and
    // arrive at the roots their headers commit to
    let State { mut bitmap, unspent, mut outputs, mut rangeproofs, mut kernels, .. } = state;
    let mut live: Bitmap = bitmap.as_bitmap().unwrap();
    let mut where_is: BTreeMap<Vec<u8>, u64> = unspent.iter().map(|(pos, id)| (id.commit.0.to_vec(), *pos)).collect();
    for b in &source.blocks[archive.height as usize + 1..] {
        let mut touched: Vec<u64> = Vec::new();
        let inputs: Vec<grin_core::core::CommitWrapper> = b.inputs().into();
        for i in inputs {
            let pos = where_is.remove(i.commitment().0.as_slice()).expect("an input spends an output the state has");
            let index = pmmr::n_leaves(pos + 1) - 1;
            live.remove(index as u32);
            touched.push(index);
        }
        for o in b.outputs() {
            let pos = outputs.push_leaf(&o.identifier()).unwrap();
            assert_eq!(rangeproofs.push_leaf(&o.proof()).unwrap(), pos);
            let index = pmmr::n_leaves(pos + 1) - 1;
            live.add(index as u32);
            touched.push(index);
            where_is.insert(o.commitment().0.to_vec(), pos);
        }
        for k in b.kernels() {
            kernels.push_leaf(k).unwrap();
        }
        touched.sort_unstable();
        let from = (touched[0] / 1024) * 1024;
        let leaves = pmmr::n_leaves(outputs.size());
        bitmap.apply(touched, live.iter().map(u64::from).filter(|i| *i >= from), leaves).unwrap();
        let h = &b.header;
        assert_eq!((outputs.size(), kernels.size()), (h.output_mmr_size, h.kernel_mmr_size), "height {}", h.height);
        assert_eq!((outputs.root(), bitmap.root()).hash_with_index(h.output_mmr_size), h.output_root, "height {}", h.height);
        assert_eq!(rangeproofs.root(), h.range_proof_root, "height {}", h.height);
        assert_eq!(kernels.root(), h.kernel_root, "height {}", h.height);
    }
    assert_eq!(where_is.len(), source.unspent_at(236).len());
}

/// Nothing is taken on a node's word: a segment for another header, a
/// segment with one thing changed, a segment out of turn, a wrong claim
/// about the output root - each is refused, and what was collected so far
/// is still good.
#[test]
fn segments_that_do_not_fit_the_header_are_refused() {
    let source = shared();
    let segmenter = source.chain.segmenter().unwrap();
    let archive = source.archive();
    let bitmap_id = SegmentIdentifier { height: 9, idx: 0 };
    let (bitmap, output_root) = segmenter.bitmap_segment(bitmap_id).unwrap();
    let out = |idx| segmenter.output_segment(SegmentIdentifier { height: 11, idx }).unwrap().0;

    // out of turn
    let mut c = Collector::new(archive.clone());
    assert_eq!(c.add_output(out(0)).err(), Some(Refused::NotWanted), "before the bitmap");
    assert_eq!(c.add_kernel_tail(segmenter.kernel_segment(SegmentIdentifier { height: 11, idx: 0 }).unwrap()).err(), Some(Refused::NotWanted));
    assert!(c.finish().is_none());
    // a wrong claim about the output root
    let mut c = Collector::new(archive.clone());
    assert_eq!(c.add_bitmap(bitmap.clone(), Hash::from_vec(&[5; 32])).err(), Some(Refused::Invalid));
    assert_eq!(c.wanted(), Wanted::Bitmap(bitmap_id));
    // the right segments for another header: the one before the archive header
    let earlier = source.chain.get_header_by_height(archive.height - 1).unwrap();
    let mut c = Collector::new(earlier);
    assert_eq!(c.add_bitmap(bitmap.clone(), output_root).err(), Some(Refused::Invalid));

    let mut c = Collector::new(archive.clone());
    c.add_bitmap(bitmap.clone(), output_root).unwrap();
    assert_eq!(c.add_bitmap(bitmap.clone(), output_root).err(), Some(Refused::NotWanted), "twice");
    assert_eq!(c.add_output(out(1)).err(), Some(Refused::NotWanted), "the second before the first");
    // one output's commitment changed, one left out, one pruned hash changed
    let good = out(0);
    let (id, hash_pos, hashes, leaf_pos, leaves, proof) = good.clone().parts();
    let live = leaf_pos.iter().position(|pos| *pos == source.collect().unspent[0].0).unwrap();
    let mut bent = leaves.clone();
    bent[live].commit.0[5] ^= 1;
    let changed = Segment::from_parts(id, hash_pos.clone(), hashes.clone(), leaf_pos.clone(), bent, proof.clone());
    assert_eq!(c.add_output(changed).err(), Some(Refused::Invalid));
    // the data of an unspent output left out
    let (mut fewer_pos, mut fewer) = (leaf_pos.clone(), leaves.clone());
    fewer_pos.remove(live);
    fewer.remove(live);
    let dropped = Segment::from_parts(id, hash_pos.clone(), hashes.clone(), fewer_pos, fewer, proof.clone());
    assert_eq!(c.add_output(dropped).err(), Some(Refused::Invalid));
    // a segment that makes no sense at all does not bring the collector down
    let nonsense = Segment::from_parts(id, vec![3, u64::MAX], vec![Hash::from_vec(&[1; 32]); 2], vec![2, 7], leaves[..2].to_vec(), proof.clone());
    assert_eq!(c.add_output(nonsense).err(), Some(Refused::Invalid));
    let empty = Segment::from_parts(id, vec![], vec![], vec![], Vec::<OutputIdentifier>::new(), proof);
    assert_eq!(c.add_output(empty).err(), Some(Refused::Invalid));
    // after all that the real segments are still taken, to the end
    assert_eq!(c.wanted(), Wanted::Output(SegmentIdentifier { height: 11, idx: 0 }));
    c.add_output(good).unwrap();
    while c.wanted() != Wanted::Nothing {
        source.serve(&mut c).unwrap();
    }
    let whole = c.finish().unwrap();

    // data that nobody needs may be missing: the node's check passes a
    // segment without the data of spent outputs whose sibling is spent too,
    // and the same state comes out of it
    let mut lean = Collector::new(archive.clone());
    lean.add_bitmap(bitmap.clone(), output_root).unwrap();
    let live: std::collections::BTreeSet<u64> = whole.unspent.iter().map(|(pos, _)| *pos).collect();
    for idx in 0..2 {
        let (id, hash_pos, hashes, leaf_pos, leaves, proof) = out(idx).parts();
        let needed = |pos: u64| live.contains(&pos) || live.contains(&pmmr::family(pos).1) || pos + 1 == archive.output_mmr_size;
        let kept: Vec<usize> = (0..leaf_pos.len()).filter(|i| needed(leaf_pos[*i])).collect();
        assert!(kept.len() < leaf_pos.len());
        let slim = Segment::from_parts(
            id,
            hash_pos,
            hashes,
            kept.iter().map(|i| leaf_pos[*i]).collect(),
            kept.iter().map(|i| leaves[*i]).collect(),
            proof,
        );
        lean.add_output(slim).unwrap();
    }
    while lean.wanted() != Wanted::Nothing {
        source.serve(&mut lean).unwrap();
    }
    let lean = lean.finish().unwrap();
    assert_eq!((&lean.unspent, &lean.outputs), (&whole.unspent, &whole.outputs));

    // A node that has not pruned sends every hash and every leaf, and the
    // node's check looks at only some of them. Change any one piece: either
    // the segment is refused, or the piece was one nobody reads and the
    // same state comes out. A changed piece never changes the state.
    let (id, hash_pos, hashes, leaf_pos, leaves, proof) = out(0).parts();
    // true if the segment was refused; if it was taken, the state is the same
    let trial = |segment: Segment<OutputIdentifier>| {
        let mut k = Collector::new(archive.clone());
        k.add_bitmap(bitmap.clone(), output_root).unwrap();
        match k.add_output(segment) {
            Err(Refused::Invalid) => true,
            Ok(()) => {
                while k.wanted() != Wanted::Nothing {
                    source.serve(&mut k).unwrap();
                }
                let got = k.finish().unwrap();
                assert_eq!((&got.unspent, &got.outputs), (&whole.unspent, &whole.outputs));
                false
            }
            other => panic!("{other:?}"),
        }
    };
    // what the check reads, worked out here from the unspent set alone: the
    // hash of a subtree with nothing unspent whose sibling has something,
    // and the data of a leaf that is unspent or has an unspent sibling
    let segment_last = (1u64 << 12) - 2;
    let spent_under = |top: u64| live.range(pmmr::bintree_leftmost(top)..=top).next().is_none();
    let hash_read = |pos: u64| {
        let (parent, sibling) = pmmr::family(pos);
        parent <= segment_last && spent_under(pos) && !spent_under(sibling)
    };
    let leaf_read = |pos: u64| live.contains(&pos) || live.contains(&pmmr::family(pos).1);
    let spread = |all: Vec<usize>| -> Vec<usize> {
        let step = (all.len() / 5).max(1);
        all.into_iter().step_by(step).take(6).collect()
    };
    // three kinds of hash: the ones the check reads; the ones inside a
    // larger subtree without unspent outputs, which stand at the very place
    // a hash is read from and are not the one; and all the others
    let inside = |pos: u64| spent_under(pos) && spent_under(pmmr::family(pos).0);
    type Kind<'a> = (&'a str, bool, Box<dyn Fn(u64) -> bool + 'a>);
    let kinds: [Kind; 3] = [
        ("read", true, Box::new(hash_read)),
        ("inside a larger spent subtree", false, Box::new(inside)),
        ("neither", false, Box::new(|pos| !hash_read(pos) && !inside(pos))),
    ];
    for (kind, read, is) in &kinds {
        let picked = spread((0..hashes.len()).filter(|i| is(hash_pos[*i])).collect());
        assert!(!picked.is_empty(), "hashes of the kind: {kind}");
        for i in picked {
            let mut other = hashes.clone();
            other[i] = Hash::from_vec(&[8; 32]);
            let refused = trial(Segment::from_parts(id, hash_pos.clone(), other, leaf_pos.clone(), leaves.clone(), proof.clone()));
            assert_eq!(refused, *read, "the hash at {} ({kind})", hash_pos[i]);
        }
    }
    for read in [true, false] {
        let picked = spread((0..leaves.len()).filter(|i| leaf_read(leaf_pos[*i]) == read).collect());
        assert!(!picked.is_empty(), "leaves the check {}", if read { "reads" } else { "does not read" });
        for i in picked {
            let mut other = leaves.clone();
            other[i].commit.0[7] ^= 1;
            let refused = trial(Segment::from_parts(id, hash_pos.clone(), hashes.clone(), leaf_pos.clone(), other, proof.clone()));
            assert_eq!(refused, read, "the leaf at {}", leaf_pos[i]);
        }
    }
    // an entry among the leaves at a place where no leaf can be: one more
    // piece the check does not read
    assert_eq!(&leaf_pos[..3], &[0, 1, 3]);
    let (mut more_pos, mut more) = (leaf_pos.clone(), leaves.clone());
    more_pos.insert(2, 2);
    more.insert(2, leaves[0]);
    assert!(!trial(Segment::from_parts(id, hash_pos.clone(), hashes.clone(), more_pos, more, proof.clone())));
    // tails of the wrong MMR size or with a changed leaf
    let mut c2 = Collector::new(archive.clone());
    while !matches!(c2.wanted(), Wanted::RangeproofTail(_)) {
        source.serve(&mut c2).unwrap();
    }
    let Wanted::RangeproofTail(tail) = c2.wanted() else { unreachable!() };
    let good = segmenter.rangeproof_segment(tail).unwrap();
    let (id, hash_pos, hashes, leaf_pos, mut leaves, proof) = good.clone().parts();
    // the newest output is unspent, so its rangeproof is one the check reads
    let newest = leaves.len() - 1;
    leaves[newest].proof[9] ^= 1;
    let bent = Segment::from_parts(id, hash_pos, hashes, leaf_pos, leaves, proof);
    assert_eq!(c2.add_rangeproof_tail(bent).err(), Some(Refused::Invalid));
    if tail.idx > 0 {
        let not_last = segmenter.rangeproof_segment(SegmentIdentifier { height: 11, idx: 0 }).unwrap();
        assert_eq!(c2.add_rangeproof_tail(not_last).err(), Some(Refused::NotWanted));
    }
    c2.add_rangeproof_tail(good).unwrap();
    let Wanted::KernelTail(tail) = c2.wanted() else { unreachable!() };
    let good = segmenter.kernel_segment(tail).unwrap();
    let (id, hash_pos, hashes, leaf_pos, mut leaves, proof) = good.clone().parts();
    leaves.pop();
    let short = Segment::from_parts(id, hash_pos, hashes, leaf_pos[..leaves.len()].to_vec(), leaves, proof);
    assert_eq!(c2.add_kernel_tail(short).err(), Some(Refused::Invalid));
    c2.add_kernel_tail(good).unwrap();
    assert!(c2.finish().is_some());
}

/// The same from a node that has compacted its files: its segments carry
/// hashes in place of what it pruned, and the same state comes out. (The
/// chain ends at a height where the archive point is the node's pruning
/// horizon, as it always is on the real networks.)
#[test]
fn a_compacted_node_gives_the_same_state() {
    let source = Source::mine(130);
    let before = source.collect();
    assert_eq!(before.header.height, 110);
    let pieces = |s: &Source| {
        let (_, hash_pos, _, leaf_pos, _, _) = s.chain.segmenter().unwrap().output_segment(SegmentIdentifier { height: 11, idx: 0 }).unwrap().0.parts();
        (hash_pos.len(), leaf_pos.len())
    };
    let full = pieces(&source);
    source.chain.compact().unwrap();
    let pruned = pieces(&source);
    assert!(pruned.1 < full.1, "the node pruned leaves: {full:?} -> {pruned:?}");
    let after = source.collect();
    assert_eq!(after.header.hash(), before.header.hash());
    assert_eq!(after.unspent, before.unspent);
    assert_eq!((after.outputs.clone(), after.rangeproofs.clone(), after.kernels.clone()), (before.outputs, before.rangeproofs, before.kernels));
    assert_eq!(after.bitmap.root(), before.bitmap.root());
    assert_eq!(after.unspent.len(), source.unspent_at(110).len());
}

fn same(a: &State, b: &State) {
    assert_eq!(a.header.hash(), b.header.hash());
    assert_eq!(a.unspent, b.unspent);
    assert_eq!((&a.outputs, &a.rangeproofs, &a.kernels), (&b.outputs, &b.rangeproofs, &b.kernels));
    assert_eq!(a.bitmap.root(), b.bitmap.root());
}

/// A longer chain: its output MMR is three of the segments nodes exchange,
/// and two of the next height.
fn long() -> &'static Source {
    static SOURCE: std::sync::OnceLock<Source> = std::sync::OnceLock::new();
    let source = SOURCE.get_or_init(|| Source::mine(476));
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    source
}

/// Everything the collector asks for, to the end; how many segments of
/// the output MMR that was.
fn serve_all(source: &Source, collector: &mut Collector) -> u64 {
    let mut outputs = 0;
    while collector.wanted() != Wanted::Nothing {
        outputs += u64::from(matches!(collector.wanted(), Wanted::Output(_)));
        source.serve(collector).unwrap();
    }
    outputs
}

/// The output MMR is collected in larger segments than the ones nodes
/// exchange with one another - fewer requests for the same tree - when a
/// node gives them. The state is the same whatever the height of the
/// segments: the same roots, the same unspent outputs, and of the leaves
/// a node sends along only those the bitmap names. The height is chosen
/// before the first segment of the output MMR and holds from there on.
#[test]
fn larger_segments_give_the_same_state() {
    let source = long();
    let archive = source.archive();
    let segmenter = source.chain.segmenter().unwrap();
    assert_eq!((SMALL_OUTPUT_HEIGHT, LARGE_OUTPUT_HEIGHT), (11, 15));

    // as the nodes exchange them
    let mut collector = Collector::new(archive.clone());
    assert_eq!((collector.output_height(), collector.output_segments()), (11, 3));
    assert_eq!(serve_all(source, &mut collector), 3);
    let whole = collector.finish().unwrap();
    assert_eq!(whole.unspent.len(), source.unspent_at(archive.height).len());

    for (height, segments) in [(12u8, 2u64), (13, 1), (14, 1), (15, 1)] {
        let mut collector = Collector::new(archive.clone());
        let (total, _) = collector.progress();
        assert!(collector.set_output_height(height));
        assert_eq!((collector.output_height(), collector.output_segments()), (height, segments));
        assert_eq!(collector.progress(), (total - 3 + segments, 0), "fewer segments in all");
        assert_eq!(serve_all(source, &mut collector), segments, "at height {height}");
        same(&collector.finish().unwrap(), &whole);
    }

    // the node sent more leaves than are unspent, and more in a large
    // segment than the bitmap names in it
    let large = segmenter.output_segment(SegmentIdentifier { height: 12, idx: 0 }).unwrap().0;
    assert!(large.leaf_iter().count() > whole.unspent.len());

    // only heights the nodes give
    let mut collector = Collector::new(archive.clone());
    for height in [0u8, 9, 10, 16, 17, 255] {
        assert!(!collector.set_output_height(height), "{height}");
        assert_eq!(collector.output_height(), 11);
    }
    // any number of times before the first segment of the output MMR
    assert!(collector.set_output_height(15));
    assert!(collector.set_output_height(12));
    source.serve(&mut collector).unwrap();
    assert!(collector.set_output_height(11));
    assert!(collector.set_output_height(12));
    assert_eq!(collector.wanted(), Wanted::Output(SegmentIdentifier { height: 12, idx: 0 }));
    // a segment of another height is not what is wanted, true as it is
    let small = |idx| segmenter.output_segment(SegmentIdentifier { height: 11, idx }).unwrap().0;
    assert!(!collector.verifies_output(&small(0)));
    assert_eq!(collector.add_output(small(0)), Err(Refused::NotWanted));
    assert!(collector.verifies_output(&large));
    assert_eq!(collector.add_output(large), Ok(()));
    // and from the first segment on the height holds
    assert!(!collector.set_output_height(11));
    assert!(!collector.set_output_height(15));
    assert_eq!((collector.output_height(), collector.output_segments()), (12, 2));
    assert_eq!(collector.add_output(small(2)), Err(Refused::NotWanted));
    assert_eq!(collector.wanted(), Wanted::Output(SegmentIdentifier { height: 12, idx: 1 }));
    assert_eq!(serve_all(source, &mut collector), 1);
    same(&collector.finish().unwrap(), &whole);
}

/// The file keeps the segments as they came, and with them the height
/// the output MMR was collected in: a restart goes on in segments of that
/// height, whatever the program would choose for a new file.
#[test]
fn the_file_keeps_the_height_of_its_segments() {
    let source = long();
    let archive = source.archive();
    let whole = source.collect();
    for (height, segments) in [(12u8, 2u64), (11, 3)] {
        let dir = Temp::new("heights");
        let (mut store, _) = Store::open(&dir.0, archive.clone()).unwrap();
        assert_eq!(store.output_height(), 11);
        // nothing of the output MMR yet: a restart is free to choose
        source.serve_store(&mut store).unwrap();
        assert!(matches!(store.wanted(), Wanted::Output(_)));
        drop(store);
        let (mut store, opened) = Store::open(&dir.0, archive.clone()).unwrap();
        assert_eq!((opened.kept, store.output_height()), (1, 11));
        assert!(store.set_output_height(height));
        assert_eq!(store.output_segments(), segments);
        let (total, _) = store.progress();
        // the first segment of the output MMR, and the process ends
        source.serve_store(&mut store).unwrap();
        drop(store);
        let (mut store, opened) = Store::open(&dir.0, archive.clone()).unwrap();
        assert_eq!(opened, Opened { kept: 2, cut_bytes: 0 });
        assert_eq!((store.output_height(), store.output_segments(), store.progress()), (height, segments, (total, 2)));
        assert_eq!(store.wanted(), Wanted::Output(SegmentIdentifier { height, idx: 1 }));
        for other in [11u8, 12, 15] {
            assert!(!store.set_output_height(other), "{other} over {height}");
        }
        assert_eq!(store.output_height(), height);
        while store.wanted() != Wanted::Nothing {
            source.serve_store(&mut store).unwrap();
        }
        same(&store.finish().unwrap(), &whole);
        // and the whole file again
        let (store, opened) = Store::open(&dir.0, archive.clone()).unwrap();
        assert_eq!((opened, store.output_height()), (Opened { kept: total, cut_bytes: 0 }, height));
        same(&store.finish().unwrap(), &whole);
    }
}

/// Collecting goes on after a restart from what the file holds, and the
/// file is believed no more than a peer: what it holds goes through the
/// same checks again, and what does not pass is cut off and asked for anew.
#[test]
fn collecting_goes_on_from_the_file() {
    let source = shared();
    let archive = source.archive();
    let whole = source.collect();
    let dir = Temp::new("store");
    let path = dir.0.join(FILE_NAME);
    assert_eq!(Store::peek(&dir.0).unwrap(), None);

    let (mut store, opened) = Store::open(&dir.0, archive.clone()).unwrap();
    assert_eq!(opened, Opened { kept: 0, cut_bytes: 0 });
    let (total, _) = store.progress();
    assert!(total >= 5, "a bitmap segment, two of outputs, two tails");
    // one process at a time
    assert!(matches!(Store::open(&dir.0, archive.clone()), Err(StoreError::Busy)));
    // a refused segment is not written
    let segmenter = source.chain.segmenter().unwrap();
    let (bitmap, _) = segmenter.bitmap_segment(SegmentIdentifier { height: 9, idx: 0 }).unwrap();
    assert!(matches!(store.add_bitmap(bitmap, Hash::from_vec(&[5; 32])), Err(AddError::Refused(Refused::Invalid))));
    assert_eq!(store.file_len(), 48);
    // all but the last two segments, then the process ends
    for _ in 0..total - 2 {
        source.serve_store(&mut store).unwrap();
    }
    let wanted = store.wanted();
    assert!(store.finish().is_none());
    assert_eq!(Store::peek(&dir.0).unwrap(), Some((archive.height, archive.hash())));

    // what is kept is what was read: far less than the node sent
    let sent: usize = (0..2)
        .map(|idx| {
            let segment = segmenter.output_segment(SegmentIdentifier { height: 11, idx }).unwrap().0;
            grin_core::ser::ser_vec(&segment, grin_core::ser::ProtocolVersion::local()).unwrap().len()
        })
        .sum();
    let on_disk = std::fs::metadata(&path).unwrap().len();
    assert!(on_disk < sent as u64 * 3 / 4, "{on_disk} bytes kept of {sent} sent in the output segments alone");

    // the next process goes on where the first stopped
    let (mut store, opened) = Store::open(&dir.0, archive.clone()).unwrap();
    assert_eq!(opened, Opened { kept: total - 2, cut_bytes: 0 });
    assert_eq!((store.wanted(), store.progress()), (wanted, (total, total - 2)));
    source.serve_store(&mut store).unwrap();
    source.serve_store(&mut store).unwrap();
    assert_eq!(store.wanted(), Wanted::Nothing);
    same(&store.finish().unwrap(), &whole);
    let full = std::fs::read(&path).unwrap();

    // and a process after that has the state without asking anybody
    let (store, opened) = Store::open(&dir.0, archive.clone()).unwrap();
    assert_eq!(opened, Opened { kept: total, cut_bytes: 0 });
    same(&store.finish().unwrap(), &whole);

    // the file for another header is left alone until it is begun over
    let other = source.chain.get_header_by_height(archive.height - 1).unwrap();
    match Store::open(&dir.0, other.clone()) {
        Err(StoreError::Other(height, hash)) => assert_eq!((height, hash), (archive.height, archive.hash())),
        _ => panic!("the file is for another header"),
    }
    assert_eq!(std::fs::read(&path).unwrap(), full);

    // a write that stopped half way: the torn end is cut off
    let records = |bytes: &[u8]| {
        let mut at = 48;
        let mut starts = Vec::new();
        while at < bytes.len() {
            starts.push(at);
            at += 5 + u32::from_be_bytes(bytes[at + 1..at + 5].try_into().unwrap()) as usize;
        }
        assert_eq!(at, bytes.len());
        starts
    };
    let starts = records(&full);
    assert_eq!(starts.len() as u64, total);
    let torn = full.len() - 7;
    std::fs::write(&path, &full[..torn]).unwrap();
    let (mut store, opened) = Store::open(&dir.0, archive.clone()).unwrap();
    assert_eq!(opened, Opened { kept: total - 1, cut_bytes: (torn - starts[starts.len() - 1]) as u64 });
    assert_eq!(std::fs::metadata(&path).unwrap().len(), starts[starts.len() - 1] as u64);
    source.serve_store(&mut store).unwrap();
    same(&store.finish().unwrap(), &whole);
    assert_eq!(std::fs::read(&path).unwrap(), full);

    // one byte of a segment in the middle changed on disk: that segment
    // does not pass, and it and everything after it is collected again
    for (record, offset) in [(1usize, 40usize), (2, 60), (0, 5 + 32 + 30)] {
        let mut bent = full.clone();
        bent[starts[record] + offset] ^= 1;
        std::fs::write(&path, &bent).unwrap();
        let (mut store, opened) = Store::open(&dir.0, archive.clone()).unwrap();
        assert_eq!(opened, Opened { kept: record as u64, cut_bytes: (full.len() - starts[record]) as u64 }, "record {record}");
        while store.wanted() != Wanted::Nothing {
            source.serve_store(&mut store).unwrap();
        }
        same(&store.finish().unwrap(), &whole);
        assert_eq!(std::fs::read(&path).unwrap(), full);
    }
    // a record of a kind there is not, a length beyond any segment
    for (offset, value) in [(0usize, 9u8), (1, 0x7f)] {
        let mut bent = full.clone();
        bent[starts[1] + offset] = value;
        std::fs::write(&path, &bent).unwrap();
        let (_, opened) = Store::open(&dir.0, archive.clone()).unwrap();
        assert_eq!(opened.kept, 1);
    }
    // a record that is a segment and one byte more
    let mut longer = full[..starts[2]].to_vec();
    longer.push(0);
    longer.extend_from_slice(&full[starts[2]..]);
    let length = u32::from_be_bytes(longer[starts[1] + 1..starts[1] + 5].try_into().unwrap()) + 1;
    longer[starts[1] + 1..starts[1] + 5].copy_from_slice(&length.to_be_bytes());
    std::fs::write(&path, &longer).unwrap();
    let (_, opened) = Store::open(&dir.0, archive.clone()).unwrap();
    assert_eq!(opened.kept, 1);
    // segments in the wrong order in the file: the second is not wanted yet
    let mut swapped = full[..starts[0]].to_vec();
    swapped.extend_from_slice(&full[starts[1]..starts[2]]);
    swapped.extend_from_slice(&full[starts[0]..starts[1]]);
    std::fs::write(&path, &swapped).unwrap();
    let (_, opened) = Store::open(&dir.0, archive.clone()).unwrap();
    assert_eq!(opened, Opened { kept: 0, cut_bytes: (starts[2] - starts[0]) as u64 });

    // a file that is not a state file is never written over
    std::fs::write(&path, b"somebody else's notes, longer than a start of ours would be").unwrap();
    assert!(matches!(Store::open(&dir.0, archive.clone()), Err(StoreError::NotOurs)));
    assert!(matches!(Store::begin(&dir.0, archive.clone()), Err(StoreError::NotOurs)));
    std::fs::write(&path, b"short").unwrap();
    assert!(matches!(Store::open(&dir.0, archive.clone()), Err(StoreError::NotOurs)));
    assert_eq!(std::fs::read(&path).unwrap(), b"short");
    // a start of ours that was never finished is
    std::fs::write(&path, &full[..20]).unwrap();
    let (store, opened) = Store::open(&dir.0, archive.clone()).unwrap();
    assert_eq!((opened, store.file_len()), (Opened { kept: 0, cut_bytes: 0 }, 48));
    drop(store);

    // beginning over: the state at another header replaces what was there
    std::fs::write(&path, &full).unwrap();
    let mut store = Store::begin(&dir.0, other.clone()).unwrap();
    assert_eq!(store.progress().1, 0);
    assert!(matches!(source.serve_store(&mut store), Err(AddError::Refused(Refused::Invalid))), "the node serves another header");
    drop(store);
    assert_eq!(Store::peek(&dir.0).unwrap(), Some((other.height, other.hash())));
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 48);
}

/// On the real networks the bitmap takes more than one segment (one holds
/// 524 288 outputs). No chain mined in a test is that long, so here the
/// node's accumulator is filled directly and its segments are cut by the
/// node's code; the header has only what the bitmap is checked against.
#[test]
fn a_bitmap_of_several_segments_is_checked_segment_by_segment() {
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    let outputs: u64 = (512 + 200) * 1024 - 300;
    let mut node = BitmapAccumulator::new();
    node.init((0..outputs).filter(|i| i % 7 == 3 || i % 1000 == 0), outputs).unwrap();
    let output_root = Hash::from_vec(&[4; 32]);
    let mut header = BlockHeader::default();
    header.height = 100;
    header.output_mmr_size = pmmr::insertion_to_pmmr_index(outputs);
    header.output_root = (output_root, node.root()).hash_with_index(header.output_mmr_size);
    let cut = |idx| Segment::from_pmmr(SegmentIdentifier { height: 9, idx }, &node.readonly_pmmr(), false).unwrap();
    let wanted = |idx| Wanted::Bitmap(SegmentIdentifier { height: 9, idx });

    let mut c = Collector::new(header.clone());
    assert_eq!(c.wanted(), wanted(0));
    assert_eq!(c.add_bitmap(cut(1), output_root).err(), Some(Refused::NotWanted), "the second before the first");
    c.add_bitmap(cut(0), output_root).unwrap();
    assert_eq!((c.wanted(), c.progress().1), (wanted(1), 1));
    assert_eq!(c.add_bitmap(cut(0), output_root).err(), Some(Refused::NotWanted), "the first again");
    // the second segment with one bit more: refused on the spot, and what
    // was collected stays
    let (id, hash_pos, hashes, leaf_pos, mut chunks, proof) = cut(1).parts();
    chunks[3].set(17, true);
    let bent: Segment<BitmapChunk> = Segment::from_parts(id, hash_pos, hashes, leaf_pos, chunks, proof);
    assert_eq!(c.add_bitmap(bent, output_root).err(), Some(Refused::Invalid));
    assert_eq!((c.wanted(), c.progress().1), (wanted(1), 1));
    // the second segment with another story about the output root
    assert_eq!(c.add_bitmap(cut(1), Hash::from_vec(&[6; 32])).err(), Some(Refused::Invalid));
    assert_eq!((c.wanted(), c.progress().1), (wanted(1), 1));
    // the second segment with chunks after the last one there is: the
    // check does not read them, and they are not taken
    let (id, hash_pos, hashes, mut leaf_pos, mut chunks, proof) = cut(1).parts();
    assert_eq!(chunks.len(), 200);
    for extra in 0..3 {
        leaf_pos.push(pmmr::insertion_to_pmmr_index(512 + 200 + extra));
        chunks.push(chunks[5].clone());
    }
    let longer: Segment<BitmapChunk> = Segment::from_parts(id, hash_pos, hashes, leaf_pos, chunks, proof);
    assert_eq!(c.add_bitmap(longer, output_root).err(), None);
    assert_eq!(c.wanted(), Wanted::Output(SegmentIdentifier { height: 11, idx: 0 }));
    assert!(c.finish().is_none());

    // and the file keeps both and takes both back
    let dir = Temp::new("bitmap");
    let (mut store, _) = Store::open(&dir.0, header.clone()).unwrap();
    store.add_bitmap(cut(0), output_root).unwrap();
    store.add_bitmap(cut(1), output_root).unwrap();
    drop(store);
    let (store, opened) = Store::open(&dir.0, header).unwrap();
    assert_eq!(opened, Opened { kept: 2, cut_bytes: 0 });
    assert_eq!(store.wanted(), Wanted::Output(SegmentIdentifier { height: 11, idx: 0 }));
}

/// A node that has pruned a stretch without unspent outputs longer than a
/// segment sends, for every segment in it, the one hash of the subtree
/// around them. The first such segment brings the whole subtree; the ones
/// after it bring nothing new - and still each of them, as it is kept in
/// the file, must pass the check when the file is opened again. (Found on
/// the test network, where the file lost everything from the first such
/// segment on at every restart.)
#[test]
#[allow(clippy::field_reassign_with_default)]
fn segments_inside_one_pruned_subtree_are_kept_whole() {
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    // five segments of outputs; the third and the fourth - one subtree -
    // hold no unspent output
    let count: u64 = 4 * 2048 + 700;
    let unspent = |i: u64| !(4096..8192).contains(&i) && (i.is_multiple_of(5) || i + 1 == count);
    let leaf = |i: u64| {
        let mut commit = [3u8; 33];
        commit[1..9].copy_from_slice(&i.to_be_bytes());
        OutputIdentifier {
            features: grin_core::core::OutputFeatures::Plain,
            commit: grin_util::secp::pedersen::Commitment(commit),
        }
    };
    let mut backend = VecBackend::<OutputIdentifier>::new();
    let mut mmr = PMMR::new(&mut backend);
    for i in 0..count {
        mmr.push(&leaf(i)).unwrap();
    }
    let (size, output_root) = (mmr.unpruned_size(), mmr.root().unwrap());
    let mut node = BitmapAccumulator::new();
    node.init((0..count).filter(|i| unspent(*i)), count).unwrap();
    let mut header = BlockHeader::default();
    header.height = 100;
    header.output_mmr_size = size;
    header.output_root = (output_root, node.root()).hash_with_index(size);

    let read = ReadonlyPMMR::at(&backend, size);
    let full = |idx| Segment::from_pmmr(SegmentIdentifier { height: 11, idx }, &read, true).unwrap();
    // as a node that has pruned sends the third and the fourth: the hash
    // of the subtree around both, and a proof that starts above it
    let around = pmmr::family(full(2).segment_pos_range(size).1).0;
    let pruned = |idx| {
        let (id, _, _, _, _, proof) = full(idx).parts();
        let bytes = grin_core::ser::ser_vec(&proof, grin_core::ser::ProtocolVersion::local()).unwrap();
        let hashes = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        let mut shorter = (hashes - 1).to_be_bytes().to_vec();
        shorter.extend_from_slice(&bytes[8 + 32..]);
        let proof = grin_core::ser::deserialize(&mut &shorter[..], grin_core::ser::ProtocolVersion::local(), Default::default()).unwrap();
        Segment::from_parts(id, vec![around], vec![read.get_hash(around).unwrap()], vec![], Vec::<OutputIdentifier>::new(), proof)
    };
    let bitmap = Segment::from_pmmr(SegmentIdentifier { height: 9, idx: 0 }, &node.readonly_pmmr(), false).unwrap();
    let serve = |store: &mut Store, idx: u64| {
        let segment = if idx == 2 || idx == 3 { pruned(idx) } else { full(idx) };
        store.add_output(segment)
    };

    let dir = Temp::new("pruned");
    let (mut store, _) = Store::open(&dir.0, header.clone()).unwrap();
    store.add_bitmap(bitmap, output_root).unwrap();
    for idx in 0..5 {
        serve(&mut store, idx).unwrap_or_else(|e| panic!("segment {idx}: {e:?}"));
    }
    // all the outputs are in: the peaks give the root the header binds
    assert!(matches!(store.wanted(), Wanted::RangeproofTail(_)));
    drop(store);
    let (store, opened) = Store::open(&dir.0, header.clone()).unwrap();
    assert_eq!(opened, Opened { kept: 6, cut_bytes: 0 });
    assert!(matches!(store.wanted(), Wanted::RangeproofTail(_)));
    drop(store);

    // the same from a node that has pruned nothing
    let dir = Temp::new("unpruned");
    let (mut store, _) = Store::open(&dir.0, header.clone()).unwrap();
    store.add_bitmap(Segment::from_pmmr(SegmentIdentifier { height: 9, idx: 0 }, &node.readonly_pmmr(), false).unwrap(), output_root).unwrap();
    for idx in 0..5 {
        store.add_output(full(idx)).unwrap();
    }
    drop(store);
    let (_, opened) = Store::open(&dir.0, header).unwrap();
    assert_eq!(opened, Opened { kept: 6, cut_bytes: 0 });
}
