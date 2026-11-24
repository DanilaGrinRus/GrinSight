//! `fly-chain proofs`: header proofs of a node with the HEADER_PROOF_HIST
//! extension, asked for by hand, checked and timed. The node here is the
//! Grin node's own network code; it builds the proofs with the node's own
//! function from the headers of a chain mined in the test. Run with
//! `cargo test --features test-net`.
mod kit;

use fly_chain::TEST_START_FILE;
use fly_chain_headers::testkit::TestChain;
use fly_chain_state::testkit::Source;
use kit::{proofs, proofs_sample, Node, Run, Temp};
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};

/// Forty blocks; headers have the fifth version from height 12.
fn chain_of_40() -> Arc<RwLock<Source>> {
    Arc::new(RwLock::new(Source::thin(40)))
}
fn data(tag: &str, source: &Arc<RwLock<Source>>, start: u64) -> Temp {
    let t = Temp::new(tag);
    let record = TestChain::from_headers(source.read().unwrap().headers()).record(start);
    std::fs::write(t.0.join(TEST_START_FILE), record).unwrap();
    t
}
fn line<'a>(run: &'a Run, kind: &str) -> &'a str {
    run.out
        .lines()
        .find(|l| l.starts_with("proofs:") && l.contains(&format!("kind={kind} ")) && l.contains("answered="))
        .unwrap_or_else(|| panic!("no line for {kind} in:\n{}", run.out))
}

/// Proofs for headers this program has verified itself and for headers
/// from before its starting point: every header is a leaf of the anchor's
/// header MMR, carries a proof of work for its fields, passes the full
/// check with its two predecessors, and - where this program has the
/// header - is that header. Headers from before the fourth hard fork are
/// shown to be members and nothing more is claimed for them. A request
/// the node cannot answer is ignored, and the node goes on answering.
#[test]
fn header_proofs_are_asked_for_and_checked() {
    let source = chain_of_40();
    let node = Node::with_state(&source);

    // the starting point at 14: the anchor is the header at 20, and
    // everything from 14 up this program has verified itself
    let run = proofs(&data("proofs14", &source, 14), &[node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(run.out.contains("anchor: height=20 ") && run.out.contains("this program has verified 14..=40; headers of version 5 from 12"), "{}", run.out);
    assert!(run.out.contains("header_proofs=yes"), "{}", run.out);
    let one = line(&run, "one-verified");
    assert!(one.contains("heights=3 answered=2/2") && one.contains("members=3 pow=3 full=1 before_hf4=0 same_as_verified=3"), "{one}");
    let many = line(&run, "many-verified");
    assert!(many.contains("heights=6 answered=2/2") && many.contains("members=6 pow=6 full=4 before_hf4=0 same_as_verified=6"), "{many}");
    let early = line(&run, "before-hf4");
    assert!(early.contains("heights=3 answered=2/2") && early.contains("members=3 pow=3 full=0 before_hf4=1 same_as_verified=0"), "{early}");
    assert!(!run.out.contains("kind=one-old"), "nothing of the fifth version lies below 14 with two predecessors: {}", run.out);
    assert!(run.out.contains("kind=unknown-anchor ignored (no answer in 3 s); the request after it: served"), "{}", run.out);
    // What the node's own helper says of an answer taken as a whole: every
    // header in it is asked for its own two predecessors, so the first two
    // of a run of three cannot pass.
    assert!(run.out.contains("kind=one-verified the node's own helper on the whole answer, nothing trusted beforehand: sampled height 14 requires header h-1=13"), "{}", run.out);
    assert!(run.out.contains("kind=before-hf4 the node's own helper on the whole answer, nothing trusted beforehand: pre-HF4 header at height"), "{}", run.out);

    // the starting point at 30: the anchor is that header, and the
    // headers asked for are older than anything this program has
    let run = proofs(&data("proofs30", &source, 30), &[node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(run.out.contains("anchor: height=30 "), "{}", run.out);
    let one = line(&run, "one-old");
    assert!(one.contains("heights=3 answered=2/2") && one.contains("members=3 pow=3 full=1 before_hf4=0 same_as_verified=0"), "{one}");
    let many = line(&run, "many-old");
    assert!(many.contains("heights=18 answered=2/2") && many.contains("members=18 pow=18 full=16 before_hf4=0 same_as_verified=0"), "{many}");
    assert!(!run.out.contains("kind=one-verified"), "{}", run.out);
    assert!(!run.out.contains("REFUSED"), "{}", run.out);
}

/// A sample over the whole history below the anchor: runs of three
/// heights drawn at random, asked for in requests of up to twenty-one
/// runs, every answer checked, and the cost added up. Asked for more than
/// the history holds, the sample is all of it.
#[test]
fn a_sample_over_the_history_is_asked_for_and_checked() {
    let source = chain_of_40();
    let node = Node::with_state(&source);
    let t = data("sample", &source, 20);
    let found = |run: &Run| {
        run.out
            .lines()
            .find(|l| l.starts_with("sample: node="))
            .unwrap_or_else(|| panic!("no line for the sample in:\n{}", run.out))
            .to_string()
    };

    // the anchor is the header at 20: six runs of three lie below it
    let run = proofs_sample(&t, &[node.addr], 60, 50);
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(run.out.contains("sample: drawn=6 from 1..20, each with its two predecessors; below version 5: 3;"), "{}", run.out);
    let all = found(&run);
    assert!(all.contains("sampled=6 heights=18 requests=1 answered=1/1 "), "{all}");
    // 1..=18 in one answer: sixteen have their two predecessors there, nine of them from before version 5
    assert!(all.ends_with("members=18 pow=18 full=7 before_hf4=9 same_as_verified=0"), "{all}");
    assert!(!run.out.contains("kind="), "the sample is asked for instead of the fixed requests: {}", run.out);

    // two runs out of the six
    let run = proofs_sample(&t, &[node.addr], 60, 2);
    assert_eq!(run.code, 0, "{}", run.out);
    let two = found(&run);
    assert!(two.contains("sampled=2 heights=6 requests=1 answered=1/1 ") && two.contains("members=6 pow=6 "), "{two}");

    // a node whose proofs do not hold - a path changed, then a header
    // changed, which the reader of the answer already refuses: the run
    // says so and fails
    node.served.bend_header_proofs.store(2, Ordering::Relaxed);
    let run = proofs_sample(&t, &[node.addr], 60, 50);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(found(&run).contains("answered=1/1 ") && found(&run).contains(" REFUSED: header proof root mismatch"), "{}", run.out);
    node.served.bend_header_proofs.store(1, Ordering::Relaxed);
    let run = proofs_sample(&t, &[node.addr], 60, 50);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(found(&run).contains("answered=0/1 ") && found(&run).ends_with(" the session ended: the answer could not be read"), "{}", run.out);
}

/// What a proof does not show is not taken from it - here without a
/// network, on proofs built with the node's own function. A header with
/// one field changed is still a leaf of the header MMR, because a leaf is
/// made of the proof-of-work nonces alone; it is refused because its proof
/// of work does not cover the changed field.
#[test]
fn a_proof_is_not_believed_beyond_what_it_shows() {
    use fly_chain::probe::{check, Checked};
    use grin_core::core::hash::{Hash, Hashed};
    use grin_core::core::pmmr::{VecBackend, PMMR};
    use grin_core::core::BlockHeader;
    use grin_p2p::header_proof::{build_header_proofs, verify_memberships};
    let source = chain_of_40();
    let headers = source.read().unwrap().headers();
    grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::AutomatedTesting);
    let anchor = headers[30].clone();
    let mut backend = VecBackend::<BlockHeader>::new();
    {
        let mut mmr = PMMR::new(&mut backend);
        headers.iter().take(30).for_each(|h| {
            mmr.push(h).unwrap();
        });
    }
    let asked = [14u64, 15, 16, 22];
    let wanted: Vec<BlockHeader> = asked.iter().map(|h| headers[*h as usize].clone()).collect();
    let build = || build_header_proofs(&backend, &anchor, &wanted).unwrap();
    let known = |height: u64| (height >= 15).then(|| headers[height as usize].clone());
    let nothing = |_: u64| None;

    // 16 has its two predecessors here, 22 has not; 15, 16 and 22 are known
    assert_eq!(check(&anchor, &build(), &asked, known), Ok(Checked { members: 4, pow: 4, full: 1, before_hf4: 0, same: 3 }));
    assert_eq!(check(&anchor, &build(), &asked, nothing).map(|c| c.same), Ok(0));

    // a field changed: a member all the same, and refused
    let mut bent = build();
    bent.items[2].header.output_mmr_size += 1;
    assert_eq!(verify_memberships(&anchor, &bent), Ok(()), "the leaf is the nonces alone");
    assert_eq!(check(&anchor, &bent, &asked, nothing), Err("the header at 16 carries no valid proof of work for its fields".to_string()));
    // a hash of a path changed
    let mut bent = build();
    bent.items[1].path[0] = Hash::from_vec(&[7; 32]);
    assert_eq!(check(&anchor, &bent, &asked, nothing), Err("header proof root mismatch at height 15".to_string()));
    // a header of the chain, with its own true path, in the place of another
    let mut swapped = build();
    swapped.items.swap(0, 1);
    assert_eq!(check(&anchor, &swapped, &asked, nothing), Err("the answer holds other heights than were asked for".to_string()));
    let mut short = build();
    short.items.pop();
    assert_eq!(check(&anchor, &short, &asked, nothing), Err("the answer holds other heights than were asked for".to_string()));
    // proofs under another anchor
    assert_eq!(check(&headers[31], &build(), &asked, nothing), Err("the answer is for another anchor".to_string()));
    let mut renamed = build();
    renamed.anchor = headers[31].hash();
    assert!(check(&headers[31], &renamed, &asked, nothing).is_err(), "the paths lead to the root of 30, not of 31");
    // a header this program has verified, and the node's is another
    let other = |height: u64| (height == 15).then(|| headers[16].clone());
    assert_eq!(check(&anchor, &build(), &asked, other), Err("the header at 15 is not the one this program has verified".to_string()));
    // the links between a header and its predecessors: 16 given with 14 and 15 of ... 14 and 15
    // themselves, but in an answer that claims to be 13, 14, 16 the heights say so
    let gap = [14u64, 15, 17];
    let wanted_gap: Vec<BlockHeader> = gap.iter().map(|h| headers[*h as usize].clone()).collect();
    let apart = build_header_proofs(&backend, &anchor, &wanted_gap).unwrap();
    assert_eq!(check(&anchor, &apart, &gap, nothing).map(|c| c.full), Ok(0), "17 without 16: no full check is claimed");
}

/// The same over the network. The node's reader already refuses a header
/// whose proof of work does not cover its fields: such an answer cannot be
/// read at all. A changed path is refused by the check. A node that does
/// not say it gives header proofs is not asked.
#[test]
fn a_node_with_bent_proofs_is_caught() {
    let source = chain_of_40();
    let node = Node::with_state(&source);
    node.served.bend_header_proofs.store(1, Ordering::Relaxed);
    let run = proofs(&data("bentfield", &source, 14), &[node.addr], 60);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(line(&run, "one-verified").contains("answered=0/2") && line(&run, "one-verified").contains("the answer could not be read"), "{}", run.out);
    assert!(!run.out.contains("members="), "{}", run.out);

    node.served.bend_header_proofs.store(2, Ordering::Relaxed);
    let run = proofs(&data("bentpath", &source, 14), &[node.addr], 60);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(line(&run, "one-verified").contains("REFUSED: header proof root mismatch at height 14"), "{}", run.out);

    let plain = Node::start(&source.read().unwrap().headers());
    let run = proofs(&data("noproofs", &source, 14), &[plain.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(run.out.contains("header_proofs=no") && !run.out.contains("answered="), "{}", run.out);
    assert_eq!(plain.served.header_proofs_asked.load(Ordering::Relaxed), 0);
}

/// `fly-chain segments`: once the state is collected, a node is asked for
/// segments of the rangeproof and output MMRs of larger heights than this
/// program uses, and every answer is checked like the usual ones - against
/// the roots in the verified header, with the verified bitmap. The node
/// here is the node's own code for cutting segments, which gives any
/// height; what the nodes of a network give is for a run there to show.
#[test]
fn segments_of_other_heights_are_asked_for_and_checked() {
    let source = chain_of_40();
    let node = Node::with_state(&source);
    let t = data("segments", &source, 14);
    let run = kit::segments(&t, &[node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(run.out.contains("segments: state at height=20 "), "{}", run.out);
    for kind in ["rangeproofs", "outputs"] {
        for height in 11..=16 {
            let line = run
                .out
                .lines()
                .find(|l| l.starts_with("segments: node=") && l.contains(&format!("kind={kind} height={height} ")))
                .unwrap_or_else(|| panic!("no line for {kind} at {height} in:\n{}", run.out));
            // a small tree: one segment of any of these heights is all of it
            assert!(line.contains("whole_tree=1 asked=1 answered=1 valid=1 "), "{line}");
        }
        assert!(run.out.contains(&format!("kind={kind} given and valid at heights: 11,12,13,14,15,16")), "{}", run.out);
    }
    // A node that changes what it gives: the answers do not hold, and the
    // run fails. The state is in the file by now and is not asked for again.
    node.served.bend_proofs.store(true, Ordering::Relaxed);
    let run = kit::segments(&t, &[node.addr], 60);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(run.out.contains("kind=rangeproofs height=11 whole_tree=1 asked=1 answered=1 valid=0 "), "{}", run.out);
    assert!(run.out.contains("kind=rangeproofs given and valid at heights: none"), "{}", run.out);
    assert!(run.out.contains("kind=outputs given and valid at heights: 11,12,13,14,15,16"), "{}", run.out);
    // and the same for the outputs
    node.served.bend_proofs.store(false, Ordering::Relaxed);
    node.served.bend.store(true, Ordering::Relaxed);
    let run = kit::segments(&t, &[node.addr], 60);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(run.out.contains("kind=outputs height=13 whole_tree=1 asked=1 answered=1 valid=0 "), "{}", run.out);
    assert!(run.out.contains("kind=rangeproofs given and valid at heights: 11,12,13,14,15,16"), "{}", run.out);
}
