//! The limits of the port, which both sides of it rely on.
use fly_paycore_chain_port::{
    plain_problem, BlockFacts, ChainFeed, OldOutputs, OutputFact, Posted, Status, Step, Tip, Unknown, MAX_INPUTS, MAX_KERNELS,
    MAX_OLD_OUTPUTS, MAX_OUTPUTS, MAX_PROBLEM_LEN, MAX_PROOF_LEN, MAX_V_DELTA,
};

fn output(proof: usize) -> OutputFact {
    OutputFact { commit: [2; 33], proof: vec![1; proof], pos: 1, coinbase: false }
}

#[test]
fn a_block_is_within_limits_or_it_is_not_a_block() {
    let full = BlockFacts {
        height: 1,
        hash: [1; 32],
        outputs: vec![output(MAX_PROOF_LEN); MAX_OUTPUTS],
        inputs: vec![[3; 33]; MAX_INPUTS],
        kernels: vec![[4; 33]; MAX_KERNELS],
        v_delta: vec![0; MAX_V_DELTA],
    };
    assert!(full.within_limits());
    assert!(BlockFacts::default().within_limits());
    let mut b = full.clone();
    b.outputs.push(output(1));
    assert!(!b.within_limits());
    let mut b = full.clone();
    b.inputs.push([3; 33]);
    assert!(!b.within_limits());
    let mut b = full.clone();
    b.kernels.push([4; 33]);
    assert!(!b.within_limits());
    let mut b = full.clone();
    b.v_delta.push(0);
    assert!(!b.within_limits());
    for proof in [0, MAX_PROOF_LEN + 1] {
        let mut b = full.clone();
        b.outputs[7] = output(proof);
        assert!(!b.within_limits(), "a proof of {proof} bytes");
    }
}

#[test]
fn a_problem_is_short_plain_text() {
    assert_eq!(plain_problem("only one peer answers"), "only one peer answers");
    assert_eq!(plain_problem("line\none\u{7}"), "line?one?");
    assert_eq!(plain_problem(&"y".repeat(1000)).len(), MAX_PROBLEM_LEN);
}

fn piece(next: Option<u64>, pieces: u64) -> OldOutputs {
    OldOutputs {
        outputs: vec![output(MAX_PROOF_LEN); MAX_OLD_OUTPUTS],
        at: Tip { height: 900, hash: [9; 32] },
        before: 900,
        next,
        pieces,
        bare: false,
    }
}

/// A piece of the old outputs is the answer to one question: it is within
/// the limits, it is one of the pieces there are, it is complete up to a
/// block that has been applied, and it names the piece after itself - or
/// none, if it is the last.
#[test]
fn an_old_piece_answers_its_question_or_it_is_not_a_piece() {
    assert!(piece(Some(4), 10).answers(3));
    assert!(piece(None, 4).answers(3), "the last piece");
    assert!(piece(None, 1).answers(0), "the only piece");
    assert!(OldOutputs { outputs: Vec::new(), ..piece(Some(1), 2) }.answers(0), "an empty piece");
    assert!(OldOutputs { before: 0, ..piece(Some(4), 10) }.answers(3));

    assert!(!piece(Some(4), 10).answers(2), "the answer to another question");
    assert!(!piece(Some(4), 10).answers(4));
    assert!(!piece(Some(5), 10).answers(3), "a piece is skipped");
    assert!(!piece(Some(3), 10).answers(3), "the same piece again");
    assert!(!piece(None, 10).answers(3), "the end before the last piece");
    assert!(!piece(Some(4), 4).answers(3), "a piece after the last");
    assert!(!piece(None, 3).answers(3), "a piece that is not there");
    assert!(!piece(None, 0).answers(0), "a piece of nothing");
    assert!(!piece(None, u64::MAX).answers(u64::MAX), "no piece has this number");
    assert!(!OldOutputs { before: 901, ..piece(Some(4), 10) }.answers(3), "complete up to a block that is not applied");
    let mut p = piece(Some(4), 10);
    p.outputs.push(output(1));
    assert!(!p.answers(3), "an output too many");
    for proof in [0, MAX_PROOF_LEN + 1] {
        let mut p = piece(Some(4), 10);
        p.outputs[7] = output(proof);
        assert!(!p.answers(3), "a proof of {proof} bytes");
    }
}

/// A chain layer that was not taught to give old outputs says so: "I
/// cannot say", never "there are none".
#[test]
fn a_layer_without_old_outputs_does_not_say_there_are_none() {
    struct Plain;
    impl ChainFeed for Plain {
        fn status(&mut self) -> Option<Status> {
            None
        }
        fn next(&mut self, _at: Option<Tip>) -> Result<Step, Unknown> {
            Ok(Step::Nothing)
        }
        fn post(&mut self, _tx: &[u8]) -> Posted {
            Posted::Unknown
        }
    }
    assert_eq!(Plain.old_outputs(0), Err(Unknown));
}

/// A piece without range proofs is an answer only to a question that
/// named a block the wallet knew its outputs up to: in answer to any
/// other it would read as "nothing of yours here". A piece is bare or
/// whole, never a mix, and every other rule of a piece holds for both.
#[test]
fn a_bare_piece_answers_only_a_question_that_named_a_block() {
    let mut bare = piece(Some(4), 10);
    bare.outputs.iter_mut().for_each(|o| o.proof.clear());
    bare.bare = true;
    assert!(bare.answers_since(3));
    assert!(!bare.answers(3), "no block was named");
    assert!(piece(Some(4), 10).answers_since(3), "a whole piece answers such a question too");
    assert!(OldOutputs { outputs: Vec::new(), ..bare.clone() }.answers_since(3), "an empty one");

    let mut mixed = bare.clone();
    mixed.outputs[7] = output(40);
    assert!(!mixed.answers_since(3), "bare, with a range proof");
    let mut hollow = piece(Some(4), 10);
    hollow.outputs[7].proof.clear();
    assert!(!hollow.answers_since(3), "whole, with a range proof missing");
    assert!(!hollow.answers(3));

    assert!(!bare.answers_since(2), "the answer to another question");
    assert!(!OldOutputs { next: None, ..bare.clone() }.answers_since(3), "the end before the last piece");
    assert!(!OldOutputs { before: 901, ..bare.clone() }.answers_since(3));
    let mut many = bare.clone();
    many.outputs.push(many.outputs[0].clone());
    assert!(!many.answers_since(3), "an output too many");

    // A chain layer that was not taught to tell what a wallet knew gives
    // the piece whole: always right, only more to read.
    struct Whole(Vec<u64>);
    impl ChainFeed for Whole {
        fn status(&mut self) -> Option<Status> {
            None
        }
        fn next(&mut self, _at: Option<Tip>) -> Result<Step, Unknown> {
            Ok(Step::Nothing)
        }
        fn post(&mut self, _tx: &[u8]) -> Posted {
            Posted::Unknown
        }
        fn old_outputs(&mut self, asked: u64) -> Result<OldOutputs, Unknown> {
            self.0.push(asked);
            Ok(piece(Some(asked + 1), 10))
        }
    }
    let mut layer = Whole(Vec::new());
    let answer = layer.old_outputs_since(3, Tip { height: 5, hash: [5; 32] }).unwrap();
    assert!(!answer.bare && answer.answers(3));
    assert_eq!(layer.0, [3]);
}
