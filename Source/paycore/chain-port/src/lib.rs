//! The chain layer as the wallet sees it.
//!
//! The wallet says where it stands; the chain layer says what comes next:
//! the next verified block, a step back, a new starting point, or nothing.
//! The chain layer keeps no memory of the wallet and is told nothing about
//! it but blocks of the chain it stands or stood at: no commitment, key or
//! amount of the wallet ever travels this way.
//! The wallet gets whole blocks and finds its own outputs itself.
//!
//! Two rules hold for every implementation:
//!
//! * "unknown" is never "nothing". A chain layer that cannot answer - it is
//!   starting, a peer is silent, a proof does not check - answers with
//!   [`Unknown`] or `None`, not with "nothing new" and not with an empty
//!   block;
//! * a block handed over here has been checked against its header by the
//!   chain layer, and the header against the chain the layer follows. How
//!   much that is worth is said by [`Status`], not assumed by the wallet.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Length of a Pedersen commitment.
pub const COMMIT_LEN: usize = 33;
/// Largest range proof of one output.
pub const MAX_PROOF_LEN: usize = 675;
/// Most outputs one block can hold (block weight 40 000, an output weighs 21).
pub const MAX_OUTPUTS: usize = 2_000;
/// Most inputs one block can hold.
pub const MAX_INPUTS: usize = 40_000;
/// Most kernels one block can hold (a kernel weighs 3).
pub const MAX_KERNELS: usize = 13_400;
/// Largest change of the verified state carried with one block.
pub const MAX_V_DELTA: usize = 1024 * 1024;
/// Largest transaction handed over for broadcast.
pub const MAX_TX_LEN: usize = 2 * 1024 * 1024;
/// Longest text a chain layer may report as its problem.
pub const MAX_PROBLEM_LEN: usize = 240;

/// A block of the chain by height and header hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tip {
    /// Height of the block.
    pub height: u64,
    /// Hash of its header.
    pub hash: [u8; 32],
}

/// One output a block adds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputFact {
    /// The commitment.
    pub commit: [u8; COMMIT_LEN],
    /// Its range proof.
    pub proof: Vec<u8>,
    /// Its position in the output MMR.
    pub pos: u64,
    /// Whether it is a coinbase output.
    pub coinbase: bool,
}

/// Everything one verified block changes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockFacts {
    /// Height of the block.
    pub height: u64,
    /// Hash of its header.
    pub hash: [u8; 32],
    /// Every output the block adds.
    pub outputs: Vec<OutputFact>,
    /// Every commitment the block spends.
    pub inputs: Vec<[u8; COMMIT_LEN]>,
    /// Excess of every kernel in the block.
    pub kernels: Vec<[u8; COMMIT_LEN]>,
    /// Opaque change of the verified state for this block.
    pub v_delta: Vec<u8>,
}

impl BlockFacts {
    /// Whether the block is within the limits of this port.
    pub fn within_limits(&self) -> bool {
        self.outputs.len() <= MAX_OUTPUTS
            && self.inputs.len() <= MAX_INPUTS
            && self.kernels.len() <= MAX_KERNELS
            && self.v_delta.len() <= MAX_V_DELTA
            && self.outputs.iter().all(|o| !o.proof.is_empty() && o.proof.len() <= MAX_PROOF_LEN)
    }
}

/// What comes after the wallet's position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// The wallet stands at the tip the chain layer has verified.
    Nothing,
    /// The block right above the wallet's position.
    Block(Box<BlockFacts>),
    /// The wallet's block is not on the followed chain: undo every block
    /// above this height and ask again.
    Rollback {
        /// Height to go back to.
        to: u64,
    },
    /// The wallet's position cannot be reached by steps back (it has none,
    /// or the gap is too deep): start over from this block.
    Reanchor(Tip),
    /// The archive is above the requested wallet tip and the chain process
    /// verified that the exact previous (height, hash) is on its prefix.
    ReanchorExtending(Tip),
}

/// How far the chain layer is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// No verified state for the current chain.
    Unknown,
    /// Verified up to a height below the tip.
    Behind,
    /// Verified at the tip.
    AtTip,
}

/// What the chain layer vouches for right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    /// How far verification is.
    pub level: Level,
    /// The highest block whose facts can be handed over.
    pub tip: Option<Tip>,
    /// The tip the chain layer has *selected* by its acceptance rules. A
    /// layer that follows one source without such rules has none.
    pub selected: Option<Tip>,
    /// Time confirmed independently of the local clock, in Unix seconds.
    pub confirmed_time: Option<u64>,
    /// Blocks after which a payment counts as confirmed.
    pub k_conf: u64,
    /// Whether the range proofs of handed-over outputs are authenticated
    /// by the chain's commitments.
    pub rangeproofs_authenticated: bool,
    /// Whether what is selected stands on something nobody vouches for
    /// yet: a starting point taken for development, or a claim of more
    /// work that went unsettled not long ago. Whatever is built on such a
    /// tip stays preliminary.
    pub provisional: bool,
}

/// What happened to a transaction handed over for broadcast.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Posted {
    /// A node holds it in its pool, or it is in a block. This is not a
    /// confirmation.
    Accepted,
    /// It was refused: the chain layer found that it cannot be valid on
    /// the chain it has verified, and sent it nowhere. Nodes themselves do
    /// not say when they refuse a transaction.
    Rejected,
    /// Nothing is known: it was not sent, or it was sent and no node has
    /// been found to hold it yet. Handing the same transaction over again
    /// asks again; it is not sent twice.
    Unknown,
}

/// The chain layer could not answer. It is not "nothing new".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unknown;

/// Most outputs in one piece of the old outputs.
pub const MAX_OLD_OUTPUTS: usize = 2_048;

/// A piece of the outputs that are older than any block the wallet was
/// given: the output MMR is cut into stretches of equal length, and piece
/// `i` is what is unspent in stretch `i`. A wallet restored from its seed
/// reads all the pieces to find what is its own.
///
/// The piece is complete in this sense: an output of its stretch that was
/// created in the block at height `before` or earlier and is unspent after
/// the block `at` is in `outputs`. Younger outputs of the stretch may be
/// missing; the wallet has them from the blocks.
///
/// A wallet that knew every output of its own up to some block has
/// nothing to find in a stretch that was full by that block: it only
/// needs to learn which of its outputs there are still unspent. Asked
/// with that block ([`ChainFeed::old_outputs_since`]), the layer may give
/// such a piece `bare`: the same outputs, complete in the same sense,
/// without their range proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OldOutputs {
    /// Outputs of this piece's stretch that are unspent after the block
    /// `at`.
    pub outputs: Vec<OutputFact>,
    /// The outputs come without range proofs: the piece says what is
    /// unspent, and a wallet can find in it only outputs it knows.
    pub bare: bool,
    /// The last block the chain layer had applied when it answered. What
    /// happens to the outputs later the blocks above `at` will tell.
    pub at: Tip,
    /// The height up to which the piece is complete; never above `at`.
    pub before: u64,
    /// The piece to ask for next; `None` after the last one.
    pub next: Option<u64>,
    /// How many pieces there are.
    pub pieces: u64,
}

impl OldOutputs {
    /// Whether the piece is within the limits of this port and makes sense
    /// as the answer to a request for piece `asked`: every output with its
    /// range proof. A bare piece is no answer to this question - a wallet
    /// that searches would find nothing in it and take that for "nothing
    /// of mine".
    pub fn answers(&self, asked: u64) -> bool {
        !self.bare && self.answers_since(asked)
    }

    /// The same for a request that named a block up to which the wallet
    /// knew its outputs: the piece may be bare, and then no output has a
    /// range proof.
    pub fn answers_since(&self, asked: u64) -> bool {
        self.outputs.len() <= MAX_OLD_OUTPUTS
            && self.outputs.iter().all(|o| if self.bare { o.proof.is_empty() } else { !o.proof.is_empty() && o.proof.len() <= MAX_PROOF_LEN })
            && self.before <= self.at.height
            && match self.next {
                Some(next) => asked.checked_add(1) == Some(next) && next < self.pieces,
                None => asked.checked_add(1) == Some(self.pieces),
            }
    }
}

/// The chain layer as the wallet sees it.
pub trait ChainFeed {
    /// What the layer vouches for now; `None` if it cannot say.
    fn status(&mut self) -> Option<Status>;
    /// What comes after the wallet's position `at` (`None`: the wallet has
    /// no position yet).
    fn next(&mut self, at: Option<Tip>) -> Result<Step, Unknown>;
    /// Hand a finished transaction to the network.
    fn post(&mut self, tx: &[u8]) -> Posted;
    /// The same, with the owner's agreement that this one transaction may
    /// go out from this computer's address if it cannot be sent privately
    /// (K192). A layer that knows no such difference hands it over as
    /// always - never less privately than `post`.
    fn post_direct(&mut self, tx: &[u8]) -> Posted {
        self.post(tx)
    }
    /// The owner switched Tor off (`true`) or back on while the layer runs
    /// (K193). True when the layer took it up; a layer that has no such
    /// switch says false, and nothing is assumed about how it sends.
    fn set_tor(&mut self, off: bool) -> bool {
        let _ = off;
        false
    }
    /// Why the layer is not getting on, in words for the user; `None` when
    /// nothing is known to be wrong. A description to show, never a fact.
    fn problem(&mut self) -> Option<String> {
        None
    }
    /// Piece `piece` of the outputs from before the wallet's history. A
    /// layer that cannot give it now - or at all - says so; that is never
    /// "there are none".
    fn old_outputs(&mut self, piece: u64) -> Result<OldOutputs, Unknown> {
        let _ = piece;
        Err(Unknown)
    }
    /// The same piece for a wallet that knew every output of its own that
    /// was created in the block `since` or earlier. If `since` is a block
    /// of the chain the layer follows, a piece whose stretch was full by
    /// that block may come bare. A layer that cannot tell - it does not
    /// have that block, or it is of another branch - gives the piece
    /// whole: that is always right, only more to read.
    fn old_outputs_since(&mut self, piece: u64, since: Tip) -> Result<OldOutputs, Unknown> {
        let _ = since;
        self.old_outputs(piece)
    }
    /// The record of a starting point made from the chain the layer has
    /// verified, for a later start from there (K188). A layer that makes
    /// none - now, or at all - says why, in words for the user. The
    /// record is at most [`MAX_POINT_LEN`] long.
    fn point(&mut self) -> Result<Vec<u8>, String> {
        Err("this chain layer makes no starting points".to_string())
    }
}

/// Longest record of a starting point handed over.
pub const MAX_POINT_LEN: usize = 64 * 1024;

/// A problem text made safe to show: plain printable characters only, cut
/// to [`MAX_PROBLEM_LEN`]. The text may quote a peer, which is anybody.
pub fn plain_problem(text: &str) -> String {
    text.chars()
        .take(MAX_PROBLEM_LEN)
        .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' })
        .collect()
}
