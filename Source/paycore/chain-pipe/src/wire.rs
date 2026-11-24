//! Frames of the chain pipe and the encoding of what they carry.
use fly_paycore_chain_port::{BlockFacts, Level, OldOutputs, OutputFact, Posted, Status, Tip, COMMIT_LEN};
use fly_paycore_pipe_link::Cut;

/// Largest frame in either direction: room for the largest block.
pub const MAX_FRAME: usize = 4 * 1024 * 1024;
/// Version of this protocol; the two sides must agree exactly.
pub const VERSION: u8 = 7;

// requests
pub(crate) const STATUS: u8 = 0x01;
pub(crate) const NEXT: u8 = 0x02;
pub(crate) const POST: u8 = 0x03;
pub(crate) const PROBLEM: u8 = 0x04;
pub(crate) const OLD: u8 = 0x05;
pub(crate) const OLD_SINCE: u8 = 0x06;
// answers
pub(crate) const STATUS_IS: u8 = 0x81;
pub(crate) const NOTHING: u8 = 0x82;
pub(crate) const BLOCK: u8 = 0x83;
pub(crate) const ROLLBACK: u8 = 0x84;
pub(crate) const REANCHOR: u8 = 0x85;
pub(crate) const POSTED: u8 = 0x86;
pub(crate) const TEXT: u8 = 0x87;
pub(crate) const NO_PROBLEM: u8 = 0x88;
pub(crate) const OLD_ARE: u8 = 0x89;
pub(crate) const REANCHOR_EXTENDING: u8 = 0x8A;
pub(crate) const UNKNOWN: u8 = 0x8F;

/// What the chain process needs to start. Nothing in it is secret, and
/// nothing in it is about the wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The chain: 1 main, 2 test, 3 automated tests.
    pub network: u8,
    /// Hash of the genesis block the wallet's journal is bound to.
    pub genesis: [u8; 32],
    /// Directory for the chain process's own files.
    pub data_dir: String,
    /// Peers or nodes the user named, if any.
    pub peers: Vec<String>,
    /// Longest wait for the chain process to report ready, in seconds.
    pub start_timeout_secs: u32,
    /// The user agreed that a transaction may go to a node directly, from
    /// this computer's address, when it cannot be sent through Tor.
    pub direct_post: bool,
    /// Tor bridges the user chose, one a line; empty for none. The chain
    /// process reads and checks them; with any, Tor is reached through
    /// them only.
    pub tor_bridges: String,
}

impl Config {
    /// The wire form.
    pub fn encode(&self) -> Option<Vec<u8>> {
        let mut out = vec![VERSION, self.network];
        out.extend_from_slice(&self.genesis);
        let mut text = |t: &str| -> Option<()> {
            out.extend_from_slice(&u16::try_from(t.len()).ok()?.to_le_bytes());
            out.extend_from_slice(t.as_bytes());
            Some(())
        };
        text(&self.data_dir)?;
        let n = u16::try_from(self.peers.len()).ok()?;
        let peers = self.peers.clone();
        let mut out2 = Vec::new();
        for p in &peers {
            out2.extend_from_slice(&u16::try_from(p.len()).ok()?.to_le_bytes());
            out2.extend_from_slice(p.as_bytes());
        }
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&out2);
        out.extend_from_slice(&self.start_timeout_secs.to_le_bytes());
        out.extend_from_slice(&u16::try_from(self.tor_bridges.len()).ok()?.to_le_bytes());
        out.extend_from_slice(self.tor_bridges.as_bytes());
        // the agreement to the direct way stays the last byte
        out.push(u8::from(self.direct_post));
        (out.len() < MAX_FRAME).then_some(out)
    }

    /// Read the wire form; every byte must be accounted for.
    pub fn decode(payload: &[u8]) -> Option<Config> {
        let mut c = Cut(payload);
        if c.u8()? != VERSION {
            return None;
        }
        let network = c.u8()?;
        let genesis = c.array()?;
        let data_dir = c.short_text()?;
        let n = usize::from(c.u16()?);
        let mut peers = Vec::new();
        for _ in 0..n {
            peers.push(c.short_text()?);
        }
        let config = Config {
            network,
            genesis,
            data_dir,
            peers,
            start_timeout_secs: c.u32()?,
            tor_bridges: c.short_text()?,
            direct_post: match c.u8()? {
                0 => false,
                1 => true,
                _ => return None,
            },
        };
        c.done().then_some(config)
    }
}

fn put_tip(out: &mut Vec<u8>, tip: Option<Tip>) {
    match tip {
        None => out.push(0),
        Some(t) => {
            out.push(1);
            out.extend_from_slice(&t.height.to_le_bytes());
            out.extend_from_slice(&t.hash);
        }
    }
}

fn cut_tip(c: &mut Cut<'_>) -> Option<Option<Tip>> {
    match c.u8()? {
        0 => Some(None),
        1 => Some(Some(Tip {
            height: c.u64()?,
            hash: c.array()?,
        })),
        _ => None,
    }
}

/// A position (or none) in its wire form.
pub fn encode_tip(tip: Option<Tip>) -> Vec<u8> {
    let mut out = Vec::new();
    put_tip(&mut out, tip);
    out
}

/// Read a position (or none); every byte must be accounted for.
pub fn decode_tip(payload: &[u8]) -> Option<Option<Tip>> {
    let mut c = Cut(payload);
    let tip = cut_tip(&mut c)?;
    c.done().then_some(tip)
}

/// A status in its wire form.
pub fn encode_status(s: &Status) -> Vec<u8> {
    let mut out = vec![match s.level {
        Level::Unknown => 0,
        Level::Behind => 1,
        Level::AtTip => 2,
    }];
    put_tip(&mut out, s.tip);
    put_tip(&mut out, s.selected);
    match s.confirmed_time {
        None => out.push(0),
        Some(t) => {
            out.push(1);
            out.extend_from_slice(&t.to_le_bytes());
        }
    }
    out.extend_from_slice(&s.k_conf.to_le_bytes());
    out.push(u8::from(s.rangeproofs_authenticated));
    out.push(u8::from(s.provisional));
    out
}

/// Read a status; every byte must be accounted for.
pub fn decode_status(payload: &[u8]) -> Option<Status> {
    let mut c = Cut(payload);
    let level = match c.u8()? {
        0 => Level::Unknown,
        1 => Level::Behind,
        2 => Level::AtTip,
        _ => return None,
    };
    let tip = cut_tip(&mut c)?;
    let selected = cut_tip(&mut c)?;
    let confirmed_time = match c.u8()? {
        0 => None,
        1 => Some(c.u64()?),
        _ => return None,
    };
    let k_conf = c.u64()?;
    let rangeproofs_authenticated = match c.u8()? {
        0 => false,
        1 => true,
        _ => return None,
    };
    let provisional = match c.u8()? {
        0 => false,
        1 => true,
        _ => return None,
    };
    c.done().then_some(Status {
        level,
        tip,
        selected,
        confirmed_time,
        k_conf,
        rangeproofs_authenticated,
        provisional,
    })
}

/// A block in its wire form; `None` if it is beyond the limits of the port.
pub fn encode_block(b: &BlockFacts) -> Option<Vec<u8>> {
    if !b.within_limits() {
        return None;
    }
    let mut out = Vec::new();
    out.extend_from_slice(&b.height.to_le_bytes());
    out.extend_from_slice(&b.hash);
    out.extend_from_slice(&u32::try_from(b.outputs.len()).ok()?.to_le_bytes());
    for o in &b.outputs {
        out.extend_from_slice(&o.commit);
        out.extend_from_slice(&o.pos.to_le_bytes());
        out.push(u8::from(o.coinbase));
        out.extend_from_slice(&u16::try_from(o.proof.len()).ok()?.to_le_bytes());
        out.extend_from_slice(&o.proof);
    }
    for list in [&b.inputs, &b.kernels] {
        out.extend_from_slice(&u32::try_from(list.len()).ok()?.to_le_bytes());
        for c in list {
            out.extend_from_slice(c);
        }
    }
    out.extend_from_slice(&u32::try_from(b.v_delta.len()).ok()?.to_le_bytes());
    out.extend_from_slice(&b.v_delta);
    (out.len() < MAX_FRAME).then_some(out)
}

/// Read a block. Counts are checked against the limits of the port before
/// anything is allocated for them, and every byte must be accounted for.
pub fn decode_block(payload: &[u8]) -> Option<BlockFacts> {
    use fly_paycore_chain_port::{MAX_INPUTS, MAX_KERNELS, MAX_OUTPUTS, MAX_PROOF_LEN, MAX_V_DELTA};
    let mut c = Cut(payload);
    let height = c.u64()?;
    let hash = c.array()?;
    let n = usize::try_from(c.u32()?).ok().filter(|n| *n <= MAX_OUTPUTS)?;
    let mut outputs = Vec::with_capacity(n);
    for _ in 0..n {
        let commit = c.array::<COMMIT_LEN>()?;
        let pos = c.u64()?;
        let coinbase = match c.u8()? {
            0 => false,
            1 => true,
            _ => return None,
        };
        let len = usize::from(c.u16()?);
        if len == 0 || len > MAX_PROOF_LEN {
            return None;
        }
        outputs.push(OutputFact {
            commit,
            proof: c.take(len)?.to_vec(),
            pos,
            coinbase,
        });
    }
    let mut lists = [Vec::new(), Vec::new()];
    for (list, max) in lists.iter_mut().zip([MAX_INPUTS, MAX_KERNELS]) {
        let n = usize::try_from(c.u32()?).ok().filter(|n| *n <= max)?;
        list.reserve(n);
        for _ in 0..n {
            list.push(c.array::<COMMIT_LEN>()?);
        }
    }
    let [inputs, kernels] = lists;
    let v_delta = c.bytes(MAX_V_DELTA)?.to_vec();
    c.done().then_some(BlockFacts {
        height,
        hash,
        outputs,
        inputs,
        kernels,
        v_delta,
    })
}

/// The request for piece `piece` by a wallet that knew its outputs up
/// to the block `since`.
pub fn encode_old_since(piece: u64, since: Tip) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(&piece.to_le_bytes());
    out.extend_from_slice(&since.height.to_le_bytes());
    out.extend_from_slice(&since.hash);
    out
}

/// Read that request: exactly a piece and a block.
pub fn decode_old_since(payload: &[u8]) -> Option<(u64, Tip)> {
    let mut c = Cut(payload);
    let piece = c.u64()?;
    let since = Tip {
        height: c.u64()?,
        hash: c.array()?,
    };
    c.done().then_some((piece, since))
}

/// A piece of the old outputs, as the answer to a request for piece
/// `asked`; `since` says whether the request named a block up to which
/// the wallet knew its outputs - only then may the piece be bare. `None`
/// if it is beyond the limits of the port or makes no sense as that
/// answer.
pub fn encode_old(old: &OldOutputs, asked: u64, since: bool) -> Option<Vec<u8>> {
    if !(if since { old.answers_since(asked) } else { old.answers(asked) }) {
        return None;
    }
    let mut out = Vec::new();
    // the number of the piece goes along: the same bytes are not the
    // answer to any other question
    out.extend_from_slice(&asked.to_le_bytes());
    out.extend_from_slice(&old.at.height.to_le_bytes());
    out.extend_from_slice(&old.at.hash);
    out.extend_from_slice(&old.before.to_le_bytes());
    out.extend_from_slice(&old.pieces.to_le_bytes());
    out.push(u8::from(old.next.is_some()));
    out.push(u8::from(old.bare));
    out.extend_from_slice(&u32::try_from(old.outputs.len()).ok()?.to_le_bytes());
    for o in &old.outputs {
        out.extend_from_slice(&o.commit);
        out.extend_from_slice(&o.pos.to_le_bytes());
        out.push(u8::from(o.coinbase));
        out.extend_from_slice(&u16::try_from(o.proof.len()).ok()?.to_le_bytes());
        out.extend_from_slice(&o.proof);
    }
    (out.len() < MAX_FRAME).then_some(out)
}

/// Read a piece of the old outputs sent in answer to a request for piece
/// `asked`; `since` says whether the request named a block, and only then
/// is a bare piece an answer. The count is checked against the limit of
/// the port before anything is allocated, every byte must be accounted
/// for, and the piece must make sense as that answer.
pub fn decode_old(payload: &[u8], asked: u64, since: bool) -> Option<OldOutputs> {
    use fly_paycore_chain_port::{MAX_OLD_OUTPUTS, MAX_PROOF_LEN};
    let mut c = Cut(payload);
    if c.u64()? != asked {
        return None;
    }
    let at = Tip {
        height: c.u64()?,
        hash: c.array()?,
    };
    let before = c.u64()?;
    let pieces = c.u64()?;
    let next = match c.u8()? {
        0 => None,
        1 => Some(asked.checked_add(1)?),
        _ => return None,
    };
    let bare = match c.u8()? {
        0 => false,
        1 if since => true,
        _ => return None,
    };
    let n = usize::try_from(c.u32()?).ok().filter(|n| *n <= MAX_OLD_OUTPUTS)?;
    let mut outputs = Vec::with_capacity(n);
    for _ in 0..n {
        let commit = c.array::<COMMIT_LEN>()?;
        let pos = c.u64()?;
        let coinbase = match c.u8()? {
            0 => false,
            1 => true,
            _ => return None,
        };
        let len = usize::from(c.u16()?);
        // whether a proof may be missing is the port's rule, below
        if len > MAX_PROOF_LEN {
            return None;
        }
        outputs.push(OutputFact {
            commit,
            proof: c.take(len)?.to_vec(),
            pos,
            coinbase,
        });
    }
    let old = OldOutputs {
        outputs,
        bare,
        at,
        before,
        next,
        pieces,
    };
    (c.done() && if since { old.answers_since(asked) } else { old.answers(asked) }).then_some(old)
}

pub(crate) fn posted_code(p: Posted) -> u8 {
    match p {
        Posted::Accepted => 1,
        Posted::Rejected => 2,
        Posted::Unknown => 3,
    }
}

pub(crate) fn posted_from(code: &[u8]) -> Option<Posted> {
    match code {
        [1] => Some(Posted::Accepted),
        [2] => Some(Posted::Rejected),
        [3] => Some(Posted::Unknown),
        _ => None,
    }
}
