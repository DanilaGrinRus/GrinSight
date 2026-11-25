//! Trying a node's header proofs.
//!
//! A node with the HEADER_PROOF_HIST extension (mimblewimble/grin pull
//! request 3963) gives, for a header it is asked about, the header and its
//! path in the header MMR up to the root that a later header - the anchor -
//! commits to. This module asks for such proofs, checks them and measures
//! the answers. It is a probe: the chain process itself does not rely on
//! these proofs for anything.
//!
//! The anchor is a header of the chain this program has verified from its
//! starting point. What a proof is checked for:
//!
//! * the answer is the answer to the question: the anchor, and the heights
//!   that were asked for, in order;
//! * every header is a leaf of the header MMR the anchor commits to (the
//!   node's own check, `verify_memberships`). A leaf of that MMR is made of
//!   the proof-of-work nonces alone, so this says nothing yet about the
//!   other fields of the header;
//! * every header carries a valid proof of work for all its fields
//!   (`pow::verify_size`): that binds the fields to the nonces;
//! * for a header whose two predecessors came in the same answer, the
//!   node's full check of the three (`verify_header_proofs_with_pow`):
//!   links, times, total work, and the difficulty the consensus rules
//!   demand of it;
//! * a header at a height this program has verified itself is, byte for
//!   byte, the header it has.
//!
//! The connection is made by hand: the node's network code hands a
//! received answer of this kind to nobody.
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::{BlockHeader, OutputIdentifier, Segment, SegmentIdentifier};
use grin_core::pow::{self, Difficulty};
use grin_core::ser::{self, ProtocolVersion};
use grin_p2p::handshake::Handshake;
use grin_p2p::header_proof::{verify_header_proofs_with_pow, verify_memberships};
use grin_p2p::msg::{self, GetHeaderProofs, HeaderProofItem, HeaderProofs, MsgHeader, MsgHeaderWrapper, OutputSegmentResponse, Ping, Pong, SegmentRequest, SegmentResponse, Type};
use grin_util::secp::pedersen::RangeProof;
use grin_p2p::{Capabilities, P2PConfig, PeerAddr, MAX_HEADER_PROOF_ITEMS};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// Between two requests to one node, as everywhere in this program.
pub const ASK_GAP: Duration = Duration::from_millis(250);
/// The largest message that is read past instead of ending the session.
const MAX_OTHER_MESSAGE: u64 = 8 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// The heights to ask for so that each of `tops` comes with its two
/// predecessors: strictly increasing, none twice. `None` if that is more
/// than one request may carry, or a height has no two predecessors.
pub fn with_predecessors(tops: &[u64]) -> Option<Vec<u64>> {
    let mut heights = Vec::new();
    for top in tops {
        heights.extend([top.checked_sub(2)?, top.checked_sub(1)?, *top]);
    }
    heights.sort_unstable();
    heights.dedup();
    (!heights.is_empty() && heights.len() <= usize::from(MAX_HEADER_PROOF_ITEMS)).then_some(heights)
}

/// `count` heights spread evenly over `low..high`, the lowest of them at
/// least two above `low`, in increasing order and none twice.
pub fn spread(low: u64, high: u64, count: u64) -> Vec<u64> {
    let first = low.saturating_add(2);
    if first >= high || count == 0 {
        return Vec::new();
    }
    let span = high.saturating_sub(first);
    let mut tops: Vec<u64> = (0..count).map(|i| first.saturating_add(span.saturating_mul(i).checked_div(count).unwrap_or(0))).collect();
    tops.dedup();
    tops
}

/// At most `count` heights drawn from `low..high` by `random`, in
/// increasing order. The stretch is cut into runs of three heights and a
/// run is drawn at most once, so each height drawn has its two
/// predecessors to itself and above `low`. When the stretch has no more
/// runs than `count`, every run is taken. `random` is asked a bounded
/// number of times: a source that repeats itself gives fewer heights, not
/// an endless wait.
pub fn sample(low: u64, high: u64, count: usize, mut random: impl FnMut() -> u64) -> Vec<u64> {
    // the run `slot` holds low + 3*slot ..= low + 3*slot + 2, and all of it lies below `high`
    let slots = high.saturating_sub(low) / 3;
    let top = |slot: u64| low.saturating_add(slot.saturating_mul(3)).saturating_add(2);
    let wanted = u64::try_from(count).unwrap_or(u64::MAX);
    if slots <= wanted {
        return (0..slots).map(top).collect();
    }
    let mut drawn = std::collections::BTreeSet::new();
    let mut tries = count.saturating_mul(64);
    while drawn.len() < count && tries > 0 {
        tries = tries.saturating_sub(1);
        drawn.insert(random().checked_rem(slots).unwrap_or(0));
    }
    drawn.into_iter().map(top).collect()
}

/// What an answer was found to hold.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Checked {
    /// Headers shown to be leaves of the anchor's header MMR.
    pub members: usize,
    /// Headers whose proof of work covers their fields.
    pub pow: usize,
    /// Headers that passed the full check together with their two predecessors.
    pub full: usize,
    /// Headers from before the fourth hard fork: the full check does not apply to them.
    pub before_hf4: usize,
    /// Headers that are the ones this program had verified itself.
    pub same: usize,
}

fn bytes_of(header: &BlockHeader) -> Option<Vec<u8>> {
    ser::ser_vec(header, ProtocolVersion::local()).ok()
}

/// Check an answer to a request for `asked` under `anchor`. `known` gives
/// the header this program has verified at a height, if it has one.
pub fn check(anchor: &BlockHeader, proofs: &HeaderProofs, asked: &[u64], known: impl Fn(u64) -> Option<BlockHeader>) -> Result<Checked, String> {
    if proofs.anchor != anchor.hash() {
        return Err("the answer is for another anchor".to_string());
    }
    let got: Vec<u64> = proofs.items.iter().map(|item| item.header.height).collect();
    if got != asked {
        return Err("the answer holds other heights than were asked for".to_string());
    }
    verify_memberships(anchor, proofs)?;
    let mut checked = Checked {
        members: proofs.items.len(),
        ..Checked::default()
    };
    for item in &proofs.items {
        let height = item.header.height;
        // the leaf is the nonces; the proof of work ties the other fields to them
        pow::verify_size(&item.header).map_err(|_| format!("the header at {height} carries no valid proof of work for its fields"))?;
        checked.pow = checked.pow.saturating_add(1);
        if let Some(ours) = known(height) {
            if bytes_of(&ours).is_none() || bytes_of(&ours) != bytes_of(&item.header) {
                return Err(format!("the header at {height} is not the one this program has verified"));
            }
            checked.same = checked.same.saturating_add(1);
        }
    }
    // the full check, for every header whose two predecessors are here
    for (at, item) in proofs.items.iter().enumerate() {
        let height = item.header.height;
        let before: Vec<BlockHeader> = proofs
            .items
            .iter()
            .take(at)
            .rev()
            .take(2)
            .map(|item| item.header.clone())
            .collect();
        let together = match (before.first(), before.get(1)) {
            (Some(one), Some(two)) => height.checked_sub(1) == Some(one.height) && height.checked_sub(2) == Some(two.height),
            _ => false,
        };
        if !together {
            continue;
        }
        if item.header.version < grin_core::core::HeaderVersion(5) {
            checked.before_hf4 = checked.before_hf4.saturating_add(1);
            continue;
        }
        let alone = HeaderProofs {
            anchor: proofs.anchor,
            mmr_size: proofs.mmr_size,
            items: vec![HeaderProofItem {
                header: item.header.clone(),
                path: item.path.clone(),
            }],
        };
        verify_header_proofs_with_pow(anchor, &alone, &before)?;
        checked.full = checked.full.saturating_add(1);
    }
    Ok(checked)
}

/// What the node's own helper says about an answer taken as a whole, with
/// nothing trusted beforehand.
pub fn helper_on_whole(anchor: &BlockHeader, proofs: &HeaderProofs) -> Result<(), String> {
    verify_header_proofs_with_pow(anchor, proofs, &[])
}

/// An answer and what it cost.
pub struct Answer {
    /// The proofs.
    pub proofs: HeaderProofs,
    /// Bytes of the message, header included.
    pub bytes: u64,
    /// From the request written to the answer read.
    pub took: Duration,
}

/// A peer's software label for a single diagnostic line.
pub fn display_agent(agent: &str) -> String {
    agent.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(60).collect()
}

/// A connection to one node, made by hand.
pub struct Session {
    conn: TcpStream,
    version: ProtocolVersion,
    /// What the node says it can do.
    pub capabilities: Capabilities,
    /// What the node calls itself.
    pub user_agent: String,
    /// How long connecting and the handshake took.
    pub connected_in: Duration,
    work: Difficulty,
    height: u64,
    last_sent: Option<Instant>,
}

impl Session {
    /// Connect and shake hands. `genesis` is the genesis hash of the
    /// network; `work` and `height` are what this side says of its chain.
    pub fn connect(addr: SocketAddr, genesis: [u8; 32], work: u64, height: u64) -> Result<Session, String> {
        let began = Instant::now();
        let mut conn = crate::net::connect(&addr, CONNECT_TIMEOUT).map_err(|e| format!("no connection ({})", e.kind()))?;
        let handshake = Handshake::new(Hash::from_vec(&genesis), P2PConfig::default());
        let nowhere = PeerAddr(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0));
        let work = Difficulty::from_num(work.max(1));
        let info = handshake
            .initiate(Capabilities::UNKNOWN, work, nowhere, &mut conn)
            .map_err(|e| {
                match e {
                    grin_p2p::Error::GenesisMismatch { .. } => "a node of another chain",
                    // a node closes a second connection from an address it still holds one from
                    grin_p2p::Error::Connection(_) | grin_p2p::Error::ConnectionClose => "the node closed the connection during the handshake",
                    grin_p2p::Error::Timeout => "no answer to the handshake in time",
                    grin_p2p::Error::Banned => "the node refuses this address",
                    grin_p2p::Error::Serialization(_) | grin_p2p::Error::BadMessage | grin_p2p::Error::UnexpectedMessage => "not a Grin node, or one this program cannot talk to",
                    _ => "the handshake failed",
                }
                .to_string()
            })?;
        Ok(Session {
            conn,
            version: info.version,
            capabilities: info.capabilities,
            user_agent: display_agent(&info.user_agent),
            connected_in: began.elapsed(),
            work,
            height,
            last_sent: None,
        })
    }

    /// Whether the node says it gives its state out in segments.
    pub fn serves_state(&self) -> bool {
        self.capabilities.contains(Capabilities::PIBD_HIST)
    }

    /// Whether the node says it gives header proofs.
    pub fn serves_proofs(&self) -> bool {
        self.capabilities.contains(Capabilities::HEADER_PROOF_HIST)
    }

    fn send<T: ser::Writeable>(&mut self, kind: Type, body: &T) -> Result<(), String> {
        let body = ser::ser_vec(body, self.version).map_err(|_| "the request cannot be written".to_string())?;
        let len = u64::try_from(body.len()).map_err(|_| "the request cannot be written".to_string())?;
        let mut bytes = ser::ser_vec(&MsgHeader::new(kind, len), self.version).map_err(|_| "the request cannot be written".to_string())?;
        bytes.extend_from_slice(&body);
        self.conn.write_all(&bytes).map_err(|e| format!("the request could not be sent ({})", e.kind()))
    }

    /// Ask for the headers at `heights` with their proofs under the anchor
    /// with the hash `anchor`. `None`: no answer came within `wait`. A node
    /// ignores a request it cannot or will not answer, so that is an
    /// outcome and not a failure of the connection - but what was read
    /// half-way is lost, and the session should not be used again if the
    /// wait ended in the middle of a message.
    pub fn ask(&mut self, anchor: Hash, heights: &[u64], wait: Duration) -> Result<Option<Answer>, String> {
        let request = GetHeaderProofs {
            anchor,
            heights: heights.to_vec(),
        };
        let got: Option<(HeaderProofs, u64, Duration)> = self.exchange(Type::GetHeaderProofs, &request, Type::HeaderProofs, wait)?;
        Ok(got.map(|(proofs, bytes, took)| Answer { proofs, bytes, took }))
    }

    /// Ask for a segment of the rangeproof MMR at the header `block`.
    /// `None`: no answer within `wait`.
    pub fn ask_rangeproofs(&mut self, block: Hash, id: SegmentIdentifier, wait: Duration) -> Result<Option<Piece<RangeProof>>, String> {
        let request = SegmentRequest { block_hash: block, identifier: id };
        let got: Option<(SegmentResponse<RangeProof>, u64, Duration)> = self.exchange(Type::GetRangeProofSegment, &request, Type::RangeProofSegment, wait)?;
        Ok(got.map(|(answer, bytes, took)| Piece {
            block: answer.block_hash,
            segment: answer.segment,
            bitmap_root: None,
            bytes,
            took,
        }))
    }

    /// Ask for a segment of the output MMR at the header `block`. The
    /// answer carries the root of the bitmap's accumulator as well.
    pub fn ask_outputs(&mut self, block: Hash, id: SegmentIdentifier, wait: Duration) -> Result<Option<Piece<OutputIdentifier>>, String> {
        let request = SegmentRequest { block_hash: block, identifier: id };
        let got: Option<(OutputSegmentResponse, u64, Duration)> = self.exchange(Type::GetOutputSegment, &request, Type::OutputSegment, wait)?;
        Ok(got.map(|(answer, bytes, took)| Piece {
            block: answer.response.block_hash,
            segment: answer.response.segment,
            bitmap_root: Some(answer.output_bitmap_root),
            bytes,
            took,
        }))
    }

    /// Send one request and read until its answer comes, answering pings
    /// and reading past everything else. `None`: no answer within `wait`.
    fn exchange<B: ser::Writeable, R: ser::Readable>(&mut self, ask: Type, body: &B, answer: Type, wait: Duration) -> Result<Option<(R, u64, Duration)>, String> {
        if let Some(last) = self.last_sent {
            std::thread::sleep(ASK_GAP.saturating_sub(last.elapsed()));
        }
        let began = Instant::now();
        self.send(ask, body)?;
        self.last_sent = Some(began);
        loop {
            let left = wait.saturating_sub(began.elapsed());
            if left.is_zero() {
                return Ok(None);
            }
            let _ = self.conn.set_read_timeout(Some(left));
            let header = match msg::read_header(&mut self.conn, self.version) {
                Ok(MsgHeaderWrapper::Known(header)) => header,
                Ok(MsgHeaderWrapper::Unknown(len, _)) if len <= MAX_OTHER_MESSAGE => {
                    msg::read_discard(len, &mut self.conn).map_err(|_| "the connection ended".to_string())?;
                    continue;
                }
                Ok(MsgHeaderWrapper::Unknown(..)) => return Err("the node sent a message too large to read past".to_string()),
                Err(grin_p2p::Error::Connection(e)) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => return Ok(None),
                Err(_) => return Err("the connection ended".to_string()),
            };
            // the body may take its time, the wait for it is not cut short
            let _ = self.conn.set_read_timeout(Some(wait.max(Duration::from_secs(10))));
            if header.msg_type == answer {
                let read: R = msg::read_body(&header, &mut self.conn, self.version).map_err(|_| "the answer could not be read".to_string())?;
                let bytes = header.msg_len.saturating_add(u64::try_from(MsgHeader::LEN).unwrap_or(0));
                return Ok(Some((read, bytes, began.elapsed())));
            }
            match header.msg_type {
                Type::Ping => {
                    let _: Ping = msg::read_body(&header, &mut self.conn, self.version).map_err(|_| "the connection ended".to_string())?;
                    let pong = Pong {
                        total_difficulty: self.work,
                        height: self.height,
                    };
                    self.send(Type::Pong, &pong)?;
                }
                _ if header.msg_len <= MAX_OTHER_MESSAGE => {
                    msg::read_discard(header.msg_len, &mut self.conn).map_err(|_| "the connection ended".to_string())?;
                }
                _ => return Err("the node sent a message too large to read past".to_string()),
            }
        }
    }
}

/// A segment a node gave, and what it cost.
pub struct Piece<T> {
    /// The header the node says the segment is at.
    pub block: Hash,
    /// The segment.
    pub segment: Segment<T>,
    /// The root of the bitmap's accumulator, where the answer carries one.
    pub bitmap_root: Option<Hash>,
    /// Bytes of the message, header included.
    pub bytes: u64,
    /// From the request written to the answer read.
    pub took: Duration,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Each height comes with its two predecessors, in order and once; a
    /// request never carries more than the node takes.
    #[test]
    fn heights_come_with_their_predecessors() {
        assert_eq!(with_predecessors(&[10]), Some(vec![8, 9, 10]));
        assert_eq!(with_predecessors(&[10, 20]), Some(vec![8, 9, 10, 18, 19, 20]));
        assert_eq!(with_predecessors(&[20, 10]), Some(vec![8, 9, 10, 18, 19, 20]), "in order whatever the order given");
        assert_eq!(with_predecessors(&[10, 11]), Some(vec![8, 9, 10, 11]), "none twice");
        assert_eq!(with_predecessors(&[2]), Some(vec![0, 1, 2]));
        assert_eq!(with_predecessors(&[1]), None, "no two predecessors");
        assert_eq!(with_predecessors(&[]), None);
        let most: Vec<u64> = (0..21).map(|i| 100 + 10 * i).collect();
        assert_eq!(with_predecessors(&most).unwrap().len(), 63);
        let more: Vec<u64> = (0..22).map(|i| 100 + 10 * i).collect();
        assert_eq!(with_predecessors(&more), None, "sixty-six heights are more than a request carries");
    }

    /// A sample: runs of three that do not touch, inside the stretch, each
    /// at most once, as many as asked for or all there are.
    #[test]
    fn a_sample_is_drawn_in_runs_of_three() {
        let mut state = 7u64;
        let mut random = move || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            state >> 11
        };
        let tops = sample(1, 4_117_948, 1000, &mut random);
        assert_eq!(tops.len(), 1000);
        assert!(tops.windows(2).all(|pair| pair[0] + 3 <= pair[1]), "no two runs touch");
        assert!(tops.iter().all(|top| *top >= 3 && *top < 4_117_948 && (top - 1) % 3 == 2));
        assert!(tops.iter().any(|top| *top < 1_048_320) && tops.iter().any(|top| *top > 3_000_000), "over the whole stretch");
        for request in tops.chunks(21) {
            assert_eq!(with_predecessors(request).unwrap().len(), request.len() * 3);
        }
        // a short stretch: every run, whatever the source says
        assert_eq!(sample(1, 20, 50, || 0), vec![3, 6, 9, 12, 15, 18]);
        assert_eq!(sample(1, 4, 50, || 0), vec![3]);
        assert_eq!(sample(1, 3, 50, || 0), Vec::<u64>::new());
        assert_eq!(sample(10, 5, 50, || 0), Vec::<u64>::new());
        assert_eq!(sample(1, 1000, 0, || 0), Vec::<u64>::new());
        // a source that repeats itself: fewer heights, and an end
        assert_eq!(sample(1, 1000, 5, || 4), vec![15]);
    }

    /// Heights are spread over the whole stretch, each with room for its
    /// two predecessors above the lower end, and none at the upper end.
    #[test]
    fn heights_are_spread_over_the_stretch() {
        assert_eq!(spread(100, 200, 4), vec![102, 126, 151, 175]);
        assert_eq!(spread(100, 104, 4), vec![102, 103], "a short stretch gives fewer");
        assert_eq!(spread(100, 102, 4), Vec::<u64>::new());
        assert_eq!(spread(100, 50, 4), Vec::<u64>::new());
        assert_eq!(spread(100, 200, 0), Vec::<u64>::new());
        let many = spread(1_048_320, 4_113_930, 21);
        assert_eq!(many.len(), 21);
        assert!(many.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(*many.first().unwrap() == 1_048_322 && *many.last().unwrap() < 4_113_930);
    }
}
