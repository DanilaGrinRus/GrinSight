//! Whom to ask for which piece of the state, and when to stop waiting.
//!
//! A node answers a request for a segment or it does not answer at all:
//! there is no "I do not have it". So every request has a time limit, and a
//! piece that was not answered is asked of somebody else. A node also
//! counts what it is sent and drops a peer it finds too talkative; requests
//! to one node are therefore spaced out and few at a time.
use grin_core::core::SegmentIdentifier;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Requests out to one peer at a time.
pub const PER_PEER: usize = 4;
/// Between two requests to the same peer. A node drops a peer that sends
/// it more than 500 messages a minute; this is under half of that.
pub const ASK_GAP: Duration = Duration::from_millis(250);
/// How long an answer is waited for.
pub const SEGMENT_TIMEOUT: Duration = Duration::from_secs(if cfg!(feature = "test-net") { 3 } else { 20 });
/// Requests in a row without an answer before a peer is left.
pub const MAX_SILENT: u32 = 3;
/// Segments in a row that nobody asked a peer for before it is left. An
/// answer that comes after its time is one of these, so a few are normal.
pub const MAX_STRAY: u32 = 16;

/// A piece of the state: which MMR and which segment of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Piece {
    /// A segment of the bitmap MMR.
    Bitmap(SegmentIdentifier),
    /// A segment of the output MMR.
    Output(SegmentIdentifier),
    /// The last segment of the rangeproof MMR.
    RangeproofTail(SegmentIdentifier),
    /// The last segment of the kernel MMR.
    KernelTail(SegmentIdentifier),
}

struct Out<K> {
    piece: K,
    addr: SocketAddr,
    at: Instant,
}

#[derive(Default)]
struct Use {
    last: Option<Instant>,
    silent: u32,
    stray: u32,
}

/// The requests that are out and what each peer has been asked. `K` names
/// what is asked for: a piece of the state, or a block by its height.
pub struct Schedule<K> {
    out: Vec<Out<K>>,
    peers: HashMap<SocketAddr, Use>,
    /// Who last left a piece unanswered: asked last for it the next time.
    failed: Vec<(K, SocketAddr)>,
}

impl<K: Copy + PartialEq> Default for Schedule<K> {
    fn default() -> Self {
        Schedule::new()
    }
}

impl<K: Copy + PartialEq> Schedule<K> {
    /// Nothing out, nobody asked.
    pub fn new() -> Schedule<K> {
        Schedule {
            out: Vec::new(),
            peers: HashMap::new(),
            failed: Vec::new(),
        }
    }

    /// How many requests are out.
    pub fn out(&self) -> usize {
        self.out.len()
    }

    /// How many requests are out to this peer.
    pub fn out_to(&self, addr: SocketAddr) -> usize {
        self.out.iter().filter(|o| o.addr == addr).count()
    }

    /// The requests to send now. Of the `wanted` pieces, in their order,
    /// each one not already asked for goes to a peer that has room, has not
    /// been asked anything for [`ASK_GAP`] and gets nothing else in this
    /// round - the one with the fewest requests out, and not the one that
    /// last left this piece unanswered if there is another peer at all.
    pub fn plan(&mut self, now: Instant, wanted: &[K], peers: &[SocketAddr]) -> Vec<(SocketAddr, K)> {
        let mut plan: Vec<(SocketAddr, K)> = Vec::new();
        for piece in wanted {
            if self.out.iter().any(|o| o.piece == *piece) {
                continue;
            }
            let avoid = self.failed.iter().find(|(failed, _)| failed == piece).map(|(_, addr)| *addr);
            let others = peers.iter().any(|addr| Some(*addr) != avoid);
            let choice = peers
                .iter()
                .filter(|addr| !(others && Some(**addr) == avoid))
                .filter(|addr| !plan.iter().any(|(taken, _)| taken == *addr))
                .filter(|addr| self.out_to(**addr) < PER_PEER)
                .filter(|addr| {
                    let last = self.peers.get(*addr).and_then(|peer| peer.last);
                    last.is_none_or(|last| now.saturating_duration_since(last) >= ASK_GAP)
                })
                .min_by_key(|addr| self.out_to(**addr))
                .copied();
            let Some(addr) = choice else {
                continue;
            };
            plan.push((addr, *piece));
        }
        for (addr, piece) in &plan {
            self.out.push(Out {
                piece: *piece,
                addr: *addr,
                at: now,
            });
            self.peers.entry(*addr).or_default().last = Some(now);
        }
        plan
    }

    /// Ask a second peer for `piece` when the one asked has not answered
    /// it for `after`: for what everything else waits on, so that one slow
    /// or silent peer holds nothing up until its time is out. Only one
    /// second peer, with room, not asked anything for [`ASK_GAP`]; the
    /// first request stays out and is answered or expires as before.
    pub fn hedge(&mut self, now: Instant, piece: K, after: Duration, peers: &[SocketAddr]) -> Option<SocketAddr> {
        let mut asked = self.out.iter().filter(|o| o.piece == piece);
        let first = asked.next()?;
        if asked.next().is_some() || now.saturating_duration_since(first.at) < after {
            return None;
        }
        let first = first.addr;
        let choice = peers
            .iter()
            .filter(|addr| **addr != first)
            .filter(|addr| self.out_to(**addr) < PER_PEER)
            .filter(|addr| {
                let last = self.peers.get(*addr).and_then(|peer| peer.last);
                last.is_none_or(|last| now.saturating_duration_since(last) >= ASK_GAP)
            })
            .min_by_key(|addr| self.out_to(**addr))
            .copied()?;
        self.out.push(Out {
            piece,
            addr: choice,
            at: now,
        });
        self.peers.entry(choice).or_default().last = Some(now);
        Some(choice)
    }

    /// An answer came: whether `piece` had been asked of `from`. If it had,
    /// the request is closed and the peer has answered.
    pub fn answered(&mut self, from: SocketAddr, piece: K) -> bool {
        let Some(at) = self.out.iter().position(|o| o.addr == from && o.piece == piece) else {
            return false;
        };
        self.out.swap_remove(at);
        self.failed.retain(|(failed, _)| *failed != piece);
        let peer = self.peers.entry(from).or_default();
        peer.silent = 0;
        peer.stray = 0;
        true
    }

    /// A segment came from `from` that it was not asked for. Whether that
    /// makes more than [`MAX_STRAY`] of them in a row.
    pub fn stray(&mut self, from: SocketAddr) -> bool {
        let peer = self.peers.entry(from).or_default();
        peer.stray = peer.stray.saturating_add(1);
        peer.stray > MAX_STRAY
    }

    /// Give up on requests that have waited longer than
    /// [`SEGMENT_TIMEOUT`]; their pieces are free to be asked for again.
    /// Returns the peers that have now left [`MAX_SILENT`] requests in a
    /// row unanswered.
    pub fn expire(&mut self, now: Instant) -> Vec<SocketAddr> {
        let mut leave = Vec::new();
        let (late, waiting): (Vec<Out<K>>, Vec<Out<K>>) = std::mem::take(&mut self.out)
            .into_iter()
            .partition(|o| now.saturating_duration_since(o.at) > SEGMENT_TIMEOUT);
        self.out = waiting;
        for o in late {
            self.failed.retain(|(failed, _)| *failed != o.piece);
            self.failed.push((o.piece, o.addr));
            let peer = self.peers.entry(o.addr).or_default();
            peer.silent = peer.silent.saturating_add(1);
            if peer.silent >= MAX_SILENT && !leave.contains(&o.addr) {
                leave.push(o.addr);
            }
        }
        leave
    }

    /// Whether a request for one of the pieces `which` names has waited
    /// longer than [`SEGMENT_TIMEOUT`].
    pub fn overdue(&self, now: Instant, which: impl Fn(&K) -> bool) -> bool {
        self.out.iter().any(|o| which(&o.piece) && now.saturating_duration_since(o.at) > SEGMENT_TIMEOUT)
    }

    /// Take back the requests for the pieces `which` names: they are
    /// waited for no longer, and nobody is held to have left them
    /// unanswered. When each was asked stays counted, so a peer is asked
    /// no faster for it.
    pub fn withdraw(&mut self, which: impl Fn(&K) -> bool) {
        self.out.retain(|o| !which(&o.piece));
        self.failed.retain(|(piece, _)| !which(piece));
    }

    /// A peer is gone: what it was asked is free to be asked of others.
    pub fn forget(&mut self, addr: SocketAddr) {
        self.out.retain(|o| o.addr != addr);
        self.peers.remove(&addr);
        self.failed.retain(|(_, failed)| *failed != addr);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn output(idx: u64) -> Piece {
        Piece::Output(SegmentIdentifier { height: 11, idx })
    }
    fn addr(n: u16) -> SocketAddr {
        format!("127.0.0.1:{n}").parse().unwrap()
    }

    /// One node is asked one thing at a time, a quarter second apart, and
    /// never more than four things at once - a node drops a peer that
    /// sends it too much.
    #[test]
    fn a_node_is_asked_slowly_and_little_at_a_time() {
        let t0 = Instant::now();
        let wanted: Vec<Piece> = (0..10).map(output).collect();
        let mut s = Schedule::new();
        assert_eq!(s.plan(t0, &wanted, &[addr(1)]), vec![(addr(1), output(0))]);
        assert_eq!(s.plan(t0, &wanted, &[addr(1)]), vec![], "the same instant");
        assert_eq!(s.plan(t0 + ASK_GAP - Duration::from_millis(1), &wanted, &[addr(1)]), vec![]);
        assert_eq!(s.plan(t0 + ASK_GAP, &wanted, &[addr(1)]), vec![(addr(1), output(1))], "not what is already asked for");
        assert_eq!(s.plan(t0 + ASK_GAP * 2, &wanted, &[addr(1)]), vec![(addr(1), output(2))]);
        assert_eq!(s.plan(t0 + ASK_GAP * 3, &wanted, &[addr(1)]), vec![(addr(1), output(3))]);
        assert_eq!(s.plan(t0 + ASK_GAP * 4, &wanted, &[addr(1)]), vec![], "four are out");
        assert_eq!(s.out(), PER_PEER);
        // an answer makes room
        assert!(s.answered(addr(1), output(1)));
        assert!(!s.answered(addr(1), output(1)), "once");
        assert!(!s.answered(addr(2), output(2)), "asked of another");
        assert!(!s.answered(addr(1), output(7)), "never asked");
        assert_eq!(s.plan(t0 + ASK_GAP * 5, &wanted, &[addr(1)]), vec![(addr(1), output(1))], "the first that is wanted and not out");
        // nobody to ask
        assert_eq!(Schedule::<Piece>::new().plan(t0, &wanted, &[]), vec![]);
    }

    /// Several nodes share the work: one request each per round, to
    /// whoever has the fewest out.
    #[test]
    fn nodes_share_the_work() {
        let t0 = Instant::now();
        let wanted: Vec<Piece> = (0..10).map(output).collect();
        let peers = [addr(1), addr(2), addr(3)];
        let mut s = Schedule::new();
        assert_eq!(s.plan(t0, &wanted, &peers), vec![(addr(1), output(0)), (addr(2), output(1)), (addr(3), output(2))]);
        assert!(s.answered(addr(2), output(1)));
        // the node with the fewest out comes first
        assert_eq!(
            s.plan(t0 + ASK_GAP, &wanted, &peers),
            vec![(addr(2), output(1)), (addr(1), output(3)), (addr(3), output(4))]
        );
        // a node that joins later is asked at once
        let more = [addr(1), addr(2), addr(3), addr(4)];
        assert_eq!(s.plan(t0 + ASK_GAP, &wanted, &more), vec![(addr(4), output(5))]);
    }

    /// A request that is not answered in time is given up, its piece goes
    /// to another node, and a node that leaves three in a row unanswered is
    /// named for leaving. One answer clears its record.
    #[test]
    fn silence_is_noticed() {
        let t0 = Instant::now();
        let wanted = [output(0)];
        let peers = [addr(1), addr(2)];
        let mut s = Schedule::new();
        assert_eq!(s.plan(t0, &wanted, &peers), vec![(addr(1), output(0))]);
        assert_eq!(s.expire(t0 + SEGMENT_TIMEOUT), vec![]);
        assert_eq!(s.out(), 1, "not late yet");
        let t1 = t0 + SEGMENT_TIMEOUT + Duration::from_millis(1);
        assert_eq!(s.expire(t1), vec![]);
        assert_eq!(s.out(), 0);
        assert!(!s.answered(addr(1), output(0)), "an answer after the limit was not asked for any more");
        // the piece goes to the other node, though the first has less out
        assert_eq!(s.plan(t1, &wanted, &peers), vec![(addr(2), output(0))]);
        // with nobody else there, the same node is asked again
        let mut alone = Schedule::new();
        let only = [addr(1)];
        let mut now = t0;
        for round in 1..=MAX_SILENT {
            assert_eq!(alone.plan(now, &wanted, &only), vec![(addr(1), output(0))], "round {round}");
            now += SEGMENT_TIMEOUT + Duration::from_millis(1);
            let leave = alone.expire(now);
            assert_eq!(leave, if round == MAX_SILENT { vec![addr(1)] } else { vec![] }, "round {round}");
        }
        // an answer in between clears the record
        let mut s = Schedule::new();
        let mut now = t0;
        for _ in 0..MAX_SILENT - 1 {
            s.plan(now, &wanted, &only);
            now += SEGMENT_TIMEOUT + Duration::from_millis(1);
            assert_eq!(s.expire(now), vec![]);
        }
        s.plan(now, &wanted, &only);
        assert!(s.answered(addr(1), output(0)));
        s.plan(now + ASK_GAP, &wanted, &only);
        assert_eq!(s.expire(now + ASK_GAP + SEGMENT_TIMEOUT + Duration::from_millis(1)), vec![], "one in a row, not three");
        // segments nobody asked for: a few are answers that came late; a
        // node that keeps sending them is named for leaving
        let mut s = Schedule::<Piece>::new();
        for _ in 0..MAX_STRAY {
            assert!(!s.stray(addr(1)));
        }
        assert!(s.stray(addr(1)));
        let mut s = Schedule::new();
        for _ in 0..MAX_STRAY {
            assert!(!s.stray(addr(1)));
        }
        s.plan(t0, &wanted, &only);
        assert!(s.answered(addr(1), output(0)));
        assert!(!s.stray(addr(1)), "an answer that was asked for clears the record");
        assert!(!s.stray(addr(2)), "each node has its own");
        // a node that is gone: what it was asked goes to others at once
        let mut s = Schedule::new();
        assert_eq!(s.plan(t0, &wanted, &peers), vec![(addr(1), output(0))]);
        s.forget(addr(1));
        assert_eq!(s.plan(t0, &wanted, &[addr(2)]), vec![(addr(2), output(0))]);
    }

    /// Requests can be taken back: they are waited for no longer, nobody
    /// is held silent for them, and a peer is asked no sooner because of
    /// it.
    #[test]
    fn requests_are_taken_back() {
        let t0 = Instant::now();
        let large = |idx| Piece::Output(SegmentIdentifier { height: 15, idx });
        let is_large = |piece: &Piece| matches!(piece, Piece::Output(id) if id.height == 15);
        let peers = [addr(1), addr(2)];
        let mut s = Schedule::new();
        assert_eq!(s.plan(t0, &[large(0), output(7)], &peers), vec![(addr(1), large(0)), (addr(2), output(7))]);
        // overdue: asked for longer ago than an answer is waited for
        assert!(!s.overdue(t0 + SEGMENT_TIMEOUT, is_large));
        let t1 = t0 + SEGMENT_TIMEOUT + Duration::from_millis(1);
        assert!(s.overdue(t1, is_large));
        assert!(!s.overdue(t1, |piece| *piece == output(3)), "only what is asked about");
        assert!(s.overdue(t1, |piece| *piece == output(7)));
        // taken back: the request is gone, the other one is not
        s.withdraw(is_large);
        assert_eq!((s.out(), s.out_to(addr(1)), s.out_to(addr(2))), (1, 0, 1));
        assert!(!s.overdue(t1, is_large));
        assert!(!s.answered(addr(1), large(0)), "an answer to it was not asked for any more");
        assert!(s.answered(addr(2), output(7)));
        // nobody was silent: three more unanswered requests before the peer is left
        let only = [addr(1)];
        let mut now = t1;
        for round in 1..=MAX_SILENT {
            assert_eq!(s.plan(now, &[output(0)], &only), vec![(addr(1), output(0))], "round {round}");
            now += SEGMENT_TIMEOUT + Duration::from_millis(1);
            assert_eq!(s.expire(now), if round == MAX_SILENT { vec![addr(1)] } else { vec![] }, "round {round}");
        }
        // and the piece that was taken back is not remembered against the
        // peer: it would be asked of that peer first again
        let mut s = Schedule::new();
        assert_eq!(s.plan(t0, &[large(0)], &peers), vec![(addr(1), large(0))]);
        assert_eq!(s.expire(t1), vec![]);
        s.withdraw(is_large);
        assert_eq!(s.plan(t1, &[large(0)], &peers), vec![(addr(1), large(0))]);
        // a peer is asked no sooner for it
        let mut s = Schedule::new();
        assert_eq!(s.plan(t0, &[large(0)], &only), vec![(addr(1), large(0))]);
        s.withdraw(is_large);
        assert_eq!(s.plan(t0 + ASK_GAP - Duration::from_millis(1), &[output(0)], &only), vec![]);
        assert_eq!(s.plan(t0 + ASK_GAP, &[output(0)], &only), vec![(addr(1), output(0))]);
    }

    /// What everything waits on is asked of a second peer once the first
    /// has kept it long enough - not before, not of the same peer, not a
    /// third time; the second peer has to have room and must not have
    /// been asked just now. Either answer closes its own request.
    #[test]
    fn what_everything_waits_on_is_asked_twice() {
        let mut s: Schedule<u64> = Schedule::new();
        let t0 = Instant::now();
        let (a, b, c) = (addr(1), addr(2), addr(3));
        let peers = [a, b, c];
        assert_eq!(s.plan(t0, &[7], &peers), vec![(a, 7)]);
        let after = Duration::from_secs(3);
        assert_eq!(s.hedge(t0 + Duration::from_secs(2), 7, after, &peers), None, "not yet");
        assert_eq!(s.hedge(t0 + after, 7, after, &[a]), None, "nobody else");
        assert_eq!(s.hedge(t0 + after, 8, after, &peers), None, "not asked at all");
        let second = s.hedge(t0 + after, 7, after, &peers).unwrap();
        assert_ne!(second, a);
        assert_eq!(s.hedge(t0 + after * 3, 7, after, &peers), None, "a third time: no");
        assert_eq!(s.out(), 2);
        // the second answers: its request is closed, the first is still out
        assert!(s.answered(second, 7));
        assert_eq!(s.out(), 1);
        assert!(s.answered(a, 7), "the first may still answer");
        // a peer asked just now, or without room, is not the second
        let mut s: Schedule<u64> = Schedule::new();
        assert_eq!(s.plan(t0, &[1], &[a]), vec![(a, 1)]);
        assert_eq!(s.plan(t0, &[2], &[b]), vec![(b, 2)]);
        assert_eq!(s.hedge(t0 + Duration::from_millis(100), 1, Duration::ZERO, &[a, b]), None, "b was asked just now");
        assert_eq!(s.hedge(t0 + ASK_GAP, 1, Duration::ZERO, &[a, b]), Some(b));
        let mut s: Schedule<u64> = Schedule::new();
        let t = t0 + ASK_GAP * 10;
        for (round, piece) in (0u32..).zip(10..10 + PER_PEER as u64) {
            assert_eq!(s.plan(t + ASK_GAP * round, &[piece], &[b]), vec![(b, piece)]);
        }
        assert_eq!(s.plan(t, &[1], &[a]), vec![(a, 1)]);
        assert_eq!(s.hedge(t + ASK_GAP * 20, 1, Duration::ZERO, &[a, b]), None, "b has no room");
    }
}