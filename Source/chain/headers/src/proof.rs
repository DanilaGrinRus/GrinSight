//! The proof that travels with a starting point: the history before it,
//! from the first block, answered for at points of its work that nobody
//! chose (see [`crate::sample`]).
//!
//! For every point drawn the proof shows the header that covers it, with
//! the headers before it that the difficulty rule of its era reads - two
//! from the fourth hard fork on, sixty-one before it - and one path that
//! places the header in the tree the starting point commits to. The
//! headers before it need no path of their own: each is named by the hash
//! in the one after it, and a valid proof of work binds the fields of a
//! header to that hash.
//!
//! This is the experiment of version 0.4.6e. The number of points is the
//! caller's, and no bound on what a passing proof means is claimed here.
use crate::rules::{self, Reject};
use crate::sample::{self, Leaf, Node, Path, Root};
use crate::{hash_bytes, read_header, write_header, Net};
use grin_core::consensus::{self, HeaderDifficultyInfo};
use grin_core::core::block::HeaderVersion;
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::merkle_proof::MerkleProof;
use grin_core::core::pmmr;
use grin_core::core::BlockHeader;
use grin_core::pow::{self, Difficulty};

const MAGIC: &[u8] = b"GSHP1";
/// Longest run of headers one point is answered with.
pub const MAX_RUN: usize = 64;
/// Longest path taken, in either tree.
const MAX_PATH: usize = 64;
/// Longest proof read.
pub const MAX_PROOF: usize = 64 << 20;

/// Why a proof is not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Not the form of a proof, or of another network.
    Form,
    /// The starting point is not a header with a valid proof of work.
    Point,
    /// The tree of work is not of this history.
    Tree,
    /// A point of the work is not answered for (its number).
    Sample(u32, Why),
}

/// What is wrong with the answer for one point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The leaf does not cover the point, or is not under the root.
    Work(sample::Refused),
    /// The headers are not the run the rule needs.
    Run,
    /// A header of the run has no valid proof of work.
    Pow,
    /// The header does not follow the ones before it by the rule of its era.
    Rule,
    /// A header failed this crate's own check of a version 5 header.
    Header(Reject),
    /// The header is not in the tree the starting point commits to.
    Place,
}

/// The answer for one point of the work.
#[derive(Debug, Clone)]
pub struct Answer {
    /// The leaf's number in the tree of work: its height less one.
    pub index: u64,
    /// The way from the leaf to the root of the tree of work.
    pub path: Path,
    /// The headers the rule reads and, last, the header of the leaf.
    pub run: Vec<BlockHeader>,
    /// The place of the leaf's header in the header tree.
    pub place: MerkleProof,
}

/// A whole proof.
#[derive(Debug, Clone)]
pub struct Proof {
    /// The starting point.
    pub point: BlockHeader,
    /// The header before the starting point, with its place in the header tree.
    pub last: BlockHeader,
    /// The place of `last`.
    pub last_place: MerkleProof,
    /// What the tree of work comes to.
    pub root: Root,
    /// One answer for every point drawn.
    pub answers: Vec<Answer>,
}

/// What a proof that passed says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Passed {
    /// The height of the starting point.
    pub height: u64,
    /// Its hash.
    pub hash: [u8; 32],
    /// The work of the history before it, from the first block.
    pub work: u64,
    /// How many points of that work were answered for.
    pub points: u32,
    /// How many of them fell before the fourth hard fork.
    pub early: u32,
}

/// How many headers before a header the difficulty rule of its era reads.
fn reads(height: u64) -> u64 {
    if consensus::header_version(height) < HeaderVersion(5) {
        consensus::DMA_WINDOW.saturating_add(1)
    } else {
        2
    }
}

/// The height the run for the header at `height` begins at: the headers the
/// rule reads, and one more for the work of the earliest of them.
pub fn run_from(height: u64) -> u64 {
    height.saturating_sub(reads(height).saturating_add(1))
}

/// Checks a run: consecutive headers, each naming the one before, each with
/// a valid proof of work, and the last one following by the rule of its era.
fn check_run(run: &[BlockHeader]) -> Result<(), Why> {
    let header = run.last().ok_or(Why::Run)?;
    let first = run.first().ok_or(Why::Run)?;
    if first.height != run_from(header.height) || run.len() > MAX_RUN || run.len() < 2 {
        return Err(Why::Run);
    }
    for (before, after) in run.iter().zip(run.iter().skip(1)) {
        if before.height.checked_add(1) != Some(after.height) || after.prev_hash != before.hash() || after.timestamp <= before.timestamp {
            return Err(Why::Run);
        }
    }
    for one in run {
        // the first block has no proof of work to check
        if one.height > 0 && pow::verify_size(one).is_err() {
            return Err(Why::Pow);
        }
    }
    // from the fourth hard fork on: this crate's own check, the one a header passes on its way into the wallet
    if let [.., older, prev, last] = run {
        if consensus::header_version(older.height) >= HeaderVersion(5) {
            return rules::check_step(older, prev, last).map_err(Why::Header);
        }
    }
    // before it: the node's rule, over what the node would read. Its sums
    // are checked first so that it cannot overflow on a run no node accepted.
    let mut infos = Vec::new();
    let mut sum = 0u64;
    let mut below = if first.height == 0 { None } else { Some(first.total_difficulty().to_num()) };
    for one in run.iter().skip(usize::from(first.height != 0)).take(run.len().saturating_sub(1).saturating_sub(usize::from(first.height != 0))) {
        let total = one.total_difficulty().to_num();
        let work = match below {
            Some(b) => total.checked_sub(b).filter(|w| *w > 0).ok_or(Why::Rule)?,
            None => total,
        };
        below = Some(total);
        sum = sum.checked_add(work).ok_or(Why::Rule)?;
        let seconds = u64::try_from(one.timestamp.timestamp()).map_err(|_| Why::Rule)?;
        infos.push(HeaderDifficultyInfo::new(None, seconds, Difficulty::from_num(work), one.pow.secondary_scaling, one.pow.is_secondary()));
    }
    sum.checked_mul(consensus::BLOCK_TIME_SEC).ok_or(Why::Rule)?;
    infos.reverse();
    let height = header.height;
    let next = std::panic::catch_unwind(move || consensus::next_difficulty(height, infos)).map_err(|_| Why::Rule)?;
    let claimed = header.total_difficulty().to_num().checked_sub(below.ok_or(Why::Rule)?).filter(|w| *w > 0).ok_or(Why::Rule)?;
    if claimed != next.difficulty.to_num() || header.pow.to_difficulty(height).to_num() < claimed {
        return Err(Why::Rule);
    }
    if consensus::header_version(height) < HeaderVersion(5) && header.pow.secondary_scaling != next.secondary_scaling {
        return Err(Why::Rule);
    }
    Ok(())
}

fn placed(root: Hash, leaves: u64, header: &BlockHeader, place: &MerkleProof) -> bool {
    place.mmr_size == pmmr::insertion_to_pmmr_index(leaves)
        && place.path.len() <= MAX_PATH
        && place.verify(root, header, pmmr::insertion_to_pmmr_index(header.height)).is_ok()
}

/// Checks a proof for the network `net` with `points` points. The network
/// must have been entered.
pub fn check(proof: &Proof, net: Net, points: u32) -> Result<Passed, Refused> {
    let point = &proof.point;
    if point.height < 3 || pow::verify_size(point).is_err() {
        return Err(Refused::Point);
    }
    // the header before the point: named by it, and the last leaf of the tree it commits to
    let last = &proof.last;
    if last.height.checked_add(1) != Some(point.height) || point.prev_hash != last.hash() || pow::verify_size(last).is_err() {
        return Err(Refused::Point);
    }
    if !placed(point.prev_root, point.height, last, &proof.last_place) {
        return Err(Refused::Point);
    }
    // the line: every header from height 1 to the one before the point
    let work = last.total_difficulty().to_num().checked_sub(first_work(net)).ok_or(Refused::Tree)?;
    if proof.root.leaves != last.height || proof.root.top.sum != work || work == 0 {
        return Err(Refused::Tree);
    }
    if points == 0 || points > sample::MAX_POINTS || usize::try_from(points).ok() != Some(proof.answers.len()) {
        return Err(Refused::Form);
    }
    let seed = sample::seed(net.tag(), &hash_bytes(point), 0, &proof.root, points);
    let mut early = 0u32;
    for (number, answer) in (0u32..).zip(proof.answers.iter()) {
        let no = |why| Refused::Sample(number, why);
        let at = sample::draw(&seed, number, work).ok_or(Refused::Tree)?;
        let header = answer.run.last().ok_or(no(Why::Run))?;
        let prev = answer.run.iter().rev().nth(1).ok_or(no(Why::Run))?;
        if header.height.checked_sub(1) != Some(answer.index) {
            return Err(no(Why::Run));
        }
        let leaf: Leaf = sample::leaf_of(prev, header).ok_or(no(Why::Run))?;
        sample::covers(&proof.root, at, answer.index, &leaf, &answer.path).map_err(|e| no(Why::Work(e)))?;
        check_run(&answer.run).map_err(no)?;
        if !placed(point.prev_root, point.height, header, &answer.place) {
            return Err(no(Why::Place));
        }
        if consensus::header_version(header.height) < HeaderVersion(5) {
            early = early.saturating_add(1);
        }
    }
    Ok(Passed { height: point.height, hash: hash_bytes(point), work, points, early })
}

/// The total difficulty of the first block: where the line of work begins.
pub fn first_work(net: Net) -> u64 {
    match net {
        Net::Main => grin_core::genesis::genesis_main().header.total_difficulty().to_num(),
        Net::Test => grin_core::genesis::genesis_test().header.total_difficulty().to_num(),
        Net::Automated => grin_core::genesis::genesis_dev().header.total_difficulty().to_num(),
    }
}

// ----- the form in which a proof travels

fn put_header(out: &mut Vec<u8>, header: &BlockHeader) -> Option<()> {
    let raw = write_header(header)?;
    out.extend_from_slice(&u16::try_from(raw.len()).ok()?.to_be_bytes());
    out.extend_from_slice(&raw);
    Some(())
}

fn put_place(out: &mut Vec<u8>, place: &MerkleProof) -> Option<()> {
    out.extend_from_slice(&place.mmr_size.to_be_bytes());
    out.push(u8::try_from(place.path.len()).ok()?);
    for hash in &place.path {
        out.extend_from_slice(hash.as_bytes());
    }
    Some(())
}

/// The bytes of a proof.
pub fn write(proof: &Proof, net: Net) -> Option<Vec<u8>> {
    let mut out = MAGIC.to_vec();
    out.push(net.tag());
    put_header(&mut out, &proof.point)?;
    put_header(&mut out, &proof.last)?;
    put_place(&mut out, &proof.last_place)?;
    out.extend_from_slice(&proof.root.top.hash);
    out.extend_from_slice(&proof.root.top.sum.to_be_bytes());
    out.extend_from_slice(&proof.root.leaves.to_be_bytes());
    out.extend_from_slice(&u32::try_from(proof.answers.len()).ok()?.to_be_bytes());
    for answer in &proof.answers {
        out.extend_from_slice(&answer.index.to_be_bytes());
        out.push(u8::try_from(answer.path.beside.len()).ok()?);
        for node in &answer.path.beside {
            out.extend_from_slice(&node.hash);
            out.extend_from_slice(&node.sum.to_be_bytes());
        }
        out.push(u8::try_from(answer.run.len()).ok()?);
        for header in &answer.run {
            put_header(&mut out, header)?;
        }
        put_place(&mut out, &answer.place)?;
    }
    Some(out)
}

struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn take(&mut self, count: usize) -> Option<&[u8]> {
        let (head, rest) = (self.0.get(..count)?, self.0.get(count..)?);
        self.0 = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    fn hash(&mut self) -> Option<[u8; 32]> {
        self.take(32)?.try_into().ok()
    }
    fn header(&mut self) -> Option<BlockHeader> {
        let size = usize::from(self.u16()?);
        read_header(self.take(size)?)
    }
    fn place(&mut self) -> Option<MerkleProof> {
        let mmr_size = self.u64()?;
        let count = usize::from(self.u8()?);
        if count > MAX_PATH {
            return None;
        }
        let mut path = Vec::with_capacity(count);
        for _ in 0..count {
            path.push(Hash::from_vec(&self.hash()?));
        }
        Some(MerkleProof { mmr_size, path })
    }
}

/// Reads a proof for the network `net`; nothing of it is checked but its
/// form. The network must have been entered.
pub fn read(raw: &[u8], net: Net) -> Option<Proof> {
    if raw.len() > MAX_PROOF {
        return None;
    }
    let mut bytes = Bytes(raw);
    if bytes.take(MAGIC.len())? != MAGIC || bytes.u8()? != net.tag() {
        return None;
    }
    let point = bytes.header()?;
    let last = bytes.header()?;
    let last_place = bytes.place()?;
    let root = Root { top: Node { hash: bytes.hash()?, sum: bytes.u64()? }, leaves: bytes.u64()? };
    let count = bytes.u32()?;
    if count > sample::MAX_POINTS {
        return None;
    }
    let mut answers = Vec::new();
    for _ in 0..count {
        let index = bytes.u64()?;
        let steps = usize::from(bytes.u8()?);
        if steps > MAX_PATH {
            return None;
        }
        let mut beside = Vec::with_capacity(steps);
        for _ in 0..steps {
            beside.push(Node { hash: bytes.hash()?, sum: bytes.u64()? });
        }
        let headers = usize::from(bytes.u8()?);
        if headers > MAX_RUN {
            return None;
        }
        let mut run = Vec::with_capacity(headers);
        for _ in 0..headers {
            run.push(bytes.header()?);
        }
        answers.push(Answer { index, path: Path { beside }, run, place: bytes.place()? });
    }
    bytes.0.is_empty().then_some(Proof { point, last, last_place, root, answers })
}

// ----- making a proof

/// Makes the proof for the starting point at `point_height` with `points`
/// points. `header_at` gives the header of a height of the history; every
/// height up to the point is asked for. Needs memory for the two trees of
/// the whole history (about 600 MB for four million headers). `None` if a
/// header is missing or the history is not one chain.
pub fn build(header_at: &dyn Fn(u64) -> Option<BlockHeader>, point_height: u64, net: Net, points: u32) -> Option<Proof> {
    use grin_core::core::pmmr::{ReadablePMMR, VecBackend, PMMR};
    if point_height < 3 || points == 0 || points > sample::MAX_POINTS {
        return None;
    }
    let mut backend = VecBackend::<BlockHeader>::new_hash_only();
    let mut tree = PMMR::new(&mut backend);
    let mut leaves = Vec::new();
    let mut before = None::<BlockHeader>;
    for height in 0..point_height {
        let header = header_at(height)?;
        if header.height != height {
            return None;
        }
        if let Some(prev) = &before {
            if header.prev_hash != prev.hash() {
                return None;
            }
            leaves.push(sample::leaf_of(prev, &header)?);
        }
        tree.push(&header).ok()?;
        before = Some(header);
    }
    let last = before?;
    let point = header_at(point_height)?;
    if point.prev_hash != last.hash() || tree.root().ok()? != point.prev_root {
        return None;
    }
    let place = |height: u64| tree.merkle_proof(pmmr::insertion_to_pmmr_index(height)).ok();
    let work = sample::Tree::build(&leaves)?;
    let root = work.root()?;
    let seed = sample::seed(net.tag(), &hash_bytes(&point), 0, &root, points);
    let mut answers = Vec::new();
    for number in 0..points {
        let at = sample::draw(&seed, number, root.top.sum)?;
        let index = work.leaf_at(at)?;
        let height = leaves.get(index)?.height;
        let mut run = Vec::new();
        for h in run_from(height)..=height {
            run.push(header_at(h)?);
        }
        answers.push(Answer { index: u64::try_from(index).ok()?, path: work.path(index)?, run, place: place(height)? });
    }
    let last_place = place(last.height)?;
    Some(Proof { point, last, last_place, root, answers })
}

// ----- a proof for the starting point a program carries

/// How many points the proof that travels with a starting point has.
/// Provisional: the number is not yet worked out for a stated bound.
pub const POINTS: u32 = 420;

/// What a program knows of the history before its starting point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum History {
    /// There is no proof with this program: the point is taken on trust.
    Unproved,
    /// The proof with the program does not pass for this point: the point
    /// is taken on trust, and this is why.
    Refused(Refused),
    /// The history before the point answered for every point of its work.
    Sampled(Passed),
    /// K202: a later point - made by a wallet from a chain that began at the
    /// program's point - carries that point in its history: the history up
    /// to the program's point answered for every point of its work, and
    /// from there to this one only the wallet that made it vouches.
    Extended(Passed),
}

/// Checks `raw` as the proof of history for the starting point `start`:
/// it must be a proof for exactly that header. The network must have been
/// entered (as [`crate::checkpoint::check`] does).
pub fn check_for(start: &crate::checkpoint::Start, raw: &[u8]) -> History {
    let Some(proof) = read(raw, start.net) else { return History::Refused(Refused::Form) };
    // the same header, to the byte - not only the same height or hash
    let same = write_header(&proof.point).is_some() && write_header(&proof.point) == write_header(&start.anchor);
    // K202: or a later point whose range holds the proof's point at its
    // height; the root is that of the peaks checked with the point
    let later = !same
        && start.track.target() == proof.point.height
        && proof.point.height < start.height()
        && start.track.path().is_some_and(|path| {
            let place = MerkleProof { mmr_size: start.peaks.size(), path };
            placed(start.peaks.root(), start.peaks.leaves(), &proof.point, &place)
        });
    if !same && !later {
        return History::Refused(Refused::Point);
    }
    match check(&proof, start.net, POINTS) {
        Ok(passed) if same => History::Sampled(passed),
        Ok(passed) => History::Extended(passed),
        Err(why) => History::Refused(why),
    }
}

/// The proof of history compiled into this crate for the starting point of
/// `net` - only in a build made with the feature `history-proof` (the
/// experiment of version 0.4.6e). The file belongs to the point: the two
/// are replaced together.
pub fn baked_history(net: Net) -> Option<&'static [u8]> {
    #[cfg(feature = "history-proof")]
    if net == Net::Main {
        return Some(include_bytes!("../points/main.history"));
    }
    let _ = net;
    None
}

/// What this build knows of the history before `start`.
pub fn history_of(start: &crate::checkpoint::Start) -> History {
    match baked_history(start.net) {
        Some(raw) => check_for(start, raw),
        None => History::Unproved,
    }
}
