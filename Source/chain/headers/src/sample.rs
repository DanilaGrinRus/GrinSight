//! The history before a starting point, checked by sampling its work
//! (the experiment of version 0.4.6e; after FlyClient, Bünz, Kiffer, Luu
//! and Zamani, and a colleague's "FlyClient for Grin" package).
//!
//! A starting point is a header the program carries. Its `prev_root`
//! commits to every header before it, but says nothing of the work in
//! them. Here that work is laid out as one line - each header takes a
//! stretch as long as the difficulty it met - and points of the line are
//! drawn from a hash nobody can choose. For every point drawn the header
//! that covers it is shown and checked as a header is checked on its way
//! into the wallet. A history with a large part of its claimed work
//! missing cannot answer for all the points.
//!
//! Grin's header tree holds hashes only, so the line is committed
//! separately: a tree whose every node carries the sum of the work
//! beneath it ([`Tree`]). A path in it leads from a point of the line to
//! exactly one leaf; a subtree that claims more work than its leaves have
//! cannot be passed through, because the sums are part of what is hashed.
//!
//! What is here: the tree, its paths, the drawing of points, and the tie
//! of a leaf to its three headers. What is not here yet: the proof that
//! those headers are leaves of the header tree under the point's
//! `prev_root`, the number of points worked out for a stated bound, and
//! the form in which a proof travels with the program.
use crate::rules::{self, Reject};
use blake2::blake2b::blake2b;
use grin_core::core::BlockHeader;

/// Most leaves a tree takes: more headers than the chain will have.
pub const MAX_LEAVES: usize = 1 << 28;
/// Most points drawn for one proof.
pub const MAX_POINTS: u32 = 4096;

const LEAF_TAG: &[u8] = b"GrinSight work leaf v1";
const NODE_TAG: &[u8] = b"GrinSight work node v1";
const SEED_TAG: &[u8] = b"GrinSight work sample v1";
const DRAW_TAG: &[u8] = b"GrinSight work point v1";

/// Why a part of a proof is not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Sums that do not fit, or a count that is out of bounds.
    Shape,
    /// The path does not lead from this leaf to the root.
    Path,
    /// The leaf does not cover the point it is shown for.
    Point,
    /// The leaf is not the header it is shown with.
    Leaf,
    /// The headers do not pass the rules for a header.
    Header(Reject),
}

/// One header on the line: where it is, what it is, how much work it took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leaf {
    /// The height of the header.
    pub height: u64,
    /// The hash of the header.
    pub hash: [u8; 32],
    /// The difficulty the header met: its total difficulty less the one before.
    pub work: u64,
}

/// A node of the tree: a hash, and the work of all leaves beneath it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node {
    /// Of a leaf: its place, header and work. Of a node above: the two beneath it with their sums.
    pub hash: [u8; 32],
    /// The work of all leaves beneath.
    pub sum: u64,
}

/// What a tree comes to: its top node and how many leaves it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Root {
    /// The node everything is under.
    pub top: Node,
    /// How many leaves the tree has.
    pub leaves: u64,
}

fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut all = Vec::new();
    for part in parts {
        all.extend_from_slice(part);
    }
    let mut out = [0u8; 32];
    for (to, from) in out.iter_mut().zip(blake2b(32, &[], &all).as_bytes()) {
        *to = *from;
    }
    out
}

fn leaf_node(leaf: &Leaf) -> Node {
    Node { hash: digest(&[LEAF_TAG, &leaf.height.to_be_bytes(), &leaf.hash, &leaf.work.to_be_bytes()]), sum: leaf.work }
}

fn join(left: &Node, right: &Node) -> Option<Node> {
    let sum = left.sum.checked_add(right.sum)?;
    Some(Node { hash: digest(&[NODE_TAG, &left.hash, &left.sum.to_be_bytes(), &right.hash, &right.sum.to_be_bytes()]), sum })
}

/// The tree over the leaves of a stretch of history, kept whole so that
/// any path can be read from it. Level 0 is the leaves; each level above
/// joins the nodes below in pairs, and a node left without a pair goes up
/// as it is.
#[derive(Debug, Clone)]
pub struct Tree {
    levels: Vec<Vec<Node>>,
}

/// The way from a leaf to the root: the node beside it at every level
/// where there is one, bottom up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    /// The nodes beside the way, bottom up.
    pub beside: Vec<Node>,
}

impl Tree {
    /// Build the tree. The leaves must be consecutive heights, each with
    /// work; `None` otherwise, or if the work does not fit.
    pub fn build(leaves: &[Leaf]) -> Option<Tree> {
        if leaves.is_empty() || leaves.len() > MAX_LEAVES {
            return None;
        }
        let consecutive = leaves.iter().zip(leaves.iter().skip(1)).all(|(a, b)| a.height.checked_add(1) == Some(b.height));
        if !consecutive || leaves.iter().any(|l| l.work == 0) {
            return None;
        }
        let mut levels = vec![leaves.iter().map(leaf_node).collect::<Vec<Node>>()];
        loop {
            let below = levels.last()?;
            if below.len() <= 1 {
                break;
            }
            let mut above = Vec::with_capacity(below.len().div_ceil(2));
            for pair in below.chunks(2) {
                above.push(match pair {
                    [left, right] => join(left, right)?,
                    [alone] => *alone,
                    _ => return None,
                });
            }
            levels.push(above);
        }
        Some(Tree { levels })
    }

    /// What the tree comes to.
    pub fn root(&self) -> Option<Root> {
        let top = *self.levels.last()?.first()?;
        let leaves = u64::try_from(self.levels.first()?.len()).ok()?;
        Some(Root { top, leaves })
    }

    /// The index of the leaf whose stretch of the line holds `point`.
    pub fn leaf_at(&self, point: u64) -> Option<usize> {
        let mut left = point;
        let mut index = 0usize;
        // top down: into the left node if the point is within its sum
        for level in self.levels.iter().rev().skip(1) {
            let first = index.checked_mul(2)?;
            let node = level.get(first)?;
            match level.get(first.checked_add(1)?) {
                Some(_) if left < node.sum => index = first,
                Some(_) => {
                    left = left.checked_sub(node.sum)?;
                    index = first.checked_add(1)?;
                }
                None => index = first,
            }
        }
        (left < self.levels.first()?.get(index)?.sum).then_some(index)
    }

    /// The path of the leaf at `index`.
    pub fn path(&self, index: usize) -> Option<Path> {
        self.levels.first()?.get(index)?;
        let mut beside = Vec::new();
        let mut at = index;
        for level in self.levels.iter().take(self.levels.len().saturating_sub(1)) {
            if let Some(node) = level.get(at ^ 1) {
                beside.push(*node);
            }
            at /= 2;
        }
        Some(Path { beside })
    }
}

/// Checks that `leaf`, the `index`-th of the tree, lies under `root` by
/// `path`, and returns where its stretch of the line begins: the work of
/// every leaf before it.
pub fn begins_at(root: &Root, index: u64, leaf: &Leaf, path: &Path) -> Result<u64, Refused> {
    if root.leaves == 0 || index >= root.leaves || usize::try_from(root.leaves).map_or(true, |n| n > MAX_LEAVES) {
        return Err(Refused::Shape);
    }
    let mut node = leaf_node(leaf);
    let mut before = 0u64;
    let mut at = index;
    let mut width = root.leaves;
    let mut beside = path.beside.iter();
    while width > 1 {
        let last_alone = at == width.saturating_sub(1) && width % 2 == 1;
        if !last_alone {
            let other = beside.next().ok_or(Refused::Path)?;
            node = if at % 2 == 1 {
                before = before.checked_add(other.sum).ok_or(Refused::Shape)?;
                join(other, &node).ok_or(Refused::Shape)?
            } else {
                join(&node, other).ok_or(Refused::Shape)?
            };
        }
        at /= 2;
        width = width.div_ceil(2);
    }
    if beside.next().is_some() || node != root.top {
        return Err(Refused::Path);
    }
    Ok(before)
}

/// Checks that `leaf` is the one that covers `point` of the line under `root`.
pub fn covers(root: &Root, point: u64, index: u64, leaf: &Leaf, path: &Path) -> Result<(), Refused> {
    let begin = begins_at(root, index, leaf, path)?;
    let end = begin.checked_add(leaf.work).ok_or(Refused::Shape)?;
    if point < begin || point >= end {
        return Err(Refused::Point);
    }
    Ok(())
}

/// What the points are drawn from: the network, the starting point the
/// history leads to, the height below the first leaf, and the tree. Every
/// one of them is fixed before the first point is known; changing any
/// changes all the points.
pub fn seed(net_tag: u8, point_hash: &[u8; 32], below: u64, root: &Root, points: u32) -> [u8; 32] {
    digest(&[
        SEED_TAG,
        &[net_tag],
        point_hash,
        &below.to_be_bytes(),
        &root.top.hash,
        &root.top.sum.to_be_bytes(),
        &root.leaves.to_be_bytes(),
        &points.to_be_bytes(),
    ])
}

/// The `number`-th point of the line of length `total`, drawn from `seed`.
/// Sixteen bytes of a hash are reduced to the line: the lean towards its
/// beginning is less than one part in 2^64.
pub fn draw(seed: &[u8; 32], number: u32, total: u64) -> Option<u64> {
    if total == 0 {
        return None;
    }
    let hash = digest(&[DRAW_TAG, seed, &number.to_be_bytes()]);
    let mut wide = [0u8; 16];
    for (to, from) in wide.iter_mut().zip(hash.iter()) {
        *to = *from;
    }
    u64::try_from(u128::from_be_bytes(wide).checked_rem(u128::from(total))?).ok()
}

/// The leaf a header makes, given the header before it.
pub fn leaf_of(prev: &BlockHeader, header: &BlockHeader) -> Option<Leaf> {
    let work = header.total_difficulty().to_num().checked_sub(prev.total_difficulty().to_num()).filter(|w| *w > 0)?;
    Some(Leaf { height: header.height, hash: crate::hash_bytes(header), work })
}

/// Ties a leaf to its headers: `header` is the leaf's header, follows
/// `prev` and `older` by every rule a header is held to, and each of the
/// three has a valid proof of work of its own - which is what binds the
/// fields of a header to its hash.
pub fn check_leaf(leaf: &Leaf, older: &BlockHeader, prev: &BlockHeader, header: &BlockHeader) -> Result<(), Refused> {
    if leaf_of(prev, header) != Some(*leaf) {
        return Err(Refused::Leaf);
    }
    rules::check_alone(older).map_err(Refused::Header)?;
    rules::check_alone(prev).map_err(Refused::Header)?;
    rules::check_step(older, prev, header).map_err(Refused::Header)
}
