//! Grin-compatible header MMR prefix peaks for checkpoint sync.
//!
//! RESEARCH / NOT VERIFIED. No consensus change.

use blake2::blake2b::Blake2b;
use grin_core::core::hash::{Hash, ZERO_HASH};
use grin_core::core::pmmr;
use grin_core::core::BlockHeader;
use std::fs;

pub fn blake2b256(bytes: &[u8]) -> Hash {
    let mut state = Blake2b::new(32);
    state.update(bytes);
    Hash::from_vec(state.finalize().as_bytes())
}

/// H(be64(pos) || packed nonces), same as Grin's header MMR leaf.
pub fn header_leaf_hash(pos0: u64, header: &BlockHeader) -> Hash {
    let mut buf = Vec::with_capacity(8 + 42 * 8);
    buf.extend_from_slice(&pos0.to_be_bytes());
    buf.extend_from_slice(&header.pow.proof.pack_nonces());
    blake2b256(&buf)
}

pub fn mrr_parent_hash(pos0: u64, left: Hash, right: Hash) -> Hash {
    let mut buf = Vec::with_capacity(8 + 32 + 32);
    buf.extend_from_slice(&pos0.to_be_bytes());
    buf.extend_from_slice(left.as_bytes());
    buf.extend_from_slice(right.as_bytes());
    blake2b256(&buf)
}

pub fn bag_peaks(mmr_size: u64, peaks: &[Hash]) -> Hash {
    let mut res: Option<Hash> = None;
    for peak in peaks.iter().rev() {
        res = Some(match res {
            None => *peak,
            Some(rhs) => mrr_parent_hash(mmr_size, *peak, rhs),
        });
    }
    res.unwrap_or(ZERO_HASH)
}

#[derive(Clone, Debug)]
pub struct PeakAccum {
    pub peaks: Vec<(u64, u64, Hash)>, // (pos, height, hash), left -> right
    pub size: u64,
    pub leaves: u64,
}

impl PeakAccum {
    pub fn root(&self) -> Hash {
        let hashes: Vec<Hash> = self.peaks.iter().map(|p| p.2).collect();
        bag_peaks(self.size, &hashes)
    }

    /// Append a header leaf; the new root is what the next header commits.
    pub fn append(&mut self, header: &BlockHeader) -> Result<(), String> {
        let leaf_pos = pmmr::insertion_to_pmmr_index(self.leaves);
        let leaf_hash = header_leaf_hash(leaf_pos, header);
        let mut pos = leaf_pos;
        self.size += 1;
        self.leaves += 1;
        let mut node = (leaf_pos, 0u64, leaf_hash);
        self.peaks.push(node);
        loop {
            let n = self.peaks.len();
            if n < 2 || self.peaks[n - 2].1 != self.peaks[n - 1].1 {
                break;
            }
            let left = self.peaks.remove(n - 2);
            let right = self.peaks.pop().expect("peak");
            pos = self.size;
            self.size += 1;
            let hash = mrr_parent_hash(pos, left.2, right.2);
            node = (pos, left.1 + 1, hash);
            self.peaks.push(node);
        }
        Ok(())
    }

}

/// Parsed `RWM1` checkpoint file. AUDIT: `root` and `header` used to be parsed
/// and then ignored; the caller (main.rs `load_checkpoint`) now cross-checks
/// every field. Duplicate or unknown keys are rejected.
pub struct CheckpointFile {
    pub acc: PeakAccum,
    pub height: u64,
    pub hash: Hash,
    pub root: Hash,
    pub header_bytes: Option<Vec<u8>>,
}

impl CheckpointFile {
    /// RWM1 / height H / hash HEX / header HEX / leaves L / size S / root HEX /
    /// peak POS HEIGHT HASH ...
    pub fn from_text(path: &str) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("checkpoint read: {e}"))?;
        Self::parse(&text)
    }

    /// Same as `from_text`, from the file contents.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut lines = text.lines();
        if lines.next() != Some("RWM1") {
            return Err("checkpoint magic".into());
        }
        let mut height = None;
        let mut hash = None;
        let mut leaves = None;
        let mut size = None;
        let mut root = None;
        let mut header_bytes: Option<Vec<u8>> = None;
        let mut peaks = Vec::new();
        fn once<T>(slot: &mut Option<T>, v: Option<T>, key: &str) -> Result<(), String> {
            if slot.is_some() {
                return Err(format!("duplicate {key}"));
            }
            *slot = Some(v.ok_or_else(|| format!("bad {key}"))?);
            Ok(())
        }
        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            let mut it = line.split_whitespace();
            match it.next() {
                Some("height") => once(&mut height, it.next().and_then(|v| v.parse().ok()), "height")?,
                Some("hash") => once(&mut hash, it.next().and_then(parse_hash), "hash")?,
                Some("header") => once(&mut header_bytes, it.next().and_then(parse_hex), "header")?,
                Some("leaves") => once(&mut leaves, it.next().and_then(|v| v.parse().ok()), "leaves")?,
                Some("size") => once(&mut size, it.next().and_then(|v| v.parse().ok()), "size")?,
                Some("root") => once(&mut root, it.next().and_then(parse_hash), "root")?,
                Some("peak") => {
                    let pos = it.next().and_then(|v| v.parse().ok()).ok_or("peak pos")?;
                    let height = it.next().and_then(|v| v.parse().ok()).ok_or("peak height")?;
                    let h = it.next().and_then(parse_hash).ok_or("peak hash")?;
                    peaks.push((pos, height, h));
                }
                Some(k) => return Err(format!("unknown checkpoint key {k}")),
                None => {}
            }
        }
        Ok(CheckpointFile {
            acc: PeakAccum {
                peaks,
                size: size.ok_or("checkpoint size")?,
                leaves: leaves.ok_or("checkpoint leaves")?,
            },
            height: height.ok_or("checkpoint height")?,
            hash: hash.ok_or("checkpoint hash")?,
            root: root.ok_or("checkpoint root")?,
            header_bytes,
        })
    }
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    // non-ASCII would make the byte slicing panic (fuzz finding)
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    let mut v = Vec::with_capacity(s.len() / 2);
    for i in 0..s.len() / 2 {
        v.push(u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?);
    }
    Some(v)
}

fn parse_hash(s: &str) -> Option<Hash> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut v = vec![0u8; 32];
    for i in 0..32 {
        v[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(Hash::from_vec(&v))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bag_empty() {
        assert_eq!(bag_peaks(0, &[]), ZERO_HASH);
    }
}

