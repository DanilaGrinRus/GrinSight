//! Reads a file of every header of a chain, as `dump_headers.py` writes it
//! (for each header two bytes of length, then the header), and checks the
//! whole of it the way a node would on the way from the first block:
//! every header is the next height, names the hash of the one before,
//! commits in `prev_root` to all headers before it, and carries a valid
//! proof of work that meets the difficulty it claims, and the difficulty
//! it claims is what the rule of its era gives: from the fourth hard fork
//! on by this crate's own check of a header against the two before it,
//! before that by the node's rule over the sixty headers before it, with
//! the scaling of the secondary proof of work.
//!
//! Prints what it found, and how the work of the chain divides at the
//! fourth hard fork. Changes nothing.
#![forbid(unsafe_code)]
use fly_chain_headers::peaks::Peaks;
use fly_chain_headers::{hash_bytes, read_header, rules, Net};
use grin_core::consensus::{self, HeaderDifficultyInfo};
use grin_core::pow::Difficulty;
use std::collections::VecDeque;
use grin_core::core::block::HeaderVersion;
use grin_core::core::hash::Hashed;
use grin_core::core::BlockHeader;
use grin_core::pow;
use std::io::Read;
use std::process::ExitCode;

/// The first problems are named; the rest are counted.
const NAMED: usize = 20;

#[derive(Default)]
struct Found {
    headers: u64,
    /// Headers of each version, 1 to 5.
    by_version: [u64; 6],
    bad_pow: u64,
    bad_work: u64,
    bad_step: u64,
    steps: u64,
    /// The rule of the eras before version 5: checked, failed.
    old_steps: u64,
    bad_old_step: u64,
    problems: Vec<String>,
    /// Total difficulty of the last header before version 5.
    before_five: Option<(u64, u64)>,
    first_five: Option<u64>,
}

impl Found {
    fn problem(&mut self, text: String) {
        if self.problems.len() < NAMED {
            self.problems.push(text);
        }
    }
}

fn next_record(file: &mut impl Read) -> Result<Option<Vec<u8>>, String> {
    let mut size = [0u8; 2];
    match file.read(&mut size).map_err(|e| e.to_string())? {
        0 => return Ok(None),
        2 => {}
        1 => file.read_exact(size.get_mut(1..).ok_or("size")?).map_err(|e| e.to_string())?,
        _ => return Err("a read past the buffer".into()),
    }
    let mut raw = vec![0u8; usize::from(u16::from_be_bytes(size))];
    file.read_exact(&mut raw).map_err(|e| format!("the file ends inside a header: {e}"))?;
    Ok(Some(raw))
}

fn run(path: &str) -> Result<Found, String> {
    Net::Main.enter();
    let file = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut file = std::io::BufReader::with_capacity(1 << 20, file);
    let mut found = Found::default();
    let mut peaks = Peaks::empty();
    let mut prev: Option<BlockHeader> = None;
    let mut older: Option<BlockHeader> = None;
    // what the rule of the early eras reads of the headers before, newest first
    let mut window: VecDeque<HeaderDifficultyInfo> = VecDeque::new();
    let keep = usize::try_from(consensus::DMA_WINDOW).map_err(|_| "window")?.saturating_add(1);
    while let Some(raw) = next_record(&mut file)? {
        let height = found.headers;
        let header = read_header(&raw).ok_or_else(|| format!("height {height}: not a header"))?;
        if header.height != height {
            return Err(format!("height {} where {height} was expected", header.height));
        }
        if let Some(prev) = &prev {
            if header.prev_hash != prev.hash() {
                return Err(format!("height {height} does not name the hash of the header before it"));
            }
        }
        if header.prev_root != peaks.root() && height > 0 {
            return Err(format!("height {height}: prev_root is not the root of the headers before it"));
        }
        let version = consensus::header_version(height);
        if let Some(count) = found.by_version.get_mut(usize::from(version.0)) {
            *count = count.saturating_add(1);
        }
        if height > 0 {
            if pow::verify_size(&header).is_err() {
                found.bad_pow = found.bad_pow.saturating_add(1);
                found.problem(format!("height {height}: the proof of work is not valid"));
            }
            let before = prev.as_ref().map_or(0, |p| p.total_difficulty().to_num());
            match header.total_difficulty().to_num().checked_sub(before).filter(|w| *w > 0) {
                Some(work) if header.pow.to_difficulty(height).to_num() >= work => {}
                _ => {
                    found.bad_work = found.bad_work.saturating_add(1);
                    found.problem(format!("height {height}: the proof of work does not meet the difficulty claimed"));
                }
            }
        }
        if version < HeaderVersion(5) && height > 0 {
            // as the node does on its way from the first block
            let next = consensus::next_difficulty(height, window.iter().cloned());
            let before = prev.as_ref().map_or(0, |p| p.total_difficulty().to_num());
            let claimed = header.total_difficulty().to_num().checked_sub(before);
            found.old_steps = found.old_steps.saturating_add(1);
            let scaling = header.pow.secondary_scaling == next.secondary_scaling;
            if claimed != Some(next.difficulty.to_num()) || !scaling {
                found.bad_old_step = found.bad_old_step.saturating_add(1);
                found.problem(format!("height {height}: the difficulty is not what the rule of its era gives"));
            }
        }
        if version >= HeaderVersion(5) {
            if found.first_five.is_none() {
                found.first_five = Some(height);
                found.before_five = prev.as_ref().map(|p| (p.height, p.total_difficulty().to_num()));
            }
            // the rule reads the two headers before; both must be of version 5 for it to be the rule of this era
            if let (Some(older), Some(prev)) = (&older, &prev) {
                if consensus::header_version(older.height) >= HeaderVersion(5) {
                    found.steps = found.steps.saturating_add(1);
                    if let Err(why) = rules::check_step(older, prev, &header) {
                        found.bad_step = found.bad_step.saturating_add(1);
                        found.problem(format!("height {height}: {why:?}"));
                    }
                }
            }
        }
        let work = header.total_difficulty().to_num().saturating_sub(prev.as_ref().map_or(0, |p| p.total_difficulty().to_num()));
        let seconds = u64::try_from(header.timestamp.timestamp()).map_err(|_| format!("height {height}: a time before 1970"))?;
        window.push_front(HeaderDifficultyInfo::new(None, seconds, Difficulty::from_num(work), header.pow.secondary_scaling, header.pow.is_secondary()));
        window.truncate(keep);
        peaks.append(&header).map_err(|_| format!("height {height}: the header tree cannot take it"))?;
        found.headers = found.headers.saturating_add(1);
        older = prev.take();
        prev = Some(header);
        if found.headers % 500_000 == 0 {
            eprintln!("  {} headers", found.headers);
        }
    }
    let Some(last) = prev else { return Err("the file has no headers".into()) };
    let total = last.total_difficulty().to_num();
    let hex: String = hash_bytes(&last).iter().map(|b| format!("{b:02x}")).collect();
    println!("headers: {} (heights 0..{})", found.headers, last.height);
    println!("last hash: {hex}");
    println!("by version 1..5: {:?}", found.by_version.get(1..).unwrap_or(&[]));
    println!("every header: next height, hash of the one before, prev_root against the tree of all before - held for all, or the run would have stopped");
    println!("proof of work not valid: {}; not meeting the difficulty claimed: {}", found.bad_pow, found.bad_work);
    println!("difficulty rule (version 5): {} checked, {} failed", found.steps, found.bad_step);
    println!("difficulty rule (versions 1 to 4, the node's rule over sixty headers): {} checked, {} failed", found.old_steps, found.bad_old_step);
    println!("total difficulty at the end: {total}");
    if let (Some(first), Some((at, before))) = (found.first_five, found.before_five) {
        let share = u128::from(before).saturating_mul(1_000_000).checked_div(u128::from(total)).unwrap_or(0);
        println!("version 5 begins at height {first}; total difficulty at height {at}: {before}");
        println!("work before version 5, parts in a million of all work: {share}");
    }
    println!("header tree: {} leaves, {} peaks", peaks.leaves(), peaks.hashes().len());
    for line in &found.problems {
        println!("problem: {line}");
    }
    Ok(found)
}

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: fly-history <file of headers>");
        return ExitCode::from(2);
    };
    match run(&path) {
        Ok(found) if found.bad_pow == 0 && found.bad_work == 0 && found.bad_step == 0 && found.bad_old_step == 0 => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(1),
        Err(why) => {
            eprintln!("fly-history: {why}");
            ExitCode::from(1)
        }
    }
}
