//! What is kept between two runs of the program about its asking.
//!
//! Three things have to outlive the program: the number of the last
//! generation, so that no number is used twice; the lower bound of the
//! last confirmed time, so that the time is never confirmed backwards; and
//! the claims that are open or still a caveat, so that restarting the
//! program does not make a claim go away.
//!
//! All three are in one small file, written whole beside itself and moved
//! into place, and ending in a digest of the rest. A file that cannot be
//! read back exactly is not replaced by an empty one: the program says so
//! and confirms nothing. The digest finds damage, not forgery - whoever
//! can write the user's files is not what this file defends against.

use crate::claims::{Claim, Claims, MAX_CLAIMS};
use crate::said::Said;
use ring::digest::{digest, SHA256, SHA256_OUTPUT_LEN};
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"FLYTIPS1";

/// The file is never longer than this.
const MAX_FILE: usize = 64 * 1024;

/// Why nothing can be confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Damaged {
    /// The file is there and cannot be read.
    Read,
    /// The file is not what was written.
    Format,
    /// The file cannot be written.
    Write,
    /// The numbers of generations have run out.
    Spent,
}

/// The file and what is in it.
#[derive(Debug)]
pub struct Memory {
    path: PathBuf,
    generation: u64,
    floor_ms: u64,
    claims: Claims,
}

impl Memory {
    /// Opens the file at `path`. No file is a first run.
    pub fn open(path: &Path) -> Result<Memory, Damaged> {
        let bytes = match read_bounded(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(Memory {
                    path: path.to_path_buf(),
                    generation: 0,
                    floor_ms: 0,
                    claims: Claims::default(),
                });
            }
            Err(_) => return Err(Damaged::Read),
        };
        let (generation, floor_ms, claims) = decode(&bytes).ok_or(Damaged::Format)?;
        Ok(Memory {
            path: path.to_path_buf(),
            generation,
            floor_ms,
            claims,
        })
    }

    /// The number for a new generation. It is on the disk before it is
    /// returned, and no number is returned twice.
    pub fn next_generation(&mut self) -> Result<u64, Damaged> {
        let next = self.generation.checked_add(1).ok_or(Damaged::Spent)?;
        self.save(next, self.floor_ms, &self.claims)?;
        self.generation = next;
        Ok(next)
    }

    /// The number of the last generation opened.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The lower bound of the last confirmed time, in milliseconds since
    /// 1970, or zero.
    pub fn floor_ms(&self) -> u64 {
        self.floor_ms
    }

    /// Takes in the lower bound of a newly confirmed time. The bound only
    /// rises.
    pub fn raise_floor(&mut self, low_ms: u64) -> Result<(), Damaged> {
        if low_ms <= self.floor_ms {
            return Ok(());
        }
        self.save(self.generation, low_ms, &self.claims)?;
        self.floor_ms = low_ms;
        Ok(())
    }

    /// Atomically publish the clock and resume the claim timers. After a
    /// restart only a lower bound recorded on disk counts as elapsed.
    pub fn resume_clock(&mut self, low: u64, high: u64, previous: Option<u64>) -> Result<(), Damaged> {
        let mut claims = self.claims.clone();
        claims.resume_at(previous.unwrap_or(self.floor_ms), high);
        let floor = self.floor_ms.max(low);
        if floor != self.floor_ms || claims != self.claims {
            self.save(self.generation, floor, &claims)?;
            self.floor_ms = floor;
            self.claims = claims;
        }
        Ok(())
    }

    /// The claims.
    pub fn claims(&self) -> &Claims {
        &self.claims
    }

    /// Changes the claims. What `change` did is on the disk before this
    /// returns; if it cannot be written, the claims stay as they were.
    pub fn change_claims(&mut self, change: impl FnOnce(&mut Claims)) -> Result<(), Damaged> {
        let mut changed = self.claims.clone();
        change(&mut changed);
        if changed == self.claims {
            return Ok(());
        }
        self.save(self.generation, self.floor_ms, &changed)?;
        self.claims = changed;
        Ok(())
    }

    fn save(&self, generation: u64, floor_ms: u64, claims: &Claims) -> Result<(), Damaged> {
        let bytes = encode(generation, floor_ms, claims).ok_or(Damaged::Write)?;
        let mut beside = self.path.clone().into_os_string();
        beside.push(".new");
        let beside = PathBuf::from(beside);
        let written = File::create(&beside)
            .and_then(|mut file| file.write_all(&bytes).and_then(|()| file.sync_all()))
            .and_then(|()| fs::rename(&beside, &self.path));
        if written.is_err() {
            let _ = fs::remove_file(&beside);
            return Err(Damaged::Write);
        }
        Ok(())
    }
}

/// Reads the file, but no more of it than the longest file this program
/// writes and one byte: a longer file is not this program's and is not
/// taken into memory.
fn read_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(u64::try_from(MAX_FILE).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn encode(generation: u64, floor_ms: u64, claims: &Claims) -> Option<Vec<u8>> {
    let (list, full) = claims.parts();
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&generation.to_le_bytes());
    out.extend_from_slice(&floor_ms.to_le_bytes());
    out.push(u8::from(full));
    out.extend_from_slice(&u16::try_from(list.len()).ok()?.to_le_bytes());
    for claim in list {
        out.push(u8::try_from(claim.host.len()).ok()?);
        out.extend_from_slice(claim.host.as_bytes());
        out.extend_from_slice(&claim.said.height.to_le_bytes());
        out.extend_from_slice(&claim.said.hash);
        out.extend_from_slice(&claim.said.total_difficulty.to_le_bytes());
        for moment in [claim.seen_ms, claim.expired_ms] {
            out.push(u8::from(moment.is_some()));
            out.extend_from_slice(&moment.unwrap_or(0).to_le_bytes());
        }
    }
    let sum = digest(&SHA256, &out);
    out.extend_from_slice(sum.as_ref());
    Some(out)
}

fn decode(bytes: &[u8]) -> Option<(u64, u64, Claims)> {
    let body_len = bytes.len().checked_sub(SHA256_OUTPUT_LEN)?;
    let (body, sum) = bytes.split_at(body_len);
    if digest(&SHA256, body).as_ref() != sum {
        return None;
    }
    let mut rest = body;
    if take(&mut rest, MAGIC.len())? != MAGIC {
        return None;
    }
    let generation = number(&mut rest)?;
    let floor_ms = number(&mut rest)?;
    let full = flag(&mut rest)?;
    let count = usize::from(u16::from_le_bytes(take(&mut rest, 2)?.try_into().ok()?));
    if count > MAX_CLAIMS {
        return None;
    }
    let mut list = Vec::new();
    for _ in 0..count {
        let host_len = usize::from(*take(&mut rest, 1)?.first()?);
        let host = std::str::from_utf8(take(&mut rest, host_len)?).ok()?.to_string();
        let height = number(&mut rest)?;
        let hash: [u8; 32] = take(&mut rest, 32)?.try_into().ok()?;
        let total_difficulty = number(&mut rest)?;
        let mut moments = [None, None];
        for moment in &mut moments {
            let there = flag(&mut rest)?;
            let value = number(&mut rest)?;
            if !there && value != 0 {
                return None;
            }
            *moment = there.then_some(value);
        }
        let [seen_ms, expired_ms] = moments;
        list.push(Claim {
            host,
            said: Said {
                height,
                hash,
                total_difficulty,
            },
            seen_ms,
            expired_ms,
        });
    }
    if !rest.is_empty() {
        return None;
    }
    Some((generation, floor_ms, Claims::from_parts(list, full)))
}

fn take<'a>(rest: &mut &'a [u8], count: usize) -> Option<&'a [u8]> {
    if rest.len() < count {
        return None;
    }
    let (head, tail) = rest.split_at(count);
    *rest = tail;
    Some(head)
}

fn number(rest: &mut &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(take(rest, 8)?.try_into().ok()?))
}

fn flag(rest: &mut &[u8]) -> Option<bool> {
    match take(rest, 1)?.first()? {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::claims::Noted;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A directory of this test's own, removed when the test ends.
    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Dir {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let name = format!(
                "fly-tips-memory-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            );
            let path = std::env::temp_dir().join(name);
            fs::create_dir_all(&path).unwrap();
            Dir(path)
        }
        fn file(&self) -> PathBuf {
            self.0.join("tips.state")
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn more(mark: u8) -> Said {
        Said {
            height: 4_118_417,
            hash: [mark; 32],
            total_difficulty: 2_378_233_360_000_000,
        }
    }

    /// The same bytes with a digest that fits them.
    fn sealed(mut body: Vec<u8>) -> Vec<u8> {
        let sum = digest(&SHA256, &body);
        body.extend_from_slice(sum.as_ref());
        body
    }

    fn body(bytes: &[u8]) -> Vec<u8> {
        bytes[..bytes.len() - SHA256_OUTPUT_LEN].to_vec()
    }

    #[test]
    fn no_number_is_given_twice() {
        let dir = Dir::new();
        let mut memory = Memory::open(&dir.file()).unwrap();
        assert_eq!((memory.generation(), memory.floor_ms()), (0, 0));
        assert!(!dir.file().exists());
        assert_eq!(memory.next_generation(), Ok(1));
        // The number is on the disk by the time it is known here.
        assert_eq!(Memory::open(&dir.file()).unwrap().generation(), 1);
        assert_eq!(memory.next_generation(), Ok(2));
        drop(memory);
        // After a restart the count goes on.
        let mut again = Memory::open(&dir.file()).unwrap();
        assert_eq!(again.generation(), 2);
        assert_eq!(again.next_generation(), Ok(3));
        // Nothing is left beside the file.
        let names: Vec<_> = fs::read_dir(&dir.0).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, ["tips.state"]);
    }

    #[test]
    fn the_numbers_run_out_rather_than_wrap() {
        let dir = Dir::new();
        fs::write(dir.file(), encode(u64::MAX - 1, 0, &Claims::default()).unwrap()).unwrap();
        let mut memory = Memory::open(&dir.file()).unwrap();
        assert_eq!(memory.next_generation(), Ok(u64::MAX));
        assert_eq!(memory.next_generation(), Err(Damaged::Spent));
        assert_eq!(memory.generation(), u64::MAX);
        assert_eq!(Memory::open(&dir.file()).unwrap().generation(), u64::MAX);
    }

    #[test]
    fn the_time_is_never_kept_backwards() {
        let dir = Dir::new();
        let mut memory = Memory::open(&dir.file()).unwrap();
        assert_eq!(memory.raise_floor(5000), Ok(()));
        assert_eq!(memory.raise_floor(4999), Ok(()));
        assert_eq!(memory.floor_ms(), 5000);
        assert_eq!(Memory::open(&dir.file()).unwrap().floor_ms(), 5000);
        assert_eq!(memory.raise_floor(5000), Ok(()));
        assert_eq!(memory.floor_ms(), 5000);
        assert_eq!(Memory::open(&dir.file()).unwrap().floor_ms(), 5000);
        memory.raise_floor(5001).unwrap();
        assert_eq!(Memory::open(&dir.file()).unwrap().floor_ms(), 5001);
        // The number of the generation is not touched by it.
        memory.next_generation().unwrap();
        memory.raise_floor(6000).unwrap();
        let again = Memory::open(&dir.file()).unwrap();
        assert_eq!((again.generation(), again.floor_ms()), (1, 6000));
    }

    #[test]
    fn claims_outlive_the_program() {
        let dir = Dir::new();
        let mut memory = Memory::open(&dir.file()).unwrap();
        memory
            .change_claims(|claims| {
                assert_eq!(claims.note("a.example", more(1), Some((10, 20))), Noted::New);
                assert_eq!(claims.note("b.example", more(2), None), Noted::New);
                assert_eq!(claims.note("c.example", more(3), Some((10, 20))), Noted::New);
            })
            .unwrap();
        // One of them expires.
        memory
            .change_claims(|claims| {
                claims.settle(|said| *said == more(3));
                claims.note("d.example", more(4), Some((0, 0)));
                claims.tick((crate::claims::TTL_MS, crate::claims::TTL_MS + 5));
            })
            .unwrap();
        let again = Memory::open(&dir.file()).unwrap();
        assert_eq!(again.claims(), memory.claims());
        let (list, full) = again.claims().parts();
        assert!(!full);
        let seen: Vec<_> = list
            .iter()
            .map(|c| (c.host.as_str(), c.said, c.seen_ms, c.expired_ms))
            .collect();
        let late = crate::claims::TTL_MS + 5;
        assert_eq!(
            seen,
            [
                ("a.example", more(1), Some(20), None),
                ("b.example", more(2), Some(late), None),
                ("d.example", more(4), Some(0), Some(late)),
            ]
        );
        assert!(again.claims().blocks() && again.claims().caveat());
        // A change that changes nothing writes nothing.
        fs::remove_file(dir.file()).unwrap();
        memory
            .change_claims(|claims| {
                claims.settle(|_| false);
            })
            .unwrap();
        assert!(!dir.file().exists());
        // A full list is kept as full.
        let mut full_list = Claims::default();
        for i in 0..=MAX_CLAIMS {
            full_list.note(&format!("{i}.example"), more(1), None);
        }
        let bytes = encode(7, 8, &full_list).unwrap();
        let (generation, floor, read) = decode(&bytes).unwrap();
        assert_eq!((generation, floor), (7, 8));
        assert_eq!(read, full_list);
        assert!(read.parts().1);
    }

    #[test]
    fn a_damaged_file_is_not_a_first_run() {
        let dir = Dir::new();
        let mut memory = Memory::open(&dir.file()).unwrap();
        memory.next_generation().unwrap();
        memory.raise_floor(1_795_392_000_000).unwrap();
        memory
            .change_claims(|claims| {
                claims.note("a.example", more(1), Some((1, 2)));
                claims.note("b.example", more(2), None);
            })
            .unwrap();
        let good = fs::read(dir.file()).unwrap();
        assert!(decode(&good).is_some());
        // Any one byte changed, any length cut off, anything added.
        for at in 0..good.len() {
            for bit in [0x01u8, 0x80] {
                let mut bad = good.clone();
                bad[at] ^= bit;
                assert!(decode(&bad).is_none(), "byte {at}");
            }
            assert!(decode(&good[..at]).is_none(), "cut at {at}");
        }
        let mut longer = good.clone();
        longer.push(0);
        assert!(decode(&longer).is_none());
        // The program is told, and nothing is started afresh.
        for bad in [&good[..good.len() - 1], &b""[..], b"FLYTIPS1"] {
            fs::write(dir.file(), bad).unwrap();
            assert_eq!(Memory::open(&dir.file()).err(), Some(Damaged::Format));
            assert_eq!(fs::read(dir.file()).unwrap(), bad);
        }
        // A directory where the file should be cannot be read at all.
        fs::remove_file(dir.file()).unwrap();
        fs::create_dir(dir.file()).unwrap();
        assert_eq!(Memory::open(&dir.file()).err(), Some(Damaged::Read));
    }

    #[test]
    fn only_what_this_program_writes_is_read() {
        let good = encode(1, 2, &{
            let mut claims = Claims::default();
            claims.note("a.example", more(1), Some((1, 2)));
            claims
        })
        .unwrap();
        let plain = body(&good);
        assert!(decode(&sealed(plain.clone())).is_some());
        // Each of these has a digest that fits; none is what is written.
        let mut other_name = plain.clone();
        other_name[7] = b'2';
        let mut odd_full = plain.clone();
        odd_full[24] = 2;
        let mut too_many = plain.clone();
        too_many[25..27].copy_from_slice(&u16::try_from(MAX_CLAIMS + 1).unwrap().to_le_bytes());
        let mut one_more = plain.clone();
        one_more[25] = 2;
        let mut extra = plain.clone();
        extra.push(0);
        // The claim: 1 byte of length, the name, 8 + 32 + 8 bytes, then
        // twice a flag and a number.
        let moments = 27 + 1 + "a.example".len() + 48;
        let mut odd_flag = plain.clone();
        odd_flag[moments] = 2;
        let mut value_without_flag = plain.clone();
        value_without_flag[moments + 9 + 1] = 1;
        let mut not_text = plain.clone();
        not_text[28] = 0xff;
        for bad in [other_name, odd_full, too_many, one_more, extra, odd_flag, value_without_flag, not_text] {
            assert!(decode(&sealed(bad)).is_none());
        }
        // One claim more than is ever kept, each of them well written.
        let claim = |i: usize| Claim {
            host: format!("{i}.example"),
            said: more(1),
            seen_ms: None,
            expired_ms: None,
        };
        let most = Claims::from_parts((0..MAX_CLAIMS).map(claim).collect(), true);
        assert!(decode(&encode(1, 2, &most).unwrap()).is_some());
        let over = Claims::from_parts((0..=MAX_CLAIMS).map(claim).collect(), true);
        assert!(decode(&encode(1, 2, &over).unwrap()).is_none());
        // The longest file this program writes is within what it reads.
        let long = |i: usize| Claim {
            host: format!("{i:0>253}"),
            said: more(1),
            seen_ms: Some(u64::MAX),
            expired_ms: Some(u64::MAX),
        };
        let longest = encode(u64::MAX, u64::MAX, &Claims::from_parts((0..MAX_CLAIMS).map(long).collect(), true)).unwrap();
        assert!(longest.len() <= MAX_FILE);
        assert!(decode(&longest).is_some());
    }

    #[test]
    fn what_cannot_be_written_is_not_taken_as_done() {
        let dir = Dir::new();
        let nowhere = dir.0.join("no-such-directory").join("tips.state");
        let mut memory = Memory::open(&nowhere).unwrap();
        assert_eq!(memory.next_generation(), Err(Damaged::Write));
        assert_eq!(memory.generation(), 0);
        assert_eq!(memory.raise_floor(9), Err(Damaged::Write));
        assert_eq!(memory.floor_ms(), 0);
        let noted = memory.change_claims(|claims| {
            claims.note("a.example", more(1), None);
        });
        assert_eq!(noted, Err(Damaged::Write));
        assert!(!memory.claims().blocks());
    }
}
