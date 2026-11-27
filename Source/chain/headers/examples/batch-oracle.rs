//! Independent native reference and bounded H3..H1000 Mainnet continuation.
//! Receipt authentication belongs to the separate pinned-image verifier.
use fly_chain_headers::{
    genesis::GenesisVerifier, hash_bytes, peaks::Peaks, read_header, write_header, Net,
};
use grin_core::{
    consensus::{self, HeaderDifficultyInfo},
    core::{hash::Hash, BlockHeader},
    global,
    pow::Difficulty,
};
use std::{
    collections::VecDeque,
    fs::File,
    io::{self, Read},
    path::Path,
};

// Reuse the pre-HF4 checks called by GenesisVerifier; these functions are
// crate-private. The example does not change the product library interface.
#[allow(dead_code)]
#[path = "../src/rules.rs"]
mod rules;

const OBSERVED_AT: u64 = 1_548_979_200;
const MAX_HEIGHT: u64 = 1000;
const WINDOW: usize = 61;
const LIMIT: usize = 4096;

fn err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn insist(ok: bool, why: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(err(why))
    }
}

fn num(s: &[u8]) -> u64 {
    u64::from_be_bytes(s.try_into().unwrap())
}
fn hex(s: &[u8]) -> String {
    s.iter().map(|b| format!("{b:02x}")).collect()
}

fn file(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut out)?;
    insist(out.len() <= limit, "oversize input")?;
    Ok(out)
}

fn header(raw: &[u8]) -> io::Result<BlockHeader> {
    let h = read_header(raw).ok_or_else(|| err("invalid header"))?;
    insist(
        write_header(&h).as_deref() == Some(raw),
        "noncanonical header",
    )?;
    Ok(h)
}

fn frame(reader: &mut impl Read) -> io::Result<BlockHeader> {
    let mut len = [0; 2];
    reader.read_exact(&mut len)?;
    let size = u16::from_be_bytes(len) as usize;
    insist((400..=600).contains(&size), "unexpected length")?;
    let mut s = vec![0; size];
    reader.read_exact(&mut s)?;
    header(&s)
}

fn row(h: &BlockHeader, delta: u64) -> HeaderDifficultyInfo {
    HeaderDifficultyInfo::new(
        None,
        h.timestamp.timestamp() as u64,
        Difficulty::from_num(delta),
        h.pow.secondary_scaling,
        h.pow.is_secondary(),
    )
}

fn save_row(rows: &mut VecDeque<HeaderDifficultyInfo>, info: HeaderDifficultyInfo) {
    rows.push_front(info);
    rows.truncate(WINDOW);
}

#[derive(Clone)]
struct State {
    all_secondary: bool,
    tip: BlockHeader,
    peaks: Peaks,
    rows: VecDeque<HeaderDifficultyInfo>,
}

impl State {
    fn checkpoint(&self, image: &[u8; 32]) -> io::Result<Vec<u8>> {
        let tip = &self.tip;
        let wire = write_header(tip).ok_or_else(|| err("header serialization"))?;
        insist(
            (3..=MAX_HEIGHT).contains(&tip.height) && wire.len() == 400 && self.all_secondary,
            "outside batch C29 scope",
        )?;
        let mut out = b"GSZBMH01".to_vec();
        out.extend_from_slice(image);
        out.extend_from_slice(&tip.height.to_be_bytes());
        out.extend_from_slice(&Net::Main.genesis_hash());
        out.extend_from_slice(&wire);
        out.extend_from_slice(&hash_bytes(tip));
        out.extend_from_slice(&tip.total_difficulty().to_num().to_be_bytes());
        out.extend_from_slice(&self.peaks.size().to_be_bytes());
        out.extend_from_slice(self.peaks.root().as_bytes());
        out.push(self.rows.len() as u8);
        for r in &self.rows {
            out.extend_from_slice(&r.timestamp.to_be_bytes());
            out.extend_from_slice(&r.difficulty.to_num().to_be_bytes());
            out.extend_from_slice(&r.secondary_scaling.to_be_bytes());
            out.push(u8::from(r.is_secondary));
        }
        out.push(self.peaks.hashes().len() as u8);
        for h in self.peaks.hashes() {
            out.extend_from_slice(h.as_bytes());
        }
        Ok(out)
    }

    fn load(s: &[u8], image: &[u8; 32]) -> io::Result<Self> {
        insist(
            (562..=LIMIT).contains(&s.len()) && &s[..8] == b"GSZBMH01" && &s[8..40] == image,
            "wrong batch schema/image",
        )?;
        let h = num(&s[40..48]);
        insist((3..=MAX_HEIGHT).contains(&h), "unsupported height")?;
        let tip = header(&s[80..480])?;
        rules::check_any_era(&tip).map_err(|why| err(&format!("point tip: {why:?}")))?;
        insist(tip.height == h && tip.pow.edge_bits() == 29, "invalid tip")?;
        let count = usize::from(s[560]);
        let end = 561 + count * 21;
        insist(
            count == WINDOW.min(h as usize + 1) && end < s.len(),
            "invalid DAA size",
        )?;
        let mut rows = VecDeque::new();
        let mut prev = OBSERVED_AT;
        for raw in s[561..end].chunks_exact(21) {
            let timestamp = num(&raw[..8]);
            let delta = num(&raw[8..16]);
            let scaling = u32::from_be_bytes(raw[16..20].try_into().unwrap());
            insist(
                timestamp < prev && delta > 0 && raw[20] == 1,
                "invalid DAA row",
            )?;
            rows.push_back(HeaderDifficultyInfo::new(
                None,
                timestamp,
                Difficulty::from_num(delta),
                scaling,
                true,
            ));
            prev = timestamp;
        }
        insist(
            rows[0].timestamp == tip.timestamp.timestamp() as u64
                && rows[0].secondary_scaling == tip.pow.secondary_scaling,
            "tip/DAA mismatch",
        )?;
        let n = usize::from(s[end]);
        insist(s.len() == end + 1 + n * 32, "invalid frontier length")?;
        let peaks = Peaks::from_parts(
            h + 1,
            s[end + 1..].chunks_exact(32).map(Hash::from_vec).collect(),
        )
        .map_err(|_| err("invalid peak count"))?;
        // The separate receipt verifier established the C29-only ancestry of imported points.
        let state = Self {
            tip,
            rows,
            peaks,
            all_secondary: true,
        };
        insist(
            state.checkpoint(image)? == s,
            "boundary disagrees with tip/frontier",
        )?;
        Ok(state)
    }

    fn next(&mut self, child: BlockHeader) -> io::Result<()> {
        insist(
            child.height == self.tip.height + 1
                && child.height <= MAX_HEIGHT
                && child.prev_hash.as_bytes() == hash_bytes(&self.tip)
                && child.prev_root == self.peaks.root()
                && !rules::ahead_of(&child, OBSERVED_AT),
            "invalid successor link/root/height/time",
        )?;
        rules::check_any_era(&child).map_err(|e| err(&format!("header: {e:?}")))?;
        let increment = rules::linked_work(&self.tip, &child)
            .map_err(|e| err(&format!("linked work: {e:?}")))?;
        let padded = global::difficulty_data_to_vector(self.rows.iter().cloned());
        padded
            .iter()
            .skip(1)
            .try_fold(0u64, |a, b| a.checked_add(b.difficulty.to_num()))
            .and_then(|v| v.checked_mul(consensus::BLOCK_TIME_SEC))
            .ok_or_else(|| err("DAA overflow"))?;
        let expected = consensus::next_difficulty(child.height, self.rows.iter().cloned());
        insist(
            increment == expected.difficulty.to_num()
                && expected.secondary_scaling == child.pow.secondary_scaling,
            "wrong difficulty or scaling",
        )?;
        self.peaks
            .append(&child)
            .map_err(|_| err("frontier append"))?;
        save_row(&mut self.rows, row(&child, increment));
        self.all_secondary &= child.pow.is_secondary();
        self.tip = child;
        Ok(())
    }
}

fn reference(source: &Path, height: u64) -> io::Result<State> {
    let mut chain = GenesisVerifier::new(Net::Main).map_err(|_| err("genesis"))?;
    let mut reader = File::open(source)?;
    chain
        .check_genesis(&frame(&mut reader)?)
        .map_err(|_| err("genesis mismatch"))?;
    let mut td = chain.tip().total_difficulty().to_num();
    let mut rows = VecDeque::from([row(chain.tip(), td)]);
    let mut all_secondary = chain.tip().pow.is_secondary();
    for _ in 1..=height {
        chain
            .push(&frame(&mut reader)?, OBSERVED_AT)
            .map_err(|e| err(&format!("{e:?}")))?;
        let current = chain.tip().total_difficulty().to_num();
        all_secondary &= chain.tip().pow.is_secondary();
        save_row(&mut rows, row(chain.tip(), current - td));
        td = current;
    }
    Ok(State {
        all_secondary,
        tip: chain.tip().clone(),
        peaks: chain.peaks().clone(),
        rows,
    })
}

fn image(text: &str) -> io::Result<[u8; 32]> {
    let text = text.trim();
    insist(
        text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid pinned ID",
    )?;
    let mut bytes = [0; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
    }
    Ok(bytes)
}

fn main() -> io::Result<()> {
    Net::Main.enter();
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [op, pinned, fixture, h, point] if op == "compare" || op == "export" => {
            let height: u64 = h.parse().map_err(|_| err("invalid height"))?;
            insist((3..=MAX_HEIGHT).contains(&height), "unsupported height")?;
            let state = reference(fixture.as_ref(), height)?;
            let bytes = state.checkpoint(&image(pinned)?)?;
            if op == "export" {
                use std::io::Write;
                File::create_new(point)?.write_all(&bytes)?;
            } else {
                insist(file(point.as_ref(), LIMIT)? == bytes, "full checkpoint mismatch")?;
            }
            println!(
                "{op} full native boundary height={height} rows={} peaks={}",
                state.rows.len(),
                state.peaks.hashes().len()
            );
        }
        [op, pinned, point, next] if op == "resume" => {
            let mut state = State::load(&file(point.as_ref(), LIMIT)?, &image(pinned)?)?;
            state.next(header(&file(next.as_ref(), 600)?)?)?;
            println!(
                "height={} hash={} td={} rows={} peaks={} root={}",
                state.tip.height,
                hex(&hash_bytes(&state.tip)),
                state.tip.total_difficulty().to_num(),
                state.rows.len(),
                state.peaks.hashes().len(),
                hex(state.peaks.root().as_bytes())
            );
        }
        _ => return Err(err(
            "compare/export PINNED_HEX FRAMED HEIGHT CHECKPOINT | resume PINNED_HEX CHECKPOINT NEXT_WIRE",
        )),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/mainnet/first-4100-headers.bin"
    );
    const IMAGE: [u8; 32] = [0x35; 32]; // Caller-provided tag for codec tests. No receipts minted here.

    #[test]
    fn rolling_matches_full_prefix_through_eviction_and_first_primary() {
        let mut state = reference(Path::new(FIXTURE), 3).unwrap();
        let contents = include_bytes!("../tests/mainnet/first-4100-headers.bin");
        let mut stream = Cursor::new(contents);
        let mut chain = GenesisVerifier::new(Net::Main).unwrap();
        chain.check_genesis(&frame(&mut stream).unwrap()).unwrap();
        let mut all_rows = vec![row(chain.tip(), chain.tip().total_difficulty().to_num())];
        for height in 1..=231 {
            let child = frame(&mut stream).unwrap();
            let previous = chain.tip().total_difficulty().to_num();
            chain.push(&child, OBSERVED_AT).unwrap();
            all_rows.push(row(&child, child.total_difficulty().to_num() - previous));
            if height > 3 {
                state.next(child.clone()).unwrap();
            }
            if height < 3 {
                continue;
            }
            assert_eq!(state.tip, *chain.tip());
            assert_eq!(&state.peaks, chain.peaks());
            let expected: Vec<_> = all_rows.iter().rev().take(WINDOW).collect();
            assert_eq!(state.rows.iter().collect::<Vec<_>>(), expected);
            if height < 230 {
                // Drop the entire last process state at every boundary. Only the
                // checkpoint crosses it. The independent full chain remains the oracle.
                let bytes = state.checkpoint(&IMAGE).unwrap();
                state = State::load(&bytes, &IMAGE).unwrap();
                assert_eq!(&state.peaks, chain.peaks());
                assert_eq!(state.rows.iter().collect::<Vec<_>>(), expected);
                assert!(bytes.len() <= 561 + 61 * 21 + 1 + 32 * 10);
            }
            if height == 60 {
                assert_eq!(state.rows.back().unwrap().timestamp, all_rows[0].timestamp);
            }
            if height == 61 {
                assert_eq!(state.rows.back().unwrap().timestamp, all_rows[1].timestamp);
            }
            if height == 230 {
                assert_eq!(child.pow.edge_bits(), 31);
                assert!(!state.rows[0].is_secondary);
                assert!(state.checkpoint(&IMAGE).is_err());
            }
            if height == 231 {
                assert_eq!(child.pow.edge_bits(), 29);
                assert!(!state.rows[1].is_secondary);
                assert!(state.checkpoint(&IMAGE).is_err());
            }
        }
    }

    #[test]
    fn rejects_inconsistent_boundary_and_wrong_successor() {
        let state = reference(Path::new(FIXTURE), 6).unwrap();
        let point = state.checkpoint(&IMAGE).unwrap();
        let end = 561 + 7 * 21;
        assert_eq!(point.len(), end + 1 + 3 * 32);
        for offset in [
            0,
            8,
            47,
            48,
            80,
            480,
            519,
            527,
            559,
            560,
            561,
            581,
            end,
            end + 1,
            point.len() - 1,
        ] {
            let mut bad = point.clone();
            bad[offset] ^= 1;
            assert!(State::load(&bad, &IMAGE).is_err(), "offset {offset}");
        }
        let mut with_tail = point.clone();
        with_tail.push(0);
        assert!(State::load(&with_tail, &IMAGE).is_err());
        assert!(State::load(&point[..point.len() - 1], &IMAGE).is_err());

        let mut restarted = State::load(&point, &IMAGE).unwrap();
        let later = reference(Path::new(FIXTURE), 8).unwrap().tip;
        assert!(restarted.next(later).is_err());
        assert_eq!(restarted.checkpoint(&IMAGE).unwrap(), point);
        let expected = reference(Path::new(FIXTURE), 7).unwrap();
        restarted.next(expected.tip.clone()).unwrap();
        assert_eq!(
            restarted.checkpoint(&IMAGE).unwrap(),
            expected.checkpoint(&IMAGE).unwrap()
        );
    }

    #[test]
    fn an_older_primary_remains_outside_the_guest_scope_after_it_leaves_the_window() {
        let state = reference(Path::new(FIXTURE), 330).unwrap();
        assert!(state.rows.iter().all(|r| r.is_secondary));
        assert!(!state.all_secondary);
        assert!(state.checkpoint(&IMAGE).is_err());
    }
}
