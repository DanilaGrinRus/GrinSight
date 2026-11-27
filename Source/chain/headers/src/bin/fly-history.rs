//! Check a framed Grin header dump from the network's exact genesis.
//! Format: u16 big-endian byte length followed by one full header.
//! Stops on the first invalid header. Does not contact a node or wallet.
#![forbid(unsafe_code)]
use fly_chain_headers::{genesis::GenesisVerifier, hash_bytes, read_header, Net, MAX_HEADER_LEN};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

fn next_record(input: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut size = [0; 2];
    loop {
        match input.read(&mut size[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    input.read_exact(&mut size[1..])?;
    let len = usize::from(u16::from_be_bytes(size));
    if len == 0 || len > MAX_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Grin header frame length",
        ));
    }
    let mut bytes = vec![0; len];
    input.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}

fn run(path: &Path, net: Net, point: Option<&Path>) -> Result<(), String> {
    let mut input = BufReader::new(File::open(path).map_err(|e| e.to_string())?);
    let as_io = |e: io::Error| e.to_string();
    let mut verified = GenesisVerifier::new(net).map_err(|e| format!("{e:?}"))?;
    let first = next_record(&mut input)
        .map_err(as_io)?
        .ok_or("empty header file")?;
    verified
        .check_genesis(&read_header(&first).ok_or("invalid genesis encoding")?)
        .map_err(|e| format!("height 0: {e:?}"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let mut by_version = [0u64; 6];
    while let Some(raw) = next_record(&mut input).map_err(as_io)? {
        let h = read_header(&raw).ok_or("invalid header encoding")?;
        verified
            .push(&h, now)
            .map_err(|e| format!("after verified height {}: {e:?}", verified.tip().height))?;
        if let Some(n) = by_version.get_mut(usize::from(h.version.0)) {
            *n += 1;
        }
        if h.height % 500_000 == 0 {
            eprintln!("verified height {}", h.height);
        }
    }
    let tip = verified.tip();
    println!("headers: {} (heights 0..{})", tip.height + 1, tip.height);
    println!(
        "last hash: {}",
        hash_bytes(tip)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    println!(
        "by version 1..5 (excluding genesis): {:?}",
        &by_version[1..]
    );
    println!(
        "total difficulty at the end: {}",
        tip.total_difficulty().to_num()
    );
    println!(
        "header tree: {} leaves, {} peaks",
        verified.peaks().leaves(),
        verified.peaks().hashes().len()
    );
    if let Some(file) = point {
        let bytes = verified
            .record(now)
            .ok_or("a checkpoint requires three post-HF4 headers")?;
        // Never overwrite a previous record or wallet state. A truncated export
        // fails the normal record reader; installation uses the runtime journal.
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(file)
            .map_err(as_io)?;
        output.write_all(&bytes).map_err(as_io)?;
        output.sync_all().map_err(as_io)?;
    }
    Ok(())
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let usage = "usage: fly-history <header-file> [--network main|test] [--checkpoint <new-file>]";
    let Some(path) = args.next() else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    let mut net = Net::Main;
    let mut point: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        match (arg.to_str(), args.next()) {
            (Some("--network"), Some(network)) if network == "main" => net = Net::Main,
            (Some("--network"), Some(network)) if network == "test" => net = Net::Test,
            (Some("--checkpoint"), Some(file)) if point.is_none() => point = Some(file.into()),
            _ => {
                eprintln!("{usage}");
                return ExitCode::from(2);
            }
        }
    }
    match run(Path::new(&path), net, point.as_deref()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("fly-history: {why}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::next_record;
    use fly_chain_headers::MAX_HEADER_LEN;
    use std::io::ErrorKind;

    #[test]
    fn distinguishes_boundary_eof_and_incomplete_records() {
        let mut empty: &[u8] = &[];
        assert_eq!(next_record(&mut empty).unwrap(), None);
        for bytes in [&[0u8][..], &[0, 2, 42][..]] {
            assert_eq!(
                next_record(&mut &*bytes).unwrap_err().kind(),
                ErrorKind::UnexpectedEof
            );
        }
        let too_long = u16::try_from(MAX_HEADER_LEN + 1).unwrap().to_be_bytes();
        for size in [[0, 0], too_long] {
            assert_eq!(
                next_record(&mut &size[..]).unwrap_err().kind(),
                ErrorKind::InvalidData
            );
        }
    }
}
