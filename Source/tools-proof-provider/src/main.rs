//! Optional publisher of untrusted history candidates. This program never writes wallet state.
#![forbid(unsafe_code)]
use fly_chain_headers::{checkpoint, proof, Net};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::{Builder, NamedTempFile};

mod generate;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;
const MANIFEST_LIMIT: usize = 4096;
const SCHEMA: &str = "grinsight.proof-provider.v1";

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn net_name(net: Net) -> &'static str {
    match net {
        Net::Main => "main",
        Net::Test => "test",
        Net::Automated => "automated",
    }
}
fn network(name: &str) -> Result<Net> {
    match name {
        "main" => Ok(Net::Main),
        "test" => Ok(Net::Test),
        _ => Err("expected main or test".into()),
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
struct Member {
    size: usize,
    sha256: String,
}
impl Member {
    fn of(raw: &[u8]) -> Self {
        Self {
            size: raw.len(),
            sha256: digest(raw),
        }
    }
}
#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    network: String,
    genesis: String,
    method: String,
    height: u64,
    hash: String,
    total_work: u64,
    checkpoint: Member,
    proof: Member,
}

fn read_limit(path: &Path, max: usize) -> Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err("expected a regular artifact file".into());
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > max as u64 {
        return Err("artifact exceeds bound or is not a file".into());
    }
    let mut data = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut data)?;
    if data.len() > max {
        return Err("artifact exceeds bound".into());
    }
    Ok(data)
}

fn inspect(net: Net, point: &[u8], raw: &[u8]) -> Result<Manifest> {
    let start = checkpoint::check(point, net).map_err(|e| format!("checkpoint rejected: {e:?}"))?;
    // Reject Extended as well: the advertised proof must name this exact point.
    if !matches!(proof::check_for(&start, raw), proof::History::Sampled(_)) {
        return Err("history sample failed for this exact point".into());
    }
    Ok(Manifest {
        schema: SCHEMA.into(),
        method: "GSHP1-research-candidate".into(),
        network: net_name(net).into(),
        genesis: hex(&net.genesis_hash()),
        hash: hex(&start.hash()),
        height: start.height(),
        total_work: start.anchor.total_difficulty().to_num(),
        checkpoint: Member::of(point),
        proof: Member::of(raw),
    })
}

// All paths are fixed or derived locally from a digest, never supplied by a mirror.
fn object_path(root: &Path, id: &Manifest) -> PathBuf {
    let mut key = Vec::from(b"GrinSight provider objects v1\n".as_slice());
    key.extend_from_slice(id.checkpoint.sha256.as_bytes());
    key.push(b'\n');
    key.extend_from_slice(id.proof.sha256.as_bytes());
    root.join("objects").join(digest(&key))
}

fn verify(root: &Path, net: Net) -> Result<Manifest> {
    let manifest: Manifest =
        serde_json::from_slice(&read_limit(&root.join("manifest.json"), MANIFEST_LIMIT)?)?;
    if manifest.schema != SCHEMA
        || manifest.network != net_name(net)
        || manifest.method != "GSHP1-research-candidate"
        || manifest.checkpoint.size > checkpoint::MAX_RECORD_LEN
        || manifest.proof.size > proof::MAX_PROOF
    {
        return Err("unsupported manifest".into());
    }
    let dir = object_path(root, &manifest);
    for child in [root.join("objects"), dir.clone()] {
        if !fs::symlink_metadata(child)?.file_type().is_dir() {
            return Err("expected regular object directory".into());
        }
    }
    let point = read_limit(&dir.join("checkpoint.json"), manifest.checkpoint.size)?;
    let raw = read_limit(&dir.join("history.proof"), manifest.proof.size)?;
    if Member::of(&point) != manifest.checkpoint || Member::of(&raw) != manifest.proof {
        return Err("artifact digest/size mismatch".into());
    }
    if inspect(net, &point, &raw)? != manifest {
        return Err("manifest and sample disagree".into());
    }
    Ok(manifest)
}

fn publish(root: &Path, net: Net, point: &[u8], raw: &[u8]) -> Result<Manifest> {
    let expected = inspect(net, point, raw)?;
    let objects = root.join("objects");
    fs::create_dir_all(&objects)?;
    let lock = File::options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join(".publish.lock"))?;
    lock.lock()?;
    let current = root.join("manifest.json");
    if current.try_exists()? {
        let old = verify(root, net)?;
        if old == expected {
            return Ok(old);
        }
        if old.height > expected.height
            || (old.height == expected.height && old.hash != expected.hash)
        {
            return Err("refusing to replace the current candidate with an older or conflicting candidate; use a separate publication directory".into());
        }
    }
    let target = object_path(root, &expected);
    if !target.try_exists()? {
        let temp = Builder::new().prefix(".stage-").tempdir_in(&objects)?;
        fs::write(temp.path().join("checkpoint.json"), point)?;
        fs::write(temp.path().join("history.proof"), raw)?;
        fs::rename(temp.path(), &target)?;
    }
    if read_limit(&target.join("checkpoint.json"), checkpoint::MAX_RECORD_LEN)? != point
        || read_limit(&target.join("history.proof"), proof::MAX_PROOF)? != raw
    {
        return Err("stored immutable object differs".into());
    }
    let mut new = NamedTempFile::new_in(root)?;
    serde_json::to_writer_pretty(&mut new, &expected)?;
    new.write_all(b"\n")?;
    new.flush()?;
    new.persist(&current)?;
    Ok(expected)
}

fn run(args: &[String]) -> Result<Manifest> {
    match args {
        [action, name, a, b, out] if action == "bundle" => {
            let p = read_limit(Path::new(a), checkpoint::MAX_RECORD_LEN)?;
            let h = read_limit(Path::new(b), proof::MAX_PROOF)?;
            publish(Path::new(out), network(name)?, &p, &h)
        }
        [action, name, root] if action == "check" => verify(Path::new(root), network(name)?),
        [action, name, dump, height, root] if action == "generate" => {
            let net = network(name)?;
            let (point, raw) = generate::from_dump(net, Path::new(dump), height.parse()?)?;
            publish(Path::new(root), net, &point, &raw)
        }
        _ => Err("usage: grin-proof-provider bundle NET CHECKPOINT PROOF OUT | check NET OUT | generate NET HEADER_DUMP HEIGHT OUT".into()),
    }
}

fn main() -> std::process::ExitCode {
    match run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(m) => {
            println!(
                "research candidate {} {} {} (GSHP1 sample; freshness unknown)",
                m.network, m.height, m.hash
            );
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            let _ = writeln!(io::stderr(), "provider: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod mined_test;
