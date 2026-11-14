//! Verified session and wallet policy (was `grinsight.py`).
//!
//! A *session* is the folder written by one header sync: the validated header
//! transcript (`verified-headers.bin`) and a manifest (`verified-manifest.json`)
//! that pins it by SHA-256. Everything that later moves money starts from a
//! session that the caller pins by the manifest's SHA-256.
//!
//! This module holds only decisions, no networking and no child processes:
//! * pinned file reads ([`read_pin`]);
//! * tip freshness ([`header_age`]);
//! * peer distinctness ([`distinct_peers`]);
//! * the sync verdict and the manifest it writes ([`sync_verdict`]);
//! * opening a pinned session ([`Session::open`]);
//! * the gap plan with every refusal *before* anything runs ([`plan_gap`]),
//!   including the spend gate ([`Session::spend_gate`]);
//! * the final state lines ([`gap_report`], [`state_report`]).
//!
//! The `grinsight` command line tool (header-sync) and the C ABI (grinsight-ffi) are
//! thin callers of these functions.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};

pub const MANIFEST_FILE: &str = "verified-manifest.json";
pub const TRANSCRIPT_FILE: &str = "verified-headers.bin";
pub const MANIFEST_LIMIT: u64 = 4096;
pub const TRANSCRIPT_LIMIT: u64 = 256 * 1024 * 1024;
pub const PIN_FILE_LIMIT: u64 = 128 * 1024;
/// A tip timestamp may be this far in the future (peer clock skew).
pub const FUTURE_SKEW_SEC: i64 = 720;
pub const DEFAULT_MAX_TIP_AGE_SEC: i64 = 10800;
const MAX_TRANSCRIPT_HEADERS: u32 = 512_001;
/// Same bound as the reader of the headers file (`outputs::MAX_GAP_HEADERS`).
const MAX_GAP_HEADERS: usize = crate::outputs::MAX_GAP_HEADERS;
const MAX_COMMITMENTS: usize = 64;

pub fn sha256_hex(data: &[u8]) -> String {
    let d = Sha256::digest(data);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Reads at most `limit` bytes and checks the SHA-256 pin (hex, any case).
pub fn read_pin(path: &Path, expected: &str, limit: u64) -> Result<Vec<u8>, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut data = Vec::new();
    f.take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if data.len() as u64 > limit || sha256_hex(&data) != expected.to_ascii_lowercase() {
        return Err(format!("pin mismatch or oversized file: {}", path.display()));
    }
    Ok(data)
}

/// Strict ASCII hex (even length).
pub fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 || !b.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    (0..b.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    StaleOrFuture,
}

impl Freshness {
    pub fn as_str(self) -> &'static str {
        match self {
            Freshness::Fresh => "FRESH",
            Freshness::StaleOrFuture => "STALE_OR_FUTURE",
        }
    }
}

/// Grin header: version u16 | height u64 | timestamp i64, big endian.
pub fn header_height(raw: &[u8]) -> Result<u64, String> {
    let b: [u8; 8] = raw.get(2..10).ok_or("short header")?.try_into().unwrap();
    Ok(u64::from_be_bytes(b))
}

pub fn header_age(raw: &[u8], max_age: i64, now: i64) -> Result<(Freshness, i64), String> {
    let b: [u8; 8] = raw
        .get(10..18)
        .ok_or("header is too short for timestamp")?
        .try_into()
        .unwrap();
    let age = now.saturating_sub(i64::from_be_bytes(b));
    let f = if (-FUTURE_SKEW_SEC..=max_age).contains(&age) {
        Freshness::Fresh
    } else {
        Freshness::StaleOrFuture
    };
    Ok((f, age))
}

/// `host:port` or `[v6]:port`.
pub fn split_peer(peer: &str) -> Result<(String, u16), String> {
    let bad = || "peer must be host:port (IPv6: [address]:port)".to_string();
    let (host, port) = if let Some(rest) = peer.strip_prefix('[') {
        rest.split_once("]:").ok_or_else(bad)?
    } else {
        peer.rsplit_once(':').ok_or_else(bad)?
    };
    if host.is_empty() || port.is_empty() || !port.bytes().all(|c| c.is_ascii_digit()) || port.len() > 5 {
        return Err(bad());
    }
    let port: u16 = port.parse().map_err(|_| bad())?;
    if port == 0 {
        return Err(bad());
    }
    Ok((host.to_string(), port))
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Every peer must resolve to IP addresses no other peer uses; at least two
/// peers. Returns one `ip:port` per peer (the smallest address, as text).
pub fn distinct_peers<F>(peers: &[String], mut resolve: F) -> Result<Vec<String>, String>
where
    F: FnMut(&str, u16) -> Result<Vec<IpAddr>, String>,
{
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    for peer in peers {
        let (host, port) = split_peer(peer)?;
        let addrs: BTreeSet<String> = resolve(&host, port)?
            .into_iter()
            .map(|ip| canonical_ip(ip).to_string())
            .collect();
        if addrs.is_empty() || addrs.iter().any(|a| seen.contains(a)) {
            return Err("peers resolve to overlapping IP addresses".into());
        }
        let ip = addrs.iter().next().unwrap().clone();
        seen.extend(addrs);
        out.push(if ip.contains(':') { format!("[{ip}]:{port}") } else { format!("{ip}:{port}") });
    }
    if out.len() < 2 {
        return Err("at least two distinct peer IPs are required".into());
    }
    Ok(out)
}

/// System DNS (std), for [`distinct_peers`].
pub fn dns_resolve(host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
    use std::net::ToSocketAddrs;
    let h = host.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(host);
    Ok((h, port)
        .to_socket_addrs()
        .map_err(|e| format!("{host}: {e}"))?
        .map(|a| a.ip())
        .collect())
}

/// Grin 5.5.2 `servers/src/grin/seed.rs`.
pub const MAINNET_DNS_SEEDS: &[&str] = &[
    "mainnet-seed.grinnode.live",
    "grincoin.org",
    "main.gri.mw",
    "mainnet.grinffindor.org",
    "main-seed.grin.money",
    "mainnet.fountainoffairfortune.it",
];
pub const FLOONET_DNS_SEEDS: &[&str] = &[
    "testnet.grincoin.org",
    "test.gri.mw",
    "testnet.grinffindor.org",
    "test-seed.grin.money",
    "testnet.fountainoffairfortune.it",
];

/// Peers from DNS seed answers: duplicates removed, IPv4 first, at most `limit`.
/// Which of them really serve PIBD is decided later by a handshake.
pub fn seed_peers(answers: &[Vec<IpAddr>], port: u16, limit: usize) -> Vec<String> {
    let mut v4: Vec<String> = Vec::new();
    let mut v6: Vec<String> = Vec::new();
    for ip in answers.iter().flatten() {
        let (list, t) = match ip {
            IpAddr::V4(a) => (&mut v4, format!("{a}:{port}")),
            IpAddr::V6(a) => (&mut v6, format!("[{a}]:{port}")),
        };
        if !list.contains(&t) {
            list.push(t);
        }
    }
    v4.into_iter().chain(v6).take(limit).collect()
}

/// `key=value` lines of a tool's stdout (first `=` splits; later lines win).
pub fn kv_lines(stdout: &str) -> std::collections::HashMap<String, String> {
    stdout
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Transcript file format: u32 LE count, then (u32 LE length, header bytes)*.
pub fn encode_transcript<'a>(headers: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let hs: Vec<&[u8]> = headers.into_iter().collect();
    let mut out = (hs.len() as u32).to_le_bytes().to_vec();
    for h in hs {
        out.extend_from_slice(&(h.len() as u32).to_le_bytes());
        out.extend_from_slice(h);
    }
    out
}

/// Contiguous `(height, raw header)` list.
pub fn decode_transcript(data: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let u32_at = |o: usize| -> Option<u32> { data.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap())) };
    let n = u32_at(0).ok_or("truncated transcript")?;
    if !(1..=MAX_TRANSCRIPT_HEADERS).contains(&n) {
        return Err("invalid transcript count".into());
    }
    let mut off = 4usize;
    let mut out: Vec<(u64, Vec<u8>)> = Vec::with_capacity(n.min(100_000) as usize);
    for _ in 0..n {
        let len = u32_at(off).ok_or("truncated transcript length")? as usize;
        off += 4;
        if !(1..=4096).contains(&len) || off + len > data.len() {
            return Err("invalid transcript header length".into());
        }
        let h = &data[off..off + len];
        off += len;
        if h.len() < 10 {
            return Err("short header".into());
        }
        let height = header_height(h)?;
        if let Some((last, _)) = out.last() {
            if Some(height) != last.checked_add(1) {
                return Err("non-contiguous transcript".into());
            }
        }
        out.push((height, h.to_vec()));
    }
    if off != data.len() {
        return Err("trailing bytes after transcript".into());
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Floonet,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Mainnet => "MAINNET",
            Network::Floonet => "FLOONET",
        }
    }
}

/// The pinned manifest. Unknown keys are ignored; written canonically
/// (sorted keys, no spaces), byte-identical to the earlier Python tool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub transcript_sha256: String,
    pub tip_header_sha256: String,
    pub tip_height: u64,
    pub sync_status: String,
    pub max_tip_age_sec: i64,
    pub network: Network,
    pub checkpoint_sha256: Option<String>,
    pub history_sha256: Option<String>,
}

impl Manifest {
    pub fn parse(raw: &[u8]) -> Result<Manifest, String> {
        let v: Value = serde_json::from_slice(raw).map_err(|e| format!("session manifest: {e}"))?;
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        if v.get("version").and_then(Value::as_u64) != Some(1) {
            return Err("unsupported session manifest".into());
        }
        let network = match s("network").as_deref() {
            None | Some("FLOONET") => Network::Floonet,
            Some("MAINNET") => Network::Mainnet,
            Some(x) => return Err(format!("unknown network {x}")),
        };
        Ok(Manifest {
            transcript_sha256: s("transcript_sha256").ok_or("manifest: transcript_sha256")?,
            tip_header_sha256: s("tip_header_sha256").ok_or("manifest: tip_header_sha256")?,
            tip_height: v.get("tip_height").and_then(Value::as_u64).ok_or("manifest: tip_height")?,
            sync_status: s("sync_status").unwrap_or_else(|| "UNKNOWN".into()),
            max_tip_age_sec: v
                .get("max_tip_age_sec")
                .and_then(Value::as_i64)
                .unwrap_or(DEFAULT_MAX_TIP_AGE_SEC),
            network,
            checkpoint_sha256: s("checkpoint_sha256"),
            history_sha256: s("history_sha256"),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // serde_json's Map is a BTreeMap here: keys come out sorted.
        let mut m = Map::new();
        m.insert("version".into(), json!(1));
        if let Some(c) = &self.checkpoint_sha256 {
            m.insert("checkpoint_sha256".into(), json!(c));
        }
        if let Some(h) = &self.history_sha256 {
            m.insert("history_sha256".into(), json!(h));
        }
        m.insert("transcript_sha256".into(), json!(self.transcript_sha256));
        m.insert("tip_header_sha256".into(), json!(self.tip_header_sha256));
        m.insert("tip_height".into(), json!(self.tip_height));
        m.insert("sync_status".into(), json!(self.sync_status));
        m.insert("max_tip_age_sec".into(), json!(self.max_tip_age_sec));
        m.insert("network".into(), json!(self.network.as_str()));
        serde_json::to_vec(&Value::Object(m)).expect("json")
    }

    pub fn is_pass(&self) -> bool {
        self.sync_status == "PASS"
    }
}

/// A session opened by its manifest pin; the transcript is checked against
/// the manifest (hash, contiguity, last height, tip header hash).
#[derive(Clone, Debug)]
pub struct Session {
    pub folder: PathBuf,
    pub manifest: Manifest,
    pub headers: Vec<(u64, Vec<u8>)>,
}

impl Session {
    pub fn open(folder: &Path, manifest_sha256: &str) -> Result<Session, String> {
        let raw = read_pin(&folder.join(MANIFEST_FILE), manifest_sha256, MANIFEST_LIMIT)?;
        let manifest = Manifest::parse(&raw)?;
        let data = read_pin(&folder.join(TRANSCRIPT_FILE), &manifest.transcript_sha256, TRANSCRIPT_LIMIT)?;
        let headers = decode_transcript(&data)?;
        let (last, tip) = headers.last().ok_or("empty transcript")?;
        if *last != manifest.tip_height || sha256_hex(tip) != manifest.tip_header_sha256 {
            return Err("session transcript does not match tip".into());
        }
        Ok(Session { folder: folder.to_path_buf(), manifest, headers })
    }

    pub fn tip_height(&self) -> u64 {
        self.manifest.tip_height
    }

    pub fn tip_header(&self) -> &[u8] {
        &self.headers.last().expect("non-empty").1
    }

    /// Hash (hex) of the verified tip header.
    pub fn tip_hash(&self) -> Option<String> {
        crate::outputs::header_hash_hex(self.tip_header(), self.manifest.network == Network::Mainnet)
    }

    pub fn header_at(&self, height: u64) -> Option<&[u8]> {
        let first = self.headers.first()?.0;
        let i = height.checked_sub(first)? as usize;
        self.headers.get(i).map(|(_, h)| h.as_slice())
    }

    pub fn freshness(&self, now: i64) -> (Freshness, i64) {
        header_age(self.tip_header(), self.manifest.max_tip_age_sec, now).expect("transcript headers are >= 18 bytes")
    }

    /// Money moves only on a PASS session whose tip is still fresh NOW.
    pub fn spend_gate(&self, now: i64) -> Result<(), String> {
        let (f, age) = self.freshness(now);
        if !self.manifest.is_pass() {
            return Err(format!(
                "--spend/--broadcast need a PASS session (this one is {}): run sync again",
                self.manifest.sync_status
            ));
        }
        if f != Freshness::Fresh {
            return Err(format!(
                "--spend/--broadcast need a fresh session tip (age {age}s, freshness {}): run sync again",
                f.as_str()
            ));
        }
        Ok(())
    }

    /// One JSON object for the UI: what the wallet may claim and do now.
    pub fn summary_json(&self, now: i64) -> String {
        let (f, age) = self.freshness(now);
        json!({
            "network": self.manifest.network.as_str(),
            "tip_height": self.manifest.tip_height,
            "sync_status": self.manifest.sync_status,
            "freshness": f.as_str(),
            "tip_age_seconds": age,
            "max_tip_age_sec": self.manifest.max_tip_age_sec,
            "can_spend": self.spend_gate(now).is_ok(),
            "default_archive_height": default_archive(self.manifest.tip_height),
        })
        .to_string()
    }
}

/// Newest 720-block boundary at least 2880 blocks below the tip.
pub fn default_archive(tip: u64) -> u64 {
    (tip.saturating_sub(2880) / 720) * 720
}

pub fn sync_exit_code(status: &str) -> i32 {
    if status == "PASS" {
        0
    } else {
        3
    }
}

/// Inputs of a finished header sync (the child's stdout and files it wrote).
pub struct SyncRun<'a> {
    pub stdout: &'a str,
    pub exit_code: i32,
    pub checkpoint_out: &'a str,
    pub transcript: &'a [u8],
    pub checkpoint_in: &'a [u8],
    pub history_in: &'a [u8],
    pub max_tip_age_sec: i64,
    pub network: Network,
    pub now: i64,
}

pub struct SyncVerdict {
    pub status: String,
    pub manifest: Vec<u8>,
    pub tip_header: Vec<u8>,
    /// The summary line printed for scripts (`{"status":..., "session":...}`
    /// without the session folder, which the caller adds).
    pub report: Map<String, Value>,
}

/// Every refusal of the sync step; PASS needs a fresh tip and two caught-up peers.
pub fn sync_verdict(r: &SyncRun) -> Result<SyncVerdict, String> {
    let kv = kv_lines(r.stdout);
    let get = |k: &str| kv.get(k).map(String::as_str);
    if r.exit_code != 0 || get("HEADER_SYNC") != Some("PASS") {
        return Err("header sync failed".into());
    }
    let ok: u64 = get("HEADER_SYNC_PEERS_OK")
        .unwrap_or("0/0")
        .split('/')
        .next()
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    if ok < 2 {
        return Err("fewer than two peers succeeded".into());
    }
    if get("HEADER_SYNC_NETWORK_DIFFICULTY_UNCHECKED_NO_HISTORY") != Some("0") {
        return Err("network difficulty not checked for all headers".into());
    }
    let common = get("HEADER_SYNC_COMMON_HEADERS").unwrap_or("");
    if common != "AGREE_FULL_BYTES" && !common.starts_with("MOST_WORK_CHOSEN") {
        return Err("peer chains were not compared".into());
    }
    let rejected: Vec<&str> = r
        .stdout
        .lines()
        .filter_map(|l| l.strip_prefix("HEADER_SYNC_FORK_REJECTED="))
        .collect();
    let nets: u64 = get("HEADER_SYNC_INDEPENDENT_NETS")
        .and_then(|x| x.split_whitespace().next())
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    let snapshot: Option<Map<String, Value>> = r
        .stdout
        .lines()
        .find(|l| l.starts_with("HEADER_SYNC_SNAPSHOT height="))
        .map(|l| {
            l.split(' ')
                .skip(1)
                .take(2)
                .filter_map(|x| x.split_once('='))
                .map(|(k, v)| (k.to_string(), json!(v)))
                .collect()
        });
    let headers: Vec<&str> = r.checkpoint_out.lines().filter_map(|l| l.strip_prefix("header ")).collect();
    if headers.len() != 1 {
        return Err("sync output checkpoint malformed".into());
    }
    let raw = hex_bytes(headers[0]).ok_or("sync output checkpoint malformed")?;
    if !(1..=604_800).contains(&r.max_tip_age_sec) {
        return Err("max tip age must be 1..604800 seconds".into());
    }
    let (fresh, age) = header_age(&raw, r.max_tip_age_sec, r.now)?;
    let caught_up: u64 = get("HEADER_SYNC_CAUGHT_UP_PEERS").and_then(|x| x.parse().ok()).unwrap_or(0);
    let status = if fresh == Freshness::Fresh && caught_up >= 2 { "PASS" } else { "PARTIAL" };
    if r.transcript.len() as u64 > TRANSCRIPT_LIMIT {
        return Err("verified transcript too large".into());
    }
    let tip_height: u64 = get("HEADER_SYNC_LAST_HEIGHT")
        .and_then(|x| x.parse().ok())
        .ok_or("HEADER_SYNC_LAST_HEIGHT missing")?;
    // The transcript must end in the checkpoint's header: the manifest pins both.
    let trs = decode_transcript(r.transcript)?;
    let (last_h, last_raw) = trs.last().ok_or("empty transcript")?;
    if *last_h != tip_height || *last_raw != raw {
        return Err("transcript tip differs from the sync checkpoint".into());
    }
    let header_hash = sha256_hex(&raw);
    let manifest = Manifest {
        transcript_sha256: sha256_hex(r.transcript),
        tip_header_sha256: header_hash.clone(),
        tip_height,
        sync_status: status.into(),
        max_tip_age_sec: r.max_tip_age_sec,
        network: r.network,
        checkpoint_sha256: Some(sha256_hex(r.checkpoint_in)),
        history_sha256: Some(sha256_hex(r.history_in)),
    }
    .to_bytes();
    let mut report = Map::new();
    report.insert("status".into(), json!(status));
    report.insert("height".into(), json!(tip_height));
    report.insert("full_header_sha256".into(), json!(header_hash));
    report.insert("manifest_sha256".into(), json!(sha256_hex(&manifest)));
    report.insert("difficulty_unchecked".into(), json!(0));
    report.insert(
        "peer_agreement".into(),
        json!(if rejected.is_empty() { "FULL_HEADER_AT_COMMON_HEIGHT" } else { "MOST_WORK_CHAIN" }),
    );
    report.insert("chain_support".into(), json!(get("HEADER_SYNC_CHAIN_SUPPORT")));
    report.insert("forks_rejected".into(), json!(rejected));
    report.insert("peers_caught_up_to_claims".into(), json!(caught_up));
    report.insert("tip_age_seconds".into(), json!(age));
    report.insert("freshness".into(), json!(fresh.as_str()));
    report.insert(
        "peer_independence".into(),
        json!(if nets >= 2 { format!("DISTINCT_NETS_{nets}") } else { "NOT_ESTABLISHED".into() }),
    );
    report.insert("independent_nets".into(), json!(get("HEADER_SYNC_INDEPENDENT_NETS")));
    report.insert(
        "canonical_tip".into(),
        json!(if nets >= 2 { "MOST_WORK_OF_INDEPENDENT_PEERS" } else { "NOT_PROVEN" }),
    );
    report.insert("tip_hash_is_trust_anchor".into(), json!(false));
    report.insert("checkpoint_trust".into(), json!("EXTERNALLY_PINNED_FILES"));
    report.insert(
        "work_ratio".into(),
        json!(get("HEADER_SYNC_WORK_RATIO").unwrap_or("").split(' ').next().unwrap_or("")),
    );
    report.insert("snapshot".into(), snapshot.map(Value::Object).unwrap_or(Value::Null));
    Ok(SyncVerdict { status: status.into(), manifest, tip_header: raw, report })
}

/// Absolute, `.`/`..` removed, symlinks of the existing part resolved.
pub fn resolve_path(p: &Path) -> Result<PathBuf, String> {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().map_err(|e| e.to_string())?.join(p)
    };
    let mut lexical = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::ParentDir => {
                lexical.pop();
            }
            Component::CurDir => {}
            other => lexical.push(other.as_os_str()),
        }
    }
    // Canonicalize the longest existing prefix, keep the rest as is.
    let mut existing = lexical.clone();
    let mut rest = Vec::new();
    while !existing.exists() {
        match existing.file_name() {
            Some(n) => rest.push(n.to_os_string()),
            None => break,
        }
        if !existing.pop() {
            break;
        }
    }
    let mut out = std::fs::canonicalize(&existing).map(strip_verbatim).unwrap_or(existing);
    for n in rest.into_iter().rev() {
        out.push(n);
    }
    Ok(out)
}

/// Windows canonical paths start with `\\?\`; plain `C:\...` reads better in
/// logs and works for every tool. UNC and other verbatim forms stay as they are.
fn strip_verbatim(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => p,
    }
}

pub fn inside(root: &Path, p: &Path) -> Result<PathBuf, String> {
    let r = resolve_path(root)?;
    let x = resolve_path(p)?;
    if x.starts_with(&r) {
        Ok(x)
    } else {
        Err(format!("{} must be inside GrinSight", p.display()))
    }
}

/// What the user asked of `gap`. Paths are as given (checked in [`plan_gap`]).
#[derive(Clone, Debug, Default)]
pub struct GapRequest {
    pub mainnet: bool,
    pub allow_mainnet_spend: bool,
    pub commitments: Vec<String>,
    pub kernels: Vec<String>,
    pub check_blocks: Vec<String>,
    pub archive_height: Option<u64>,
    pub state_dir: Option<PathBuf>,
    pub seeds: Option<PathBuf>,
    pub wallet_out: Option<PathBuf>,
    pub wallet_in: Option<PathBuf>,
    pub pending: Option<PathBuf>,
    pub spend: Option<String>,
    pub broadcast: bool,
    pub tx_out: Option<PathBuf>,
    pub send_to: Option<String>,
    pub send_amount: Option<u64>,
    pub pay_invoice: Option<PathBuf>,
    pub slatepack_out: Option<PathBuf>,
    pub context_out: Option<PathBuf>,
    pub blocks_all_peers: bool,
    /// Live peers, already checked by [`distinct_peers`].
    pub peers: Vec<String>,
    pub replay: Option<String>,
    pub prove: bool,
    pub save_bundle: Option<PathBuf>,
    pub segment_height: u32,
    pub max_msgs_per_min: u32,
    pub timeout_sec: u64,
}

impl GapRequest {
    pub fn new() -> GapRequest {
        GapRequest { segment_height: 11, max_msgs_per_min: 400, timeout_sec: 3600, ..Default::default() }
    }
}

#[derive(Debug)]
pub struct GapPlan {
    /// Arguments for `reverse-wtema-header-sync` (without the program).
    pub args: Vec<String>,
    /// Content of the `--gap-headers` file.
    pub headers_file: Vec<u8>,
    pub archive: u64,
}

fn opt(a: &mut Vec<String>, flag: &str, v: &Option<PathBuf>) {
    if let Some(v) = v {
        a.extend([flag.to_string(), v.display().to_string()]);
    }
}

fn is_check_block(s: &str) -> bool {
    match s.split_once(':') {
        Some((h, x)) => {
            (1..=12).contains(&h.len())
                && h.bytes().all(|c| c.is_ascii_digit())
                && x.len() == 64
                && x.bytes().all(|c| c.is_ascii_hexdigit())
        }
        None => false,
    }
}

/// Every check of `gap` before the child starts (no side effects).
/// `headers_path` is where the caller will write [`GapPlan::headers_file`].
pub fn plan_gap(s: &Session, r: &GapRequest, root: &Path, headers_path: &Path, now: i64) -> Result<GapPlan, String> {
    let network = if r.mainnet { Network::Mainnet } else { Network::Floonet };
    if s.manifest.network != network {
        return Err(format!(
            "session network {} differs from requested {}",
            s.manifest.network.as_str(),
            network.as_str()
        ));
    }
    let tip = s.tip_height();
    let archive = r.archive_height.unwrap_or_else(|| default_archive(tip));
    if archive >= tip {
        return Err("archive height must be below the session tip".into());
    }
    if r.prove && archive % 720 != 0 {
        return Err("--prove needs a 720-block archive boundary".into());
    }
    if s.header_at(archive).is_none() {
        return Err("archive height not present in validated session".into());
    }
    // The gap step needs headers from where it starts: the saved state (if it
    // is lower than the archive) or the archive, plus any block it is asked
    // to check. Not the whole range from the checkpoint: that made an old
    // shipped checkpoint (or a wallet not opened for weeks) exceed the limit.
    let mut floor = archive;
    if let Some(d) = &r.state_dir {
        let dir = if d.is_absolute() { d.clone() } else { root.join(d) };
        for name in ["state.ust", "state.prev.ust"] {
            if let Some(h) = crate::outputs::saved_state_height(&dir.join(name)) {
                floor = floor.min(h);
            }
        }
    }
    for cb in &r.check_blocks {
        if let Some(h) = cb.split_once(':').and_then(|(h, _)| h.parse::<u64>().ok()) {
            floor = floor.min(h);
        }
    }
    let pick = |floor: u64| -> Vec<&[u8]> { s.headers.iter().filter(|(h, _)| *h >= floor).map(|(_, x)| x.as_slice()).collect() };
    let mut selected = pick(floor);
    let mut start = floor;
    if selected.len() > MAX_GAP_HEADERS && floor < archive {
        // The saved state (or a checked block) is too far back: start from the
        // archive instead. The gap step then sees the old state as not linked
        // and rebuilds it from the archive (slower, same proof).
        selected = pick(archive);
        start = archive;
    }
    if selected.len() > MAX_GAP_HEADERS {
        return Err(format!("{} headers from the archive to the tip (more than {MAX_GAP_HEADERS})", selected.len()));
    }
    // Coinbase maturity (grin `verify_coinbase_maturity`) needs, for a block
    // at height H, the header at H - 1440: also pass the 1440 headers below
    // the start (as many as the session has; the gap step fails closed if a
    // coinbase spend needs one it was not given).
    selected = pick(start.saturating_sub(crate::balance::COINBASE_MATURITY));
    if !(1..=7200).contains(&r.timeout_sec) {
        return Err("timeout must be 1..7200 seconds".into());
    }
    if r.commitments.is_empty() {
        return Err("at least one --commitment is required".into());
    }
    if r.commitments.len() > MAX_COMMITMENTS {
        return Err("at most 64 commitments per run".into());
    }
    if r.peers.is_empty() == r.replay.is_none() {
        return Err("exactly one of --peer and --replay".into());
    }
    let state_dir = match &r.state_dir {
        Some(d) => {
            if !r.prove {
                return Err("--state-dir needs --prove".into());
            }
            Some(inside(root, d)?)
        }
        None => None,
    };
    let bundle = match &r.save_bundle {
        Some(b) => {
            let t = inside(root, b)?;
            if t.exists() {
                return Err("save-bundle target exists".into());
            }
            Some(t)
        }
        None => None,
    };
    let chk = |p: &Option<PathBuf>| -> Result<Option<PathBuf>, String> { p.as_ref().map(|x| inside(root, x)).transpose() };
    let wallet_out = chk(&r.wallet_out)?;
    let tx_out = chk(&r.tx_out)?;
    let wallet_in = chk(&r.wallet_in)?;
    let pending = chk(&r.pending)?;
    let slatepack_out = chk(&r.slatepack_out)?;
    let context_out = chk(&r.context_out)?;
    if let Some(seeds) = &r.seeds {
        if !r.prove {
            return Err("--seeds needs --prove".into());
        }
        if r.peers.is_empty() {
            return Err("--seeds needs live --peer".into());
        }
        if seeds.as_os_str() != "-" && !seeds.is_file() {
            return Err("seed file not found".into());
        }
    }
    if r.pay_invoice.is_some() && !(r.spend.is_some() && r.slatepack_out.is_some()) {
        return Err("--pay-invoice needs --spend auto:N and --slatepack-out".into());
    }
    if r.send_to.is_some()
        && !(r.spend.is_some() && r.send_amount.is_some() && r.slatepack_out.is_some() && r.context_out.is_some())
    {
        return Err("--send-to needs --spend auto:N, --send-amount, --slatepack-out, --context-out".into());
    }
    let moves_money = r.spend.is_some() || r.broadcast;
    if moves_money && r.seeds.is_none() {
        return Err("--spend/--broadcast need --seeds".into());
    }
    if r.mainnet && r.spend.is_some() && !r.allow_mainnet_spend {
        return Err("spending on mainnet needs --allow-mainnet-spend".into());
    }
    if moves_money {
        s.spend_gate(now)?;
    }
    for b in &r.check_blocks {
        if !is_check_block(b) {
            return Err("--check-block must be HEIGHT:HASH".into());
        }
    }

    let p = |x: &Path| x.display().to_string();
    let mut a: Vec<String> = vec!["--gap-headers".into(), p(headers_path), "--gap-archive".into(), archive.to_string()];
    if r.mainnet {
        a.push("--mainnet".into());
    }
    if r.allow_mainnet_spend {
        a.push("--allow-mainnet-spend".into());
    }
    for c in &r.commitments {
        a.extend(["--commitment".into(), c.clone()]);
    }
    for k in &r.kernels {
        a.extend(["--gap-kernel".into(), k.clone()]);
    }
    for b in &r.check_blocks {
        a.extend(["--gap-check-block".into(), b.clone()]);
    }
    if r.blocks_all_peers {
        a.push("--gap-blocks-all-peers".into());
    }
    opt(&mut a, "--gap-state", &state_dir);
    if let Some(rp) = &r.replay {
        a.extend(["--gap-replay".into(), rp.clone()]);
    }
    // `-`: phrases on standard input (wallet service), passed on unchanged.
    let seeds = r.seeds.as_ref().map(|x| if x.as_os_str() == "-" { Ok(x.clone()) } else { resolve_path(x) }).transpose()?;
    opt(&mut a, "--gap-seeds", &seeds);
    opt(&mut a, "--gap-wallet-out", &wallet_out);
    opt(&mut a, "--gap-wallet-in", &wallet_in);
    opt(&mut a, "--gap-pending", &pending);
    if let Some(sp) = &r.spend {
        a.extend(["--gap-spend".into(), sp.clone()]);
    }
    if r.broadcast {
        a.push("--gap-broadcast".into());
    }
    opt(&mut a, "--gap-tx-out", &tx_out);
    if let (Some(to), Some(amount)) = (&r.send_to, r.send_amount) {
        a.extend(["--gap-send-to".into(), to.clone(), "--gap-send-amount".into(), amount.to_string()]);
    }
    let invoice = r.pay_invoice.as_ref().map(|x| resolve_path(x)).transpose()?;
    if let Some(i) = &invoice {
        a.extend(["--gap-pay-invoice".into(), p(i)]);
    }
    if let Some(v) = &slatepack_out {
        a.extend(["--gap-slatepack-out".into(), p(v)]);
    }
    if let Some(v) = &context_out {
        a.extend(["--gap-context-out".into(), p(v)]);
    }
    for peer in &r.peers {
        a.extend(["--peer".into(), peer.clone()]);
    }
    if r.prove {
        a.push("--prove".into());
    }
    if let Some(b) = &bundle {
        a.extend(["--gap-out".into(), p(b)]);
    }
    a.extend([
        "--segment-height".into(),
        r.segment_height.to_string(),
        "--max-msgs-per-min".into(),
        r.max_msgs_per_min.to_string(),
    ]);
    Ok(GapPlan { args: a, headers_file: encode_transcript(selected), archive })
}

/// Lines printed after `gap`: is the result the state at the verified tip?
pub fn gap_report(s: &Session, stdout: &str, exit_code: i32, now: i64) -> String {
    let kv = kv_lines(stdout);
    let verdict = kv.get("GAP_PROVE_VERDICT").map(String::as_str).unwrap_or("");
    let proven = matches!(
        verdict,
        "UNSPENT_AT_TIP" | "CREATED_IN_GAP_UNSPENT_AT_TIP" | "SPENT_IN_GAP" | "NOT_IN_UTXO_AT_TIP"
    ) || verdict.starts_with("MULTI");
    let (f, _) = s.freshness(now);
    let current = proven && matches!(exit_code, 0 | 3 | 5) && s.manifest.is_pass() && f == Freshness::Fresh;
    format!(
        "HEADER_AUTHENTICATION=SESSION_SHA256_PINNED\nVERIFIED_SESSION_TIP_HEIGHT={}\nSESSION_SYNC_STATUS={}\nSESSION_TIP_FRESHNESS={}\nCURRENT_TIP_STATE={}\nCANONICAL_TIP=NOT_PROVEN\nPEER_INDEPENDENCE=NOT_ESTABLISHED\n",
        s.tip_height(),
        s.manifest.sync_status,
        f.as_str(),
        if current { "AT_VERIFIED_TIP_ONLY" } else { "NOT_PROVEN" }
    )
}

/// Lines printed after `verify-state --session` for the proof at `height`.
pub fn state_report(s: &Session, height: u64, exit_code: i32, now: i64) -> String {
    let at_tip = height == s.tip_height();
    let header = s.header_at(height).unwrap_or(s.tip_header());
    let (f, _) = header_age(header, s.manifest.max_tip_age_sec, now).unwrap_or((Freshness::StaleOrFuture, 0));
    let current = matches!(exit_code, 0 | 5) && at_tip && s.manifest.is_pass() && f == Freshness::Fresh;
    format!(
        "VERIFIED_SESSION_TIP_HEIGHT={}\nPROOF_HEADER_HEIGHT={height}\nSESSION_TIP_FRESHNESS={}\nCURRENT_TIP_STATE={}\nCANONICAL_TIP=NOT_PROVEN\n",
        s.tip_height(),
        if at_tip { f.as_str() } else { "NOT_CHECKED" },
        if current { "AT_VERIFIED_TIP_ONLY" } else { "NOT_PROVEN" }
    )
}

/// Heights `pibd` tries when none is given: the default archive and one before.
pub fn pibd_heights(tip: u64, requested: Option<u64>) -> Result<Vec<u64>, String> {
    let hs = match requested {
        Some(h) => vec![h],
        None => {
            let a = default_archive(tip);
            vec![a, a.saturating_sub(720)]
        }
    };
    for &h in &hs {
        if h % 720 != 0 || h.saturating_add(2880) > tip {
            return Err("archive height must be a 720-block boundary at least 2880 blocks behind session tip".into());
        }
    }
    Ok(hs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const NOW: i64 = 1_800_000_000;

    fn header(height: u64, ts: i64) -> Vec<u8> {
        let mut h = 5u16.to_be_bytes().to_vec();
        h.extend(height.to_be_bytes());
        h.extend(ts.to_be_bytes());
        h.extend([0u8; 16]);
        h
    }

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tmp(name: &str) -> Tmp {
        let d = std::env::temp_dir().join(format!("grinsight-session-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Tmp(resolve_path(&d).unwrap())
    }

    /// Writes a session folder like the Python tests did; returns the pin.
    fn session(dir: &Path, first: u64, last: u64, status: &str, age: i64, network: Option<&str>) -> String {
        let hs: Vec<Vec<u8>> = (first..=last).map(|h| header(h, NOW - age - (last - h) as i64 * 60)).collect();
        let raw = encode_transcript(hs.iter().map(Vec::as_slice));
        std::fs::write(dir.join(TRANSCRIPT_FILE), &raw).unwrap();
        let mut m = json!({"version":1,"transcript_sha256":sha256_hex(&raw),"tip_header_sha256":sha256_hex(hs.last().unwrap()),"tip_height":last,"sync_status":status,"max_tip_age_sec":10800});
        if let Some(n) = network {
            m["network"] = json!(n);
        }
        let data = m.to_string().into_bytes();
        std::fs::write(dir.join(MANIFEST_FILE), &data).unwrap();
        sha256_hex(&data)
    }

    fn req(peers: bool) -> GapRequest {
        let mut r = GapRequest::new();
        r.commitments = vec![format!("09{}", "00".repeat(32))];
        r.prove = true;
        r.timeout_sec = 60;
        if peers {
            r.peers = vec!["192.0.2.1:13414".into(), "192.0.2.2:13414".into()];
        }
        r
    }

    #[test]
    fn sync_exit_is_fail_closed() {
        assert_eq!(sync_exit_code("PASS"), 0);
        assert_eq!(sync_exit_code("PARTIAL"), 3);
        assert_eq!(sync_exit_code("unknown"), 3);
    }

    #[test]
    fn duplicate_resolved_ip_rejected() {
        let same = |_: &str, _: u16| Ok(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]);
        assert!(distinct_peers(&["first:1".into(), "other:2".into()], same).is_err());
        // IPv4-mapped IPv6 is the same address.
        let mut n = 0;
        let mixed = |_: &str, _: u16| {
            n += 1;
            Ok(vec![if n == 1 {
                "192.0.2.1".parse().unwrap()
            } else {
                "::ffff:192.0.2.1".parse().unwrap()
            }])
        };
        assert!(distinct_peers(&["a:1".into(), "b:1".into()], mixed).is_err());
        let fine = |h: &str, _: u16| Ok(vec![h.parse().unwrap()]);
        assert_eq!(
            distinct_peers(&["10.0.0.1:1".into(), "[2001:db8::1]:2".into()], fine).unwrap(),
            vec!["10.0.0.1:1".to_string(), "[2001:db8::1]:2".to_string()]
        );
        assert!(distinct_peers(&["10.0.0.1:1".into()], fine).is_err(), "one peer is not enough");
        for bad in ["nohost", ":1", "h:", "h:0", "h:65536", "h:x1", "[::1]1"] {
            assert!(split_peer(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn freshness_boundaries() {
        let at = |t: i64| {
            let mut h = vec![0u8; 10];
            h.extend(t.to_be_bytes());
            header_age(&h, 10800, 10000).unwrap().0
        };
        assert_eq!(at(9000), Freshness::Fresh);
        assert_eq!(at(10000 - 10800), Freshness::Fresh);
        assert_eq!(at(10000 - 10801), Freshness::StaleOrFuture);
        assert_eq!(at(10000 + 720), Freshness::Fresh);
        assert_eq!(at(10000 + 721), Freshness::StaleOrFuture);
        assert_eq!(at(-1000), Freshness::StaleOrFuture);
        assert!(header_age(&[0u8; 17], 10800, 0).is_err());
    }

    #[test]
    fn manifest_bytes_match_the_python_tool() {
        // json.dumps(manifest, sort_keys=True, separators=(',',':')) from grinsight.py
        let py = br#"{"checkpoint_sha256":"aa","history_sha256":"bb","max_tip_age_sec":10800,"network":"MAINNET","sync_status":"PASS","tip_header_sha256":"cc","tip_height":3331844,"transcript_sha256":"dd","version":1}"#;
        let m = Manifest::parse(py).unwrap();
        assert_eq!(m.to_bytes(), py.to_vec());
        assert!(Manifest::parse(br#"{"version":2,"transcript_sha256":"a","tip_header_sha256":"b","tip_height":1}"#).is_err());
        assert!(Manifest::parse(br#"{"version":1,"transcript_sha256":"a","tip_header_sha256":"b","tip_height":1,"network":"X"}"#).is_err());
    }

    #[test]
    fn session_open_checks_every_pin() {
        let t = tmp("open");
        let d = &t.0;
        let pin = session(d, 100, 110, "PASS", 0, None);
        let s = Session::open(d, &pin).unwrap();
        assert_eq!(s.tip_height(), 110);
        assert_eq!(header_height(s.header_at(105).unwrap()).unwrap(), 105);
        assert!(s.header_at(99).is_none() && s.header_at(111).is_none());
        assert!(Session::open(d, &"00".repeat(32)).is_err(), "wrong manifest pin");
        // Transcript changed after the manifest was written.
        let mut raw = std::fs::read(d.join(TRANSCRIPT_FILE)).unwrap();
        let n = raw.len();
        raw[n - 1] ^= 1;
        std::fs::write(d.join(TRANSCRIPT_FILE), &raw).unwrap();
        assert!(Session::open(d, &pin).is_err());
        // Gap in heights.
        let hs = [header(1, NOW), header(3, NOW)];
        assert!(decode_transcript(&encode_transcript(hs.iter().map(Vec::as_slice))).is_err());
        // Trailing bytes.
        let mut x = encode_transcript([header(1, NOW).as_slice()]);
        x.push(0);
        assert!(decode_transcript(&x).is_err());
    }

    #[test]
    fn default_archive_and_header_slice() {
        let t = tmp("slice");
        let d = &t.0;
        let pin = session(d, 3326000, 3330478, "PASS", 0, None);
        let s = Session::open(d, &pin).unwrap();
        let plan = plan_gap(&s, &req(true), d, &d.join("h.bin"), NOW).unwrap();
        assert_eq!(plan.archive, 3327120);
        let hs = decode_transcript(&plan.headers_file).unwrap();
        // From the archive, plus the 1440 headers below it that coinbase
        // maturity needs (as many as the session has: it starts at 3326000).
        assert_eq!(hs.len() as u64, 3330478 - 3326000 + 1);
        assert_eq!(hs[0].0, 3326000);
        assert!(plan.args.contains(&"--prove".to_string()));
        let report = gap_report(&s, "GAP_PROVE_VERDICT=UNSPENT_AT_TIP\n", 0, NOW);
        assert!(report.contains("CURRENT_TIP_STATE=AT_VERIFIED_TIP_ONLY"));
    }

    #[test]
    fn current_state_needs_proof_pass_and_freshness() {
        let t = tmp("current");
        let d = &t.0;
        for (status, age, out, code) in [
            ("PASS", 0, "GAP_SCAN_VERDICT=NO_SPEND_SEEN_HINT\n", 0),
            ("PARTIAL", 0, "GAP_PROVE_VERDICT=UNSPENT_AT_TIP\n", 0),
            ("PASS", 20000, "GAP_PROVE_VERDICT=UNSPENT_AT_TIP\n", 0),
            ("PASS", 0, "GAP_PROVE_VERDICT=NO_VALID_BODIES\n", 1),
            ("PASS", 0, "GAP_PROVE_VERDICT=UNSPENT_AT_TIP\n", 1),
        ] {
            let pin = session(d, 3326000, 3330478, status, age, None);
            let s = Session::open(d, &pin).unwrap();
            assert!(gap_report(&s, out, code, NOW).contains("CURRENT_TIP_STATE=NOT_PROVEN"), "{status} {age} {out}");
        }
        let pin = session(d, 3326000, 3330478, "PASS", 0, None);
        let s = Session::open(d, &pin).unwrap();
        assert!(gap_report(&s, "GAP_PROVE_VERDICT=SPENT_IN_GAP\n", 5, NOW).contains("AT_VERIFIED_TIP_ONLY"));
        assert!(gap_report(&s, "GAP_PROVE_VERDICT=MULTI worst_exit=3\n", 3, NOW).contains("AT_VERIFIED_TIP_ONLY"));
        // verify-state: only a successful proof AT the fresh PASS tip.
        assert!(state_report(&s, 3330478, 0, NOW).contains("AT_VERIFIED_TIP_ONLY"));
        assert!(state_report(&s, 3330478, 5, NOW).contains("AT_VERIFIED_TIP_ONLY"));
        for (h, c) in [(3330478, 1), (3330478, 3), (3330000, 0)] {
            assert!(state_report(&s, h, c, NOW).contains("CURRENT_TIP_STATE=NOT_PROVEN"), "{h} {c}");
        }
        assert!(state_report(&s, 3330000, 0, NOW).contains("SESSION_TIP_FRESHNESS=NOT_CHECKED"));
    }

    #[test]
    fn rejections() {
        let t = tmp("reject");
        let d = &t.0;
        let pin = session(d, 3328000, 3330478, "PASS", 0, None);
        let s = Session::open(d, &pin).unwrap();
        let seeds = d.join("seeds.txt");
        std::fs::write(&seeds, "# none\n").unwrap();
        let h = d.join("h.bin");
        let outside = std::env::temp_dir().join("grinsight-outside-x");
        let try_ = |f: &dyn Fn(&mut GapRequest)| {
            let mut r = req(true);
            r.archive_height = Some(3328560);
            f(&mut r);
            plan_gap(&s, &r, d, &h, NOW)
        };
        assert_eq!(try_(&|_| {}).err(), None);
        assert!(plan_gap(&s, &req(true), d, &h, NOW).is_err(), "default archive before the transcript");
        assert!(try_(&|r| r.archive_height = Some(3328001)).is_err(), "not a 720 boundary");
        assert!(try_(&|r| r.archive_height = Some(3330478)).is_err(), "archive at tip");
        assert!(try_(&|r| r.save_bundle = Some(outside.join("x.ugb"))).is_err());
        assert!(try_(&|r| r.save_bundle = Some(d.join("../../escape.ugb"))).is_err());
        assert!(try_(&|r| r.save_bundle = Some(d.join(MANIFEST_FILE))).is_err(), "bundle exists");
        assert!(try_(&|r| r.state_dir = Some(outside.join("st"))).is_err());
        assert!(try_(&|r| { r.prove = false; r.state_dir = Some(d.join("st")) }).is_err());
        assert!(try_(&|r| r.spend = Some("auto:1".into())).is_err(), "spend without seeds");
        assert!(try_(&|r| r.seeds = Some(d.join("nope.txt"))).is_err());
        assert!(try_(&|r| { r.seeds = Some(seeds.clone()); r.peers.clear(); r.replay = Some("x".into()) }).is_err());
        assert!(try_(&|r| r.mainnet = true).is_err(), "Floonet session as mainnet");
        assert!(try_(&|r| r.commitments = vec![format!("09{}", "00".repeat(32)); 65]).is_err());
        assert!(try_(&|r| r.commitments.clear()).is_err());
        assert!(try_(&|r| r.check_blocks = vec!["12:zz".into()]).is_err());
        assert!(try_(&|r| r.check_blocks = vec![format!("12:{}", "a".repeat(64))]).is_ok());
        assert!(try_(&|r| r.timeout_sec = 0).is_err());
        assert!(try_(&|r| r.peers.clear()).is_err(), "neither peers nor replay");
        assert!(try_(&|r| r.replay = Some("x".into())).is_err(), "both peers and replay");
        assert!(try_(&|r| { r.seeds = Some(seeds.clone()); r.pay_invoice = Some(d.join("i1.txt")) }).is_err());
        assert!(try_(&|r| { r.seeds = Some(seeds.clone()); r.send_to = Some("grin1x".into()); r.spend = Some("auto:1".into()) }).is_err());
        // Mainnet session: spend needs the explicit flag.
        let t2 = tmp("reject-main");
        let pin2 = session(&t2.0, 3328000, 3330478, "PASS", 0, Some("MAINNET"));
        let s2 = Session::open(&t2.0, &pin2).unwrap();
        let seeds2 = t2.0.join("seeds.txt");
        std::fs::write(&seeds2, "#\n").unwrap();
        let mut r = req(true);
        r.archive_height = Some(3328560);
        r.mainnet = true;
        r.seeds = Some(seeds2);
        r.spend = Some("auto".into());
        assert!(plan_gap(&s2, &r, &t2.0, &h, NOW).unwrap_err().contains("allow-mainnet-spend"));
        r.allow_mainnet_spend = true;
        assert!(plan_gap(&s2, &r, &t2.0, &t2.0.join("h"), NOW).is_ok());
    }

    #[test]
    fn spend_refused_on_partial_or_stale_session() {
        let t = tmp("spend");
        let d = &t.0;
        let seeds = d.join("seeds.txt");
        std::fs::write(&seeds, "# none\n").unwrap();
        for (status, age) in [("PARTIAL", 0), ("PASS", 20000), ("PASS", -1000)] {
            let pin = session(d, 3326000, 3330478, status, age, None);
            let s = Session::open(d, &pin).unwrap();
            assert!(s.spend_gate(NOW).is_err());
            for spend in [true, false] {
                let mut r = req(true);
                r.seeds = Some(seeds.clone());
                if spend {
                    r.spend = Some("auto:1".into());
                } else {
                    r.broadcast = true;
                }
                assert!(plan_gap(&s, &r, d, &d.join("h"), NOW).is_err(), "{status} {age} {spend}");
            }
            let v: Value = serde_json::from_str(&s.summary_json(NOW)).unwrap();
            assert_eq!(v["can_spend"], json!(false));
        }
        let pin = session(d, 3326000, 3330478, "PASS", 0, None);
        let s = Session::open(d, &pin).unwrap();
        let mut r = req(true);
        r.seeds = Some(seeds);
        r.spend = Some("auto:1".into());
        let plan = plan_gap(&s, &r, d, &d.join("h"), NOW).unwrap();
        assert!(plan.args.contains(&"--gap-spend".to_string()));
        // The same session is refused once the tip ages past the limit.
        assert!(plan_gap(&s, &r, d, &d.join("h"), NOW + 10801).is_err());
        let v: Value = serde_json::from_str(&s.summary_json(NOW)).unwrap();
        assert_eq!(v["can_spend"], json!(true));
        assert_eq!(v["default_archive_height"], json!(3327120));
    }

    #[test]
    fn state_dir_passes_headers_from_saved_state_and_flags() {
        let t = tmp("statedir");
        let d = &t.0;
        let pin = session(d, 3326000, 3330478, "PASS", 0, None);
        let s = Session::open(d, &pin).unwrap();
        let mut r = req(true);
        r.state_dir = Some(d.join("st"));
        r.commitments.push(format!("08{}", "11".repeat(32)));
        r.kernels = vec![format!("09{}", "22".repeat(32))];
        // No saved state yet: from the archive (not the whole range since the checkpoint).
        let plan = plan_gap(&s, &r, d, &d.join("h"), NOW).unwrap();
        assert_eq!(decode_transcript(&plan.headers_file).unwrap()[0].0, 3327120 - 1120);
        // A saved state below the archive: from its height (only its first bytes are read).
        std::fs::create_dir_all(d.join("st")).unwrap();
        let mut ust = b"UST1".to_vec();
        ust.extend_from_slice(&300u32.to_le_bytes());
        ust.extend_from_slice(&1u16.to_be_bytes());
        ust.extend_from_slice(&3326500u64.to_be_bytes());
        std::fs::write(d.join("st").join("state.ust"), &ust).unwrap();
        assert_eq!(crate::outputs::saved_state_height(&d.join("st").join("state.ust")), Some(3326500));
        let plan = plan_gap(&s, &r, d, &d.join("h"), NOW).unwrap();
        let hs = decode_transcript(&plan.headers_file).unwrap();
        assert_eq!(hs[0].0, 3326000);
        assert_eq!(hs.len() as u64, 3330478 - 3326000 + 1);
        let a = &plan.args;
        let after = |f: &str| a[a.iter().position(|x| x == f).unwrap() + 1].clone();
        assert_eq!(after("--gap-archive"), "3327120");
        assert_eq!(after("--gap-state"), d.join("st").display().to_string());
        assert_eq!(after("--gap-kernel"), format!("09{}", "22".repeat(32)));
        assert_eq!(a.iter().filter(|x| *x == "--commitment").count(), 2);
    }

    #[test]
    fn sync_verdict_pass_partial_and_refusals() {
        let tipraw = header(500, NOW - 100);
        let hs = [header(499, NOW - 160), tipraw.clone()];
        let transcript = encode_transcript(hs.iter().map(Vec::as_slice));
        let cp = format!("version 1\nheader {}\n", tipraw.iter().map(|b| format!("{b:02x}")).collect::<String>());
        let good = "HEADER_SYNC=PASS\nHEADER_SYNC_PEERS_OK=2/2\nHEADER_SYNC_NETWORK_DIFFICULTY_UNCHECKED_NO_HISTORY=0\nHEADER_SYNC_COMMON_HEADERS=AGREE_FULL_BYTES\nHEADER_SYNC_INDEPENDENT_NETS=2 (a,b)\nHEADER_SYNC_CAUGHT_UP_PEERS=2\nHEADER_SYNC_LAST_HEIGHT=500\n";
        let run = |stdout: &str, code: i32, now: i64| {
            sync_verdict(&SyncRun {
                stdout,
                exit_code: code,
                checkpoint_out: &cp,
                transcript: &transcript,
                checkpoint_in: b"cp",
                history_in: b"hi",
                max_tip_age_sec: 10800,
                network: Network::Mainnet,
                now,
            })
        };
        let v = run(good, 0, NOW).unwrap();
        assert_eq!(v.status, "PASS");
        let m = Manifest::parse(&v.manifest).unwrap();
        assert_eq!((m.tip_height, m.network, m.is_pass()), (500, Network::Mainnet, true));
        assert_eq!(m.transcript_sha256, sha256_hex(&transcript));
        assert_eq!(v.report["manifest_sha256"], json!(sha256_hex(&v.manifest)));
        assert_eq!(v.report["peer_independence"], json!("DISTINCT_NETS_2"));
        assert_eq!(run(good, 0, NOW + 20000).unwrap().status, "PARTIAL", "stale tip");
        assert_eq!(run(&good.replace("CAUGHT_UP_PEERS=2", "CAUGHT_UP_PEERS=1"), 0, NOW).unwrap().status, "PARTIAL");
        assert!(run(good, 1, NOW).is_err());
        assert!(run(&good.replace("HEADER_SYNC=PASS", "HEADER_SYNC=FAIL"), 0, NOW).is_err());
        assert!(run(&good.replace("PEERS_OK=2/2", "PEERS_OK=1/2"), 0, NOW).is_err());
        assert!(run(&good.replace("NO_HISTORY=0", "NO_HISTORY=3"), 0, NOW).is_err());
        assert!(run(&good.replace("AGREE_FULL_BYTES", "NOT_COMPARED"), 0, NOW).is_err());
        assert!(run(&good.replace("LAST_HEIGHT=500", "LAST_HEIGHT=501"), 0, NOW).is_err(), "transcript tip mismatch");
    }

    #[test]
    fn seed_peers_dedup_and_order() {
        let a: Vec<IpAddr> = vec!["2001:db8::1".parse().unwrap(), "10.0.0.1".parse().unwrap()];
        let b: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
        assert_eq!(
            seed_peers(&[a.clone(), b.clone()], 3414, 40),
            vec!["10.0.0.1:3414", "10.0.0.2:3414", "[2001:db8::1]:3414"]
        );
        assert_eq!(seed_peers(&[a, b], 3414, 1).len(), 1);
    }

    #[test]
    fn pibd_heights_rules() {
        assert_eq!(pibd_heights(3330478, None).unwrap(), vec![3327120, 3326400]);
        assert!(pibd_heights(3330478, Some(3327121)).is_err());
        assert!(pibd_heights(3330478, Some(3328560)).is_err(), "less than 2880 behind");
        assert!(pibd_heights(1000, None).is_err(), "chain shorter than 2880 blocks");
    }
}
