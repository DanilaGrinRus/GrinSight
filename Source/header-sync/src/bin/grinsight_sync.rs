//! `grinsight`: the research command line (was `grinsight.py`).
//!
//! Explicit checkpoint pins, no automatic trust bootstrap. All decisions live
//! in `grinsight_state::session`; this file only parses arguments, starts the
//! verifying binary (`reverse-wtema-header-sync`, same folder) and prints.
//!
//!   grinsight sync --checkpoint F --checkpoint-sha256 H --history F --history-sha256 H
//!              --peer A:P --peer B:P [...] [--mainnet] [--batches N] [--timeout S]
//!              [--max-tip-age-sec S] [--snapshot-at H --snapshot-dir D]
//!   grinsight gap --session D --session-sha256 H --commitment C [...] (--peer A:P ... | --replay F)
//!             [--prove] [--state-dir D] [--seeds F] [--wallet-in F] [--wallet-out F] [--pending F]
//!             [--spend auto:N|C] [--broadcast] [--tx-out F] [--send-to A --send-amount NANO]
//!             [--pay-invoice F] [--slatepack-out F] [--context-out F] [--kernel K ...]
//!             [--check-block H:HASH ...] [--blocks-all-peers] [--archive-height H]
//!             [--mainnet] [--allow-mainnet-spend] [--save-bundle F]
//!             [--segment-height N] [--max-msgs-per-min N] [--timeout S]
//!   grinsight pibd --session D --session-sha256 H --leaf-index N --commitment C
//!              (--peer A:P ... | --proof F) [--height H] [--save-proof F]
//!   grinsight verify-state --commitment C --proof F
//!              (--session D --session-sha256 H --height H | --header F --header-sha256 H)
//!   grinsight session --session D --session-sha256 H      (JSON summary: can the wallet spend now?)
//!   grinsight dns-seeds [--testnet] [--limit N]           (KNOWN_PEER=ip:port from the Grin DNS seeds)
//!
//! Exit codes are those of the verifying binary; 1 = refused (`VERDICT=FAIL_CLOSED`).

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use grinsight_state::session::{self as ss, GapRequest, Network, Session, SyncRun};

const MULTI: &[&str] = &["peer", "commitment", "kernel", "check-block"];
const FLAGS: &[&str] = &["mainnet", "prove", "broadcast", "blocks-all-peers", "allow-mainnet-spend", "allow-partial", "testnet"];

struct Args {
    one: HashMap<String, String>,
    many: HashMap<String, Vec<String>>,
    flags: Vec<String>,
}

impl Args {
    fn parse(v: &[String]) -> Result<Args, String> {
        let mut a = Args { one: HashMap::new(), many: HashMap::new(), flags: Vec::new() };
        let mut i = 0;
        while i < v.len() {
            let k = v[i].strip_prefix("--").ok_or_else(|| format!("unexpected argument {}", v[i]))?;
            if FLAGS.contains(&k) {
                a.flags.push(k.into());
                i += 1;
                continue;
            }
            let val = v.get(i + 1).ok_or_else(|| format!("--{k} needs a value"))?.clone();
            if MULTI.contains(&k) {
                a.many.entry(k.into()).or_default().push(val);
            } else if a.one.insert(k.into(), val).is_some() {
                return Err(format!("--{k} given twice"));
            }
            i += 2;
        }
        Ok(a)
    }
    /// A single value; a repeatable option given once counts too.
    fn get(&self, k: &str) -> Option<&str> {
        match (self.one.get(k), self.many.get(k)) {
            (Some(v), _) => Some(v),
            (None, Some(v)) if v.len() == 1 => Some(&v[0]),
            _ => None,
        }
    }
    fn req(&self, k: &str) -> Result<&str, String> {
        self.get(k).ok_or_else(|| format!("--{k} is required"))
    }
    fn path(&self, k: &str) -> Option<PathBuf> {
        self.get(k).map(PathBuf::from)
    }
    fn num<T: std::str::FromStr>(&self, k: &str, default: T) -> Result<T, String> {
        match self.get(k) {
            Some(x) => x.parse().map_err(|_| format!("--{k}: not a number")),
            None => Ok(default),
        }
    }
    fn list(&self, k: &str) -> Vec<String> {
        self.many.get(k).cloned().unwrap_or_default()
    }
    fn flag(&self, k: &str) -> bool {
        self.flags.iter().any(|f| f == k)
    }
    /// Refuses options this mode does not know (a typo must not be ignored).
    fn only(&self, allowed: &[&str]) -> Result<(), String> {
        let keys = self.one.keys().chain(self.many.keys()).chain(self.flags.iter());
        for k in keys {
            if !allowed.contains(&k.as_str()) {
                return Err(format!("--{k} is not an option of this mode"));
            }
        }
        Ok(())
    }
}

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn bin_dir() -> PathBuf {
    std::env::var_os("GRINSIGHT_BIN_DIR").map(PathBuf::from).unwrap_or_else(exe_dir)
}

fn binary(name: &str) -> PathBuf {
    bin_dir().join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

/// The GrinSight folder: GRINSIGHT_ROOT, else the first ancestor of this program that
/// holds `header-sync` and `grinsight-state`, else the current folder.
fn root() -> PathBuf {
    if let Some(r) = std::env::var_os("GRINSIGHT_ROOT") {
        return PathBuf::from(r);
    }
    let mut d = exe_dir();
    loop {
        if d.join("header-sync").is_dir() && d.join("grinsight-state").is_dir() {
            return d;
        }
        if !d.pop() {
            return std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        }
    }
}

struct Done {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Starts the program directly (no shell), collects output, kills it on timeout.
fn run(program: &Path, args: &[String], timeout: Duration) -> Result<Done, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {e}", program.display()))?;
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let t1 = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = so.read_to_end(&mut s);
        s
    });
    let t2 = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = se.read_to_end(&mut s);
        s
    });
    let start = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            break st;
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err("timed out".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let stdout = String::from_utf8_lossy(&t1.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&t2.join().unwrap_or_default()).into_owned();
    Ok(Done { code: status.code().unwrap_or(1), stdout, stderr })
}

/// New, empty folder `<parent>/<prefix>XXXXXXXX` (created exclusively).
fn fresh_dir(parent: &Path, prefix: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    for n in 0..1000u32 {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let p = parent.join(format!("{prefix}{:08x}", t ^ std::process::id().rotate_left(16) ^ n.wrapping_mul(0x9e37_79b9)));
        match std::fs::create_dir(&p) {
            Ok(()) => return Ok(p),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("{}: {e}", p.display())),
        }
    }
    Err("cannot create a temporary folder".into())
}

/// Removed when dropped (temporary files of one run).
struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write(p: &Path, data: &[u8]) -> Result<(), String> {
    std::fs::write(p, data).map_err(|e| format!("{}: {e}", p.display()))
}

fn sync(a: &Args, root: &Path) -> Result<i32, String> {
    a.only(&[
        "checkpoint", "checkpoint-sha256", "history", "history-sha256", "mainnet", "peer", "batches",
        "snapshot-at", "snapshot-dir", "timeout", "max-tip-age-sec", "allow-partial",
    ])?;
    let checkpoint = ss::read_pin(Path::new(a.req("checkpoint")?), a.req("checkpoint-sha256")?, ss::PIN_FILE_LIMIT)?;
    let history = ss::read_pin(Path::new(a.req("history")?), a.req("history-sha256")?, ss::PIN_FILE_LIMIT)?;
    let peers = ss::distinct_peers(&a.list("peer"), ss::dns_resolve)?;
    let max_age: i64 = a.num("max-tip-age-sec", ss::DEFAULT_MAX_TIP_AGE_SEC)?;
    if !(1..=604_800).contains(&max_age) {
        return Err("max tip age must be 1..604800 seconds".into());
    }
    let batches: u32 = a.num("batches", 1000)?;
    if !(1..=1000).contains(&batches) {
        return Err("batches must be between 1 and 1000".into());
    }
    let timeout: u64 = a.num("timeout", 600)?;
    if !(1..=600).contains(&timeout) {
        return Err("timeout must be between 1 and 600 seconds".into());
    }
    let mainnet = a.flag("mainnet");
    let folder = fresh_dir(&root.join("sessions"), "sync-")?;
    write(&folder.join("checkpoint.rwm"), &checkpoint)?;
    write(&folder.join("recent-headers.bin"), &history)?;
    let mut args: Vec<String> = vec![
        "--checkpoint-file".into(),
        folder.join("checkpoint.rwm").display().to_string(),
        "--state-dir".into(),
        folder.display().to_string(),
        "--batches".into(),
        batches.to_string(),
    ];
    if mainnet {
        args.push("--mainnet".into());
    }
    for p in &peers {
        args.extend(["--peer".into(), p.clone()]);
    }
    let snap_at: u64 = a.num("snapshot-at", 0)?;
    if let (true, Some(d)) = (snap_at > 0, a.get("snapshot-dir")) {
        args.extend(["--snapshot-at".into(), snap_at.to_string(), "--snapshot-dir".into(), d.into()]);
    }
    let log = folder.join("sync.log");
    let done = run(&binary("reverse-wtema-header-sync"), &args, Duration::from_secs(timeout))
        .map_err(|e| format!("header sync {e}; session={}", folder.display()))?;
    write(&log, format!("{}\n{}", done.stdout, done.stderr).as_bytes())?;
    let read = |n: &str| std::fs::read(folder.join(n)).map_err(|e| format!("{n}: {e}; see {}", log.display()));
    // Refusals before the files are read: a failed child may not have written them.
    let early = ss::kv_lines(&done.stdout);
    if done.code != 0 || early.get("HEADER_SYNC").map(String::as_str) != Some("PASS") {
        return Err(format!("header sync failed; see {}", log.display()));
    }
    let cp_out = String::from_utf8(read("checkpoint.rwm")?).map_err(|_| "sync output checkpoint malformed")?;
    let transcript = read(ss::TRANSCRIPT_FILE)?;
    let v = ss::sync_verdict(&SyncRun {
        stdout: &done.stdout,
        exit_code: done.code,
        checkpoint_out: &cp_out,
        transcript: &transcript,
        checkpoint_in: &checkpoint,
        history_in: &history,
        max_tip_age_sec: max_age,
        network: if mainnet { Network::Mainnet } else { Network::Floonet },
        now: ss::now_unix(),
    })
    .map_err(|e| format!("{e}; see {}", log.display()))?;
    write(&folder.join("tip-header.bin"), &v.tip_header)?;
    write(&folder.join(ss::MANIFEST_FILE), &v.manifest)?;
    let mut report = v.report;
    report.insert("session".into(), serde_json::json!(folder.display().to_string()));
    println!("{}", serde_json::Value::Object(report));
    Ok(ss::sync_exit_code(&v.status))
}

fn gap(a: &Args, root: &Path) -> Result<i32, String> {
    a.only(&[
        "session", "session-sha256", "commitment", "archive-height", "state-dir", "seeds", "wallet-out", "wallet-in",
        "pending", "spend", "broadcast", "tx-out", "send-to", "send-amount", "pay-invoice", "slatepack-out",
        "context-out", "kernel", "check-block", "blocks-all-peers", "mainnet", "allow-mainnet-spend", "peer",
        "replay", "prove", "save-bundle", "segment-height", "max-msgs-per-min", "timeout",
    ])?;
    let s = Session::open(Path::new(a.req("session")?), a.req("session-sha256")?)?;
    let peers = a.list("peer");
    let mut r = GapRequest::new();
    r.mainnet = a.flag("mainnet");
    r.allow_mainnet_spend = a.flag("allow-mainnet-spend");
    r.commitments = a.list("commitment");
    r.kernels = a.list("kernel");
    r.check_blocks = a.list("check-block");
    r.archive_height = a.get("archive-height").map(|x| x.parse().map_err(|_| "--archive-height: not a number")).transpose()?;
    r.state_dir = a.path("state-dir");
    r.seeds = a.path("seeds");
    r.wallet_out = a.path("wallet-out");
    r.wallet_in = a.path("wallet-in");
    r.pending = a.path("pending");
    r.spend = a.get("spend").map(str::to_string);
    r.broadcast = a.flag("broadcast");
    r.tx_out = a.path("tx-out");
    r.send_to = a.get("send-to").map(str::to_string);
    r.send_amount = a.get("send-amount").map(|x| x.parse().map_err(|_| "--send-amount: not a number")).transpose()?;
    r.pay_invoice = a.path("pay-invoice");
    r.slatepack_out = a.path("slatepack-out");
    r.context_out = a.path("context-out");
    r.blocks_all_peers = a.flag("blocks-all-peers");
    r.replay = a.get("replay").map(str::to_string);
    r.prove = a.flag("prove");
    r.save_bundle = a.path("save-bundle");
    r.segment_height = a.num("segment-height", 11)?;
    r.max_msgs_per_min = a.num("max-msgs-per-min", 400)?;
    r.timeout_sec = a.num("timeout", 3600)?;
    if !peers.is_empty() {
        r.peers = ss::distinct_peers(&peers, ss::dns_resolve)?;
    }
    let tmp = TempDir(fresh_dir(&root.join("evidence"), "gap-")?);
    let hf = tmp.0.join("gap-headers.bin");
    let plan = ss::plan_gap(&s, &r, root, &hf, ss::now_unix())?;
    write(&hf, &plan.headers_file)?;
    let done = run(&binary("reverse-wtema-header-sync"), &plan.args, Duration::from_secs(r.timeout_sec))
        .map_err(|e| format!("gap experiment {e}"))?;
    print!("{}", done.stdout);
    if !done.stderr.trim().is_empty() {
        eprintln!("{}", done.stderr.trim());
    }
    print!("{}", ss::gap_report(&s, &done.stdout, done.code, ss::now_unix()));
    Ok(done.code)
}

fn without_auth(stdout: &str) -> String {
    stdout
        .lines()
        .filter(|l| !l.starts_with("HEADER_AUTHENTICATION="))
        .collect::<Vec<_>>()
        .join("\n")
}

fn pibd(a: &Args, root: &Path) -> Result<i32, String> {
    a.only(&["session", "session-sha256", "height", "peer", "proof", "save-proof", "leaf-index", "commitment"])?;
    let peers = a.list("peer");
    let proof = a.get("proof");
    if peers.is_empty() == proof.is_none() {
        return Err("exactly one of --peer and --proof".into());
    }
    if proof.is_some() && a.get("save-proof").is_some() {
        return Err("--save-proof cannot be used with offline --proof".into());
    }
    let leaf = a.req("leaf-index")?.to_string();
    let commitment = a.req("commitment")?.to_string();
    let s = Session::open(Path::new(a.req("session")?), a.req("session-sha256")?)?;
    let height = a.get("height").map(|x| x.parse::<u64>().map_err(|_| "--height: not a number")).transpose()?;
    let heights = ss::pibd_heights(s.tip_height(), height)?;
    let save = a.path("save-proof").map(|p| ss::inside(root, &p)).transpose()?;
    let tip = s.tip_height();
    let tail = |h: u64| format!("HEADER_AUTHENTICATION=SESSION_SHA256_PINNED\nVERIFIED_SESSION_TIP_HEIGHT={tip}\nPROOF_HEADER_HEIGHT={h}\nCURRENT_TIP_STATE=NOT_PROVEN");
    let mut failures = Vec::new();
    let mut unique: Vec<String> = Vec::new();
    for p in peers {
        if !unique.contains(&p) {
            unique.push(p);
        }
    }
    for h in heights {
        let Some(header) = s.header_at(h) else {
            failures.push(format!("{h}: height not present in validated session"));
            continue;
        };
        let tmp = TempDir(fresh_dir(&root.join("evidence"), "pibd-")?);
        let hf = tmp.0.join("header.bin");
        write(&hf, header)?;
        let base: Vec<String> = vec!["--pibd-header".into(), hf.display().to_string()];
        let tailargs = vec!["--leaf-index".into(), leaf.clone(), "--commitment".into(), commitment.clone()];
        if let Some(pf) = proof {
            let args = [base.clone(), vec!["--pibd-replay".into(), pf.into()], tailargs.clone()].concat();
            let done = run(&binary("reverse-wtema-header-sync"), &args, Duration::from_secs(45))?;
            if done.code != 0 {
                return Err(format!("offline PIBD proof rejected: {}", done.stderr.trim()));
            }
            println!("{}\n{}", without_auth(&done.stdout), tail(h));
            return Ok(0);
        }
        for peer in &unique {
            let tp = tmp.0.join("proof.upb");
            let mut args = [base.clone(), vec!["--peer".into(), peer.clone()], tailargs.clone()].concat();
            if save.is_some() {
                args.extend(["--pibd-out".into(), tp.display().to_string()]);
            }
            let done = match run(&binary("reverse-wtema-header-sync"), &args, Duration::from_secs(45)) {
                Ok(d) => d,
                Err(e) => {
                    failures.push(format!("{peer} height={h}: {e}"));
                    continue;
                }
            };
            if done.code == 0 && done.stdout.contains("PIBD_VERDICT=UNSPENT_AT_ARCHIVE_HEADER") {
                if let Some(target) = &save {
                    let data = std::fs::read(&tp).map_err(|e| e.to_string())?;
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(target)
                        .map_err(|e| format!("{}: {e}", target.display()))?;
                    std::io::Write::write_all(&mut f, &data).map_err(|e| e.to_string())?;
                    println!("PIBD_PROOF_SAVED={}", target.display());
                }
                println!("PIBD_PEER={peer}\n{}\n{}\nPEER_INDEPENDENCE=NOT_ESTABLISHED", without_auth(&done.stdout), tail(h));
                return Ok(0);
            }
            let why = if done.stderr.trim().is_empty() { "no valid segment".to_string() } else { done.stderr.trim().to_string() };
            failures.push(format!("{peer} height={h}: {why}"));
        }
    }
    Err(format!("PIBD unavailable or invalid: {}", failures.join("; ")))
}

fn verify_state(a: &Args, root: &Path) -> Result<i32, String> {
    a.only(&["commitment", "header", "session", "header-sha256", "session-sha256", "height", "proof", "proof-url"])?;
    if a.get("proof-url").is_some() {
        return Err("--proof-url was removed: asking a server for a proof tells it which output you hold; fetch the file and pass --proof".into());
    }
    let proof = a.req("proof")?;
    let commitment = a.req("commitment")?;
    let verify = |header: &Path, sha: &str| -> Result<i32, String> {
        let args: Vec<String> = vec![
            "--header".into(), header.display().to_string(), "--header-sha256".into(), sha.into(),
            "--commitment".into(), commitment.into(), "--proof".into(), proof.into(),
        ];
        let d = run(&binary("grinsight-state-verify"), &args, Duration::from_secs(600))?;
        print!("{}", d.stdout);
        eprint!("{}", d.stderr);
        Ok(d.code)
    };
    match (a.get("session"), a.get("header")) {
        (Some(folder), None) => {
            let (Some(sha), Some(h)) = (a.get("session-sha256"), a.get("height")) else {
                return Err("--session requires --session-sha256 and --height".into());
            };
            let h: u64 = h.parse().map_err(|_| "--height: not a number")?;
            let s = Session::open(Path::new(folder), sha)?;
            let header = s.header_at(h).ok_or("height not present in validated session")?;
            let tmp = TempDir(fresh_dir(&root.join("evidence"), "header-")?);
            let hf = tmp.0.join("header.bin");
            write(&hf, header)?;
            let code = verify(&hf, &ss::sha256_hex(header))?;
            print!("{}", ss::state_report(&s, h, code, ss::now_unix()));
            Ok(code)
        }
        (None, Some(h)) => verify(Path::new(h), a.req("header-sha256")?),
        _ => Err("exactly one of --session and --header".into()),
    }
}

/// Public peers from the Grin DNS seeds: `DNS_SEED=host OK n|FAIL`, then
/// `KNOWN_PEER=ip:port`. Exit 3 when no seed answered.
fn dns_seeds(a: &Args) -> Result<i32, String> {
    a.only(&["testnet", "limit"])?;
    let testnet = a.flag("testnet");
    let (seeds, port) = if testnet { (ss::FLOONET_DNS_SEEDS, 13414) } else { (ss::MAINNET_DNS_SEEDS, 3414) };
    let limit: usize = a.num("limit", 40)?;
    let mut answers = Vec::new();
    for host in seeds {
        match ss::dns_resolve(host, port) {
            Ok(ips) => {
                println!("DNS_SEED={host} OK {}", ips.len());
                answers.push(ips);
            }
            Err(e) => println!("DNS_SEED={host} FAIL {e}"),
        }
    }
    let peers = ss::seed_peers(&answers, port, limit);
    for p in &peers {
        println!("KNOWN_PEER={p}");
    }
    Ok(if peers.is_empty() { 3 } else { 0 })
}

fn session(a: &Args) -> Result<i32, String> {
    a.only(&["session", "session-sha256"])?;
    let s = Session::open(Path::new(a.req("session")?), a.req("session-sha256")?)?;
    println!("{}", s.summary_json(ss::now_unix()));
    Ok(0)
}

fn main() {
    let v: Vec<String> = std::env::args().skip(1).collect();
    let Some(mode) = v.first() else {
        eprintln!("usage: grinsight sync|gap|pibd|verify-state|session|dns-seeds [options]  (see the top of header-sync/src/bin/grinsight_sync.rs)");
        std::process::exit(2);
    };
    let root = root();
    let res = Args::parse(&v[1..]).and_then(|a| match mode.as_str() {
        "sync" => sync(&a, &root),
        "gap" => gap(&a, &root),
        "pibd" => pibd(&a, &root),
        "verify-state" => verify_state(&a, &root),
        "session" => session(&a),
        "dns-seeds" => dns_seeds(&a),
        m => Err(format!("unknown mode {m}")),
    });
    match res {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("VERDICT=FAIL_CLOSED {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Result<Args, String> {
        Args::parse(&v.iter().map(|x| x.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn arguments() {
        let x = a(&["--peer", "a:1", "--peer", "b:2", "--prove", "--timeout", "5"]).unwrap();
        assert_eq!(x.list("peer"), vec!["a:1", "b:2"]);
        assert!(x.flag("prove"));
        assert_eq!(x.num::<u64>("timeout", 0).unwrap(), 5);
        assert!(x.only(&["peer", "prove", "timeout"]).is_ok());
        assert!(x.only(&["peer", "prove"]).is_err(), "unknown option is refused");
        assert!(a(&["--session", "x", "--session", "y"]).is_err());
        assert_eq!(a(&["--commitment", "c"]).unwrap().get("commitment"), Some("c"));
        assert_eq!(a(&["--commitment", "c", "--commitment", "d"]).unwrap().get("commitment"), None);
        assert!(a(&["--session"]).is_err());
        assert!(a(&["stray"]).is_err());
        assert!(a(&["--timeout", "x"]).unwrap().num::<u64>("timeout", 0).is_err());
    }

    #[test]
    fn child_timeout_kills() {
        if cfg!(windows) {
            return;
        }
        let r = run(Path::new("/bin/sleep"), &["5".into()], Duration::from_millis(300));
        assert_eq!(r.err().as_deref(), Some("timed out"));
        let d = run(Path::new("/bin/sh"), &["-c".into(), "echo A=1; echo E >&2; exit 3".into()], Duration::from_secs(5)).unwrap();
        assert_eq!((d.code, d.stdout.as_str(), d.stderr.as_str()), (3, "A=1\n", "E\n"));
    }

    #[test]
    fn fresh_dirs_are_distinct() {
        let base = std::env::temp_dir().join(format!("grinsight-cli-{}", std::process::id()));
        let x = fresh_dir(&base, "s-").unwrap();
        let y = fresh_dir(&base, "s-").unwrap();
        assert_ne!(x, y);
        let _ = std::fs::remove_dir_all(&base);
    }
}
