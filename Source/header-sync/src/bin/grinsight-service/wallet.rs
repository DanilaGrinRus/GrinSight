//! Wallet flows (was run_user.ps1). One unlocked profile at a time.
//!
//! Profile folder `<data>/profiles/<network>/<name>/`:
//!   vault.json              encrypted phrase (vault.rs)
//!   state/                  proven UTXO state (core)
//!   wallet-outputs.jsonl    own outputs at the proven tip (core, MAC)
//!   pending-receives.jsonl  payment journal (core)
//!   checkpoint/ rolling/    accepted release checkpoint, rolling checkpoint
//!   sessions/               verified header sessions (newest 3 kept)
//!   peers.txt settings.json last-open.json address.txt confirmed-kernels.txt
//!   txs/<id>/               one folder per payment (slatepacks, context, tx, logs, meta.json)
//!   tor-wallet-1/           Tor daemon (grinsight-tor) files
//!
//! Every decision about what is true comes from the core (header sync, gap
//! proof, slatepack checks); this file only runs it in the right order and
//! keeps the files.

use crate::jobs::{run_exe, Done, Job, Jobs};
use crate::vault;
use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use grinsight_state::session::{self as ss, GapRequest, Network, Session, SyncRun};
use zeroize::Zeroizing;

/// Probe commitment: proves the run (never an own output).
const PROBE_COMMITMENT: &str = "0800000000000000000000000000000000000000000000000000000000000000ff";
/// Floonet checkpoint of 2026-11-10 (run_testnet_balance.ps1) when no pin file ships.
const FLOONET_CP_SHA: &str = "271e40ceb31ca99978d7a320e50970dfdf8b10f9ce8622e6dff7d5f9b9728f66";
const FLOONET_HI_SHA: &str = "3e69fc015f25f45cb2dc2010bf569a967f3284f54377d8414b1c857e6567dc7e";
/// A block this deep is treated as final for the history (a deeper reorg is
/// not realistic); shallower ones are re-checked on every refresh.
const DEEP_REORG: u64 = 1440;
/// Older than this, the header sync from the shipped point may not reach the
/// tip in one run (512 000 headers is about 355 days): ask for an own point.
const OLD_CHECKPOINT_DAYS: i64 = 300;
const FLOONET_PEERS: &[&str] = &["96.44.159.174:13414", "66.154.127.84:13414"];
pub const CONFIRMATIONS: u64 = 10;

pub struct Config {
    pub data_dir: PathBuf,
    pub bin_dir: PathBuf,
    pub checkpoints_dir: PathBuf,
}

pub struct Wallet {
    pub name: String,
    pub network: Network,
    pub dir: PathBuf,
    phrase: Zeroizing<String>,
}

impl Wallet {
    fn p(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }
    fn known(&self) -> PathBuf {
        self.p("wallet-outputs.jsonl")
    }
    fn pending(&self) -> PathBuf {
        self.p("pending-receives.jsonl")
    }
    fn state_dir(&self) -> PathBuf {
        self.p("state")
    }
    fn installed(&self) -> bool {
        self.state_dir().join("state.ust").exists() && self.known().exists()
    }
    fn mainnet(&self) -> bool {
        self.network == Network::Mainnet
    }
    fn net(&self) -> Vec<String> {
        if self.mainnet() {
            vec!["--mainnet".into()]
        } else {
            vec![]
        }
    }
    fn port(&self) -> u16 {
        if self.mainnet() {
            3414
        } else {
            13414
        }
    }
    fn logs(&self) -> PathBuf {
        let d = self.p("logs");
        let _ = std::fs::create_dir_all(&d);
        d
    }
    fn log(&self, name: &str) -> PathBuf {
        self.logs().join(format!("{}-{name}.log", stamp()))
    }
    fn settings(&self) -> Value {
        // glauxnet: our own mailbox (local gateway behind our onion) runs while
        // the wallet is open; glauxnet_relay: optional remote GlauxNet used
        // only when Tor cannot start.
        let mut s = json!({
            "auto_broadcast": true, "extra_peers": [], "glauxnet": true, "glauxnet_relay": "", "verify_mode": "checkpoint",
            "checkpoint_source": "release", "checkpoint_offer_seen": false,
        });
        if let Ok(t) = std::fs::read_to_string(self.p("settings.json")) {
            if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(&t) {
                for (k, v) in m {
                    if s.get(&k).is_some() {
                        s[k] = v;
                    }
                }
            }
        }
        s
    }
    /// Keys can be handed out: the wallet was scanned once, or it is a new
    /// phrase made here (nothing of it can be on chain).
    fn keys_known(&self) -> bool {
        self.known().exists()
            || std::fs::read_to_string(self.p("profile.json")).is_ok_and(|t| t.contains("\"origin\":\"new\""))
    }
    /// Tip of the last successful verification (last-open.json), else the
    /// outputs file's tip: the height the history is measured against.
    fn verified_tip(&self) -> u64 {
        std::fs::read_to_string(self.p("last-open.json"))
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| v["tip_height"].as_u64())
            .or_else(|| self.tip_height_of_known())
            .unwrap_or(0)
    }

    fn tip_height_of_known(&self) -> Option<u64> {
        let t = std::fs::read_to_string(self.known()).ok()?;
        let v: Value = serde_json::from_str(t.lines().next()?).ok()?;
        v.get("tip_height")?.as_u64()
    }
}

/// A core program next to the service: `name(.exe)`, or on Android, where an
/// app may run only files from its native library folder, `lib<name_>.so`.
pub fn program(dir: &Path, name: &str) -> PathBuf {
    let plain = dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    let lib = dir.join(format!("lib{}.so", name.replace('-', "_")));
    if !plain.exists() && lib.exists() {
        return lib;
    }
    plain
}

pub fn network_from(s: &str) -> Result<Network, String> {
    match s.to_ascii_lowercase().as_str() {
        "mainnet" => Ok(Network::Mainnet),
        "floonet" | "testnet" => Ok(Network::Floonet),
        _ => Err("network must be mainnet or floonet".into()),
    }
}

fn net_name(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet",
        Network::Floonet => "floonet",
    }
}

fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 32 || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err("wallet name: 1-32 letters, digits, '-' or '_'".into());
    }
    Ok(())
}

fn stamp() -> String {
    chrono::Utc::now().format("%Y%m%d-%H%M%S%.3f").to_string()
}

fn sha_file(p: &Path) -> Result<String, String> {
    Ok(ss::sha256_hex(&std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?))
}

fn read(p: &Path) -> Result<String, String> {
    std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))
}

fn write(p: &Path, data: &str) -> Result<(), String> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let tmp = p.with_extension("tmp-write");
    std::fs::write(&tmp, data).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, p).map_err(|e| format!("{}: {e}", p.display()))
}

fn pin_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| l.trim().strip_prefix(key).and_then(|r| r.strip_prefix('=')).map(str::to_string))
}

/// One peer of the probe: address, serves PIBD, claimed total difficulty.
#[derive(Clone, Debug, PartialEq)]
pub struct Peer {
    pub addr: String,
    pub pibd: bool,
    pub td: u128,
    /// Advertises HEADER_PROOF_HIST (bit 0x100, PR #3963) — a "future" node.
    pub header_proof: bool,
}

fn net16(p: &str) -> String {
    let ip = p.rsplit_once(':').map_or(p, |(a, _)| a);
    let o: Vec<&str> = ip.split('.').collect();
    if o.len() == 4 {
        format!("{}.{}", o[0], o[1])
    } else {
        ip.to_string()
    }
}

/// Header sync: up to four peers from different /16 networks first.
/// Blocks/segments: PIBD peers not used by the sync first (a node refuses a
/// quick reconnect from the same IP), then the rest; `gap_max` of them.
pub fn select_peers(ok: &[Peer], gap_max: usize) -> (Vec<String>, Vec<String>) {
    let mut sync: Vec<String> = Vec::new();
    let mut nets: BTreeSet<String> = BTreeSet::new();
    for x in ok {
        if sync.len() >= 4 {
            break;
        }
        if nets.insert(net16(&x.addr)) {
            sync.push(x.addr.clone());
        }
    }
    for x in ok {
        if sync.len() >= 4 {
            break;
        }
        if !sync.contains(&x.addr) {
            sync.push(x.addr.clone());
        }
    }
    let rest: Vec<&Peer> = ok.iter().filter(|p| !sync.contains(&p.addr)).collect();
    let mut gap: Vec<String> = Vec::new();
    for a in rest.iter().filter(|p| p.pibd).chain(rest.iter().filter(|p| !p.pibd)).map(|p| p.addr.clone()).chain(sync.iter().cloned()) {
        if gap.len() < gap_max && !gap.contains(&a) {
            gap.push(a);
        }
    }
    (sync, gap)
}

/// `PROBE_PEER=ip:port OK ... pibd=yes ... total_difficulty=N`, heaviest first.
pub fn parse_probe(stdout: &str) -> (Vec<Peer>, Vec<String>) {
    let mut ok: Vec<Peer> = Vec::new();
    for l in stdout.lines() {
        let Some(r) = l.strip_prefix("PROBE_PEER=") else { continue };
        let mut f = r.split(' ');
        let addr = f.next().unwrap_or("").to_string();
        if f.next() != Some("OK") || ok.iter().any(|p| p.addr == addr) {
            continue;
        }
        let td = r.split("total_difficulty=").nth(1).and_then(|x| x.split(' ').next()).and_then(|x| x.parse().ok()).unwrap_or(0);
        let caps = r.split("caps=0x").nth(1).and_then(|x| x.split(' ').next()).and_then(|x| u64::from_str_radix(x, 16).ok()).unwrap_or(0);
        ok.push(Peer { addr, pibd: r.contains("pibd=yes"), td, header_proof: caps & 0x100 != 0 });
    }
    ok.sort_by(|a, b| b.td.cmp(&a.td));
    let disc = stdout.lines().filter_map(|l| l.strip_prefix("DISCOVERED_PEER=")).map(str::to_string).collect();
    (ok, disc)
}

struct Checkpoint {
    cp: PathBuf,
    hist: PathBuf,
    cp_sha: String,
    hi_sha: String,
    base_sha: String,
    height: u64,
}

pub struct SyncOut {
    pub session: Session,
    pub manifest_sha: String,
    pub report: Map<String, Value>,
}

/// What a wallet run does besides updating the balance.
#[derive(Default, Clone)]
pub struct Extra {
    pub commitments: Vec<String>,
    pub kernels: Vec<String>,
    pub check_blocks: Vec<String>,
    pub send_to: Option<(String, u64)>,
    pub pay_invoice: Option<PathBuf>,
    pub tx_dir: Option<PathBuf>,
}

pub struct Service {
    pub cfg: Config,
    pub jobs: Arc<Jobs>,
    open: Mutex<Option<Arc<Wallet>>>,
    tor: Mutex<Option<Child>>,
    /// SHA-256 of phrases generated by `new_phrase` in this run: only those
    /// count as "new" (never used, nothing on chain).
    generated: Mutex<Vec<String>>,
}

impl Service {
    pub fn new(cfg: Config) -> Service {
        Service { cfg, jobs: Arc::new(Jobs::default()), open: Mutex::new(None), tor: Mutex::new(None), generated: Mutex::new(Vec::new()) }
    }

    fn exe(&self) -> PathBuf {
        program(&self.cfg.bin_dir, "reverse-wtema-header-sync")
    }
    fn tor_exe(&self) -> PathBuf {
        program(&self.cfg.bin_dir, "grinsight-tor")
    }

    fn profile_dir(&self, network: Network, name: &str) -> PathBuf {
        self.cfg.data_dir.join("profiles").join(net_name(network)).join(name)
    }

    pub fn wallet(&self) -> Result<Arc<Wallet>, String> {
        self.open.lock().unwrap().clone().ok_or_else(|| "the wallet is locked".to_string())
    }

    // ---- profiles -------------------------------------------------------

    pub fn profiles(&self) -> Vec<Value> {
        let mut out = Vec::new();
        for n in [Network::Mainnet, Network::Floonet] {
            let d = self.cfg.data_dir.join("profiles").join(net_name(n));
            if let Ok(rd) = std::fs::read_dir(&d) {
                let mut names: Vec<String> = rd
                    .flatten()
                    .filter(|e| e.path().join("vault.json").exists())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                names.sort();
                for name in names {
                    let installed = d.join(&name).join("state").join("state.ust").exists();
                    out.push(json!({ "name": name, "network": net_name(n), "installed": installed }));
                }
            }
        }
        out
    }

    pub fn new_phrase(&self, words: usize) -> Result<Zeroizing<String>, String> {
        let p = vault::new_phrase(words)?;
        self.generated.lock().unwrap().push(ss::sha256_hex(p.as_bytes()));
        Ok(p)
    }

    /// `restored` = the phrase may have been used before (keys and coins on
    /// chain): the wallet must be scanned once before it hands out keys.
    pub fn create(&self, name: &str, network: Network, phrase: &str, password: &str, restored: bool) -> Result<Value, String> {
        check_name(name)?;
        let dir = self.profile_dir(network, name);
        let norm = vault::normalize_phrase(phrase)?;
        // "new" only for a phrase this service generated and nobody saw before.
        let fresh = !restored && self.generated.lock().unwrap().contains(&ss::sha256_hex(norm.as_bytes()));
        vault::create(&dir.join("vault.json"), &norm, password)?;
        if fresh {
            self.generated.lock().unwrap().retain(|h| *h != ss::sha256_hex(norm.as_bytes()));
        }
        let origin = if fresh { "new" } else { "restored" };
        write(&dir.join("profile.json"), &json!({ "origin": origin, "created": chrono::Utc::now().to_rfc3339() }).to_string())?;
        // Open the new wallet in memory right away: the password was just proven
        // by creating the vault, and the UI goes straight to the wallet screen
        // (its restore/create path does not call unlock). Without this, status()
        // reports "the wallet is locked".
        self.lock();
        let w = Arc::new(Wallet { name: name.into(), network, dir, phrase: norm });
        *self.open.lock().unwrap() = Some(w);
        self.apply_pre_settings();
        Ok(json!({ "name": name, "network": net_name(network), "origin": origin }))
    }

    /// Developer test bench only: one phrase of a seed file goes straight into
    /// a vault (the file is read here, never shown).
    pub fn import_seed_file(&self, file: &Path, index: usize, name: &str, network: Network, password: &str) -> Result<Value, String> {
        let phrases = grinsight_state::wallet::read_phrases(&file.display().to_string())?;
        let p = Zeroizing::new(phrases.get(index.wrapping_sub(1)).ok_or("no phrase with this number in the file")?.clone());
        self.create(name, network, &p, password, true)
    }

    pub fn unlock(&self, name: &str, network: Network, password: &str) -> Result<Value, String> {
        check_name(name)?;
        let dir = self.profile_dir(network, name);
        let phrase = vault::open(&dir.join("vault.json"), password)?;
        self.lock();
        let w = Arc::new(Wallet { name: name.into(), network, dir, phrase });
        *self.open.lock().unwrap() = Some(w);
        self.apply_pre_settings();
        let mut st = self.status()?;
        // GlauxNet starts with the wallet unless the user turned it off; a
        // failure here never blocks the wallet (it is reported instead).
        if let Ok(w) = self.wallet() {
            if w.settings()["glauxnet"].as_bool().unwrap_or(true) {
                if let Err(e) = self.tor_start(None) {
                    st["glauxnet_error"] = json!(e);
                }
            }
        }
        st["glauxnet"] = self.glauxnet_status()?;
        Ok(st)
    }

    pub fn lock(&self) {
        self.tor_stop();
        *self.open.lock().unwrap() = None;
    }

    /// The recovery phrase of the open wallet, only for the right password.
    pub fn show_phrase(&self, password: &str) -> Result<Value, String> {
        let w = self.wallet()?;
        let phrase = vault::open(&w.dir.join("vault.json"), password)?;
        Ok(json!({ "phrase": *phrase }))
    }

    pub fn change_password(&self, old: &str, new: &str) -> Result<Value, String> {
        let w = self.wallet()?;
        vault::change_password(&w.dir.join("vault.json"), old, new)?;
        Ok(json!({ "changed": true }))
    }

    /// Renames the open wallet's profile folder (the name is only the folder
    /// name; keys come from the phrase). Tor is stopped for the move (open
    /// files block a rename on Windows) and started again afterwards.
    pub fn rename_profile(&self, new_name: &str) -> Result<Value, String> {
        check_name(new_name)?;
        let w = self.wallet()?;
        if w.name == new_name {
            return Ok(json!({ "name": new_name }));
        }
        if let Some(running) = self.jobs.busy() {
            return Err(format!("wait until \"{running}\" finishes, then rename"));
        }
        let new_dir = self.profile_dir(w.network, new_name);
        if new_dir.exists() {
            return Err(format!("a wallet named {new_name} already exists"));
        }
        self.tor_stop();
        *self.open.lock().unwrap() = None;
        let moved = std::fs::rename(&w.dir, &new_dir);
        let (name, dir) = match &moved {
            Ok(()) => (new_name.to_string(), new_dir),
            Err(_) => (w.name.clone(), w.dir.clone()),
        };
        let nw = Arc::new(Wallet { name, network: w.network, dir, phrase: w.phrase.clone() });
        if moved.is_ok() {
            // `last-open.json` keeps an absolute path to the proof session inside
            // the profile folder: follow the move, or the proof shows as lost.
            let f = nw.p("last-open.json");
            if let Some(mut v) = std::fs::read_to_string(&f).ok().and_then(|x| serde_json::from_str::<Value>(&x).ok()) {
                let (from, to) = (w.dir.display().to_string(), nw.dir.display().to_string());
                if let Some(s) = v["session"].as_str().and_then(|s| s.strip_prefix(from.as_str())).map(|rest| format!("{to}{rest}")) {
                    v["session"] = json!(s);
                    let _ = write(&f, &v.to_string());
                }
            }
        }
        *self.open.lock().unwrap() = Some(nw.clone());
        if nw.settings()["glauxnet"].as_bool().unwrap_or(true) {
            let _ = self.tor_start(None);
        }
        moved.map_err(|e| format!("cannot rename the wallet folder: {e}"))?;
        Ok(json!({ "name": new_name }))
    }

    pub fn set_settings(&self, p: &Value) -> Result<Value, String> {
        // Before login there is no wallet: the choices that are made ON the
        // login screen (verification mode, own peer) are kept in
        // `pre-login.json` and applied to the wallet that opens next.
        let w = match self.wallet() {
            Ok(w) => w,
            Err(_) => return self.set_pre_settings(p),
        };
        let mut s = w.settings();
        if let Some(b) = p.get("auto_broadcast").and_then(Value::as_bool) {
            s["auto_broadcast"] = json!(b);
        }
        if let Some(a) = p.get("extra_peers").and_then(Value::as_array) {
            let list: Vec<String> = a.iter().filter_map(Value::as_str).map(str::to_string).collect();
            for x in &list {
                ss::split_peer(x)?;
            }
            s["extra_peers"] = json!(list);
        }
        if let Some(r) = p.get("glauxnet_relay").and_then(Value::as_str) {
            let r = r.trim();
            if !(r.is_empty() || r.starts_with("http://") || r.starts_with("https://")) {
                return Err("GlauxNet relay must be an http(s):// URL".into());
            }
            s["glauxnet_relay"] = json!(r);
        }
        if let Some(m) = p.get("verify_mode").and_then(Value::as_str) {
            // "checkpoint" = обычный путь (PIBD от подписанного чекпоинта);
            // "header_proof" = экспериментальный режим «Пощупать будущее»
            // (проверка через HEADER_PROOF_HIST-ноды, PR #3963).
            if !matches!(m, "checkpoint" | "header_proof") {
                return Err("verify_mode: checkpoint | header_proof".into());
            }
            s["verify_mode"] = json!(m);
        }
        if let Some(src) = p.get("checkpoint_source").and_then(Value::as_str) {
            match src {
                "release" => {}
                "own" => {
                    let own = self.own_info(w.network);
                    if own["built"].as_bool() != Some(true) {
                        return Err("the own checkpoint is not built yet".into());
                    }
                }
                _ => return Err("checkpoint_source: release | own".into()),
            }
            s["checkpoint_source"] = json!(src);
        }
        if let Some(b) = p.get("checkpoint_offer_seen").and_then(Value::as_bool) {
            s["checkpoint_offer_seen"] = json!(b);
        }
        let was = s["glauxnet"].as_bool().unwrap_or(true);
        if let Some(b) = p.get("glauxnet").and_then(Value::as_bool) {
            s["glauxnet"] = json!(b);
        }
        write(&w.p("settings.json"), &serde_json::to_string_pretty(&s).unwrap())?;
        match (was, s["glauxnet"].as_bool().unwrap_or(true)) {
            (true, false) => self.tor_stop(),
            (false, true) => {
                self.tor_start(None)?;
            }
            _ => {}
        }
        Ok(s)
    }

    pub fn settings(&self) -> Result<Value, String> {
        match self.wallet() {
            Ok(w) => Ok(w.settings()),
            Err(_) => Ok(self.pre_settings()),
        }
    }

    // ---- choices made before login --------------------------------------

    fn pre_path(&self) -> PathBuf {
        self.cfg.data_dir.join("pre-login.json")
    }

    /// The login-screen choices (defaults where nothing was chosen).
    fn pre_settings(&self) -> Value {
        let mut s = json!({ "verify_mode": "checkpoint", "extra_peers": [] });
        if let Ok(t) = std::fs::read_to_string(self.pre_path()) {
            if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(&t) {
                for (k, v) in m {
                    if s.get(&k).is_some() {
                        s[k] = v;
                    }
                }
            }
        }
        s
    }

    /// `verify_mode` and `extra_peers` only; anything else needs an open wallet.
    fn set_pre_settings(&self, p: &Value) -> Result<Value, String> {
        let mut s = self.pre_settings();
        let mut touched = false;
        if let Some(a) = p.get("extra_peers").and_then(Value::as_array) {
            let list: Vec<String> = a.iter().filter_map(Value::as_str).map(str::to_string).collect();
            for x in &list {
                ss::split_peer(x)?;
            }
            s["extra_peers"] = json!(list);
            touched = true;
        }
        if let Some(m) = p.get("verify_mode").and_then(Value::as_str) {
            if !matches!(m, "checkpoint" | "header_proof") {
                return Err("verify_mode: checkpoint | header_proof".into());
            }
            s["verify_mode"] = json!(m);
            touched = true;
        }
        if !touched {
            return Err("the wallet is locked".into());
        }
        write(&self.pre_path(), &serde_json::to_string_pretty(&s).unwrap())?;
        Ok(s)
    }

    /// The wallet that was just opened takes the login-screen choices (once:
    /// the file is removed, so the wallet's own settings rule afterwards).
    fn apply_pre_settings(&self) {
        let path = self.pre_path();
        let Ok(text) = std::fs::read_to_string(&path) else { return };
        let Ok(Value::Object(pre)) = serde_json::from_str::<Value>(&text) else {
            let _ = std::fs::remove_file(&path);
            return;
        };
        if let Ok(w) = self.wallet() {
            let mut s = w.settings();
            for k in ["verify_mode", "extra_peers"] {
                if let Some(v) = pre.get(k) {
                    s[k] = v.clone();
                }
            }
            if write(&w.p("settings.json"), &serde_json::to_string_pretty(&s).unwrap()).is_ok() {
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    // ---- status ---------------------------------------------------------

    /// Balance and proof for the main screen (no network).
    pub fn status(&self) -> Result<Value, String> {
        let w = self.wallet()?;
        // A missing file is "nothing yet"; any other read error is an error,
        // never an empty file (that would show a wrong balance as proven).
        let read_opt = |p: PathBuf| -> Result<String, String> {
            match std::fs::read_to_string(&p) {
                Ok(t) => Ok(t),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
                Err(e) => Err(format!("{}: {e}", p.display())),
            }
        };
        let known = read_opt(w.known())?;
        let pending = read_opt(w.pending())?;
        // A journal that existed once must not silently become "empty": the
        // marker is written the first time the journal is seen.
        let seen_marker = w.p("pending.seen");
        let pending_exists = w.pending().exists();
        if pending_exists && !seen_marker.exists() {
            let _ = write(&seen_marker, "the reservations journal existed; its loss is reported\n");
        }
        let pending_lost = !pending_exists && seen_marker.exists();
        let bal = grinsight_state::balance::balance(&known, &pending, 1)?;
        let last: Value = std::fs::read_to_string(w.p("last-open.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
        let now = ss::now_unix();
        // Freshness is recomputed now: an old proof is shown as old.
        let session = match (last["session"].as_str(), last["manifest_sha256"].as_str()) {
            (Some(d), Some(sha)) => Session::open(Path::new(d), sha).ok(),
            _ => None,
        };
        let session_json = session.as_ref().map(|s| serde_json::from_str::<Value>(&s.summary_json(now)).unwrap()).unwrap_or(Value::Null);
        // The balance may be shown as proven only if the outputs file is the one
        // this wallet's proof wrote (MAC with its seed) and describes the same
        // tip as the proof session.
        let balance_check: Result<(), String> = (|| {
            let entropy = grin_keychain::mnemonic::to_entropy(&w.phrase).map_err(|e| format!("phrase: {e:?}"))?;
            let tip = match session.as_ref() {
                Some(s) => Some((s.tip_height(), s.tip_hash().ok_or("cannot read the verified tip header")?)),
                None => None,
            };
            grinsight_state::balance::check_binding(&known, &[entropy], tip.as_ref().map(|(h, x)| (*h, x.as_str())))?;
            if pending_lost {
                return Err("the reservations journal (pending-receives.jsonl) disappeared; reserved and incoming amounts are unknown".into());
            }
            Ok(())
        })();
        Ok(json!({
            "unlocked": true,
            "name": w.name,
            "network": net_name(w.network),
            "installed": w.installed(),
            "address": std::fs::read_to_string(w.p("address.txt")).ok().map(|s| s.trim().to_string()),
            "balance": serde_json::from_str::<Value>(&bal.to_json()).unwrap(),
            "proof": {
                "last_open": last,
                "session": session_json,
                "proven_at_height": bal.tip_height,
            },
            "job": self.jobs.busy(),
            "tor": self.tor_status_brief(&w),
            "verify_mode": w.settings()["verify_mode"].as_str().unwrap_or("checkpoint"),
            "balance_check": match &balance_check {
                Ok(()) => json!({ "ok": true, "reason": null }),
                Err(e) => json!({ "ok": false, "reason": e }),
            },
        }))
    }

    // ---- checkpoint, peers, sync -----------------------------------------

    fn checkpoint(&self, w: &Wallet, job: &Job) -> Result<Checkpoint, String> {
        job.phase("checkpoint");
        // «Своя» точка: всё проверено от genesis этим же устройством. Берётся,
        // если её выбрали, или сама, если она новее поставочной и содержит её
        // (так кошелёк с устаревшей поставочной точкой открывается после
        // «Проверить сам»).
        let own_dir = self.own_cp_dir(w.network);
        let own_res: Option<Value> = std::fs::read_to_string(own_dir.join("result.json")).ok().and_then(|t| serde_json::from_str(&t).ok());
        let chosen = w.settings()["checkpoint_source"].as_str() == Some("own");
        let fresher = own_res.as_ref().is_some_and(|r| {
            r["matches"].as_bool() == Some(true)
                && r["height"].as_u64().unwrap_or(0) > self.shipped_info(w.network)["height"].as_u64().unwrap_or(0)
        });
        let no_shipped = self.shipped_info(w.network)["exists"].as_bool() != Some(true) && own_res.is_some();
        if chosen || fresher || no_shipped {
            let dir = own_dir;
            let res: Value = own_res.ok_or("the own checkpoint is selected but not built: build it or switch back to the shipped one")?;
            let (cp, hist) = (dir.join("state").join("checkpoint.rwm"), dir.join("state").join("recent-headers.bin"));
            let (cs, hs) = (sha_file(&cp)?, sha_file(&hist)?);
            if res["checkpoint_sha256"].as_str() != Some(cs.as_str()) || res["history_sha256"].as_str() != Some(hs.as_str()) {
                return Err("own checkpoint files changed since they were built".into());
            }
            let height = res["height"].as_u64().unwrap_or(0);
            job.line(&format!("own checkpoint at height {height}{}", if chosen { "" } else { " (newer than the shipped one, which it contains)" }));
            return Ok(Checkpoint { cp, hist, cp_sha: cs.clone(), hi_sha: hs, base_sha: cs, height });
        }
        let src = self.cfg.checkpoints_dir.join(net_name(w.network));
        // A very old shipped point (the app was not updated for about a year):
        // syncing from it would not reach the tip. Say what to do instead of
        // failing somewhere in the header sync. Newer wallets roll forward and
        // never get here; the own point (above) is used when it exists.
        if let Some(days) = Self::rwm_age_days(&src.join("checkpoint.rwm")) {
            if days > OLD_CHECKPOINT_DAYS {
                return Err(format!(
                    "CHECKPOINT_TOO_OLD: the shipped checkpoint is {days} days old. Build a fresh one yourself: «Проверить сам» / «Check myself» (checks every header from genesis, no trust in the shipped one), or update the app"
                ));
            }
        }
        let dst = w.p("checkpoint");
        std::fs::create_dir_all(&dst).map_err(|e| e.to_string())?;
        let pin = dst.join("pin.txt");
        if src.join("release.txt").exists() {
            // Signed release: signature with the keys compiled into the core,
            // files match, never back from the release accepted last time.
            let acc = dst.join("accepted-release.txt");
            let mut args = w.net();
            args.extend(["--verify-release".into(), src.display().to_string(), "--accepted".into(), acc.display().to_string()]);
            let d = run_exe(&self.exe(), &args, None, &w.log("release"), Some(job), Duration::from_secs(60))?;
            if d.code != 0 || d.value("RELEASE") != Some("VERIFIED") {
                return Err(format!("the shipped checkpoint release is not valid: {}", d.value("RELEASE").unwrap_or("?")));
            }
            let rel = read(&src.join("release.txt"))?;
            if std::fs::read_to_string(&acc).ok().as_deref() != Some(rel.as_str()) {
                for f in ["checkpoint.rwm", "recent-headers.bin"] {
                    std::fs::copy(src.join(f), dst.join(f)).map_err(|e| format!("{f}: {e}"))?;
                }
                let pins: Vec<&str> = rel.lines().filter(|l| l.starts_with("checkpoint_sha256=") || l.starts_with("history_sha256=")).collect();
                write(&pin, &(pins.join("\n") + "\n"))?;
                write(&acc, &rel)?;
                job.line("signed checkpoint release accepted");
            }
        } else if !pin.exists() {
            // Developer / test bench: pin.txt next to the files, or the
            // built-in Floonet pins.
            let (a, b) = match std::fs::read_to_string(src.join("pin.txt")) {
                Ok(t) => (pin_value(&t, "checkpoint_sha256").ok_or("pin.txt: checkpoint_sha256")?, pin_value(&t, "history_sha256").ok_or("pin.txt: history_sha256")?),
                Err(_) if w.network == Network::Floonet => (FLOONET_CP_SHA.into(), FLOONET_HI_SHA.into()),
                Err(_) => return Err(format!("no checkpoint for {} in {}", net_name(w.network), src.display())),
            };
            for f in ["checkpoint.rwm", "recent-headers.bin"] {
                std::fs::copy(src.join(f), dst.join(f)).map_err(|e| format!("checkpoint {}: {e}", src.join(f).display()))?;
            }
            write(&pin, &format!("checkpoint_sha256={a}\nhistory_sha256={b}\n"))?;
        }
        let pt = read(&pin)?;
        let (cp, hist) = (dst.join("checkpoint.rwm"), dst.join("recent-headers.bin"));
        let (cs, hs) = (sha_file(&cp)?, sha_file(&hist)?);
        if pin_value(&pt, "checkpoint_sha256").as_deref() != Some(cs.as_str()) || pin_value(&pt, "history_sha256").as_deref() != Some(hs.as_str()) {
            return Err("checkpoint files changed since they were pinned".into());
        }
        let mut c = Checkpoint { cp, hist, cp_sha: cs.clone(), hi_sha: hs, base_sha: cs, height: 0 };
        // Rolling checkpoint grown from this base (tip-4320, 720-aligned).
        let roll = w.p("rolling");
        if let Ok(rp) = std::fs::read_to_string(roll.join("pin.txt")) {
            let (rc, rh) = (roll.join("checkpoint.rwm"), roll.join("recent-headers.bin"));
            let ok = pin_value(&rp, "root_base").as_deref() == Some(c.base_sha.as_str())
                && sha_file(&rc).ok() == pin_value(&rp, "checkpoint_sha256")
                && sha_file(&rh).ok() == pin_value(&rp, "history_sha256");
            if ok {
                c.cp_sha = sha_file(&rc)?;
                c.hi_sha = sha_file(&rh)?;
                c.cp = rc;
                c.hist = rh;
                job.line(&format!("rolling checkpoint at height {}", pin_value(&rp, "height").unwrap_or_default()));
            } else {
                let _ = std::fs::remove_dir_all(&roll);
                job.line("rolling checkpoint dropped (other base or changed files)");
            }
        }
        c.height = read(&c.cp)?
            .lines()
            .find_map(|l| l.strip_prefix("height ").and_then(|h| h.trim().parse().ok()))
            .unwrap_or(0);
        Ok(c)
    }

    fn peers(&self, w: &Wallet, job: &Job, force_probe: bool) -> Result<Vec<Peer>, String> {
        job.phase("peers");
        let cache = w.p("peers.txt");
        let cached: Vec<Peer> = std::fs::read_to_string(&cache)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                let (a, p) = l.split_once(' ')?;
                ss::split_peer(a).ok()?;
                Some(Peer { addr: a.into(), pibd: p == "pibd=yes", td: 0, header_proof: false })
            })
            .collect();
        let fresh = std::fs::metadata(&cache)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|e| e.as_secs() < 24 * 3600);
        let enough = if w.mainnet() { 6 } else { 2 };
        // Every extra connection makes a node refuse our next one for a while:
        // reuse the peers that answered last time (like a node's peer store).
        if w.installed() && fresh && cached.len() >= enough && !force_probe {
            job.line(&format!("peers from the peer store: {}", cached.len()));
            return Ok(cached);
        }
        let port = w.port();
        let seeds = if w.mainnet() { ss::MAINNET_DNS_SEEDS } else { ss::FLOONET_DNS_SEEDS };
        let answers: Vec<_> = seeds.iter().filter_map(|h| ss::dns_resolve(h, port).ok()).collect();
        let seed_peers = ss::seed_peers(&answers, port, 16);
        let extra: Vec<String> = w.settings()["extra_peers"].as_array().cloned().unwrap_or_default().iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        let builtin: Vec<String> = if w.mainnet() { vec![] } else { FLOONET_PEERS.iter().map(|s| s.to_string()).collect() };
        let mut list: Vec<String> = Vec::new();
        for a in extra.into_iter().chain(cached.iter().map(|p| p.addr.clone())).chain(builtin).chain(seed_peers) {
            if list.len() < 32 && !list.contains(&a) {
                list.push(a);
            }
        }
        if list.is_empty() {
            return Err("no DNS seed answered and no peers are known (add peers in settings)".into());
        }
        let probe = |peers: &[String], discover: bool, tag: &str| -> Result<Done, String> {
            let mut a = w.net();
            if discover {
                a.push("--discover".into());
            }
            for p in peers {
                a.extend(["--probe-peer".into(), p.clone()]);
            }
            run_exe(&self.exe(), &a, None, &w.log(tag), Some(job), Duration::from_secs(180))
        };
        let d = probe(&list, true, "probe")?;
        let (mut ok, disc) = parse_probe(&d.stdout);
        let disc: Vec<String> = disc.into_iter().filter(|x| !list.contains(x)).take(24).collect();
        if (ok.iter().filter(|p| p.pibd).count() < 8 || ok.len() < 8) && !disc.is_empty() {
            let d2 = probe(&disc, false, "probe-gossip")?;
            let (more, _) = parse_probe(&d2.stdout);
            for p in more {
                if !ok.iter().any(|x| x.addr == p.addr) {
                    ok.push(p);
                }
            }
            ok.sort_by(|a, b| b.td.cmp(&a.td));
        }
        if ok.len() < 2 {
            return Err("fewer than two public peers answered".into());
        }
        let text: String = ok.iter().map(|p| format!("{} pibd={}\n", p.addr, if p.pibd { "yes" } else { "no" })).collect();
        write(&cache, &text)?;
        job.line(&format!("peers answered: {} (pibd {})", ok.len(), ok.iter().filter(|p| p.pibd).count()));
        // The probe just connected to all of them: let them drop it first.
        std::thread::sleep(Duration::from_secs(5));
        Ok(ok)
    }

    fn sync(&self, w: &Wallet, cp: &Checkpoint, sync_peers: &[String], job: &Job) -> Result<SyncOut, String> {
        job.phase("headers");
        let checkpoint = std::fs::read(&cp.cp).map_err(|e| e.to_string())?;
        let history = std::fs::read(&cp.hist).map_err(|e| e.to_string())?;
        let peers = ss::distinct_peers(sync_peers, ss::dns_resolve)?;
        let sessions = w.p("sessions");
        std::fs::create_dir_all(&sessions).map_err(|e| e.to_string())?;
        let folder = sessions.join(format!("sync-{}", stamp()));
        std::fs::create_dir(&folder).map_err(|e| format!("{}: {e}", folder.display()))?;
        std::fs::write(folder.join("checkpoint.rwm"), &checkpoint).map_err(|e| e.to_string())?;
        std::fs::write(folder.join("recent-headers.bin"), &history).map_err(|e| e.to_string())?;
        let mut args = w.net();
        args.extend([
            "--checkpoint-file".into(), folder.join("checkpoint.rwm").display().to_string(),
            "--state-dir".into(), folder.display().to_string(),
            "--batches".into(), "1000".into(),
        ]);
        for p in &peers {
            args.extend(["--peer".into(), p.clone()]);
        }
        // Rolling checkpoint: snapshot at (last tip - 4320), 720-aligned.
        let roll_new = w.p("rolling-new");
        let mut snap = false;
        if let Some(last) = w.tip_height_of_known() {
            let target = (last.saturating_sub(4320) / 720) * 720;
            if target >= cp.height + 720 {
                let _ = std::fs::remove_dir_all(&roll_new);
                args.extend(["--snapshot-at".into(), target.to_string(), "--snapshot-dir".into(), roll_new.display().to_string()]);
                snap = true;
            }
        }
        // An old shipped checkpoint means many headers (up to ~a year): give it time.
        let d = run_exe(&self.exe(), &args, None, &folder.join("sync.log"), Some(job), Duration::from_secs(3600))?;
        let kv = ss::kv_lines(&d.stdout);
        if d.code != 0 || kv.get("HEADER_SYNC").map(String::as_str) != Some("PASS") {
            return Err(format!("header sync failed ({})", kv.get("HEADER_SYNC").cloned().unwrap_or_else(|| format!("exit {}", d.code))));
        }
        let cp_out = read(&folder.join("checkpoint.rwm"))?;
        let transcript = std::fs::read(folder.join(ss::TRANSCRIPT_FILE)).map_err(|e| e.to_string())?;
        let v = ss::sync_verdict(&SyncRun {
            stdout: &d.stdout,
            exit_code: d.code,
            checkpoint_out: &cp_out,
            transcript: &transcript,
            checkpoint_in: &checkpoint,
            history_in: &history,
            max_tip_age_sec: ss::DEFAULT_MAX_TIP_AGE_SEC,
            network: w.network,
            now: ss::now_unix(),
        })?;
        std::fs::write(folder.join("tip-header.bin"), &v.tip_header).map_err(|e| e.to_string())?;
        std::fs::write(folder.join(ss::MANIFEST_FILE), &v.manifest).map_err(|e| e.to_string())?;
        let manifest_sha = ss::sha256_hex(&v.manifest);
        let session = Session::open(&folder, &manifest_sha)?;
        if snap && v.report.get("snapshot").is_some_and(|s| !s.is_null()) && roll_new.join("checkpoint.rwm").exists() {
            let snapv = &v.report["snapshot"];
            let pin = format!(
                "root_base={}\nheight={}\nhash={}\ncheckpoint_sha256={}\nhistory_sha256={}\nmade={}\n",
                cp.base_sha,
                snapv["height"].as_str().unwrap_or(""),
                snapv["hash"].as_str().unwrap_or(""),
                sha_file(&roll_new.join("checkpoint.rwm"))?,
                sha_file(&roll_new.join("recent-headers.bin"))?,
                stamp()
            );
            write(&roll_new.join("pin.txt"), &pin)?;
            let roll = w.p("rolling");
            let _ = std::fs::remove_dir_all(&roll);
            std::fs::rename(&roll_new, &roll).map_err(|e| e.to_string())?;
            job.line(&format!("rolling checkpoint moved to {}", snapv["height"].as_str().unwrap_or("")));
        }
        // Keep the newest three sessions (the last-open one among them).
        if let Ok(rd) = std::fs::read_dir(&sessions) {
            let mut all: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
            all.sort();
            let n = all.len();
            for old in all.into_iter().take(n.saturating_sub(3)) {
                let _ = std::fs::remove_dir_all(old);
            }
        }
        job.line(&format!("headers: {} at height {}", v.status, session.tip_height()));
        Ok(SyncOut { session, manifest_sha, report: v.report })
    }

    // ---- open (sync + proven wallet update), with optional spend ----------

    /// The wallet run: checkpoint, peers, verified headers, then the proven
    /// UTXO state and own outputs at the tip (install the first time, only
    /// new blocks afterwards). `extra` adds a payment or a confirmation.
    pub fn run_open(&self, w: &Wallet, job: &Job, extra: &Extra) -> Result<(Value, Done), String> {
        let cp = self.checkpoint(w, job)?;
        let ok = self.peers(w, job, false)?;
        let installed = w.installed();
        let (sync_list, gap_list) = select_peers(&ok, if installed { 4 } else { 8 });
        let s = self.sync(w, &cp, &sync_list, job)?;
        if s.session.manifest.sync_status != "PASS" {
            return Err(format!("header sync is {} (tip too old or peers not caught up); try again later", s.session.manifest.sync_status));
        }
        let mut mode = if installed { "QUICK" } else { "INSTALL" };
        job.phase(if installed { "new blocks" } else { "install (archive state + full wallet scan)" });
        let mut d = self.gap(w, &s, &gap_list, mode, extra, job)?;
        if mode == "QUICK" && d.value("GAP_WALLET_STALE").is_some() {
            job.line("saved wallet is older than the saved state: full scan once");
            mode = "INSTALL";
            d = self.gap(w, &s, &gap_list, mode, extra, job)?;
        }
        if !matches!(d.code, 0 | 3 | 5) || d.stdout.lines().any(|l| l.starts_with("GAP=FAIL")) {
            let why = d.stdout.lines().rev().find(|l| l.starts_with("GAP=FAIL") || l.starts_with("GAP_PROVE_VERDICT=")).unwrap_or("");
            return Err(format!("wallet update failed (exit {}) {why}", d.code));
        }
        let report = ss::gap_report(&s.session, &d.stdout, d.code, ss::now_unix());
        let kv = ss::kv_lines(&report);
        let wallet_line = d.value("GAP_WALLET").unwrap_or("").to_string();
        let last = json!({
            "at": chrono::Utc::now().to_rfc3339(),
            "mode": mode,
            "session": s.session.folder.display().to_string(),
            "manifest_sha256": s.manifest_sha,
            "tip_height": s.session.tip_height(),
            "sync": Value::Object(s.report.clone()),
            "proof_verdict": d.value("GAP_PROVE_VERDICT"),
            "current_tip_state": kv.get("CURRENT_TIP_STATE"),
            "balance_authentication": d.value("GAP_WALLET_BALANCE_AUTHENTICATION"),
            "wallet": wallet_line,
            "blocks": d.value("GAP_BLOCKS"),
            "peers_sync": sync_list,
            "peers_blocks": gap_list,
        });
        write(&w.p("last-open.json"), &serde_json::to_string_pretty(&last).unwrap())?;
        self.apply_block_checks(w, &d, s.session.tip_height());
        Ok((last, d))
    }

    /// Outgoing payments whose block must be re-checked: (folder, "HEIGHT:HASH").
    fn recheck_targets(&self, w: &Wallet) -> Vec<(PathBuf, String)> {
        let tip = w.verified_tip();
        let mut out = Vec::new();
        for d in std::fs::read_dir(w.p("txs")).map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect::<Vec<_>>()).unwrap_or_default() {
            let Some(c) = std::fs::read_to_string(d.join("confirm.json")).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()) else { continue };
            if !matches!(c["state"].as_str(), Some("in_block" | "confirmed" | "unknown")) {
                continue;
            }
            let (Some(h), Some(hash)) = (c["height"].as_u64(), c["hash"].as_str()) else { continue };
            if hash.len() != 64 || h + DEEP_REORG < tip {
                continue;
            }
            out.push((d, format!("{h}:{hash}")));
        }
        out
    }

    /// Results of the block checks of [`Self::recheck_targets`] into each
    /// payment's confirm.json, stamped with the tip they were checked at.
    fn apply_block_checks(&self, w: &Wallet, d: &Done, tip: u64) {
        let checks = d.values("GAP_BLOCK_CHECK");
        for (dir, spec) in self.recheck_targets(w) {
            let Some(chk) = checks.iter().find(|v| v.starts_with(&format!("{spec} "))) else { continue };
            let Ok(mut c) = std::fs::read_to_string(dir.join("confirm.json")).map_err(|_| ()).and_then(|t| serde_json::from_str::<Value>(&t).map_err(|_| ())) else { continue };
            if chk.contains("NOT_ON_VERIFIED_CHAIN") {
                c["state"] = json!("reorged");
                c["depth"] = json!(0);
            } else if let Some(dep) = chk.split("ON_VERIFIED_CHAIN depth=").nth(1).and_then(|x| x.split(' ').next()).and_then(|x| x.parse::<u64>().ok()) {
                c["state"] = json!(if dep >= CONFIRMATIONS { "confirmed" } else { "in_block" });
                c["depth"] = json!(dep);
            } else {
                c["state"] = json!("unknown");
                c["note"] = json!(chk);
            }
            c["checked_at_tip"] = json!(tip);
            let _ = write(&dir.join("confirm.json"), &c.to_string());
            if let Some(s) = c["state"].as_str().filter(|s| *s != "unknown") {
                let _ = Self::set_meta(&dir, json!({ "stage": s }));
            }
        }
    }

    fn gap(&self, w: &Wallet, s: &SyncOut, peers: &[String], mode: &str, extra: &Extra, job: &Job) -> Result<Done, String> {
        let mut r = GapRequest::new();
        r.mainnet = w.mainnet();
        r.commitments = vec![PROBE_COMMITMENT.into()];
        r.commitments.extend(extra.commitments.iter().cloned());
        r.kernels = extra.kernels.clone();
        r.check_blocks = extra.check_blocks.clone();
        // Blocks of recent outgoing payments: re-checked on this verified chain
        // with every refresh, so the history never shows a stale "in block".
        for (_, spec) in self.recheck_targets(w) {
            if !r.check_blocks.contains(&spec) {
                r.check_blocks.push(spec);
            }
        }
        r.peers = ss::distinct_peers(peers, ss::dns_resolve)?;
        r.prove = true;
        r.state_dir = Some(w.state_dir());
        r.seeds = Some(PathBuf::from("-"));
        r.pending = Some(w.pending());
        r.wallet_out = Some(w.known());
        if mode == "QUICK" {
            r.wallet_in = Some(w.known());
        }
        r.segment_height = if w.mainnet() { 13 } else { 11 };
        r.timeout_sec = 7200;
        if let Some(t) = &extra.tx_dir {
            if let Some((to, amount)) = &extra.send_to {
                r.spend = Some("auto:1".into());
                r.send_to = Some(to.clone());
                r.send_amount = Some(*amount);
                r.slatepack_out = Some(t.join("slatepack-s1.txt"));
                r.context_out = Some(t.join("send-context.json"));
            }
            if let Some(inv) = &extra.pay_invoice {
                r.spend = Some("auto:1".into());
                r.pay_invoice = Some(inv.clone());
                r.slatepack_out = Some(t.join("invoice-i2.txt"));
            }
            r.allow_mainnet_spend = r.spend.is_some() && w.mainnet();
        }
        let tmp = w.p("tmp");
        std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
        let hf = tmp.join("gap-headers.bin");
        let plan = ss::plan_gap(&s.session, &r, &w.dir, &hf, ss::now_unix())?;
        std::fs::write(&hf, &plan.headers_file).map_err(|e| e.to_string())?;
        let log = match &extra.tx_dir {
            Some(t) => t.join("wallet-run.log"),
            None => w.log("wallet"),
        };
        let d = run_exe(&self.exe(), &plan.args, Some(&w.phrase), &log, Some(job), Duration::from_secs(r.timeout_sec + 60));
        let _ = std::fs::remove_file(&hf);
        d
    }

    // ---- offline operations ----------------------------------------------

    pub fn address(&self) -> Result<Value, String> {
        let w = self.wallet()?;
        let f = w.p("address.txt");
        if let Ok(a) = std::fs::read_to_string(&f) {
            return Ok(json!({ "address": a.trim() }));
        }
        let mut a = w.net();
        a.extend(["--slatepack-address".into(), "--seeds".into(), "-".into()]);
        let d = run_exe(&self.exe(), &a, Some(&w.phrase), &w.log("address"), None, Duration::from_secs(60))?;
        let addr = d
            .values("SLATEPACK_ADDRESS")
            .into_iter()
            .find_map(|v| v.strip_prefix("wallet=1 "))
            .ok_or("no slatepack address")?
            .trim()
            .to_string();
        write(&f, &addr)?;
        Ok(json!({ "address": addr }))
    }

    fn new_tx(&self, w: &Wallet, kind: &str) -> Result<(String, PathBuf), String> {
        let id = format!("{}-{kind}", stamp());
        let d = w.p("txs").join(&id);
        std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
        Ok((id, d))
    }

    fn tx_dir(&self, w: &Wallet, id: &str) -> Result<PathBuf, String> {
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_') || id.contains("..") {
            return Err("bad payment id".into());
        }
        let d = w.p("txs").join(id);
        if !d.is_dir() {
            return Err("no such payment".into());
        }
        Ok(d)
    }

    fn find_tx(&self, w: &Wallet, kind: &str, slate_id: &str) -> Option<String> {
        let mut dirs: Vec<PathBuf> = std::fs::read_dir(w.p("txs")).ok()?.flatten().map(|e| e.path()).collect();
        dirs.sort();
        dirs.into_iter()
            .find(|d| {
                let m = Self::meta(d);
                m["kind"] == kind && m["slate_id"] == slate_id
            })
            .map(|d| d.file_name().unwrap().to_string_lossy().into_owned())
    }

    fn meta(dir: &Path) -> Value {
        std::fs::read_to_string(dir.join("meta.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(json!({}))
    }

    fn set_meta(dir: &Path, add: Value) -> Result<(), String> {
        let mut m = Self::meta(dir);
        if let (Some(o), Value::Object(a)) = (m.as_object_mut(), add) {
            for (k, v) in a {
                o.insert(k, v);
            }
        }
        write(&dir.join("meta.json"), &serde_json::to_string_pretty(&m).unwrap())
    }

    /// A slatepack (armored) or a plain V4 slate JSON: JSON is what
    /// grin-wallet's Tor foreign API sends and what the Tor daemon saves in
    /// its inbox/pending folders.
    fn check_slatepack(text: &str) -> Result<(), String> {
        let t = text.trim_start();
        if text.len() > 64 * 1024 || !(t.starts_with('{') || text.contains("BEGINSLATEPACK")) {
            return Err("not a slatepack (BEGINSLATEPACK ... ENDSLATEPACK., or a plain slate JSON)".into());
        }
        Ok(())
    }

    /// Someone pays us: their S1 -> our S2 (no network).
    pub fn receive(&self, slatepack: &str) -> Result<Value, String> {
        self.receive_text(slatepack, None)
    }

    /// The receive itself. `armor_out` gets the answer as a slatepack even
    /// when the S1 was JSON (the Tor foreign API answers in JSON, but a person
    /// handing the S2 over by hand needs the armor for `grin-wallet finalize`).
    fn receive_text(&self, slatepack: &str, armor_out: Option<&Path>) -> Result<Value, String> {
        let w = self.wallet()?;
        Self::check_slatepack(slatepack)?;
        if !w.keys_known() {
            return Err("open the wallet once first: a restored wallet must find which keys are already used".into());
        }
        let (id, dir) = self.new_tx(&w, "receive")?;
        let inp = dir.join("slatepack-in.txt");
        write(&inp, slatepack)?;
        let out = dir.join("slatepack-answer.txt");
        let mut a = w.net();
        a.extend([
            "--receive-slatepack".into(), inp.display().to_string(), "--seeds".into(), "-".into(), "--wallet".into(), "1".into(),
            "--response-out".into(), out.display().to_string(), "--pending".into(), w.pending().display().to_string(),
            "--known-outputs".into(), w.known().display().to_string(),
        ]);
        if let Some(t) = w.tip_height_of_known() {
            a.extend(["--tip-height".into(), t.to_string()]);
        }
        if let Some(ao) = armor_out {
            a.extend(["--armor-out".into(), ao.display().to_string()]);
        }
        let d = run_exe(&self.exe(), &a, Some(&w.phrase), &dir.join("receive.log"), None, Duration::from_secs(120))?;
        if d.code != 0 {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(d.value("RECEIVE").unwrap_or("receive failed").to_string());
        }
        let sid = d.value("RECEIVE_SLATE_ID").unwrap_or("").to_string();
        if d.value("RECEIVE").is_some_and(|x| x.starts_with("RESENT")) {
            // Already received: the same answer; keep the first record only.
            if let Some(first) = self.find_tx(&w, "receive", &sid) {
                let answer = read(&out)?;
                let _ = std::fs::remove_dir_all(&dir);
                let m = Self::meta(&w.p("txs").join(&first));
                return Ok(json!({ "tx_id": first, "answer": answer.trim(), "amount": m["amount"], "slate_id": sid,
                                  "from": m["from"], "sender_verified": m["sender_verified"], "resent": true }));
            }
        }
        let amount: u64 = d.value("RECEIVE_AMOUNT").and_then(|x| x.parse().ok()).unwrap_or(0);
        Self::set_meta(&dir, json!({
            "kind": "receive", "created": chrono::Utc::now().to_rfc3339(), "amount": amount,
            "slate_id": d.value("RECEIVE_SLATE_ID"), "from": d.value("RECEIVE_FROM"),
            "sender_verified": d.value("RECEIVE_SENDER_VERIFIED") == Some("true"),
            "commit": d.value("RECEIVE_NEW_OUTPUT"), "resent": d.value("RECEIVE").is_some_and(|x| x.starts_with("RESENT")),
        }))?;
        Ok(json!({ "tx_id": id, "answer": read(&out)?.trim(), "amount": amount, "slate_id": d.value("RECEIVE_SLATE_ID"),
                   "from": d.value("RECEIVE_FROM"), "sender_verified": d.value("RECEIVE_SENDER_VERIFIED") == Some("true"), "resent": false }))
    }

    /// Accept a payment from the Tor daemon's inbox by hand (the sender's
    /// wait ran out, so the answer is a slatepack for `grin-wallet finalize`).
    /// Returns the S2 armor; the inbox file and its meta sidecar are removed.
    pub fn receive_inbox(&self, file: &str) -> Result<Value, String> {
        let w = self.wallet()?;
        let f = Self::inbox_payment_path(&w, file)?;
        let text = read(&f)?;
        Self::check_slatepack(&text)?;
        let tmp = w.p("tmp");
        std::fs::create_dir_all(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        let armor = tmp.join(format!("inbox-answer-{}.txt", stamp()));
        let r = self.receive_text(&text, Some(&armor))?;
        // JSON S1 in, JSON S2 in the response file; the armor file is what a
        // person can hand to grin-wallet (also when the input was armor).
        let answer = std::fs::read_to_string(&armor)
            .map(|t| t.trim().to_string())
            .unwrap_or_else(|_| r["answer"].as_str().unwrap_or("").to_string());
        let _ = std::fs::remove_file(&armor);
        // Accepted: the request is done; the daemon expects the file to go.
        let _ = std::fs::remove_file(&f);
        let inbox = w.p("tor-wallet-1/inbox");
        let _ = std::fs::remove_file(inbox.join(meta_name(file)));
        let _ = std::fs::remove_file(inbox.join(format!("{file}.meta.json")));
        Ok(json!({
            "tx_id": r["tx_id"], "answer": &answer, "slatepack": &answer,
            "amount": r["amount"], "from": r["from"], "sender_verified": r["sender_verified"],
            "slate_id": r["slate_id"], "resent": r["resent"],
        }))
    }

    /// A payment file in the Tor daemon's inbox: a plain file name only, never
    /// an invoice (those are paid with `wallet.pay_invoice`) or a sidecar.
    fn inbox_payment_path(w: &Wallet, file: &str) -> Result<PathBuf, String> {
        if file.is_empty() || file.contains(['/', '\\', ':']) || file.contains("..") {
            return Err("bad inbox file".into());
        }
        if file.ends_with(".meta.json") || file.ends_with(".peer") || file.ends_with(".s2.txt") {
            return Err("bad inbox file".into());
        }
        if file.starts_with("invoice-") {
            return Err("this is an invoice, not a payment: pay it with wallet.pay_invoice".into());
        }
        let p = w.p("tor-wallet-1/inbox").join(file);
        if !p.is_file() {
            return Err("no such inbox file".into());
        }
        Ok(p)
    }

    /// Ask for a payment: I1 (no network).
    pub fn invoice_create(&self, amount: u64, payer: Option<&str>) -> Result<Value, String> {
        let w = self.wallet()?;
        if amount == 0 {
            return Err("amount must be positive".into());
        }
        if !w.keys_known() {
            return Err("open the wallet once first: a restored wallet must find which keys are already used".into());
        }
        let (id, dir) = self.new_tx(&w, "invoice")?;
        let i1 = dir.join("invoice-i1.txt");
        let mut a = w.net();
        a.extend([
            "--issue-invoice".into(), amount.to_string(), "--seeds".into(), "-".into(), "--wallet".into(), "1".into(),
            "--pending".into(), w.pending().display().to_string(), "--known-outputs".into(), w.known().display().to_string(),
            "--slatepack-out".into(), i1.display().to_string(), "--context-out".into(), dir.join("invoice-context.json").display().to_string(),
        ]);
        if let Some(p) = payer.filter(|p| !p.is_empty()) {
            self.check_address(&w, p)?;
            a.extend(["--payer".into(), p.into()]);
        }
        let d = run_exe(&self.exe(), &a, Some(&w.phrase), &dir.join("invoice.log"), None, Duration::from_secs(120))?;
        if d.code != 0 {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(d.value("INVOICE").unwrap_or("invoice failed").to_string());
        }
        Self::set_meta(&dir, json!({ "kind": "invoice", "created": chrono::Utc::now().to_rfc3339(), "amount": amount,
            "slate_id": d.value("INVOICE_SLATE_ID"), "to": payer, "commit": d.value("INVOICE_OUTPUT") }))?;
        Ok(json!({ "tx_id": id, "slatepack": read(&i1)?.trim(), "slate_id": d.value("INVOICE_SLATE_ID") }))
    }

    fn check_address(&self, w: &Wallet, a: &str) -> Result<(), String> {
        let prefix = if w.mainnet() { "grin1" } else { "tgrin1" };
        if !a.starts_with(prefix) || a.len() > 120 || !a.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(format!("the address must be a {prefix}... slatepack address"));
        }
        Ok(())
    }

    // ---- jobs: send, pay invoice, finalize, broadcast, confirm, open -------

    pub fn start_open(self: &Arc<Self>) -> Result<Value, String> {
        let w = self.wallet()?;
        // «Обновить» дважды подряд: второй вызов присоединяется к идущему
        // обновлению (тот же job), а не падает с «another wallet operation».
        if let Some(running) = self.jobs.busy() {
            if running.starts_with("open-") {
                return Ok(json!({ "job": running, "joined": true }));
            }
        }
        let me = self.clone();
        let id = self.jobs.start("open", true, move |job| {
            let (last, _) = me.run_open(&w, job, &Extra::default())?;
            Ok(json!({ "last_open": last, "status": me.status().unwrap_or(Value::Null) }))
        })?;
        Ok(json!({ "job": id }))
    }

    // ---- own checkpoint (works before login: no wallet needed) ------------
    //
    // The user can check the shipped checkpoint himself: every header from
    // GENESIS is validated (PoW, difficulty, header MMR) from independent
    // peers up to the shipped checkpoint height, and the result is compared
    // with the shipped one. It lives in `<data>/own-checkpoint/<net>/`, shared
    // by all wallets of that network. Resumable: cancel = pause (snapshots in
    // `progress/`), the next start continues from the last one.

    fn own_cp_dir(&self, n: Network) -> PathBuf {
        self.cfg.data_dir.join("own-checkpoint").join(net_name(n))
    }

    /// The open wallet's network, else `network` from the request (login screen).
    fn request_network(&self, p: &Value) -> Result<Network, String> {
        if let Ok(w) = self.wallet() {
            return Ok(w.network);
        }
        network_from(p.get("network").and_then(Value::as_str).unwrap_or("mainnet"))
    }

    /// `height` / `hash` lines of a checkpoint.rwm.
    fn rwm_head(path: &Path) -> Option<(u64, String)> {
        let t = std::fs::read_to_string(path).ok()?;
        let h = t.lines().find_map(|l| l.strip_prefix("height ").and_then(|x| x.trim().parse().ok()))?;
        let x = t.lines().find_map(|l| l.strip_prefix("hash ").map(|x| x.trim().to_string()))?;
        Some((h, x))
    }

    /// Age in days of a checkpoint.rwm: the timestamp in its header (bytes 10..18, big-endian).
    fn rwm_age_days(path: &Path) -> Option<i64> {
        let t = std::fs::read_to_string(path).ok()?;
        let hex = t.lines().find_map(|l| l.strip_prefix("header "))?.trim();
        let ts = i64::from_str_radix(hex.get(20..36)?, 16).ok()?;
        Some((chrono::Utc::now().timestamp() - ts) / 86_400)
    }

    /// The checkpoint shipped with the app for this network.
    fn shipped_info(&self, n: Network) -> Value {
        let src = self.cfg.checkpoints_dir.join(net_name(n));
        let Some((height, hash)) = Self::rwm_head(&src.join("checkpoint.rwm")) else {
            return json!({ "exists": false, "height": null, "hash": null, "signed": false });
        };
        let signed = src.join("release.txt").exists();
        json!({ "exists": true, "height": height, "hash": hash, "signed": signed,
                "age_days": Self::rwm_age_days(&src.join("checkpoint.rwm")),
                "checkpoint_sha256": sha_file(&src.join("checkpoint.rwm")).ok() })
    }

    fn own_info(&self, n: Network) -> Value {
        let dir = self.own_cp_dir(n);
        let res: Option<Value> = std::fs::read_to_string(dir.join("result.json")).ok().and_then(|t| serde_json::from_str(&t).ok());
        match res {
            Some(r) => {
                let mut r = r;
                r["built"] = json!(true);
                r["paused"] = json!(false);
                r
            }
            None => {
                let paused = std::fs::read_dir(dir.join("progress")).map(|mut d| d.next().is_some()).unwrap_or(false);
                json!({ "built": false, "paused": paused, "height": null, "hash": null, "matches": null })
            }
        }
    }

    /// Shipped and own checkpoint of a network, and the open wallet's choice.
    pub fn checkpoint_info(&self, p: &Value) -> Result<Value, String> {
        let n = self.request_network(p)?;
        let (source, offer_seen) = match self.wallet() {
            Ok(w) => {
                let s = w.settings();
                (s["checkpoint_source"].as_str().unwrap_or("release").to_string(), s["checkpoint_offer_seen"].as_bool().unwrap_or(false))
            }
            Err(_) => ("release".to_string(), false),
        };
        Ok(json!({
            "network": net_name(n),
            "source": source,
            "offer_seen": offer_seen,
            "shipped": self.shipped_info(n),
            "own": self.own_info(n),
            "running": self.jobs.busy().filter(|j| j.starts_with("own-checkpoint-")),
        }))
    }

    /// Public peers for a genesis sync, without a wallet: DNS seeds, the
    /// user's own peers, probe; then up to 3 peers from different /16 nets.
    fn own_cp_peers(&self, n: Network, dir: &Path, job: &Job) -> Result<Vec<String>, String> {
        job.phase("peers");
        let mainnet = n == Network::Mainnet;
        let port = if mainnet { 3414 } else { 13414 };
        let seeds = if mainnet { ss::MAINNET_DNS_SEEDS } else { ss::FLOONET_DNS_SEEDS };
        let answers: Vec<_> = seeds.iter().filter_map(|h| ss::dns_resolve(h, port).ok()).collect();
        let settings = self.wallet().map(|w| w.settings()).unwrap_or_else(|_| self.pre_settings());
        let extra: Vec<String> = settings["extra_peers"].as_array().cloned().unwrap_or_default().iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        let builtin: Vec<String> = if mainnet { vec![] } else { FLOONET_PEERS.iter().map(|s| s.to_string()).collect() };
        let mut list: Vec<String> = Vec::new();
        for a in extra.into_iter().chain(builtin).chain(ss::seed_peers(&answers, port, 16)) {
            if list.len() < 24 && !list.contains(&a) {
                list.push(a);
            }
        }
        if list.is_empty() {
            return Err("no DNS seed answered and no peers are known (add your own peer)".into());
        }
        let mut a: Vec<String> = if mainnet { vec!["--mainnet".into(), "--discover".into()] } else { vec!["--discover".into()] };
        for p in &list {
            a.extend(["--probe-peer".into(), p.clone()]);
        }
        let d = run_exe(&self.exe(), &a, None, &dir.join("probe.log"), Some(job), Duration::from_secs(180))?;
        let (mut ok, _) = parse_probe(&d.stdout);
        ok.sort_by(|a, b| b.td.cmp(&a.td));
        // Different /16 networks (IPv4) or /32 (IPv6): independent operators.
        let net16 = |addr: &str| -> String {
            let host = ss::split_peer(addr).map(|(h, _)| h).unwrap_or_default();
            if host.contains(':') {
                host.split(':').take(2).collect::<Vec<_>>().join(":")
            } else {
                host.split('.').take(2).collect::<Vec<_>>().join(".")
            }
        };
        let mut chosen: Vec<String> = Vec::new();
        for p in ok {
            if chosen.len() >= 3 {
                break;
            }
            if !chosen.iter().any(|c| net16(c) == net16(&p.addr)) {
                chosen.push(p.addr);
            }
        }
        if chosen.len() < 2 {
            return Err("fewer than two independent public peers answered; try later or add your own peer".into());
        }
        job.line(&format!("peers for the genesis check: {}", chosen.join(", ")));
        // Let them drop the probe connection first.
        std::thread::sleep(Duration::from_secs(5));
        Ok(chosen)
    }

    /// Job: validate all headers from genesis up to the shipped checkpoint
    /// height and compare with the shipped checkpoint (no wallet needed).
    pub fn start_own_checkpoint(self: &Arc<Self>, p: &Value) -> Result<Value, String> {
        let n = self.request_network(p)?;
        if let Some(running) = self.jobs.busy() {
            if running.starts_with("own-checkpoint-") {
                return Ok(json!({ "job": running, "joined": true }));
            }
        }
        let me = self.clone();
        let id = self.jobs.start("own-checkpoint", true, move |job| {
            let dir = me.own_cp_dir(n);
            std::fs::create_dir_all(dir.join("progress")).map_err(|e| format!("{}: {e}", dir.display()))?;
            let shipped = me.shipped_info(n);
            let peers = me.own_cp_peers(n, &dir, job)?;
            job.phase("headers from genesis");
            let state = dir.join("state");
            let _ = std::fs::remove_dir_all(&state);
            let _ = std::fs::remove_file(dir.join("result.json"));
            let mut args: Vec<String> = if n == Network::Mainnet { vec!["--mainnet".into()] } else { vec![] };
            args.extend([
                "--checkpoint".into(), "genesis".into(),
                "--batches".into(), "20000".into(),
                "--digest-run".into(),
                "--state-dir".into(), state.display().to_string(),
                "--progress-dir".into(), dir.join("progress").display().to_string(),
            ]);
            // A FRESH point (3 days below the tip, below any PIBD archive), and on
            // the way the shipped one is checked: its header must be on this chain.
            args.extend(["--stop-below-tip".into(), "4320".into()]);
            if let (Some(h), Some(x)) = (shipped["height"].as_u64(), shipped["hash"].as_str()) {
                args.extend(["--check-header".into(), format!("{h}:{x}")]);
            }
            for p in &peers {
                args.extend(["--peer".into(), p.clone()]);
            }
            let d = run_exe(&me.exe(), &args, None, &dir.join("sync.log"), Some(job), Duration::from_secs(12 * 3600))?;
            let kv = ss::kv_lines(&d.stdout);
            if d.code != 0 || kv.get("HEADER_SYNC").map(String::as_str) != Some("PASS") {
                return Err(format!(
                    "headers from genesis did not pass ({}); progress is kept, start again to continue",
                    kv.get("HEADER_SYNC").cloned().unwrap_or_else(|| format!("exit {}", d.code))
                ));
            }
            let cp = state.join("checkpoint.rwm");
            let (height, hash) = Self::rwm_head(&cp).ok_or("the genesis check wrote no checkpoint")?;
            // Every peer's chain prints a CHECK_HEADER line at the shipped height.
            let mismatch = d.stdout.lines().any(|l| l.starts_with("HEADER_SYNC_CHECK_HEADER=MISMATCH"));
            let seen = d.stdout.lines().any(|l| l.starts_with("HEADER_SYNC_CHECK_HEADER=MATCH"));
            let matches: Option<bool> = if shipped["exists"].as_bool() != Some(true) {
                None
            } else if mismatch {
                Some(false)
            } else if seen {
                Some(true)
            } else if shipped["height"].as_u64() == Some(height) {
                Some(shipped["hash"].as_str() == Some(hash.as_str()))
            } else {
                None
            };
            let res = json!({
                "height": height,
                "hash": hash,
                "checkpoint_sha256": sha_file(&cp)?,
                "history_sha256": sha_file(&state.join("recent-headers.bin")).ok(),
                "matches": matches,
                "peers": peers,
                "built_at": chrono::Utc::now().to_rfc3339(),
            });
            write(&dir.join("result.json"), &serde_json::to_string_pretty(&res).unwrap())?;
            job.line(&format!("own checkpoint at {height}: {}", match matches {
                Some(true) => "the shipped checkpoint is on this chain",
                Some(false) => "the shipped checkpoint is NOT on this chain",
                None => "nothing shipped to compare with",
            }));
            Ok(json!({ "own": me.own_info(n), "shipped": shipped }))
        })?;
        Ok(json!({ "job": id }))
    }

    /// Experiment «Пощупать будущее»: probe the network and list peers that
    /// advertise HEADER_PROOF_HIST (PR #3963). Returns {checked, patched, peers}.
    /// Network-level HEADER_PROOF_HIST discovery. Works before a wallet is
    /// open: `network` is explicit because the login screen has no profile.
    pub fn header_proof_peers(&self, p: &Value) -> Result<Value, String> {
        let network = p.get("network").and_then(Value::as_str).unwrap_or("mainnet");
        let mainnet = match network {
            "mainnet" => true,
            "floonet" | "testnet" => false,
            _ => return Err("network: mainnet | floonet".into()),
        };
        grin_core::global::set_global_chain_type(if mainnet {
            grin_core::global::ChainTypes::Mainnet
        } else {
            grin_core::global::ChainTypes::Testnet
        });
        let mut cmd = std::process::Command::new(self.exe());
        if mainnet {
            cmd.arg("--mainnet");
        }
        cmd.arg("--header-proof-peers");
        if let Some(a) = p.get("peers").and_then(Value::as_array) {
            for peer in a.iter().filter_map(Value::as_str) {
                cmd.arg("--header-proof-peer").arg(peer);
            }
        }
        let out = cmd.output().map_err(|e| format!("probe: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut checked = 0usize;
        let mut list: Vec<Value> = Vec::new();
        for line in stdout.lines() {
            if let Some(v) = line.strip_prefix("HEADER_PROOF_CHECKED=") {
                checked = v.trim().parse().unwrap_or(0);
            }
            if let Some(rest) = line.strip_prefix("HEADER_PROOF_PEER=") {
                let mut parts = rest.split_whitespace();
                let addr = parts.next().unwrap_or("").to_string();
                let agent = parts.next().unwrap_or("").to_string();
                let height = parts
                    .find_map(|x| x.strip_prefix("height="))
                    .and_then(|x| x.parse::<u64>().ok())
                    .unwrap_or(0);
                if !addr.is_empty() {
                    list.push(json!({ "addr": addr, "agent": agent, "height": height }));
                }
            }
        }
        Ok(json!({ "checked": checked, "patched": list.len(), "peers": list }))
    }

    /// Honest sample endpoint: discovery is implemented; the live proof wire
    /// path is not enabled until a HEADER_PROOF_HIST peer is reachable.
    pub fn header_proof_sample(&self, p: &Value) -> Result<Value, String> {
        let peers = self.header_proof_peers(p)?;
        let patched = peers.get("patched").and_then(Value::as_u64).unwrap_or(0);
        if patched == 0 {
            return Ok(json!({
                "sampled": 0, "verified": 0, "patched": 0,
                "message": "no HEADER_PROOF_HIST peers found; stay on checkpoint mode"
            }));
        }
        Err("HEADER_PROOF_HIST peer found, but live GetHeaderProofs sampling is not wired yet".into())
    }

    pub fn start_header_proof_peers(self: &Arc<Self>) -> Result<Value, String> {
        let w = self.wallet()?;
        let me = self.clone();
        let id = self.jobs.start("header-proof-peers", true, move |job| {
            let peers = me.peers(&w, job, true)?;
            let patched: Vec<Value> = peers
                .iter()
                .filter(|p| p.header_proof)
                .map(|p| json!({ "addr": p.addr, "pibd": p.pibd, "header_proof": true }))
                .collect();
            Ok(json!({ "checked": peers.len(), "patched": patched.len(), "peers": patched }))
        })?;
        Ok(json!({ "job": id }))
    }

    pub fn start_send(self: &Arc<Self>, to: &str, amount: u64) -> Result<Value, String> {
        let w = self.wallet()?;
        self.check_address(&w, to)?;
        if amount == 0 {
            return Err("amount must be positive".into());
        }
        let me = self.clone();
        let to = to.to_string();
        let id = self.jobs.start("send", true, move |job| {
            let (txid, dir) = me.new_tx(&w, "send")?;
            Self::set_meta(&dir, json!({ "kind": "send", "created": chrono::Utc::now().to_rfc3339(), "amount": amount, "to": to, "stage": "building" }))?;
            let extra = Extra { send_to: Some((to.clone(), amount)), tx_dir: Some(dir.clone()), ..Default::default() };
            let r = me.run_open(&w, job, &extra);
            let d = match r {
                Ok((_, d)) => d,
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&dir);
                    return Err(e);
                }
            };
            let s1 = dir.join("slatepack-s1.txt");
            if !s1.exists() {
                let why = d.stdout.lines().rev().find(|l| l.starts_with("GAP_SPEND") || l.starts_with("SEND")).unwrap_or("payment was not built").to_string();
                let _ = std::fs::remove_dir_all(&dir);
                return Err(why);
            }
            let fee: u64 = d.value("SEND_FEE").and_then(|x| x.parse().ok()).unwrap_or(0);
            Self::set_meta(&dir, json!({ "stage": "waiting_answer", "slate_id": d.value("SEND_SLATE_ID"), "fee": fee,
                "change": d.value("SEND_CHANGE").and_then(|x| x.parse::<u64>().ok()), "inputs": d.value("SEND_INPUT"),
                "change_output": d.value("SEND_CHANGE_OUTPUT") }))?;
            Ok(json!({ "tx_id": txid, "slatepack": read(&s1)?.trim(), "slate_id": d.value("SEND_SLATE_ID"), "amount": amount, "fee": fee }))
        })?;
        Ok(json!({ "job": id }))
    }

    pub fn start_pay_invoice(self: &Arc<Self>, slatepack: &str) -> Result<Value, String> {
        let w = self.wallet()?;
        Self::check_slatepack(slatepack)?;
        let me = self.clone();
        let text = slatepack.to_string();
        let id = self.jobs.start("pay-invoice", true, move |job| {
            let (txid, dir) = me.new_tx(&w, "pay-invoice")?;
            let inv = dir.join("invoice-in.txt");
            write(&inv, &text)?;
            Self::set_meta(&dir, json!({ "kind": "pay_invoice", "created": chrono::Utc::now().to_rfc3339(), "stage": "building" }))?;
            let extra = Extra { pay_invoice: Some(inv), tx_dir: Some(dir.clone()), ..Default::default() };
            let d = match me.run_open(&w, job, &extra) {
                Ok((_, d)) => d,
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&dir);
                    return Err(e);
                }
            };
            let i2 = dir.join("invoice-i2.txt");
            if !i2.exists() {
                let why = d.stdout.lines().rev().find(|l| l.starts_with("PAY_INVOICE") || l.starts_with("GAP_SPEND")).unwrap_or("invoice was not paid").to_string();
                let _ = std::fs::remove_dir_all(&dir);
                return Err(why);
            }
            let amount: u64 = d.value("PAY_INVOICE_AMOUNT").and_then(|x| x.parse().ok()).unwrap_or(0);
            Self::set_meta(&dir, json!({ "stage": "waiting_issuer", "slate_id": d.value("PAY_INVOICE_SLATE_ID"), "amount": amount,
                "to": d.value("PAY_INVOICE_TO"), "fee": d.value("PAY_INVOICE_FEE").and_then(|x| x.parse::<u64>().ok()) }))?;
            Ok(json!({ "tx_id": txid, "answer": read(&i2)?.trim(), "amount": amount, "slate_id": d.value("PAY_INVOICE_SLATE_ID") }))
        })?;
        Ok(json!({ "job": id }))
    }

    /// The other side's answer (S2 to our S1, or I2 to our I1): build and sign
    /// the transaction; broadcast it right away when `broadcast` (default: the
    /// auto_broadcast setting).
    pub fn start_finalize(self: &Arc<Self>, tx_id: &str, answer: &str, broadcast: Option<bool>) -> Result<Value, String> {
        let w = self.wallet()?;
        Self::check_slatepack(answer)?;
        let dir = self.tx_dir(&w, tx_id)?;
        let (flag, ctx_name, ctx_flag) = if dir.join("invoice-context.json").exists() {
            ("--finalize-invoice", "invoice-context.json", "--invoice-context")
        } else if dir.join("send-context.json").exists() {
            ("--finalize-slatepack", "send-context.json", "--send-context")
        } else {
            return Err("nothing to finalize in this payment (already finalized?)".into());
        };
        let bc = broadcast.unwrap_or_else(|| w.settings()["auto_broadcast"].as_bool().unwrap_or(true));
        let me = self.clone();
        let answer = answer.to_string();
        let id = self.jobs.start("finalize", true, move |job| {
            job.phase("finalize");
            let ans = dir.join("slatepack-answer-in.txt");
            write(&ans, &answer)?;
            let tx = dir.join("spend-tx.hex");
            let mut a = w.net();
            a.extend([flag.into(), ans.display().to_string(), "--seeds".into(), "-".into(), ctx_flag.into(), dir.join(ctx_name).display().to_string(), "--tx-out".into(), tx.display().to_string()]);
            if flag == "--finalize-slatepack" {
                a.extend(["--proof-out".into(), dir.join("payment-proof.json").display().to_string()]);
            }
            let d = run_exe(&me.exe(), &a, Some(&w.phrase), &dir.join("finalize.log"), Some(job), Duration::from_secs(120))?;
            if d.code != 0 || !tx.exists() {
                return Err(d.value("FINALIZE").unwrap_or("finalize failed").to_string());
            }
            let spend: String = d.stdout.lines().filter(|l| l.starts_with("GAP_SPEND_")).map(|l| format!("{l}\n")).collect();
            write(&dir.join("spend.txt"), &spend)?;
            Self::set_meta(&dir, json!({ "stage": "finalized", "kernel": d.value("GAP_SPEND_KERNEL_EXCESS"),
                "fee": d.value("GAP_SPEND_FEE").and_then(|x| x.parse::<u64>().ok()), "finalized": chrono::Utc::now().to_rfc3339() }))?;
            let mut out = json!({ "tx_id": dir.file_name().unwrap().to_string_lossy(), "kernel": d.value("GAP_SPEND_KERNEL_EXCESS"), "broadcast": Value::Null });
            if bc {
                out["broadcast"] = me.broadcast(&w, &dir, job)?;
            }
            Ok(out)
        })?;
        Ok(json!({ "job": id }))
    }

    pub fn start_broadcast(self: &Arc<Self>, tx_id: &str) -> Result<Value, String> {
        let w = self.wallet()?;
        let dir = self.tx_dir(&w, tx_id)?;
        if !dir.join("spend-tx.hex").exists() {
            return Err("this payment has no finished transaction yet (finalize first)".into());
        }
        let me = self.clone();
        let id = self.jobs.start("broadcast", true, move |job| me.broadcast(&w, &dir, job))?;
        Ok(json!({ "job": id }))
    }

    fn broadcast(&self, w: &Wallet, dir: &Path, job: &Job) -> Result<Value, String> {
        let ok = self.peers(w, job, false)?;
        let (_, gap) = select_peers(&ok, 4);
        job.phase("broadcast");
        let mut a = w.net();
        a.extend(["--broadcast-tx".into(), dir.join("spend-tx.hex").display().to_string()]);
        for p in &gap {
            a.extend(["--peer".into(), p.clone()]);
        }
        if w.mainnet() {
            a.push("--allow-mainnet-spend".into());
        }
        let d = run_exe(&self.exe(), &a, None, &dir.join("broadcast.log"), Some(job), Duration::from_secs(180))?;
        let sent = d.values("BROADCAST_TX").iter().filter(|v| v.ends_with(" SENT")).count();
        if d.code != 0 || sent == 0 {
            return Err("broadcast failed on every peer".into());
        }
        let v = json!({ "at": chrono::Utc::now().to_rfc3339(), "peers_sent": sent });
        write(&dir.join("broadcast.json"), &v.to_string())?;
        Self::set_meta(dir, json!({ "stage": "broadcast" }))?;
        Ok(v)
    }

    /// Is the transaction in a block on the verified chain? Kernel found in a
    /// proven block, input spent, outputs at the tip; an earlier confirmation
    /// counts only if its block is still on the chain verified now (reorg).
    pub fn start_confirm(self: &Arc<Self>, tx_id: &str) -> Result<Value, String> {
        let w = self.wallet()?;
        let dir = self.tx_dir(&w, tx_id)?;
        let spend = std::fs::read_to_string(dir.join("spend.txt")).map_err(|_| "this payment is not finalized here (nothing to confirm)")?;
        let get = |k: &str| spend.lines().filter_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('='))).map(str::to_string).collect::<Vec<_>>();
        let kernel = get("GAP_SPEND_KERNEL_EXCESS").pop().ok_or("no kernel in the payment record")?;
        let mut commits: Vec<String> = Vec::new();
        for k in ["GAP_SPEND_INPUT", "GAP_SPEND_NEW_OUTPUT", "GAP_SPEND_RECEIVER_OUTPUT", "GAP_SPEND_EXTRA_INPUT"] {
            for c in get(k) {
                if c.len() == 66 && !commits.contains(&c) {
                    commits.push(c);
                }
            }
        }
        let me = self.clone();
        let id = self.jobs.start("confirm", true, move |job| {
            let prev: Option<Value> = std::fs::read_to_string(dir.join("confirm.json")).ok().and_then(|t| serde_json::from_str(&t).ok());
            let prev_block = prev.as_ref().and_then(|p| Some(format!("{}:{}", p["height"].as_u64()?, p["hash"].as_str()?)));
            let extra = Extra { commitments: commits, kernels: vec![kernel.clone()], check_blocks: prev_block.clone().into_iter().collect(), ..Default::default() };
            let (last, d) = me.run_open(&w, job, &extra)?;
            let tip = last["tip_height"].as_u64().unwrap_or(0);
            let found = d.values("GAP_KERNEL").into_iter().find(|v| v.starts_with(&format!("{kernel} FOUND"))).map(str::to_string);
            let res = if let Some(f) = found {
                let h: u64 = f.split("height=").nth(1).and_then(|x| x.split(' ').next()).and_then(|x| x.parse().ok()).unwrap_or(0);
                let hash = f.split("hash=").nth(1).and_then(|x| x.split(' ').next()).unwrap_or("").to_string();
                let depth = tip.saturating_sub(h) + 1;
                json!({ "state": if depth >= CONFIRMATIONS { "confirmed" } else { "in_block" }, "height": h, "hash": hash, "depth": depth, "checked_at_tip": tip })
            } else if let Some(pb) = &prev_block {
                let chk = d.values("GAP_BLOCK_CHECK").into_iter().find(|v| v.starts_with(pb.as_str())).unwrap_or("").to_string();
                let p = prev.clone().unwrap();
                if chk.contains("NOT_ON_VERIFIED_CHAIN") {
                    json!({ "state": "reorged", "height": p["height"], "hash": p["hash"], "depth": 0, "checked_at_tip": tip })
                } else if let Some(dep) = chk.split("ON_VERIFIED_CHAIN depth=").nth(1).and_then(|x| x.split(' ').next()).and_then(|x| x.parse::<u64>().ok()) {
                    json!({ "state": if dep >= CONFIRMATIONS { "confirmed" } else { "in_block" }, "height": p["height"], "hash": p["hash"], "depth": dep, "checked_at_tip": tip })
                } else if chk.contains("BELOW_VERIFIED_RANGE") {
                    json!({ "state": "confirmed", "height": p["height"], "hash": p["hash"], "depth": Value::Null, "checked_at_tip": tip, "note": "deeper than the verified session" })
                } else {
                    json!({ "state": "unknown", "height": p["height"], "hash": p["hash"], "checked_at_tip": tip, "note": chk })
                }
            } else {
                json!({ "state": "not_in_block", "checked_at_tip": tip })
            };
            if res.get("hash").is_some_and(|h| h.as_str().is_some_and(|x| x.len() == 64)) {
                write(&dir.join("confirm.json"), &res.to_string())?;
            }
            let stage = match res["state"].as_str() {
                Some("not_in_block") | Some("unknown") => None,
                s => s.map(str::to_string),
            };
            if let Some(s) = stage {
                Self::set_meta(&dir, json!({ "stage": s }))?;
            }
            Ok(res)
        })?;
        Ok(json!({ "job": id }))
    }

    /// Give up a payment that never completed: its inputs can be spent again.
    pub fn release(&self, tx_id: &str, force: bool) -> Result<Value, String> {
        let w = self.wallet()?;
        let dir = self.tx_dir(&w, tx_id)?;
        let m = Self::meta(&dir);
        let sid = m["slate_id"].as_str().ok_or("this payment has no slate id")?;
        let mut a = vec!["--release-inputs".to_string(), sid.into(), "--pending".into(), w.pending().display().to_string()];
        if dir.join("send-context.json").exists() {
            a.extend(["--send-context".into(), dir.join("send-context.json").display().to_string()]);
        }
        if force {
            a.push("--force".into());
        }
        let d = run_exe(&self.exe(), &a, None, &dir.join("release.log"), None, Duration::from_secs(60))?;
        if d.code != 0 {
            return Err(d.stdout.lines().rev().find(|l| l.contains("RELEASE")).unwrap_or("release refused").to_string());
        }
        Self::set_meta(&dir, json!({ "stage": "cancelled" }))?;
        Ok(json!({ "released": sid }))
    }

    // ---- history ----------------------------------------------------------

    /// Payments, newest first, with their stage (from files the core wrote).
    pub fn payments(&self) -> Result<Value, String> {
        let w = self.wallet()?;
        let known = std::fs::read_to_string(w.known()).unwrap_or_default();
        let tip = w.verified_tip();
        let known_is_current = w.tip_height_of_known() == Some(tip) && tip > 0;
        let created_of = |commit: &str| -> Option<u64> {
            known.lines().filter(|l| l.contains(commit)).find_map(|l| serde_json::from_str::<Value>(l).ok()?.get("created")?.as_u64())
        };
        let mut out = Vec::new();
        let mut dirs: Vec<PathBuf> = std::fs::read_dir(w.p("txs")).map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect()).unwrap_or_default();
        dirs.sort();
        dirs.reverse();
        for d in dirs {
            let mut m = Self::meta(&d);
            let kind = m["kind"].as_str().unwrap_or("").to_string();
            let mut stage = m["stage"].as_str().unwrap_or("").to_string();
            let confirm = std::fs::read_to_string(d.join("confirm.json"))
                .ok()
                .and_then(|t| serde_json::from_str::<Value>(&t).ok())
                .unwrap_or(Value::Null);
            if !confirm.is_null() {
                m["confirmation"] = confirm.clone();
            }
            // Incoming coins: on chain once the output is among the proven own outputs.
            if matches!(kind.as_str(), "receive" | "invoice") {
                stage = match m["commit"].as_str().and_then(created_of) {
                    // The outputs file describes another tip than the verified one
                    // (old file, other branch): no proof the coin is still there.
                    Some(_) if !known_is_current => "unknown".into(),
                    Some(h) => {
                        let depth = tip.saturating_sub(h) + 1;
                        m["height"] = json!(h);
                        m["depth"] = json!(depth);
                        if depth >= CONFIRMATIONS { "confirmed" } else { "in_block" }.into()
                    }
                    None if kind == "receive" => "waiting_sender".into(),
                    None if stage.is_empty() => "waiting_payer".into(),
                    None => stage,
                };
            } else if confirm.get("state").is_some() {
                // Outgoing: confirm.json keeps the block where the kernel was found.
                // Depth and stage must follow the current verified tip, otherwise the
                // history stays "in block" forever after a refresh (the stage was
                // frozen at the moment of the last wallet.confirm call).
                // A block is shown as holding the payment only if it was checked
                // on the chain verified now (checked_at_tip == current tip), or
                // it is deeper than any realistic reorg. Otherwise: unknown
                // until the next refresh re-checks it (never a stale "in block").
                let state = confirm["state"].as_str().unwrap_or("");
                let checked_now = confirm["checked_at_tip"].as_u64() == Some(tip) && tip > 0;
                match (state, confirm["height"].as_u64()) {
                    ("reorged", _) => stage = "reorged".into(),
                    ("in_block" | "confirmed", Some(h)) => {
                        let depth = tip.saturating_sub(h) + 1;
                        m["height"] = json!(h);
                        m["depth"] = json!(depth);
                        stage = if checked_now || depth > DEEP_REORG {
                            if depth >= CONFIRMATIONS { "confirmed" } else { "in_block" }.to_string()
                        } else {
                            "unknown".to_string()
                        };
                    }
                    ("confirmed", None) if checked_now => stage = "confirmed".into(),
                    _ => stage = "unknown".into(),
                }
            }
            if let Ok(t) = std::fs::read_to_string(d.join("AUTO_STATUS.txt")) {
                m["tor_status"] = json!(t.trim());
            }
            m["stage"] = json!(stage);
            // Payment proof = the receiver's signature, kept by finalize (sends only).
            m["payment_proof"] = json!(d.join("payment-proof.json").exists());
            m["tx_id"] = json!(d.file_name().unwrap().to_string_lossy());
            m["direction"] = json!(if matches!(kind.as_str(), "receive" | "invoice") { "incoming" } else { "outgoing" });
            out.push(m);
        }
        Ok(json!({ "tip_height": tip, "confirmations_needed": CONFIRMATIONS, "payments": out }))
    }

    /// Slatepack text of a payment (to show or copy again).
    pub fn slatepack(&self, tx_id: &str) -> Result<Value, String> {
        let w = self.wallet()?;
        let dir = self.tx_dir(&w, tx_id)?;
        for f in ["slatepack-s1.txt", "invoice-i1.txt", "invoice-i2.txt", "slatepack-answer.txt"] {
            if let Ok(t) = std::fs::read_to_string(dir.join(f)) {
                return Ok(json!({ "file": f, "slatepack": t.trim() }));
            }
        }
        Err("this payment has no slatepack".into())
    }

    // ---- Tor daemon (grinsight-tor) and contacts ------------------------------

    pub fn tor_start(&self, relay: Option<&str>) -> Result<Value, String> {
        let w = self.wallet()?;
        let mut t = self.tor.lock().unwrap();
        if let Some(c) = t.as_mut() {
            if c.try_wait().ok().flatten().is_none() {
                return Ok(json!({ "running": true }));
            }
        }
        // The new daemon writes its own status; never show the last run's.
        let _ = std::fs::remove_file(w.p("tor-wallet-1/status.json"));
        let mut cmd = std::process::Command::new(self.tor_exe());
        cmd.arg("serve");
        if w.mainnet() {
            cmd.arg("--mainnet");
        }
        cmd.args(["--exe", &self.exe().display().to_string(), "--seeds", "-", "--wallet", "1", "--user-dir", &w.dir.display().to_string()]);
        let saved = w.settings()["glauxnet_relay"].as_str().unwrap_or("").to_string();
        if let Some(r) = relay.filter(|r| !r.is_empty()).or(Some(saved.as_str()).filter(|r| !r.is_empty())) {
            cmd.args(["--relay", r]);
        }
        let log = std::fs::File::create(w.log("tor")).map_err(|e| e.to_string())?;
        cmd.stdin(std::process::Stdio::piped()).stdout(log.try_clone().map_err(|e| e.to_string())?).stderr(log);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        let mut c = cmd.spawn().map_err(|e| format!("{}: {e}", self.tor_exe().display()))?;
        if let Some(mut si) = c.stdin.take() {
            let _ = std::io::Write::write_all(&mut si, w.phrase.as_bytes());
        }
        *t = Some(c);
        Ok(json!({ "running": true, "note": "first Tor start takes 30-150 s" }))
    }

    pub fn tor_stop(&self) {
        if let Some(mut c) = self.tor.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    fn tor_status_brief(&self, w: &Wallet) -> Value {
        let running = self.tor.lock().unwrap().as_mut().is_some_and(|c| c.try_wait().ok().flatten().is_none());
        // A status.json left by an earlier run says nothing about now.
        let st: Value = if running {
            std::fs::read_to_string(w.p("tor-wallet-1/status.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null)
        } else {
            Value::Null
        };
        json!({ "running": running, "status": st })
    }

    /// GlauxNet for the UI: off (disabled), stopped, starting, local (our
    /// own mailbox behind our onion), remote (fallback relay) or failed.
    pub fn glauxnet_status(&self) -> Result<Value, String> {
        let w = self.wallet()?;
        let enabled = w.settings()["glauxnet"].as_bool().unwrap_or(true);
        let b = self.tor_status_brief(&w);
        let st = &b["status"];
        let running = b["running"].as_bool().unwrap_or(false);
        let g = st["glauxnet"].as_str().unwrap_or("");
        let state = if !enabled && !running {
            "off"
        } else if !running {
            "stopped"
        } else if g == "local" {
            "local"
        } else if g.starts_with("remote") {
            "remote"
        } else if g == "off" {
            "failed"
        } else {
            "starting"
        };
        Ok(json!({
            "enabled": enabled,
            "running": running,
            "state": state,
            "onion": st["onion"],
            "messenger_address": st["messenger_address"],
            "relay": g.strip_prefix("remote ").map(str::to_string),
            "tor": st["tor"],
        }))
    }

    /// Turn GlauxNet on or off (persisted, applied now).
    pub fn glauxnet_enable(&self, on: bool) -> Result<Value, String> {
        self.set_settings(&json!({ "glauxnet": on }))?;
        self.glauxnet_status()
    }

    /// Tor/GlauxNet state for the UI: daemon status, last events, the inbox
    /// of invoices, how many requests wait for a manual answer, and the same
    /// address/onion that grin-wallet and Grin++ use to reach us over Tor.
    pub fn tor_status(&self) -> Result<Value, String> {
        let w = self.wallet()?;
        let mut v = self.tor_status_brief(&w);
        let log = std::fs::read_to_string(w.p("tor-wallet-1/daemon.log")).unwrap_or_default();
        let tail: Vec<&str> = log.lines().rev().take(15).collect::<Vec<_>>().into_iter().rev().collect();
        v["events"] = json!(tail);
        let mut inbox = Vec::new();
        if let Ok(rd) = std::fs::read_dir(w.p("tor-wallet-1/inbox")) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if n.starts_with("invoice-") && n.ends_with(".txt") {
                    let peer = std::fs::read_to_string(e.path().with_extension("peer")).ok().map(|s| s.trim().to_string());
                    inbox.push(json!({ "file": n, "from": peer }));
                }
            }
        }
        v["inbox_invoices"] = json!(inbox);
        // Counted from the files, never from the daemon's cached number.
        v["pending_count"] = json!(count_pending(&w.p("tor-wallet-1/pending")));
        let address = std::fs::read_to_string(w.p("address.txt")).ok();
        v["foreign_api"] = foreign_api_info(address.as_deref(), &v["status"]);
        Ok(v)
    }

    /// Requests waiting for a manual "Да" (Tor foreign API holds the sender's
    /// connection for up to 40 s; a messenger envelope waits without holding).
    pub fn tor_pending(&self) -> Result<Value, String> {
        let w = self.wallet()?;
        let now = ss::now_unix();
        let dir = w.p("tor-wallet-1/pending");
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
            .map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(pending_request_file)).collect())
            .unwrap_or_default();
        files.sort();
        let mut out: Vec<Value> = Vec::new();
        for p in files {
            let Ok(t) = std::fs::read_to_string(&p) else { continue };
            let Ok(v) = serde_json::from_str::<Value>(&t) else { continue };
            if let Some(x) = pending_view(&v, now) {
                out.push(x);
            }
        }
        out.sort_by(|a, b| {
            let ra = a["received_at"].as_i64().unwrap_or(0);
            let rb = b["received_at"].as_i64().unwrap_or(0);
            rb.cmp(&ra).then_with(|| a["slate_id"].as_str().unwrap_or("").cmp(b["slate_id"].as_str().unwrap_or("")))
        });
        Ok(json!(out))
    }

    /// Answer a waiting request. The decision file is written atomically first
    /// (the daemon polls for it while the sender waits); the daemon removes it
    /// together with the pending files. On "accept" the sender also goes into
    /// the address book (the daemon does the same, the add is idempotent).
    pub fn tor_decide(&self, slate_id: &str, accept: bool, add_contact: bool, name: Option<&str>) -> Result<Value, String> {
        let w = self.wallet()?;
        if !valid_uuid(slate_id) {
            return Err("slate_id must be a UUID".into());
        }
        let pf = w.p(&format!("tor-wallet-1/pending/{slate_id}.json"));
        let v: Value = std::fs::read_to_string(&pf)
            .map_err(|_| "no such pending request".to_string())
            .and_then(|t| serde_json::from_str(&t).map_err(|e| format!("the pending request is damaged: {e}")))?;
        let channel = v["channel"].as_str().unwrap_or("tor-foreign");
        let from = v["from"].as_str().filter(|s| !s.is_empty()).map(str::to_string);
        let peer = v["peer"].as_str().filter(|s| !s.is_empty()).map(str::to_string);
        let expires_at = v["expires_at"].as_i64().unwrap_or(0);
        let now = ss::now_unix();
        let name = name.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        let decision = decision_json(slate_id, accept, add_contact, name.as_deref());
        write(&w.p(&format!("tor-wallet-1/decisions/{slate_id}.json")), &serde_json::to_string(&decision).map_err(|e| e.to_string())?)?;
        let mut contact_added = false;
        if accept && add_contact {
            // Messenger channel: the envelope signature proves `peer`; the
            // claimed address (when present) is what the book keeps as id.
            let id = from.clone().or_else(|| if channel == "messenger" { peer.clone() } else { None });
            if let Some(id) = id {
                let mut a: Vec<String> = vec!["book".into(), "add".into(), "--id".into(), id];
                if let Some(n) = &name {
                    a.extend(["--name".into(), n.clone()]);
                }
                if channel == "messenger" {
                    if let Some(p) = &peer {
                        a.extend(["--messenger".into(), p.clone()]);
                    }
                }
                if self.tor_cmd(&w, &a, "book").is_ok_and(|d| d.code == 0) {
                    contact_added = true;
                }
            }
        }
        Ok(json!({
            "accepted": accept,
            "answered_over_tor": accept && channel == "tor-foreign" && now < expires_at,
            "contact_added": contact_added,
        }))
    }

    /// Payments and invoices lying in the Tor daemon's inbox (newest first).
    pub fn tor_inbox(&self) -> Result<Value, String> {
        let w = self.wallet()?;
        Ok(Value::Array(inbox_entries(&w.p("tor-wallet-1/inbox"))))
    }

    pub fn inbox_invoice(&self, file: &str) -> Result<String, String> {
        let w = self.wallet()?;
        if !file.starts_with("invoice-") || !file.ends_with(".txt") || file.contains(['/', '\\']) || file.contains("..") {
            return Err("bad inbox file".into());
        }
        read(&w.p("tor-wallet-1/inbox").join(file))
    }

    fn tor_cmd(&self, w: &Wallet, args: &[String], tag: &str) -> Result<Done, String> {
        let mut a = args.to_vec();
        a.extend(["--user-dir".into(), w.dir.display().to_string()]);
        run_exe(&self.tor_exe(), &a, None, &w.log(tag), None, Duration::from_secs(60))
    }

    /// Hand a payment to the Tor daemon: it delivers the slatepack, takes the
    /// answer, finalizes and broadcasts (send / own invoice), or delivers our
    /// answer (paid invoice). A paid grin-wallet invoice goes straight to the
    /// issuer's onion (its `grin1…` slatepack address from I1) unless the
    /// caller gives a messenger address.
    pub fn tor_deliver(&self, tx_id: &str, messenger: Option<&str>, messenger_only: bool) -> Result<Value, String> {
        let w = self.wallet()?;
        let dir = self.tx_dir(&w, tx_id)?;
        let m = Self::meta(&dir);
        let sid = m["slate_id"].as_str().ok_or("no slate id")?.to_string();
        let kind = m["kind"].as_str().unwrap_or("");
        let messenger = messenger.filter(|x| !x.is_empty());
        let mut a = vec!["queue".to_string(), "--wallet".into(), "1".into(), "--slate-id".into(), sid, "--tx-folder".into(), dir.display().to_string()];
        if kind == "pay_invoice" && messenger.is_none() {
            // No messenger address: the issuer's slatepack address goes over
            // the Tor foreign API (finalize_tx), not through GlauxNet.
            let to = m["to"].as_str().unwrap_or("").trim().to_string();
            if to.is_empty() {
                return Err("the invoice has no issuer address".into());
            }
            self.check_address(&w, &to).map_err(|_| "the invoice has no issuer address: the sender address in I1 is not a grin1…/tgrin1… slatepack address".to_string())?;
            a.extend(queue_args_for(&dir, &m, None)?);
        } else {
            a.extend(queue_args_for(&dir, &m, messenger)?);
            if kind == "send" {
                if let Some(x) = messenger {
                    a.extend(["--messenger".into(), x.into()]);
                }
                if messenger_only {
                    a.push("--messenger-only".into());
                }
            }
        }
        let d = self.tor_cmd(&w, &a, "tor-queue")?;
        if d.code != 0 {
            return Err(format!("could not queue: {}", d.stdout.lines().last().unwrap_or("")));
        }
        Self::set_meta(&dir, json!({ "tor": "queued" }))?;
        Ok(json!({ "queued": true }))
    }

    pub fn contacts(&self, op: &str, p: &Value) -> Result<Value, String> {
        let w = self.wallet()?;
        let s = |k: &str| p.get(k).and_then(Value::as_str).map(str::to_string);
        let mut a: Vec<String> = vec!["book".into()];
        match op {
            "list" => a.push("list".into()),
            "add" => {
                let id = s("id").ok_or("id (grin1... address) is needed")?;
                self.check_address(&w, &id)?;
                a.extend(["add".into(), "--id".into(), id]);
                if let Some(n) = s("name") {
                    a.extend(["--name".into(), n]);
                }
                if let Some(m) = s("messenger") {
                    a.extend(["--messenger".into(), m]);
                }
                if p.get("auto").and_then(Value::as_bool) == Some(false) {
                    a.extend(["--auto".into(), "no".into()]);
                }
            }
            "remove" => a.extend(["remove".into(), "--id".into(), s("id").ok_or("id is needed")?]),
            "auto_accept" => {
                let mode = s("mode").ok_or("mode: off|ask|contacts|all")?;
                if !matches!(mode.as_str(), "off" | "ask" | "contacts" | "all") {
                    return Err("mode: off|ask|contacts|all".into());
                }
                a.extend(["auto-accept".into(), mode]);
            }
            _ => return Err("unknown contacts operation".into()),
        }
        let d = self.tor_cmd(&w, &a, "book")?;
        if d.code != 0 {
            return Err(d.stdout.lines().last().unwrap_or("address book command failed").to_string());
        }
        let d = if op == "list" { d } else { self.tor_cmd(&w, &["book".into(), "list".into()], "book")? };
        let contacts: Vec<Value> = d.stdout.lines().filter_map(|l| l.strip_prefix("CONTACT ")).map(parse_contact).collect();
        Ok(json!({ "contacts": contacts, "auto_accept": d.value("AUTO_ACCEPT") }))
    }
}

/// `id=grin1.. name="Bob Smith" auto=yes messenger=- onion=x.onion` -> JSON.
pub fn parse_contact(l: &str) -> Value {
    let mut m = Map::new();
    let mut rest = l.trim();
    while let Some((k, r)) = rest.split_once('=') {
        let (v, r2) = if let Some(q) = r.strip_prefix('"') {
            let end = q.find('"').unwrap_or(q.len());
            (q[..end].to_string(), q.get(end + 1..).unwrap_or(""))
        } else {
            let end = r.find(' ').unwrap_or(r.len());
            (r[..end].to_string(), &r[end..])
        };
        let v = match (k.trim(), v.as_str()) {
            ("auto", x) => json!(x == "yes"),
            (_, "-") => Value::Null,
            (_, x) => json!(x),
        };
        m.insert(k.trim().to_string(), v);
        rest = r2.trim_start();
    }
    Value::Object(m)
}

// ---------------------------------------------------------------------------
// Tor daemon files: pending requests, decisions, inbox sidecars
// (the format lives in tor/grinsight-tor; the service only reads/writes it)
// ---------------------------------------------------------------------------

/// A slate id is a UUID and becomes a file name: nothing else is accepted.
fn valid_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// A request file in `pending/`: `<uuid>.json`, not its `<uuid>.s1.json` S1.
fn pending_request_file(name: &str) -> bool {
    name.ends_with(".json") && !name.ends_with(".s1.json")
}

/// `<uuid>.json` / `invoice-<uuid>.txt` -> `<stem>.meta.json` (daemon sidecar).
fn meta_name(file: &str) -> String {
    let stem = file.rsplit_once('.').map(|(s, _)| s).unwrap_or(file);
    format!("{stem}.meta.json")
}

fn json_u64(v: &Value) -> Value {
    match v {
        Value::Number(n) if n.as_u64().is_some() => v.clone(),
        Value::String(s) => s.trim().parse::<u64>().map(|x| json!(x)).unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

fn file_modified(dir: &Path, name: &str) -> i64 {
    std::fs::metadata(dir.join(name))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The UI view of one `pending/<slate_id>.json` request: a Tor sender is still
/// holding its HTTP request while `waiting` is true (the 40 s window), a
/// messenger envelope waits without holding (`waiting = false`).
fn pending_view(v: &Value, now: i64) -> Option<Value> {
    let slate_id = v["slate_id"].as_str().filter(|s| valid_uuid(s))?.to_string();
    let channel = v["channel"].as_str().unwrap_or("tor-foreign");
    let tor_foreign = channel == "tor-foreign";
    let expires_at = v["expires_at"].as_i64().unwrap_or(0);
    let left = if tor_foreign { (expires_at - now).max(0) } else { 0 };
    Some(json!({
        "slate_id": slate_id,
        "amount": json_u64(&v["amount"]),
        "fee": json_u64(&v["fee"]),
        "from": v["from"].as_str().filter(|s| !s.is_empty()).map(|s| json!(s)).unwrap_or(Value::Null),
        "channel": channel,
        "expires_in_s": left,
        "waiting": tor_foreign && now < expires_at,
        "sender_verified": v["sender_verified"].as_bool().unwrap_or(false),
        "received_at": v["received_at"].as_i64().unwrap_or(0),
    }))
}

/// The decision file the daemon polls for while the sender waits.
fn decision_json(slate_id: &str, accept: bool, add_contact: bool, name: Option<&str>) -> Value {
    json!({
        "slate_id": slate_id,
        "accept": accept,
        "add_contact": add_contact,
        "name": name.filter(|n| !n.is_empty()).unwrap_or(""),
    })
}

/// `pending/` count for `tor.status`: requests only, never the S1 companions.
fn count_pending(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|rd| rd.flatten().filter(|e| e.file_name().to_str().is_some_and(pending_request_file)).count() as u64)
        .unwrap_or(0)
}

/// The address/onion other wallets reach us on: the profile's own slatepack
/// address (written by `wallet.address`) wins, then what the daemon reports.
fn foreign_api_info(address: Option<&str>, status: &Value) -> Value {
    let a = address
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| status["foreign_api"]["address"].as_str().filter(|s| !s.is_empty()).map(str::to_string))
        .or_else(|| status["address"].as_str().filter(|s| !s.is_empty()).map(str::to_string));
    let onion = status["onion"]
        .as_str()
        .filter(|s| !s.is_empty())
        .or_else(|| status["foreign_api"]["onion"].as_str().filter(|s| !s.is_empty()))
        .map(str::to_string);
    json!({ "address": a, "onion": onion })
}

/// `inbox/` for `tor.inbox`: every meta sidecar, then files that have none
/// (a plain V4 slate JSON is a payment, `invoice-*.txt` is an invoice).
fn inbox_entries(dir: &Path) -> Vec<Value> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let names: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    let mut metas: HashMap<String, Value> = HashMap::new();
    for n in &names {
        let Some(stem) = n.strip_suffix(".meta.json") else { continue };
        let Ok(t) = std::fs::read_to_string(dir.join(n)) else { continue };
        let Ok(m) = serde_json::from_str::<Value>(&t) else { continue };
        let file = m["file"]
            .as_str()
            .filter(|f| !f.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| if stem.starts_with("invoice-") { format!("{stem}.txt") } else { format!("{stem}.json") });
        metas.insert(file, m);
    }
    let mut out: Vec<Value> = Vec::new();
    for n in &names {
        if n.ends_with(".meta.json") || n.ends_with(".peer") || n.ends_with(".s2.txt") {
            continue;
        }
        if let Some(m) = metas.get(n) {
            out.push(json!({
                "file": n,
                "kind": m["kind"].as_str().unwrap_or(if n.starts_with("invoice-") { "invoice" } else { "payment" }),
                "amount": m.get("amount").cloned().unwrap_or(Value::Null),
                "fee": m.get("fee").cloned().unwrap_or(Value::Null),
                "from": m.get("from").cloned().unwrap_or(Value::Null),
                "received_at": m["received_at"].as_i64().unwrap_or_else(|| file_modified(dir, n)),
            }));
        } else if n.starts_with("invoice-") && n.ends_with(".txt") {
            out.push(json!({ "file": n, "kind": "invoice", "amount": Value::Null, "fee": Value::Null, "from": Value::Null, "received_at": file_modified(dir, n) }));
        } else if n.ends_with(".json") {
            // Plain V4 slate JSON: `amt` is the amount; the claimed sender is
            // proof.saddr as a hex key, which we do not decode here.
            let mut amount = Value::Null;
            let mut fee = Value::Null;
            if let Ok(t) = std::fs::read_to_string(dir.join(n)) {
                if let Ok(v) = serde_json::from_str::<Value>(&t) {
                    amount = json_u64(&v["amt"]);
                    fee = json_u64(&v["fee"]);
                }
            }
            out.push(json!({ "file": n, "kind": "payment", "amount": amount, "fee": fee, "from": Value::Null, "received_at": file_modified(dir, n) }));
        }
    }
    out.sort_by(|a, b| {
        let ra = a["received_at"].as_i64().unwrap_or(0);
        let rb = b["received_at"].as_i64().unwrap_or(0);
        rb.cmp(&ra).then_with(|| a["file"].as_str().unwrap_or("").cmp(b["file"].as_str().unwrap_or("")))
    });
    out
}

/// `grinsight-tor queue` arguments for a payment folder (without the common
/// `--wallet/--slate-id/--tx-folder`). A paid invoice goes to the issuer's
/// `grin1…` slatepack address over its Tor foreign API when no messenger
/// address is known; `--messenger-only` is added only for the messenger paths.
fn queue_args_for(dir: &Path, meta: &Value, messenger: Option<&str>) -> Result<Vec<String>, String> {
    let p = |x: &Path| x.display().to_string();
    match meta["kind"].as_str().unwrap_or("") {
        "send" => Ok(vec![
            "--kind".into(), "send".into(),
            "--to".into(), meta["to"].as_str().unwrap_or("").into(),
            "--slate-json".into(), p(&dir.join("slatepack-s1.json")),
            "--armor".into(), p(&dir.join("slatepack-s1.txt")),
            "--context".into(), p(&dir.join("send-context.json")),
        ]),
        "invoice" => {
            let mut a = vec![
                "--kind".into(), "invoice".into(),
                "--to".into(), meta["to"].as_str().filter(|t| !t.is_empty()).unwrap_or("unknown").into(),
                "--armor".into(), p(&dir.join("invoice-i1.txt")),
                "--context".into(), p(&dir.join("invoice-context.json")),
            ];
            if let Some(m) = messenger {
                a.extend(["--messenger".into(), m.into()]);
            }
            a.push("--messenger-only".into());
            Ok(a)
        }
        "pay_invoice" => {
            let i2 = dir.join("invoice-i2.txt");
            match messenger {
                Some(m) => Ok(vec![
                    "--kind".into(), "reply".into(),
                    "--to".into(), m.into(),
                    "--armor".into(), p(&i2),
                    "--context".into(), "-".into(),
                    "--messenger".into(), m.into(),
                    "--messenger-only".into(),
                ]),
                None => {
                    let to = meta["to"].as_str().unwrap_or("").trim().to_string();
                    if to.is_empty() {
                        return Err("the invoice has no issuer address".into());
                    }
                    // No --messenger-only: the daemon calls finalize_tx on the
                    // issuer's onion with the I2 JSON.
                    Ok(vec![
                        "--kind".into(), "reply".into(),
                        "--to".into(), to,
                        "--armor".into(), p(&i2),
                        "--slate-json".into(), p(&dir.join("invoice-i2.json")),
                        "--context".into(), "-".into(),
                    ])
                }
            }
        }
        _ => Err("this payment cannot be delivered over Tor".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_names() {
        let d = std::env::temp_dir().join(format!("gs-prog-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let plain = d.join(format!("grinsight-tor{}", std::env::consts::EXE_SUFFIX));
        assert_eq!(program(&d, "grinsight-tor"), plain, "default name when nothing exists");
        std::fs::write(d.join("libgrinsight_tor.so"), b"").unwrap();
        assert_eq!(program(&d, "grinsight-tor"), d.join("libgrinsight_tor.so"), "Android name");
        std::fs::write(&plain, b"").unwrap();
        assert_eq!(program(&d, "grinsight-tor"), plain, "plain name wins");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn contact_lines() {
        let c = parse_contact("id=tgrin1abc name=\"Bob Smith\" auto=yes messenger=- onion=x.onion");
        assert_eq!(c, json!({ "id": "tgrin1abc", "name": "Bob Smith", "auto": true, "messenger": null, "onion": "x.onion" }));
    }

    #[test]
    fn checkpoint_age_from_rwm_header() {
        let d = std::env::temp_dir().join(format!("gs-rwm-age-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("checkpoint.rwm");
        let ts = chrono::Utc::now().timestamp() - 400 * 86_400;
        // header: version u16, height u64, timestamp i64 (big-endian), then the rest.
        std::fs::write(&f, format!("RWM1\nheight 7\nhash ab\nheader 0001{:016x}{:016x}00ff\n", 7u64, ts)).unwrap();
        assert_eq!(Service::rwm_age_days(&f), Some(400));
        assert_eq!(Service::rwm_head(&f), Some((7, "ab".to_string())));
        assert!(400 > OLD_CHECKPOINT_DAYS, "a 400-day point asks for an own checkpoint");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn parse_probe_reads_header_proof_bit() {
        // caps with 0x100 set -> header_proof; without -> not.
        let out = "PROBE_PEER=1.1.1.1:3414 OK agent=\"x\" version=1 caps=0x107 pibd=yes block_hist=no header_proof=yes total_difficulty=9\n\
                   PROBE_PEER=2.2.2.2:3414 OK agent=\"x\" version=1 caps=0x7 pibd=yes block_hist=no header_proof=no total_difficulty=8\n";
        let (ok, _) = parse_probe(out);
        let a = ok.iter().find(|p| p.addr == "1.1.1.1:3414").unwrap();
        let b = ok.iter().find(|p| p.addr == "2.2.2.2:3414").unwrap();
        assert!(a.header_proof, "0x107 has bit 0x100");
        assert!(!b.header_proof, "0x7 lacks bit 0x100");
    }

    fn peer(a: &str, pibd: bool, td: u128) -> Peer {
        Peer { addr: a.into(), pibd, td, header_proof: false }
    }

    #[test]
    fn probe_parsing_and_order() {
        let out = "PROBE_PEER=1.2.3.4:3414 OK agent=\"x\" version=3 caps=0x1 pibd=yes block_hist=1 total_difficulty=10\n\
                   PROBE_PEER=5.6.7.8:3414 OK agent=\"y\" pibd=no total_difficulty=30\n\
                   PROBE_PEER=9.9.9.9:3414 FAIL timeout\nDISCOVERED_PEER=7.7.7.7:3414\n";
        let (ok, disc) = parse_probe(out);
        assert_eq!(ok, vec![peer("5.6.7.8:3414", false, 30), peer("1.2.3.4:3414", true, 10)]);
        assert_eq!(disc, vec!["7.7.7.7:3414".to_string()]);
    }

    #[test]
    fn peer_selection() {
        let ok = vec![
            peer("10.1.0.1:3414", true, 9), peer("10.1.0.2:3414", true, 9), peer("10.2.0.1:3414", false, 9),
            peer("10.3.0.1:3414", true, 9), peer("10.4.0.1:3414", true, 9), peer("10.5.0.1:3414", true, 9), peer("10.6.0.1:3414", false, 9),
        ];
        let (sync, gap) = select_peers(&ok, 4);
        assert_eq!(sync, vec!["10.1.0.1:3414", "10.2.0.1:3414", "10.3.0.1:3414", "10.4.0.1:3414"], "distinct /16 first");
        assert_eq!(gap, vec!["10.1.0.2:3414", "10.5.0.1:3414", "10.6.0.1:3414", "10.1.0.1:3414"], "unused PIBD peers first");
        // Two peers only (Floonet): both used for both.
        let two = vec![peer("10.1.0.1:13414", true, 1), peer("10.1.0.2:13414", true, 1)];
        let (s2, g2) = select_peers(&two, 8);
        assert_eq!(s2.len(), 2);
        assert_eq!(g2.len(), 2);
    }

    #[test]
    fn names_and_networks() {
        assert!(check_name("main-1").is_ok());
        for bad in ["", "a/b", "..", "a b", &"x".repeat(33)] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
        assert_eq!(network_from("Floonet").unwrap(), Network::Floonet);
        assert!(network_from("x").is_err());
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("gs-tor-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const SID: &str = "11111111-2222-4333-8444-555555555555";

    #[test]
    fn slate_id_and_file_names() {
        assert!(valid_uuid(SID));
        for bad in ["", &SID[..35], "../1111", "1111111122223333444455555555555x", "11111111-2222-4333-8444-55555555555"] {
            assert!(!valid_uuid(bad), "{bad}");
        }
        // The S1 companion is not a request; the request itself is.
        assert!(pending_request_file(&format!("{SID}.json")));
        assert!(!pending_request_file(&format!("{SID}.s1.json")));
        assert!(!pending_request_file(&format!("{SID}.s1.txt")));
        assert_eq!(meta_name(&format!("{SID}.json")), format!("{SID}.meta.json"));
        assert_eq!(meta_name(&format!("invoice-{SID}.txt")), format!("invoice-{SID}.meta.json"));
    }

    #[test]
    fn pending_view_time_and_channel() {
        let v = json!({ "slate_id": SID, "amount": 25_000_000_000u64, "fee": "1000000", "from": "tgrin1abc",
                        "channel": "tor-foreign", "received_at": 100, "expires_at": 140, "sender_verified": false });
        let p = pending_view(&v, 100).unwrap();
        assert_eq!(p["amount"], 25_000_000_000u64);
        assert_eq!(p["fee"], 1_000_000u64, "a numeric string is accepted");
        assert_eq!((p["from"].as_str(), p["waiting"].as_bool()), (Some("tgrin1abc"), Some(true)));
        assert_eq!(p["expires_in_s"], 40);
        let late = pending_view(&v, 140).unwrap();
        assert_eq!((late["waiting"].as_bool(), late["expires_in_s"].as_i64()), (Some(false), Some(0)), "window closed");
        // A messenger envelope waits without holding the sender: no countdown.
        let m = pending_view(&json!({ "slate_id": SID, "channel": "messenger", "expires_at": 999,
                                       "from": Value::Null, "peer": "grinmsg1x" }), 100)
        .unwrap();
        assert_eq!((m["waiting"].as_bool(), m["expires_in_s"].as_i64()), (Some(false), Some(0)));
        assert_eq!(m["from"], Value::Null);
        // A damaged request (bad id) is not shown to the user.
        assert!(pending_view(&json!({ "slate_id": "../x", "channel": "tor-foreign" }), 0).is_none());
    }

    #[test]
    fn decision_file_fields() {
        assert_eq!(
            decision_json(SID, true, true, Some("Tor sender")),
            json!({ "slate_id": SID, "accept": true, "add_contact": true, "name": "Tor sender" })
        );
        assert_eq!(decision_json(SID, false, false, None), json!({ "slate_id": SID, "accept": false, "add_contact": false, "name": "" }));
    }

    #[test]
    fn pending_count_skips_s1_and_armor() {
        let d = tmpdir("count");
        for f in [format!("{SID}.json"), format!("{SID}.s1.json"), "22222222-3333-4444-8555-666666666666.json".into(), format!("{SID}.s1.txt")] {
            std::fs::write(d.join(&f), b"{}").unwrap();
        }
        assert_eq!(count_pending(&d), 2);
        assert_eq!(count_pending(&d.join("missing")), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn foreign_api_prefers_the_wallet_address() {
        let st = json!({ "onion": "abc.onion", "foreign_api": { "address": "tgrin1daemon", "onion": "abc.onion" } });
        let f = foreign_api_info(Some(" tgrin1wallet\n"), &st);
        assert_eq!(f["address"], "tgrin1wallet");
        assert_eq!(f["onion"], "abc.onion");
        // Without address.txt the daemon's report is used.
        let f = foreign_api_info(None, &st);
        assert_eq!(f["address"], "tgrin1daemon");
        let f = foreign_api_info(Some("  "), &json!({ "foreign_api": { "onion": "fa.onion" } }));
        assert_eq!(f, json!({ "address": null, "onion": "fa.onion" }));
    }

    #[test]
    fn inbox_listing_meta_and_fallbacks() {
        let d = tmpdir("inbox");
        let pay = "5f0c1111-2222-4333-8444-555555555555";
        let inv = "6f0c1111-2222-4333-8444-555555555555";
        let bare = "7f0c1111-2222-4333-8444-555555555555";
        // Payment with a meta sidecar (stem + .meta.json).
        std::fs::write(d.join(format!("{pay}.json")), br#"{"sta":"S1"}"#).unwrap();
        std::fs::write(
            d.join(format!("{pay}.meta.json")),
            json!({ "kind": "payment", "amount": 500_000_000u64, "fee": 1_000_000u64, "from": "tgrin1abc",
                    "channel": "tor-foreign", "received_at": 1234, "slate_id": pay, "file": format!("{pay}.json") }).to_string(),
        )
        .unwrap();
        // Invoice with a meta sidecar + one without any meta.
        std::fs::write(d.join(format!("invoice-{inv}.txt")), b"BEGINSLATEPACK.").unwrap();
        std::fs::write(
            d.join(format!("invoice-{inv}.meta.json")),
            json!({ "kind": "invoice", "amount": 7_000_000_000u64, "fee": Value::Null, "from": Value::Null,
                    "received_at": 99, "slate_id": inv, "file": format!("invoice-{inv}.txt") }).to_string(),
        )
        .unwrap();
        std::fs::write(d.join(format!("invoice-{bare}.txt")), b"BEGINSLATEPACK.").unwrap();
        // A plain slate JSON without meta: amount from `amt` (string or number).
        std::fs::write(d.join(format!("{bare}.json")), br#"{"sta":"S1","amt":"2500000000"}"#).unwrap();
        // Never listed.
        std::fs::write(d.join(format!("{pay}.peer")), b"x").unwrap();
        std::fs::write(d.join(format!("{pay}.s2.txt")), b"BEGINSLATEPACK.").unwrap();
        let list = inbox_entries(&d);
        let get = |f: &str| list.iter().find(|e| e["file"].as_str() == Some(f)).cloned().unwrap_or_else(|| panic!("{f} not listed: {list:?}"));
        let p = get(&format!("{pay}.json"));
        assert_eq!((p["kind"].as_str(), p["amount"].as_u64(), p["from"].as_str(), p["received_at"].as_i64()), (Some("payment"), Some(500_000_000), Some("tgrin1abc"), Some(1234)));
        let i = get(&format!("invoice-{inv}.txt"));
        assert_eq!((i["kind"].as_str(), i["amount"].as_u64()), (Some("invoice"), Some(7_000_000_000)));
        let b = get(&format!("{bare}.json"));
        assert_eq!((b["kind"].as_str(), b["amount"].as_u64(), b["from"].clone()), (Some("payment"), Some(2_500_000_000), Value::Null));
        let f = get(&format!("invoice-{bare}.txt"));
        assert_eq!((f["kind"].as_str(), f["amount"].clone()), (Some("invoice"), Value::Null));
        assert_eq!(list.len(), 4, "{list:?}");
        assert!(list.windows(2).all(|w| w[0]["received_at"].as_i64().unwrap_or(0) >= w[1]["received_at"].as_i64().unwrap_or(0)), "newest first");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn receive_accepts_plain_json_and_armor_only() {
        let json = format!(r#"{{"ver":"4:3","id":"{SID}","sta":"S1","amt":"1"}}"#);
        assert!(Service::check_slatepack(&json).is_ok());
        assert!(Service::check_slatepack("BEGINSLATEPACK. abc .ENDSLATEPACK.").is_ok());
        assert!(Service::check_slatepack("hello").is_err());
        assert!(Service::check_slatepack(&"x".repeat(64 * 1024 + 1)).is_err(), "size limit");
    }

    #[test]
    fn pay_invoice_queue_reply_over_tor_without_messenger() {
        let dir = Path::new("C:/wallet/txs/pay-1");
        let meta = json!({ "kind": "pay_invoice", "slate_id": SID, "to": "tgrin1issuer", "amount": 5u64 });
        let a = queue_args_for(dir, &meta, None).unwrap();
        let has = |k: &str| a.iter().any(|x| x == k);
        let val = |k: &str| a.iter().position(|x| x == k).and_then(|i| a.get(i + 1)).cloned();
        assert_eq!(val("--kind").as_deref(), Some("reply"));
        assert_eq!(val("--to").as_deref(), Some("tgrin1issuer"));
        assert!(val("--slate-json").unwrap().ends_with("invoice-i2.json"), "{a:?}");
        assert!(!has("--messenger") && !has("--messenger-only"), "the issuer's onion is used, not GlauxNet: {a:?}");
        assert_eq!(val("--context").as_deref(), Some("-"), "the daemon still requires --context");
        // A messenger address keeps the old path.
        let a = queue_args_for(dir, &meta, Some("grinmsg1x")).unwrap();
        assert!(a.iter().any(|x| x == "--messenger-only"), "{a:?}");
        assert_eq!(a.iter().position(|x| x == "--to").and_then(|i| a.get(i + 1)).map(String::as_str), Some("grinmsg1x"));
        // No issuer address in the meta: a clear error, nothing queued.
        let e = queue_args_for(dir, &json!({ "kind": "pay_invoice", "slate_id": SID }), None).unwrap_err();
        assert_eq!(e, "the invoice has no issuer address");
    }
}
