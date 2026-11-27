//! The host as the interface meets it: a process, lines of JSON in and out.
//! Two hosts, each with its own stand-in transport process, exchange a
//! payment; nothing is shared between the four processes but the "relay"
//! directory of the stand-ins.
//! Run with `cargo test --features test-chain`.
#![cfg(feature = "test-chain")]
use fly_paycore_bridge::chain_pipe::wire::encode_block;
use fly_paycore_bridge::chain_port::{BlockFacts, OutputFact};
use fly_paycore_keys::path::KeyPath;
use grin_core::core::hash::Hashed;
use grin_core::core::Transaction;
use grin_core::global::{self, ChainTypes};
use grin_core::libtx::proof::{self, ProofBuilder};
use grin_core::ser;
use grin_keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const HOST: &str = env!("CARGO_BIN_EXE_fly-paycore-host");
const HOST_TEST: &str = env!("CARGO_BIN_EXE_fly-paycore-host-test");
const STUB: &str = env!("CARGO_BIN_EXE_host-mailbox-stub");
const CHAIN: &str = env!("CARGO_BIN_EXE_host-chain-stub");
const ONION: &str = env!("CARGO_BIN_EXE_host-onion-stub");
const GRIN: u64 = 1_000_000_000;
/// A valid transport key that is nobody's in these tests.
const SOMEBODY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

struct Temp(PathBuf);
impl Temp {
    fn new(tag: &str) -> Temp {
        let mut r = [0u8; 8];
        getrandom::getrandom(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!("fly-host-{tag}-{}", u64::from_le_bytes(r)));
        std::fs::create_dir_all(p.join("relay")).unwrap();
        Temp(p)
    }
    fn relay(&self) -> String {
        format!("dir:{}", self.0.join("relay").to_str().unwrap())
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Proc {
    child: Child,
    stdin: Option<ChildStdin>,
    answers: Receiver<Value>,
    events: Arc<Mutex<Vec<Value>>>,
    next_id: u64,
}
impl Proc {
    /// Start a host on the profile `name` under `base`.
    fn start(program: &str, base: &Path, name: &str, relay: Option<&str>) -> Proc {
        let mut command = Command::new(program);
        command
            .arg("--profile")
            .arg(base.join(name))
            .arg("--guard-dir")
            .arg(base.join(format!("{name}-guard")));
        if let Some(relay) = relay {
            command.arg("--transport").arg(STUB).arg("--relay").arg(relay);
        }
        Proc::spawn(command)
    }
    /// Start a host with a stand-in Tor process for payments to its address.
    fn with_onion(program: &str, base: &Path, name: &str) -> Proc {
        let mut command = Command::new(program);
        command
            .arg("--profile")
            .arg(base.join(name))
            .arg("--guard-dir")
            .arg(base.join(format!("{name}-guard")))
            .arg("--onion")
            .arg(ONION);
        Proc::spawn(command)
    }
    /// As [`Proc::with_onion`], with the file of Tor bridges the user chose.
    fn with_onion_and_bridges(program: &str, base: &Path, name: &str, bridges: &Path) -> Proc {
        let mut command = Command::new(program);
        command
            .arg("--profile")
            .arg(base.join(name))
            .arg("--guard-dir")
            .arg(base.join(format!("{name}-guard")))
            .arg("--onion")
            .arg(ONION)
            .arg("--tor-bridges")
            .arg(bridges);
        Proc::spawn(command)
    }
    /// Start a host whose chain is a stand-in chain process told `peer`.
    fn with_chain(program: &str, base: &Path, name: &str, relay: Option<&str>, peer: &str) -> Proc {
        let mut command = Command::new(program);
        command
            .arg("--profile")
            .arg(base.join(name))
            .arg("--guard-dir")
            .arg(base.join(format!("{name}-guard")))
            .arg("--chain")
            .arg(CHAIN)
            .arg("--chain-peer")
            .arg(peer);
        if let Some(relay) = relay {
            command.arg("--transport").arg(STUB).arg("--relay").arg(relay);
        }
        Proc::spawn(command)
    }
    fn chain_phase(&mut self) -> String {
        self.status()["chain"]["phase"].as_str().unwrap().to_string()
    }
    fn tip(&mut self) -> Value {
        self.ok("paycore.info", json!({}))["tip_height"].clone()
    }
    fn spendable(&mut self) -> String {
        self.ok("paycore.balance", json!({}))["spendable"].as_str().unwrap().to_string()
    }
    fn spawn(mut command: Command) -> Proc {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (tx, answers) = mpsc::channel();
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                let v: Value = serde_json::from_str(&line).expect("every line is JSON");
                if v.get("id").is_some() {
                    let _ = tx.send(v);
                } else {
                    sink.lock().unwrap().push(v);
                }
            }
        });
        Proc {
            child,
            stdin,
            answers,
            events,
            next_id: 0,
        }
    }
    /// Send one line as it is and wait for the answer.
    fn raw(&mut self, line: &str) -> Value {
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(line.as_bytes()).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
        // a request may wait behind a round of delivery through a slow network
        self.answers.recv_timeout(Duration::from_secs(180)).expect("an answer")
    }
    fn call(&mut self, method: &str, params: Value) -> Result<Value, Value> {
        self.next_id += 1;
        let id = self.next_id;
        let v = self.raw(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string());
        assert_eq!(v["id"], id, "answers come in the order of the requests");
        match v.get("result") {
            Some(x) => Ok(x.clone()),
            None => Err(v["error"].clone()),
        }
    }
    fn ok(&mut self, method: &str, params: Value) -> Value {
        match self.call(method, params) {
            Ok(v) => v,
            Err(e) => panic!("{method} failed: {e}"),
        }
    }
    fn kind(&mut self, method: &str, params: Value) -> String {
        match self.call(method, params) {
            Ok(v) => panic!("{method} succeeded: {v}"),
            Err(e) => {
                assert_eq!(e["message"], e["data"]["kind"]);
                e["message"].as_str().unwrap().to_string()
            }
        }
    }
    fn status(&mut self) -> Value {
        self.ok("host.status", json!({}))
    }
    fn phase(&mut self) -> String {
        self.status()["transport"]["phase"].as_str().unwrap().to_string()
    }
    /// Close the host's input and return its exit code and what it wrote
    /// to standard error.
    fn end(mut self) -> (i32, String) {
        drop(self.stdin.take());
        let out = self.child.wait_with_output().unwrap();
        (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(30);
    while !ready() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}
/// The stand-in transports that are alive, by process id.
fn transports(base: &Path) -> Vec<u32> {
    std::fs::read_dir(base.join("relay"))
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "alive"))
        .filter_map(|e| e.path().file_stem()?.to_str()?.parse().ok())
        .collect()
}
fn kill(pid: u32) {
    let done = if cfg!(windows) {
        Command::new("taskkill").args(["/PID", &pid.to_string(), "/F"]).output()
    } else {
        Command::new("kill").args(["-9", &pid.to_string()]).output()
    };
    assert!(done.unwrap().status.success());
}
/// Every file under `dir`, with its content.
fn files(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            files(&p, out);
        } else if let Ok(b) = std::fs::read(&p) {
            out.push((p, b));
        }
    }
}
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let (p, t) = (e.path(), to.join(e.file_name()));
        if p.is_dir() {
            copy_dir(&p, &t);
        } else {
            std::fs::copy(&p, &t).unwrap();
        }
    }
}
fn only_dir(base: &Path, prefix: &str) -> PathBuf {
    let found: Vec<PathBuf> = std::fs::read_dir(base)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p.file_name().unwrap().to_str().unwrap().starts_with(prefix))
        .collect();
    assert_eq!(found.len(), 1, "{prefix} in {base:?}");
    found.into_iter().next().unwrap()
}
fn create(p: &mut Proc, password: &str, funds: &[u64]) -> String {
    let funds: Vec<String> = funds.iter().map(u64::to_string).collect();
    let made = p.ok(
        "host.profile.create",
        json!({"password": password, "network": "automated", "test": {"funds": funds}}),
    );
    made["mnemonic"].as_str().unwrap().to_string()
}

#[test]
fn process_exit_expires_pending_signature_but_preserves_final_transaction() {
    check_pending_and_final_after_process_exit(HOST_TEST);
}

#[test]
#[ignore = "needs the previous offline test host to create an old-format fixture"]
fn upgrade_expires_old_prepared_context_and_replays_only_the_saved_result() {
    let program = std::env::var("FLY_PREVIOUS_TEST_HOST").expect("path to the previous offline test host");
    check_pending_and_final_after_process_exit(&program);
}

fn check_pending_and_final_after_process_exit(first_program: &str) {
    let t = Temp::new("nonce-session");
    let mut a = Proc::start(first_program, &t.0, "a", None);
    let mut b = Proc::start(HOST_TEST, &t.0, "b", None);
    create(&mut a, "payer", &[5 * GRIN, 3 * GRIN]);
    create(&mut b, "receiver", &[]);
    a.ok("host.unlock", json!({"password":"payer"}));
    b.ok("host.unlock", json!({"password":"receiver"}));
    let mut exchange = |payer: &mut Proc| {
        let first = payer.ok("paycore.send.prepare", json!({"amount":GRIN.to_string()}));
        let second = b.ok("paycore.receive.draft", json!({"slate":first["slate"]}));
        json!({"op":first["op"], "slate":second["slate"]})
    };
    let completed = exchange(&mut a);
    let original = a.ok("paycore.send.finalize", completed.clone());
    let pending = exchange(&mut a);
    let reserved = a.ok("paycore.balance", json!({}))["reserved"].clone();
    a.child.kill().unwrap();
    a.child.wait().unwrap();
    drop(a);

    let mut reopened = Proc::start(HOST_TEST, &t.0, "a", None);
    reopened.ok("host.unlock", json!({"password":"payer"}));
    let status = reopened.ok("paycore.send.status", json!({"op":pending["op"]}));
    assert_eq!(status["session_expired"], true);
    assert!(reopened.call("paycore.send.finalize", pending).is_err());
    assert_eq!(reopened.ok("paycore.balance", json!({}))["reserved"], reserved);
    assert_eq!(reopened.ok("paycore.send.finalize", completed)["tx"], original["tx"]);
    assert_eq!(reopened.end().0, 0);
    assert_eq!(b.end().0, 0);
}

#[test]
fn genesis_choice_is_written_for_the_unlocked_profile_and_survives_lock() {
    use fly_paycore_bridge::chain_port::bootstrap;
    let t = Temp::new("genesis-choice");
    let mut h = Proc::with_chain(HOST_TEST, &t.0, "wallet", None, "empty");
    create(&mut h, "test password", &[]);
    assert_eq!(h.kind("paycore.chain.bootstrap_genesis", json!({})), "locked");
    h.ok("host.unlock", json!({"password": "test password"}));
    let profile = t.0.join("wallet");
    let folder = std::fs::read_dir(&profile).unwrap().flatten()
        .find(|e| e.file_name().to_string_lossy().starts_with("chain-")).unwrap().path();
    assert!(!bootstrap::selected(&folder, 3).unwrap());
    for _ in 0..2 {
        assert_eq!(h.ok("paycore.chain.bootstrap_genesis", json!({})), json!({"scheduled": true}));
    }
    h.ok("host.lock", json!({}));
    assert!(bootstrap::selected(&folder, 3).unwrap());
    assert!(bootstrap::selected(&folder, 1).is_err());
    assert!(!bootstrap::selected(&profile, 3).unwrap());
    // The RPC must refuse a damaged choice and preserve the original file.
    let marker = folder.join("genesis-automated-v1.intent");
    std::fs::write(&marker, b"damaged").unwrap();
    h.ok("host.unlock", json!({"password": "test password"}));
    assert_eq!(h.kind("paycore.chain.bootstrap_genesis", json!({})), "bootstrap_refused");
    assert_eq!(std::fs::read(marker).unwrap(), b"damaged");
}

#[test]
fn checkpoint_transfer_requires_the_open_profile_and_an_unambiguous_selection() {
    let t = Temp::new("import-checkpoint-files");
    let mut host = Proc::with_chain(HOST_TEST, &t.0, "wallet", None, "empty");
    create(&mut host, "test password", &[]);
    assert_eq!(host.kind("host.import_checkpoint", json!({})), "locked");
    assert_eq!(host.kind("host.export_checkpoint", json!({})), "locked");
    host.ok("host.unlock", json!({"password": "test password"}));
    let file = t.0.join("chosen file");
    std::fs::write(&file, b"unused").unwrap();
    for params in [
        json!({}),
        json!({"checkpoint_path": file, "proof_path": "relative"}),
        json!({"checkpoint_path": file, "proof_path": t.0}),
        json!({"checkpoint_path": file, "proof_path": file}),
        json!({"file_path": "relative"}),
        json!({"file_path": t.0}),
        json!({"checkpoint_path": file, "file_path": file}),
        json!({"proof_path": file, "file_path": file}),
        json!({"checkpoint_path": file, "proof_path": file, "file_path": file}),
    ] {
        assert_eq!(host.kind("host.import_checkpoint", params), "invalid_params");
        assert_eq!(host.status()["profile"], "unlocked");
    }
    assert_eq!(host.kind("host.export_checkpoint", json!({"file_path":"relative"})), "invalid_params");
    assert_eq!(host.status()["profile"], "unlocked");
}

#[test]
#[ignore = "needs the release fly-chain binary, supplied by FLY_TEST_IMPORT_CHAIN"]
fn host_imports_a_real_gshp1_pair_into_the_wallets_chain_directory() {
    let engine = std::env::var_os("FLY_TEST_IMPORT_CHAIN").expect("release chain binary");
    let t = Temp::new("import-checkpoint-pair");
    let new_host = |name: &str| {
        let mut command = Command::new(HOST);
        command.arg("--profile").arg(t.0.join(name)).arg("--guard-dir").arg(t.0.join(format!("{name}-guard")))
            .arg("--chain").arg(&engine).arg("--chain-peer").arg("127.0.0.1:1");
        Proc::spawn(command)
    };
    let mut h = new_host("sender");
    let pass = json!({"password": "test password"});
    h.ok("host.profile.create", json!({"password": "test password", "network": "main"}));
    h.ok("host.unlock", pass.clone());
    let file = t.0.join("публичная точка");
    let selection = json!({"file_path": file});
    assert_eq!(h.kind("host.export_checkpoint", selection.clone()), "checkpoint_export_unavailable");
    assert!(!file.exists());
    assert_eq!(h.status()["profile"], "unlocked");
    let builtin = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../chain/headers/points");
    let point = t.0.join("моя точка.json");
    let proof = t.0.join("образцы GSHP1.bin");
    std::fs::copy(builtin.join("main.json"), &point).unwrap();
    std::fs::write(&proof, b"incomplete").unwrap();
    let selected = json!({"checkpoint_path": point, "proof_path": proof});
    assert_eq!(h.kind("host.import_checkpoint", selected.clone()), "checkpoint_import_refused_locked");
    assert_eq!(h.status()["profile"], "locked");
    h.ok("host.unlock", pass.clone());
    std::fs::copy(builtin.join("main.history"), &proof).unwrap();
    let done = h.ok("host.import_checkpoint", selected);
    assert_eq!(done, json!({"imported":true,"locked":true,"height":4115520,
        "hash":"000622ed34fb7c40c407c79d70b27bcf5841d1c2893da88c191779b7b4761482","samples":420}));
    assert_eq!(h.status()["profile"], "locked");
    std::fs::remove_file(point).unwrap();
    std::fs::remove_file(proof).unwrap();
    h.ok("host.unlock", pass.clone());
    wait_for("verified imported origin after removing the selected files", || {
        h.status()["chain"]["problem"].as_str().is_some_and(|text| {
            text.contains("4115520") && text.contains("imported starting point") && text.contains("GSHP1")
        })
    });
    let export = h.ok("host.export_checkpoint", selection.clone());
    let expected_export = json!({"exported":true,"height":done["height"],"hash":done["hash"],"samples":done["samples"]});
    assert_eq!(export, expected_export);
    assert_eq!(h.status()["profile"], "unlocked");
    let saved = std::fs::read(&file).unwrap();
    assert_eq!(h.kind("host.export_checkpoint", selection.clone()), "checkpoint_export_refused");
    assert_eq!(std::fs::read(&file).unwrap(), saved);
    let active_chain = std::fs::read_dir(t.0.join("sender")).unwrap().flatten()
        .find(|entry| entry.file_name().to_string_lossy().starts_with("chain-")).unwrap().path();
    let internal = active_chain.join("not-wallet-state.bin");
    assert_eq!(h.kind("host.export_checkpoint", json!({"file_path":internal})), "checkpoint_export_refused");
    assert!(!internal.exists());
    assert_eq!(h.status()["profile"], "unlocked");
    assert_eq!(h.end().0, 0);

    let mut recipient = new_host("clean-recipient");
    recipient.ok("host.profile.create", json!({"password": "test password", "network": "main"}));
    recipient.ok("host.unlock", pass.clone());
    let truncated = t.0.join("неполный файл");
    std::fs::write(&truncated, &saved[..saved.len() / 2]).unwrap();
    assert_eq!(recipient.kind("host.import_checkpoint", json!({"file_path":truncated})), "checkpoint_import_refused_locked");
    assert_eq!(recipient.status()["profile"], "locked");
    recipient.ok("host.unlock", pass.clone());
    assert_eq!(recipient.ok("host.import_checkpoint", selection), done);
    assert_eq!(recipient.status()["profile"], "locked");
    std::fs::remove_file(&file).unwrap();
    recipient.ok("host.unlock", pass);
    wait_for("verified origin on the second wallet", || {
        recipient.status()["chain"]["problem"].as_str().is_some_and(|text| {
            text.contains("4115520") && text.contains("imported starting point") && text.contains("GSHP1")
        })
    });
    assert_eq!(recipient.ok("host.export_checkpoint", json!({"file_path": file})), expected_export);
    assert_eq!(std::fs::read(file).unwrap(), saved);
    assert_eq!(recipient.end().0, 0);
}

/// A profile exists only after it was created, opens only with its
/// password, and while it is locked the core answers nothing.
#[test]
fn a_profile_opens_only_with_its_password() {
    let t = Temp::new("open");
    let mut h = Proc::start(HOST_TEST, &t.0, "p", None);
    let st = h.status();
    assert_eq!((&st["profile"], &st["network"]), (&json!("none"), &Value::Null));
    assert_eq!(st["transport"], json!({"configured": false, "phase": "none", "error": null, "problem": null, "starts": 0}));
    assert_eq!(h.kind("paycore.balance", json!({})), "locked");
    assert_eq!(h.kind("host.unlock", json!({"password": "pw one"})), "no_profile");
    assert_eq!(h.kind("host.profile.create", json!({"password": "", "network": "automated"})), "invalid_params");
    assert_eq!(h.kind("host.profile.create", json!({"password": "pw one", "network": "moon"})), "invalid_params");
    assert_eq!(h.kind("host.profile.create", json!({"network": "automated"})), "invalid_params");
    assert_eq!(h.status()["profile"], "none", "a refused creation leaves no profile");

    let phrase = create(&mut h, "pw one", &[]);
    assert_eq!(phrase.split(' ').count(), 24);
    let st = h.status();
    assert_eq!((&st["profile"], &st["network"]), (&json!("locked"), &json!("automated")));
    assert_eq!(h.kind("host.profile.create", json!({"password": "x", "network": "automated"})), "profile_exists");
    assert_eq!(
        h.kind("host.profile.restore", json!({"password": "x", "network": "automated", "mnemonic": phrase})),
        "profile_exists"
    );
    assert_eq!(h.kind("paycore.balance", json!({})), "locked", "created is not unlocked");

    assert_eq!(h.kind("host.unlock", json!({"password": "pw onf"})), "wrong_password");
    assert_eq!(h.kind("host.unlock", json!({})), "invalid_params");
    assert_eq!(h.kind("paycore.balance", json!({})), "locked");
    let opened = h.ok("host.unlock", json!({"password": "pw one"}));
    // "caught_up": the blocks a profile starts with are not steps the guard
    // is moved for; it follows at the next opening
    assert_eq!(opened, json!({"guard": "caught_up", "guard_key": "existing", "recovered": false}));
    assert_eq!(h.status()["profile"], "unlocked");
    assert_eq!(h.kind("host.unlock", json!({"password": "pw one"})), "already_unlocked");
    assert_eq!(h.ok("paycore.balance", json!({}))["spendable"], "0");
    assert_eq!(h.kind("paycore.delivery.pump", json!({})), "no_mailbox", "no transport was given");

    // the phrase is shown again only for the password
    assert_eq!(h.ok("host.profile.mnemonic", json!({"password": "pw one"}))["mnemonic"], phrase.as_str());
    assert_eq!(h.kind("host.profile.mnemonic", json!({"password": "pw two"})), "wrong_password");
    assert_eq!(h.kind("host.profile.mnemonic", json!({})), "invalid_params");

    h.ok("host.lock", json!({}));
    assert_eq!(h.status()["profile"], "locked");
    assert_eq!(h.kind("paycore.balance", json!({})), "locked");
    h.ok("host.lock", json!({}));

    // a new password: the old one stops working, nothing else changes
    assert_eq!(
        h.kind("host.profile.change_password", json!({"password": "nope", "new_password": "pw two"})),
        "wrong_password"
    );
    assert_eq!(h.kind("host.profile.change_password", json!({"password": "pw one"})), "invalid_params");
    h.ok("host.profile.change_password", json!({"password": "pw one", "new_password": "pw two"}));
    assert_eq!(h.kind("host.unlock", json!({"password": "pw one"})), "wrong_password");
    assert_eq!(h.ok("host.unlock", json!({"password": "pw two"}))["recovered"], false);
    assert_eq!(h.ok("host.profile.mnemonic", json!({"password": "pw two"}))["mnemonic"], phrase.as_str());

    // the interface goes away: the host locks and ends by itself
    assert_eq!(h.end(), (0, String::new()));
    // and the profile is free for the next host
    let mut again = Proc::start(HOST_TEST, &t.0, "p", None);
    assert_eq!(again.ok("host.unlock", json!({"password": "pw two"}))["guard"], "match");
    // while that one has it open, a second host cannot open it
    let mut second = Proc::start(HOST_TEST, &t.0, "p", None);
    assert_eq!(second.kind("host.unlock", json!({"password": "pw two"})), "profile_io");
    assert_eq!(second.status()["profile"], "locked");
    assert_eq!(again.ok("paycore.balance", json!({}))["spendable"], "0");
}

/// The recovery phrase is the wallet: restored elsewhere it gives the same
/// keys. Anything that is not a phrase is refused.
#[test]
fn the_phrase_restores_the_same_wallet() {
    let t = Temp::new("restore");
    let mut a = Proc::start(HOST_TEST, &t.0, "a", None);
    let phrase = create(&mut a, "pw", &[]);
    a.ok("host.unlock", json!({"password": "pw"}));
    let address = a.ok("paycore.address", json!({}))["address"].clone();

    let mut b = Proc::start(HOST_TEST, &t.0, "b", None);
    for bad in ["", "abandon", &phrase[..phrase.len() - 1], &format!("{phrase} zoo"), &"a ".repeat(600)] {
        assert_eq!(
            b.kind("host.profile.restore", json!({"password": "other", "network": "automated", "mnemonic": bad})),
            "bad_mnemonic",
            "{bad:?}"
        );
    }
    assert_eq!(b.kind("host.profile.restore", json!({"password": "other", "network": "automated"})), "invalid_params");
    assert_eq!(b.status()["profile"], "none");
    // typed with capitals and uneven spaces
    let typed = format!("  {}  ", phrase.to_uppercase().replace(' ', "   "));
    assert_eq!(
        b.ok("host.profile.restore", json!({"password": "other", "network": "automated", "mnemonic": typed})),
        json!({})
    );
    b.ok("host.unlock", json!({"password": "other"}));
    assert_eq!(b.ok("paycore.address", json!({}))["address"], address);
    assert_eq!(b.ok("host.profile.mnemonic", json!({"password": "other"}))["mnemonic"], phrase.as_str());

    // a different phrase is a different wallet
    let mut c = Proc::start(HOST_TEST, &t.0, "c", None);
    let other = create(&mut c, "pw", &[]);
    assert_ne!(other, phrase);
    c.ok("host.unlock", json!({"password": "pw"}));
    assert_ne!(c.ok("paycore.address", json!({}))["address"], address);
}

/// The whole road: two hosts, two transport processes, one payment. The
/// transport is started by the host when the profile has an identity,
/// follows the profile's lock, and no secret of the wallet is left in any
/// file in readable form.
#[test]
fn a_payment_crosses_between_two_hosts() {
    let t = Temp::new("pay");
    let relay = t.relay();
    let mut a = Proc::start(HOST_TEST, &t.0, "a", Some(&relay));
    let mut b = Proc::start(HOST_TEST, &t.0, "b", Some(&relay));
    let phrase_a = create(&mut a, "password of a", &[5 * GRIN, 3 * GRIN]);
    create(&mut b, "password of b", &[]);
    a.ok("host.unlock", json!({"password": "password of a"}));
    b.ok("host.unlock", json!({"password": "password of b"}));
    assert_eq!(a.ok("paycore.balance", json!({}))["spendable"], (8 * GRIN).to_string());
    let st = a.status();
    assert_eq!(st["transport"]["configured"], true);
    assert_eq!(st["transport"]["phase"], "none", "no identity, no transport");
    assert!(transports(&t.0).is_empty());

    let ida = a.ok("paycore.identity.create", json!({}));
    let idb = b.ok("paycore.identity.create", json!({}));
    wait_for("both transports", || a.phase() == "ready" && b.phase() == "ready");
    assert_eq!(transports(&t.0).len(), 2);
    a.ok("paycore.contacts.set", json!({"key": idb["public"], "name": "b"}));
    b.ok("paycore.contacts.set", json!({"key": ida["public"], "name": "a"}));
    wait_for("both transports again", || a.phase() == "ready" && b.phase() == "ready");
    wait_for("the old transports to end", || transports(&t.0).len() == 2);

    b.ok("paycore.receive.set_auto", json!({"on": true}));
    let p = a.ok("paycore.send.prepare", json!({"amount": GRIN.to_string(), "deliver_to": idb["public"]}));
    wait_for("the reply to be held", || {
        a.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e["params"]["event"]["kind"] == "reply_held" && e["params"]["event"]["op"] == p["op"])
    });
    assert!(a.events.lock().unwrap().iter().all(|e| e["method"] == "paycore.event"));
    assert!(b
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|e| e["params"]["event"]["kind"] == "payment_answered"));
    // nothing is signed until the user confirms
    let st = a.ok("paycore.send.status", json!({"op": p["op"]}));
    assert_eq!((&st["state"], &st["reply_held"]), (&json!("prepared"), &json!(true)));
    let fin = a.ok("paycore.send.finalize_held", json!({"op": p["op"]}));
    assert!(fin["tx"].as_str().unwrap().len() > 100);

    // no secret of the wallet in any file, as text or as hex
    let nsec = a.ok("paycore.identity.export", json!({}))["nsec"].as_str().unwrap().to_string();
    let mut all = Vec::new();
    files(&t.0, &mut all);
    assert!(all.len() > 6);
    let words: Vec<&str> = phrase_a.split(' ').collect();
    for (path, content) in &all {
        let text = String::from_utf8_lossy(content);
        for secret in ["password of a", "password of b", &nsec, &words[..3].join(" ")] {
            assert!(!text.contains(secret), "{secret:?} in {path:?}");
        }
    }

    // locking ends the transport of that profile and no other
    let before = transports(&t.0);
    a.ok("host.lock", json!({}));
    assert_eq!(a.phase(), "none");
    wait_for("the transport of a to end", || transports(&t.0).len() == 1);
    assert!(before.contains(&transports(&t.0)[0]));
    assert_eq!(b.phase(), "ready");
    // unlocking starts it again; the identity is in the journal
    a.ok("host.unlock", json!({"password": "password of a"}));
    wait_for("the transport of a to return", || a.phase() == "ready");
    assert_eq!(a.ok("paycore.identity.get", json!({}))["public"], ida["public"]);
    assert_eq!(a.ok("paycore.send.status", json!({"op": p["op"]}))["state"], "finalized");
    // the interface goes away: the transports go with their hosts
    assert_eq!(a.end().0, 0);
    assert_eq!(b.end().0, 0);
    wait_for("every transport to end", || transports(&t.0).is_empty());
}
/// K151-K158 across processes: two hosts, each with its own Tor process
/// and its own Tor directory. A payment to an address is asked about in
/// the recipient's window, answered, and waits for the sender's signature.
/// Locking a wallet ends its Tor process and no other.
/// The Tor bridges the user chose reach the process that uses Tor, as they
/// were written. No file is no bridges. A file that is there and cannot be
/// used is never taken for "no bridges": the process is told so, and Tor
/// does not come up rather than be reached directly.
#[test]
fn the_users_tor_bridges_reach_the_process_that_uses_tor() {
    let t = Temp::new("tor-bridges");
    let lines = "# chosen in the window\nobfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=abc iat-mode=0\n\n198.51.100.25:443 7DD62766BF2052432051D7B7E08A22F7E34A4543\n";
    let file = t.0.join("tor-bridges.txt");
    std::fs::write(&file, lines).unwrap();
    let mut a = Proc::with_onion_and_bridges(HOST_TEST, &t.0, "a", &file);
    create(&mut a, "password of a", &[]);
    assert_eq!(a.status()["tor_bridges"], json!({"lines": 2, "usable": true}));
    a.ok("host.unlock", json!({"password": "password of a"}));
    wait_for("the Tor process of a", || a.ok("paycore.onion.status", json!({}))["phase"] == "listening");
    let seen = only_dir(&t.0.join("a"), "onion-").join("tor-bridges.seen");
    assert_eq!(std::fs::read_to_string(&seen).unwrap(), lines);

    // without the argument, and with a file that is not there: none
    let mut b = Proc::with_onion(HOST_TEST, &t.0, "b");
    let mut c = Proc::with_onion_and_bridges(HOST_TEST, &t.0, "c", &t.0.join("no-such-file.txt"));
    for (host, password) in [(&mut b, "password of b"), (&mut c, "password of c")] {
        create(host, password, &[]);
        assert_eq!(host.status()["tor_bridges"], json!({"lines": 0, "usable": true}));
        host.ok("host.unlock", json!({"password": password}));
        wait_for("a Tor process without bridges", || host.ok("paycore.onion.status", json!({}))["phase"] == "listening");
    }
    assert!(!only_dir(&t.0.join("b"), "onion-").join("tor-bridges.seen").exists());
    assert!(!only_dir(&t.0.join("c"), "onion-").join("tor-bridges.seen").exists());

    // a folder where the file should be: the choice cannot be read
    let odd = t.0.join("a-folder");
    std::fs::create_dir_all(&odd).unwrap();
    let mut d = Proc::with_onion_and_bridges(HOST_TEST, &t.0, "d", &odd);
    create(&mut d, "password of d", &[]);
    assert_eq!(d.status()["tor_bridges"], json!({"lines": 1, "usable": false}));
    d.ok("host.unlock", json!({"password": "password of d"}));
    wait_for("the Tor process of d to say why", || {
        let s = d.ok("paycore.onion.status", json!({}));
        s["phase"] != "listening" && s["problem"].as_str().is_some_and(|p| p.contains("bridges"))
    });
    assert_eq!(std::fs::read_to_string(only_dir(&t.0.join("d"), "onion-").join("tor-bridges.seen")).unwrap(), "unusable");
    assert_ne!(d.ok("paycore.onion.status", json!({}))["phase"], "listening");

    // one choice for everything that uses Tor: the chain process, the message
    // transport and the address process are each handed the same lines
    let mut command = Command::new(HOST_TEST);
    command
        .arg("--profile")
        .arg(t.0.join("e"))
        .arg("--guard-dir")
        .arg(t.0.join("e-guard"))
        .arg("--chain")
        .arg(CHAIN)
        .arg("--transport")
        .arg(STUB)
        .arg("--relay")
        .arg("wss://relay.example")
        .arg("--onion")
        .arg(ONION)
        .arg("--tor-bridges")
        .arg(&file);
    let mut e = Proc::spawn(command);
    create(&mut e, "password of e", &[]);
    e.ok("host.unlock", json!({"password": "password of e"}));
    e.ok("paycore.identity.create", json!({}));
    fn seen_under(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                seen_under(&path, out);
            } else if path.file_name().is_some_and(|n| n == "tor-bridges.seen") {
                out.push(path);
            }
        }
    }
    let mut found = Vec::new();
    wait_for("the three processes of e to be handed the bridges", || {
        found.clear();
        seen_under(&t.0.join("e"), &mut found);
        found.len() >= 3
    });
    assert_eq!(found.len(), 3, "{found:?}");
    for path in &found {
        assert_eq!(std::fs::read_to_string(path).unwrap(), lines, "{path:?}");
    }

    // K201: the owner changes the bridges while the wallet is open. The host
    // is told "now" and starts each of the three anew on the new lines: no
    // restart of the wallet and no password again
    let new_lines = "obfs4 203.0.113.9:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=xyz iat-mode=0\n";
    std::fs::write(&file, new_lines).unwrap();
    assert_eq!(e.ok("host.tor.bridges", json!({})), json!({"lines": 1, "usable": true}));
    wait_for("the three processes of e to be started anew on the new lines", || {
        let _ = e.tip();
        let _ = e.ok("paycore.onion.status", json!({}));
        let _ = e.ok("paycore.transport.status", json!({}));
        found.clear();
        seen_under(&t.0.join("e"), &mut found);
        found.len() == 3 && found.iter().all(|p| std::fs::read_to_string(p).is_ok_and(|text| text == new_lines))
    });
    // the wallet stayed open
    e.ok("paycore.balance", json!({}));
    // told of a choice that cannot be read, the host says so, as at its start
    assert_eq!(d.ok("host.tor.bridges", json!({})), json!({"lines": 1, "usable": false}));
}

#[test]
fn a_payment_to_an_address_crosses_between_two_hosts() {
    let t = Temp::new("onion");
    let mut a = Proc::with_onion(HOST_TEST, &t.0, "a");
    let mut b = Proc::with_onion(HOST_TEST, &t.0, "b");
    let phrase_a = create(&mut a, "password of a", &[5 * GRIN, 3 * GRIN]);
    create(&mut b, "password of b", &[]);
    assert_eq!(a.status()["onion"]["configured"], true);
    // a locked wallet has no Tor: its address key is not there to give
    assert_eq!(a.kind("paycore.onion.status", json!({})), "locked");
    a.ok("host.unlock", json!({"password": "password of a"}));
    b.ok("host.unlock", json!({"password": "password of b"}));
    wait_for("both Tor processes", || {
        a.ok("paycore.onion.status", json!({}))["phase"] == "listening" && b.ok("paycore.onion.status", json!({}))["phase"] == "listening"
    });
    // each wallet keeps Tor's files in a directory of its own
    let (dir_a, dir_b) = (only_dir(&t.0.join("a"), "onion-"), only_dir(&t.0.join("b"), "onion-"));
    assert_ne!(dir_a, dir_b);

    let to = b.ok("paycore.address", json!({}))["address"].clone();
    let p = a.ok("paycore.send.prepare", json!({"amount": GRIN.to_string(), "proof_to": to}));
    assert_eq!(a.ok("paycore.onion.send", json!({"op": p["op"]}))["state"], "posted");
    // the recipient does not know the sender: the user is asked
    wait_for("the payment to wait for b", || !b.ok("paycore.onion.status", json!({}))["asks"].as_array().unwrap().is_empty());
    let ask = b.ok("paycore.onion.status", json!({}))["asks"][0].clone();
    assert_eq!(ask["amount"], GRIN.to_string());
    assert_eq!(ask["known_sender"], false);
    assert!(b.events.lock().unwrap().iter().any(|e| e["params"]["source"] == "onion" && e["params"]["event"]["kind"] == "needs_approval"));
    let reply = b.ok("paycore.onion.accept", json!({"id": ask["id"]}));
    assert!(reply["slate"].as_str().unwrap().len() > 100);
    wait_for("the reply to be held", || {
        a.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e["params"]["source"] == "onion" && e["params"]["event"]["kind"] == "reply_held" && e["params"]["event"]["op"] == p["op"])
    });
    // nothing is signed until the user confirms
    let st = a.ok("paycore.send.status", json!({"op": p["op"]}));
    assert_eq!((&st["state"], &st["reply_held"]), (&json!("prepared"), &json!(true)));
    let fin = a.ok("paycore.send.finalize_held", json!({"op": p["op"]}));
    assert!(fin["tx"].as_str().unwrap().len() > 100);
    assert!(!fin["payment_proof"].is_null());

    // a payment nobody takes: the sender is told, the payment stays as it was
    let q = a.ok("paycore.send.prepare", json!({"amount": GRIN.to_string(), "proof_to": to}));
    a.ok("paycore.onion.send", json!({"op": q["op"]}));
    wait_for("the second payment to wait for b", || !b.ok("paycore.onion.status", json!({}))["asks"].as_array().unwrap().is_empty());
    let ask = b.ok("paycore.onion.status", json!({}))["asks"][0].clone();
    b.ok("paycore.onion.decline", json!({"id": ask["id"]}));
    wait_for("the refusal to reach a", || {
        a.ok("paycore.onion.status", json!({}))["sends"].as_array().unwrap().iter().any(|s| s["op"] == q["op"] && s["state"] == "failed")
    });
    assert_eq!(a.ok("paycore.send.status", json!({"op": q["op"]}))["state"], "prepared");

    // no secret of the wallet in any file - Tor's directories included
    let mut all = Vec::new();
    files(&t.0, &mut all);
    let words: Vec<&str> = phrase_a.split(' ').collect();
    for (path, content) in &all {
        let text = String::from_utf8_lossy(content);
        for secret in ["password of a", "password of b", &words[..3].join(" ")] {
            assert!(!text.contains(secret), "{secret:?} in {path:?}");
        }
    }

    // locking ends the Tor process of that wallet and no other
    a.ok("host.lock", json!({}));
    assert_eq!(a.kind("paycore.onion.status", json!({})), "locked");
    assert_eq!(b.ok("paycore.onion.status", json!({}))["phase"], "listening");
    a.ok("host.unlock", json!({"password": "password of a"}));
    wait_for("the Tor process of a to return", || a.ok("paycore.onion.status", json!({}))["phase"] == "listening");
    assert_eq!(a.ok("paycore.send.status", json!({"op": p["op"]}))["state"], "finalized");
    assert_eq!(a.end().0, 0);
    assert_eq!(b.end().0, 0);
}
/// The wallet never waits for the transport: a transport that is slow to
/// start, refuses, or dies is reported, tried again after a pause, and
/// meanwhile nothing is said that is not known.
#[test]
fn the_wallet_does_not_depend_on_the_transport_being_up() {
    // a transport that never becomes ready
    let t = Temp::new("slow");
    let mut h = Proc::start(HOST_TEST, &t.0, "p", Some("silent"));
    create(&mut h, "pw", &[5 * GRIN]);
    h.ok("host.unlock", json!({"password": "pw"}));
    let began = Instant::now();
    let me = h.ok("paycore.identity.create", json!({}));
    assert!(began.elapsed() < Duration::from_secs(5), "the identity does not wait for the transport");
    assert_eq!(h.phase(), "starting");
    // nothing can be sealed, so nothing is reserved either
    assert_eq!(h.kind("paycore.contacts.set", json!({"key": me["public"], "name": "me"})), "refused");
    h.ok("paycore.contacts.set", json!({"key": SOMEBODY, "name": "somebody"}));
    let refused = h.call("paycore.send.prepare", json!({"amount": GRIN.to_string(), "deliver_to": SOMEBODY}));
    assert!(refused.is_err());
    assert_eq!(h.ok("paycore.balance", json!({}))["spendable"], (5 * GRIN).to_string());
    assert_eq!(h.ok("paycore.balance", json!({}))["reserved"], "0");
    // by hand it still works
    assert!(h.call("paycore.send.prepare", json!({"amount": GRIN.to_string()})).is_ok());
    let began = Instant::now();
    h.ok("host.lock", json!({}));
    assert!(began.elapsed() < Duration::from_secs(5), "locking does not wait for the transport");
    assert_eq!(h.phase(), "none");
    assert_eq!(h.end().0, 0);

    // a transport that refuses to start: reported, and tried again
    let t = Temp::new("refuse");
    let mut h = Proc::start(HOST_TEST, &t.0, "p", Some("refuse"));
    create(&mut h, "pw", &[]);
    h.ok("host.unlock", json!({"password": "pw"}));
    h.ok("paycore.identity.create", json!({}));
    wait_for("the refusal", || h.phase() == "down");
    let st = h.status();
    assert_eq!(st["transport"]["error"], "the transport did not start: the relay address is not usable");
    let starts = st["transport"]["starts"].as_u64().unwrap();
    wait_for("another attempt", || h.status()["transport"]["starts"].as_u64().unwrap() > starts);
    assert_eq!(h.ok("paycore.delivery.pump", json!({}))["published"], json!([]));

    // a transport program that does not exist
    let mut command = Command::new(HOST_TEST);
    command
        .arg("--profile")
        .arg(t.0.join("q"))
        .arg("--guard-dir")
        .arg(t.0.join("q-guard"))
        .arg("--transport")
        .arg(t.0.join("no-such-program"))
        .arg("--relay")
        .arg("wss://relay.example");
    let mut q = Proc::spawn(command);
    create(&mut q, "pw", &[]);
    q.ok("host.unlock", json!({"password": "pw"}));
    q.ok("paycore.identity.create", json!({}));
    assert_eq!(q.phase(), "down");
    assert_eq!(q.status()["transport"]["error"], "the transport process could not be started");

    // a transport that dies is started again, with the same identity
    let t = Temp::new("dies");
    let relay = t.relay();
    let mut h = Proc::start(HOST_TEST, &t.0, "p", Some(&relay));
    create(&mut h, "pw", &[]);
    h.ok("host.unlock", json!({"password": "pw"}));
    h.ok("paycore.identity.create", json!({}));
    wait_for("the transport", || h.phase() == "ready");
    let first = transports(&t.0);
    assert_eq!((first.len(), h.status()["transport"]["starts"].as_u64()), (1, Some(1)));
    kill(first[0]);
    // the killed one could not remove its marker
    std::fs::remove_file(t.0.join("relay").join(format!("{}.alive", first[0]))).unwrap();
    wait_for("the host to notice", || h.status()["transport"]["starts"].as_u64() == Some(2));
    wait_for("the transport to return", || h.phase() == "ready");
    let second = transports(&t.0);
    assert_eq!(second.len(), 1);
    assert_ne!(second, first);
}

/// When the relay refuses, the interface is told why, in plain text, and
/// the relay is not asked again and again: the pause between attempts
/// grows. The user can ask for an attempt at once.
#[test]
fn a_refusing_relay_is_reported_and_not_hammered() {
    let t = Temp::new("refusal");
    let relay = t.relay();
    let mut h = Proc::start(HOST_TEST, &t.0, "p", Some(&relay));
    create(&mut h, "pw", &[5 * GRIN]);
    h.ok("host.unlock", json!({"password": "pw"}));
    h.ok("paycore.identity.create", json!({}));
    h.ok("paycore.contacts.set", json!({"key": SOMEBODY, "name": "somebody"}));
    wait_for("the transport", || h.phase() == "ready");
    assert_eq!(h.status()["transport"]["problem"], Value::Null);
    // what a relay says is anybody's text
    let trouble = t.0.join("relay").join("trouble");
    std::fs::write(&trouble, "the relay did not accept the message: blocked:\u{7} not\non the list \u{444}").unwrap();
    let p = h.ok("paycore.send.prepare", json!({"amount": GRIN.to_string(), "deliver_to": SOMEBODY}));
    let attempts = |h: &Proc| {
        h.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e["params"]["source"] == "published" && e["params"]["event"]["op"] == p["op"])
            .count()
    };
    wait_for("the refusal to be reported", || h.status()["transport"]["problem"].is_string());
    assert_eq!(
        h.status()["transport"]["problem"],
        "the relay did not accept the message: blocked:? not?on the list ?"
    );
    assert_eq!(h.status()["transport"]["phase"], "ready", "a refusing relay is not a dead transport");
    // the worker makes a round five times a second; the envelope is offered
    // at once, after two seconds, after four more
    std::thread::sleep(Duration::from_millis(3500));
    let seen = attempts(&h);
    assert!((1..=2).contains(&seen), "{seen} attempts in the first seconds");
    assert_eq!(h.ok("paycore.send.status", json!({"op": p["op"]}))["delivery"], "waiting_relay");
    // the relay comes round; the user does not have to wait out the pause
    std::fs::remove_file(&trouble).unwrap();
    let r = h.ok("paycore.delivery.pump", json!({"now": true}));
    assert_eq!(r["published"][0]["delivery"], "relay_accepted");
    wait_for("the report to clear", || h.status()["transport"]["problem"].is_null());
    assert_eq!(h.ok("paycore.send.status", json!({"op": p["op"]}))["delivery"], "relay_accepted");
}

/// The tail guard: a key file that is damaged is not replaced without
/// being asked; a guard that is gone and a journal that was rolled back are
/// both noticed and reported; a journal that is gone is never replaced by
/// an empty one.
#[test]
fn a_moved_or_rolled_back_profile_is_noticed() {
    let t = Temp::new("guard");
    let mut h = Proc::start(HOST_TEST, &t.0, "p", None);
    create(&mut h, "pw", &[5 * GRIN]);
    let profile = t.0.join("p");
    let journal = only_dir(&profile, "wallet-");
    let guard = only_dir(&t.0.join("p-guard"), "");
    assert_eq!(h.ok("host.unlock", json!({"password": "pw"}))["guard"], "caught_up");
    h.ok("host.lock", json!({}));
    assert_eq!(h.ok("host.unlock", json!({"password": "pw"}))["guard"], "match");
    h.ok("host.lock", json!({}));

    // the journal as it is now, then one more step, then the old copy back
    let old = t.0.join("old-journal");
    copy_dir(&journal, &old);
    h.ok("host.unlock", json!({"password": "pw"}));
    h.ok("paycore.identity.create", json!({}));
    h.ok("host.lock", json!({}));
    // the guard follows at the next opening at the latest
    assert_eq!(h.ok("host.unlock", json!({"password": "pw"}))["recovered"], false);
    assert!(h.ok("paycore.identity.get", json!({}))["public"].is_string());
    h.ok("host.lock", json!({}));
    let newer = t.0.join("newer-journal");
    std::fs::rename(&journal, &newer).unwrap();
    copy_dir(&old, &journal);
    let opened = h.ok("host.unlock", json!({"password": "pw"}));
    assert_eq!(opened, json!({"guard": "rolled_back", "guard_key": "existing", "recovered": true}));
    assert_eq!(h.ok("paycore.identity.get", json!({}))["public"], Value::Null, "the old state, and said so");
    h.ok("host.lock", json!({}));
    assert_eq!(h.ok("host.unlock", json!({"password": "pw"}))["recovered"], false, "reported once");
    h.ok("host.lock", json!({}));

    // a damaged key file
    let key = guard.join("guard.key");
    let good = std::fs::read(&key).unwrap();
    std::fs::write(&key, b"not a key file").unwrap();
    let e = h.call("host.unlock", json!({"password": "pw"})).unwrap_err();
    assert_eq!((&e["message"], &e["data"]["reason"]), (&json!("guard"), &json!("damaged")));
    assert_eq!(h.status()["profile"], "locked");
    assert_eq!(std::fs::read(&key).unwrap(), b"not a key file", "left as it was");
    // a key wrapped for somebody else
    let mut foreign = good.clone();
    let last = foreign.len() - 1;
    foreign[last] ^= 1;
    std::fs::write(&key, &foreign).unwrap();
    let e = h.call("host.unlock", json!({"password": "pw"})).unwrap_err();
    assert_eq!((&e["message"], &e["data"]["reason"]), (&json!("guard"), &json!("foreign")));
    // replaced only on request, and then the wallet says it cannot vouch
    let opened = h.ok("host.unlock", json!({"password": "pw", "reset_guard": true}));
    assert_eq!(opened, json!({"guard": "missing", "guard_key": "reset", "recovered": true}));
    h.ok("host.lock", json!({}));
    assert_eq!(
        h.ok("host.unlock", json!({"password": "pw", "reset_guard": true})),
        json!({"guard": "match", "guard_key": "existing", "recovered": false}),
        "a good key is not reset"
    );
    h.ok("host.lock", json!({}));

    // the guard is gone altogether: the profile came from elsewhere
    std::fs::rename(&guard, t.0.join("guard-moved")).unwrap();
    let opened = h.ok("host.unlock", json!({"password": "pw"}));
    assert_eq!(opened, json!({"guard": "missing", "guard_key": "created", "recovered": true}));
    assert_eq!(h.ok("paycore.balance", json!({}))["spendable"], (5 * GRIN).to_string());
    h.ok("host.lock", json!({}));

    // the journal is gone: no empty wallet appears in its place
    std::fs::rename(&journal, t.0.join("journal-moved")).unwrap();
    assert_eq!(h.kind("host.unlock", json!({"password": "pw"})), "no_journal");
    assert!(!journal.exists());
    assert_eq!(h.status()["profile"], "locked");
}

/// Lines that are not requests get an error and do no harm; the product
/// program has no test chain and no test network; a wrong start is refused.
#[test]
fn the_product_program_and_bad_input() {
    let t = Temp::new("product");
    let mut h = Proc::start(HOST, &t.0, "p", None);
    for (line, kind) in [
        ("this is not json", "parse_error"),
        ("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"host.status\"", "parse_error"),
        ("[]", "invalid_request"),
        ("{}", "invalid_request"),
        ("{\"id\":1,\"method\":\"host.status\"}", "invalid_request"),
        ("{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"host.status\"}", "invalid_request"),
        ("{\"jsonrpc\":\"2.0\",\"id\":[1],\"method\":\"host.status\"}", "invalid_request"),
        ("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":7}", "invalid_request"),
        // two methods in one request: neither is run
        ("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"host.status\",\"method\":\"host.lock\"}", "invalid_request"),
        ("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"host.nothing\"}", "method_not_found"),
        ("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"host.unlock\",\"params\":[1]}", "invalid_params"),
        ("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"host.unlock\",\"params\":{\"password\":5}}", "invalid_params"),
        ("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"paycore.balance\"}", "locked"),
        ("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"anything.else\"}", "locked"),
    ] {
        let v = h.raw(line);
        assert_eq!(v["error"]["message"], kind, "{line}");
        assert!(v.get("result").is_none());
    }
    // a line longer than any request: refused, and the next one is read
    let long = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"host.status\",\"x\":\"{}\"}}", "a".repeat(300_000));
    let v = h.raw(&long);
    assert_eq!((&v["error"]["message"], &v["error"]["data"]["reason"]), (&json!("invalid_request"), &json!("too large")));
    // empty lines are nothing
    h.stdin.as_mut().unwrap().write_all(b"\n   \n\r\n").unwrap();
    assert_eq!(h.status()["profile"], "none");
    assert_eq!(h.status()["api_version"], 1);

    // no test network and no test funds in the product
    assert_eq!(h.kind("host.profile.create", json!({"password": "pw", "network": "automated"})), "invalid_params");
    let made = h.ok("host.profile.create", json!({"password": "pw", "network": "test", "test": {"funds": ["5"]}}));
    assert_eq!(made["mnemonic"].as_str().unwrap().split(' ').count(), 24);
    assert_eq!(h.status()["network"], "test");
    assert_eq!(h.ok("host.unlock", json!({"password": "pw"}))["recovered"], false);
    assert_eq!(h.ok("paycore.info", json!({}))["tip_height"], Value::Null, "nothing was put on the chain");
    let b = h.ok("paycore.balance", json!({}));
    assert_eq!((&b["spendable"], &b["immature"]), (&json!("0"), &json!("0")));
    assert_eq!(h.kind("paycore.chain.sync", json!({})), "no_chain", "the product has no chain of its own");
    assert_eq!(h.ok("paycore.chain.status", json!({}))["state"], "unknown");
    assert_eq!(h.end(), (0, String::new()));
    // given a chain program, the product follows that and nothing else
    let chain = Chain::new(&t.0);
    let mut h = Proc::with_chain(HOST, &t.0, "p", None, &chain.peer());
    h.ok("host.unlock", json!({"password": "pw"}));
    wait_for("the product to follow the chain", || h.tip() == Chain::ANCHOR);
    assert_eq!(h.ok("paycore.chain.status", json!({}))["state"], "at_tip");
    let told = std::fs::read_to_string(only_dir(&t.0.join("p"), "chain-").join("told")).unwrap();
    assert!(told.starts_with("network=2\ngenesis=") && told.ends_with("\ndirect_post=0\n"), "{told}");
    assert_eq!(h.end(), (0, String::new()));
    // the user's agreement to send without Tor is passed on, and only then
    let mut command = Command::new(HOST);
    command
        .arg("--profile")
        .arg(t.0.join("p"))
        .arg("--guard-dir")
        .arg(t.0.join("p-guard"))
        .arg("--chain")
        .arg(CHAIN)
        .arg("--chain-peer")
        .arg(chain.peer())
        .arg("--chain-direct-post");
    let mut h = Proc::spawn(command);
    h.ok("host.unlock", json!({"password": "pw"}));
    wait_for("the chain process told again", || {
        std::fs::read_to_string(only_dir(&t.0.join("p"), "chain-").join("told")).is_ok_and(|told| told.ends_with("\ndirect_post=1\n"))
    });
    assert_eq!(h.end(), (0, String::new()));
    // K189: Tor switched off is passed on too, and only when it is
    assert!(!told.contains("tor_off"), "{told}");
    let no_tor = || {
        let mut command = Command::new(HOST);
        command.arg("--profile").arg(t.0.join("p")).arg("--guard-dir").arg(t.0.join("p-guard")).arg("--chain").arg(CHAIN).arg("--chain-peer").arg(chain.peer()).arg("--chain-no-tor");
        command
    };
    let mut h = Proc::spawn(no_tor());
    h.ok("host.unlock", json!({"password": "pw"}));
    wait_for("the chain process told that Tor is off", || {
        std::fs::read_to_string(only_dir(&t.0.join("p"), "chain-").join("told")).is_ok_and(|told| told.ends_with("\ntor_off=1\ndirect_post=0\n"))
    });
    assert_eq!(h.end(), (0, String::new()));
    // K193: programs that need Tor may be named with it; they are not
    // started while Tor is off, and the switch is turned without a restart
    let mut command = no_tor();
    command.arg("--onion").arg(ONION);
    let mut h = Proc::spawn(command);
    assert_eq!(h.status()["tor_off"], true);
    h.ok("host.unlock", json!({"password": "pw"}));
    wait_for("the chain", || h.tip() == Chain::ANCHOR);
    let onion = |h: &mut Proc| h.ok("paycore.onion.status", json!({}));
    assert_eq!(onion(&mut h)["problem"], "Tor is switched off");
    assert!(!chain.dir.join("tor").exists(), "the chain process was told at its start, not again");
    assert_eq!(h.ok("host.tor", json!({"off": false})), json!({"off": false}));
    assert_eq!(h.status()["tor_off"], false);
    wait_for("the Tor process of the address", || onion(&mut h)["phase"] == "listening");
    wait_for("the chain process told", || std::fs::read_to_string(chain.dir.join("tor")).is_ok_and(|t| t == "on"));
    assert_eq!(h.ok("host.tor", json!({"off": true})), json!({"off": true}));
    wait_for("the Tor process let go", || onion(&mut h)["problem"] == "Tor is switched off");
    wait_for("the chain process told again", || { let _ = h.tip(); std::fs::read_to_string(chain.dir.join("tor")).is_ok_and(|t| t == "off") });
    for bad in [json!({}), json!({"off": "yes"}), json!({"off": 1})] {
        assert!(h.call("host.tor", bad.clone()).is_err(), "{bad}");
    }
    assert_eq!(h.status()["tor_off"], true, "a refused turn changes nothing");
    assert_eq!(h.end(), (0, String::new()));
    // without a chain program there is nothing to send without Tor
    let mut bare = Proc::start(HOST, &t.0, "p", None);
    assert!(bare.call("host.tor", json!({"off": true})).is_err());
    assert_eq!(bare.status()["tor_off"], false);
    assert_eq!(bare.end().0, 0);
    let alone = Command::new(HOST).arg("--profile").arg(t.0.join("p")).arg("--guard-dir").arg(t.0.join("p-guard")).arg("--chain-no-tor").output().unwrap();
    assert!(String::from_utf8_lossy(&alone.stderr).contains("--chain-no-tor needs --chain"));
    // the profile file asks for real work to try a password
    let file: Value = serde_json::from_slice(&std::fs::read(t.0.join("p").join("profile.json")).unwrap()).unwrap();
    assert_eq!((&file["kdf"], &file["log_n"], &file["network"]), (&json!("scrypt"), &json!(17), &json!("test")));
    // a profile made by a test program is not opened by the product
    let mut weak = Proc::start(HOST_TEST, &t.0, "weak", None);
    create(&mut weak, "pw", &[]);
    assert_eq!(weak.end().0, 0);
    let mut h = Proc::start(HOST, &t.0, "weak", None);
    let e = h.call("host.unlock", json!({"password": "pw"})).unwrap_err();
    assert_eq!(
        (&e["message"], &e["data"]["reason"]),
        (&json!("profile_damaged"), &json!("key derivation parameters")),
        "refused for the cheap key derivation, before the password is tried"
    );

    // wrong starts: an explanation on standard error, nothing else
    let bad: [&[&str]; 10] = [
        &[],
        &["--profile"],
        &["--profile", "x", "--profile", "y"],
        &["--profile", "x", "--password", "y"],
        &["--profile", "x", "--transport", "y"],
        &["--profile", "x", "--relay", "wss://relay.example"],
        &["--profile", "x", "--chain-peer", "node.example:3414"],
        &["--profile", "x", "--chain", "y", "--chain", "z"],
        &["--profile", "x", "--chain", "y", "--chain-peer"],
        &["--profile", "x", "--chain-direct-post"],
    ];
    for args in bad {
        let mut command = Command::new(HOST);
        command.current_dir(&t.0).args(args).arg("--guard-dir").arg(t.0.join("g"));
        if args.is_empty() {
            command = Command::new(HOST);
        }
        let (code, said) = Proc::spawn(command).end();
        assert_eq!(code, 2, "{args:?}");
        assert!(said.starts_with("fly-paycore-host: "), "{args:?}: {said}");
    }
    // the guard must not travel with the profile
    let mut command = Command::new(HOST);
    command.arg("--profile").arg(t.0.join("r")).arg("--guard-dir").arg(t.0.join("r").join("guard"));
    let (code, said) = Proc::spawn(command).end();
    assert_eq!((code, said.trim()), (2, "fly-paycore-host: the guard directory must lie outside the profile directory"));
}

/// The chain the stand-in chain processes serve: a directory of blocks
/// that the test writes, the way a miner would.
struct Chain {
    dir: PathBuf,
    /// Position the next output gets in the output set.
    next_pos: u64,
    /// Height of the block the chain layer starts from.
    anchor: u64,
}
impl Chain {
    const ANCHOR: u64 = 100;
    fn new(base: &Path) -> Chain {
        let dir = base.join("chain");
        std::fs::create_dir_all(dir.join("blocks")).unwrap();
        let mut anchor = Self::ANCHOR.to_le_bytes().to_vec();
        anchor.extend_from_slice(&[1; 32]);
        std::fs::write(dir.join("anchor"), anchor).unwrap();
        std::fs::write(dir.join("time"), "1000").unwrap();
        std::fs::write(dir.join("k_conf"), "3").unwrap();
        std::fs::write(dir.join("selected"), "").unwrap();
        Chain { dir, next_pos: 1, anchor: Self::ANCHOR }
    }
    /// The chain layer starts again from a later block: it has no block
    /// below it any more, and still vouches for the block `known` - height
    /// and hash - of the chain it had.
    fn restart_at(&mut self, height: u64, fill: u8, known: (u64, u8)) {
        let mut tip = known.0.to_le_bytes().to_vec();
        tip.extend_from_slice(&[known.1; 32]);
        std::fs::write(self.dir.join("old-known"), tip).unwrap();
        self.cut(self.anchor + 1);
        let mut anchor = height.to_le_bytes().to_vec();
        anchor.extend_from_slice(&[fill; 32]);
        let part = self.dir.join("anchor.part");
        std::fs::write(&part, anchor).unwrap();
        std::fs::rename(&part, self.dir.join("anchor")).unwrap();
        self.anchor = height;
    }
    fn peer(&self) -> String {
        format!("dir:{}", self.dir.to_str().unwrap())
    }
    fn file(&self, height: u64) -> PathBuf {
        self.dir.join("blocks").join(format!("{height:020}.blk"))
    }
    fn tip(&self) -> u64 {
        let mut height = self.anchor;
        while self.file(height + 1).exists() {
            height += 1;
        }
        height
    }
    /// Put a block on top; `fill` makes its hash.
    fn mine(&mut self, fill: u8, mut block: BlockFacts) -> u64 {
        block.height = self.tip() + 1;
        block.hash = [fill; 32];
        for o in &mut block.outputs {
            o.pos = self.next_pos;
            self.next_pos += 1;
        }
        // whole or not at all: a chain process never reads half a block
        let part = self.dir.join("block.part");
        std::fs::write(&part, encode_block(&block).unwrap()).unwrap();
        std::fs::rename(&part, self.file(block.height)).unwrap();
        block.height
    }
    fn empty(&mut self, fill: u8) -> u64 {
        self.mine(fill, BlockFacts::default())
    }
    /// Forget the blocks from `height` up, as a reorganisation does.
    fn cut(&self, height: u64) {
        for h in (height..=self.tip()).rev() {
            std::fs::remove_file(self.file(h)).unwrap();
        }
    }
    fn set(&self, name: &str, text: Option<&str>) {
        match text {
            Some(text) => std::fs::write(self.dir.join(name), text).unwrap(),
            None => std::fs::remove_file(self.dir.join(name)).unwrap(),
        }
    }
    /// The chain processes that are alive, by process id.
    fn processes(&self) -> Vec<u32> {
        std::fs::read_dir(&self.dir)
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "chain-alive"))
            .filter_map(|e| e.path().file_stem()?.to_str()?.parse().ok())
            .collect()
    }
    /// Outputs from before the chain's first block, unspent: piece `piece`
    /// of `pieces`.
    fn old(&self, piece: u64, pieces: u64, outputs: Vec<OutputFact>) {
        std::fs::create_dir_all(self.dir.join("old")).unwrap();
        let block = BlockFacts { outputs, ..BlockFacts::default() };
        std::fs::write(self.dir.join("old").join(format!("{piece:020}.blk")), encode_block(&block).unwrap()).unwrap();
        self.set("old-pieces", Some(&pieces.to_string()));
    }
    /// The transactions handed over for broadcast, in order.
    fn posted(&self) -> Vec<Vec<u8>> {
        let mut found: Vec<PathBuf> = match std::fs::read_dir(self.dir.join("posted")) {
            Ok(d) => d.flatten().map(|e| e.path()).collect(),
            Err(_) => Vec::new(),
        };
        found.sort();
        found.iter().map(|p| std::fs::read(p).unwrap()).collect()
    }
}
/// An output of the wallet with this recovery phrase, as a block carries it.
fn coin(phrase: &str, amount: u64, index: u32) -> OutputFact {
    let seed = grin_keychain::mnemonic::to_entropy(phrase).unwrap();
    let k = ExtKeychain::from_seed(&seed, true).unwrap();
    let key = KeyPath::Legacy { account: 0, index }.to_identifier();
    let commit = k.commit(amount, &key, SwitchCommitmentType::Regular).unwrap();
    let rp = proof::create(&k, &ProofBuilder::new(&k), amount, &key, SwitchCommitmentType::Regular, commit, None).unwrap();
    OutputFact { commit: commit.0, proof: rp.proof[..rp.plen].to_vec(), pos: 0, coinbase: false }
}
/// What a block that includes this transaction carries.
fn block_of(tx: &[u8]) -> BlockFacts {
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    let tx: Transaction = ser::deserialize_default(&mut &tx[..]).unwrap();
    let inputs: Vec<grin_core::core::CommitWrapper> = tx.inputs().into();
    BlockFacts {
        outputs: tx
            .outputs()
            .iter()
            .map(|o| OutputFact { commit: o.commitment().0, proof: o.proof_bytes().to_vec(), pos: 0, coinbase: false })
            .collect(),
        inputs: inputs.iter().map(|i| i.commitment().0).collect(),
        kernels: tx.kernels().iter().map(|k| k.excess().0).collect(),
        ..BlockFacts::default()
    }
}

#[test]
fn used_wallet_reserves_under_quorum_and_time_loss_reopen_and_reorg() {
    // The chain process supplies the *results* of tip and time checks. The
    // core, transaction signing, journal, host RPC and IPC are real.
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    let t = Temp::new("used-wallet-quorum-time");
    let mut chain = Chain::new(&t.0);
    chain.old(0, 1, vec![]);
    let peer = chain.peer();
    let mut a = Proc::with_chain(HOST_TEST, &t.0, "payer", None, &peer);
    let mut b = Proc::with_chain(HOST_TEST, &t.0, "receiver", None, &peer);
    let phrase = create(&mut a, "local payer", &[]);
    create(&mut b, "local receiver", &[]);
    let password = json!({"password": "local payer"});
    a.ok("host.unlock", password.clone());
    b.ok("host.unlock", json!({"password":"local receiver"}));
    wait_for("both anchors", || a.tip() == Chain::ANCHOR && b.tip() == Chain::ANCHOR);
    let funding = 5 * GRIN;
    chain.mine(11, BlockFacts { outputs: vec![coin(&phrase, funding, 0), coin(&phrase, funding, 1)],
                                 ..BlockFacts::default() });
    chain.empty(12);
    wait_for("two available outputs and complete archive search", || {
        a.spendable() == (2 * funding).to_string() && a.tip() == 102 &&
            a.ok("paycore.search.status", json!({}))["state"] == "done"
    });
    let basis = |wallet: &mut Proc| wallet.ok("paycore.wallet.chain_status", json!({}));
    let reserved = |wallet: &mut Proc| wallet.ok("paycore.balance", json!({}))["reserved"].clone();
    let before = basis(&mut a);
    assert_eq!((&before["state"], &before["tip_height"], &before["selected_height"],
                &before["confirmed_time"], &before["k_conf"]),
               (&json!("at_tip"), &json!(102), &json!(102), &json!(1000), &json!(3)));
    assert_eq!(reserved(&mut a), "0");
    let prepare = json!({"amount": GRIN.to_string()});
    let pending = a.ok("paycore.send.prepare", prepare.clone());
    let op = json!({"op":pending["op"]});
    assert_eq!(reserved(&mut a), funding.to_string());

    // Time alone disappears, even though the test chain still names the same hash.
    chain.set("time", None);
    let stale = basis(&mut a);
    assert_eq!((&stale["state"], &stale["confirmed_time"], &stale["selected_height"], &stale["balance"]["reserved"]),
               (&json!("behind"), &Value::Null, &Value::Null, &json!(funding.to_string())));
    chain.set("time", Some("1000"));
    assert_eq!(basis(&mut a)["state"], "at_tip");
    chain.set("selected", None);
    let st = basis(&mut a);
    assert_eq!((&st["state"], &st["selected_height"], &st["confirmed_time"]), (&json!("behind"), &Value::Null, &json!(1000)));
    chain.set("time", None);
    let st = basis(&mut a);
    assert_eq!((&st["state"], &st["selected_height"], &st["confirmed_time"]), (&json!("behind"), &Value::Null, &Value::Null));
    assert_eq!(reserved(&mut a), funding.to_string());

    // A second manual selection is possible using the already verified
    // outputs. Cancelling this *unsigned* operation releases just its input.
    let other = a.ok("paycore.send.prepare", prepare);
    assert_eq!(reserved(&mut a), (2 * funding).to_string());
    a.ok("paycore.send.cancel", json!({"op":other["op"]}));
    assert_eq!(reserved(&mut a), funding.to_string());
    let answer = b.ok("paycore.receive.draft", json!({"slate":pending["slate"]}));
    chain.set("post-mode", Some("lost"));
    let result = a.ok("paycore.send.finalize", json!({"slate":answer["slate"], "op":pending["op"]}));
    assert!(!result["tx"].as_str().unwrap().is_empty());
    assert_eq!(a.ok("paycore.send.status", op.clone())["state"], "finalized");
    assert_eq!(a.ok("paycore.send.broadcast", op.clone())["outcome"], "unknown");
    assert!(chain.posted().is_empty());
    assert_eq!(a.end().0, 0);

    let mut a = Proc::with_chain(HOST_TEST, &t.0, "payer", None, &peer);
    a.ok("host.unlock", password);
    wait_for("reopened payer with no selected tip", || a.chain_phase() == "ready");
    assert_eq!(basis(&mut a)["state"], "behind");
    assert_eq!(a.ok("paycore.send.result", op.clone())["tx"], result["tx"]);
    assert_eq!(reserved(&mut a), funding.to_string());
    chain.set("time", Some("1100"));
    assert_eq!(basis(&mut a)["state"], "behind", "time alone never selects a tip");
    chain.set("selected", Some(""));
    assert_eq!(basis(&mut a)["state"], "at_tip");
    chain.set("post-mode", None);
    assert_eq!(a.ok("paycore.send.broadcast", op.clone())["outcome"], "accepted");
    assert_eq!(a.ok("paycore.send.status", op.clone())["state"], "finalized");
    let included = chain.mine(13, block_of(&chain.posted()[0]));
    wait_for("the transfer in the selected branch", || a.ok("paycore.send.status", op.clone())["state"] == "confirmed");
    assert_eq!(reserved(&mut a), "0");

    // The branch keeping the funding block but omitting this transaction
    // becomes visible before the next independent selection.
    chain.set("selected", None);
    chain.set("time", None);
    chain.cut(included);
    chain.empty(23);
    chain.empty(24);
    wait_for("alternate branch without the transaction", || {
        a.tip() == 104 && a.ok("paycore.send.status", op.clone())["state"] == "finalized"
    });
    let on_fork = basis(&mut a);
    assert_eq!(on_fork["state"], "behind");
    assert_eq!(on_fork["balance"]["reserved"], funding.to_string());
    assert_eq!(on_fork["balance"]["spendable"], funding.to_string());
    chain.set("time", Some("1200"));
    chain.set("selected", Some(""));
    assert_eq!(basis(&mut a)["state"], "at_tip");
    assert_eq!(reserved(&mut a), funding.to_string());
    assert_eq!(a.end().0, 0);
    assert_eq!(b.end().0, 0);
}

/// The whole road with a chain: two hosts, each with its own chain process
/// and its own transport process. The wallets learn their money from the
/// blocks, the transaction goes out through the chain process byte for
/// byte, a block confirms it for both, and a reorganisation takes the
/// confirmation back until the transaction is in a block again.
#[test]
fn a_payment_is_followed_on_the_chain() {
    let t = Temp::new("chain");
    let (relay, mut chain) = (t.relay(), Chain::new(&t.0));
    let peer = chain.peer();
    let mut a = Proc::with_chain(HOST_TEST, &t.0, "a", Some(&relay), &peer);
    let mut b = Proc::with_chain(HOST_TEST, &t.0, "b", Some(&relay), &peer);
    let st = a.status();
    assert_eq!(st["chain"], json!({"configured": true, "phase": "none", "error": null, "problem": null, "starts": 0}));
    assert!(chain.processes().is_empty(), "no profile is open, no chain process runs");
    // The test host gives a new profile a position of its own before any
    // chain is there; put on the chain it has missed blocks and searches.
    // The chain has one piece of old outputs, an empty one: until that is
    // read the wallet does not know what it holds and prepares no payment.
    chain.old(0, 1, Vec::new());
    let phrase_a = create(&mut a, "password of a", &[]);
    create(&mut b, "password of b", &[]);
    a.ok("host.unlock", json!({"password": "password of a"}));
    b.ok("host.unlock", json!({"password": "password of b"}));
    wait_for("both chain processes", || a.chain_phase() == "ready" && b.chain_phase() == "ready");
    assert_eq!(chain.processes().len(), 2);
    // each chain process has a directory of its own inside the profile and
    // is told the chain of the profile and the peers of the command line
    let told = std::fs::read_to_string(only_dir(&t.0.join("a"), "chain-").join("told")).unwrap();
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    let genesis: String = grin_core::genesis::genesis_dev().hash().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(told, format!("network=3\ngenesis={genesis}\npeers={peer}\ndirect_post=0\n"));
    assert_ne!(only_dir(&t.0.join("a"), "chain-").file_name(), only_dir(&t.0.join("b"), "chain-").file_name());
    // a wallet with no position is given the chain's starting point
    wait_for("the starting point", || a.tip() == Chain::ANCHOR && b.tip() == Chain::ANCHOR);
    assert_eq!(a.spendable(), "0");

    // money arrives in blocks; the wallet finds its own outputs in them
    chain.mine(11, BlockFacts { outputs: vec![coin(&phrase_a, 5 * GRIN, 0), coin(&phrase_a, 3 * GRIN, 1)], ..BlockFacts::default() });
    chain.empty(12);
    wait_for("the money of a", || a.spendable() == (8 * GRIN).to_string());
    assert_eq!((a.tip(), b.spendable()), (json!(102), "0".to_string()));
    // the core judges against what the layer says now, not what it said
    let seen = json!({"state": "at_tip", "k_conf": 3, "rangeproofs_authenticated": true, "selected_height": 102,
                      "confirmed_time": 1000, "tip_height": 102});
    assert_eq!(a.ok("paycore.chain.status", json!({})), seen);
    // a layer at the tip of its one source, with no tip selected by the
    // acceptance rules, does not make anything more than preliminary
    chain.set("selected", None);
    let st = a.ok("paycore.chain.status", json!({}));
    assert_eq!((&st["state"], &st["selected_height"]), (&json!("behind"), &Value::Null));
    // nor does a tip that is selected but stands on something nobody
    // vouches for: it is named, and everything stays preliminary
    chain.set("selected", Some(""));
    chain.set("provisional", Some(""));
    let st = a.ok("paycore.chain.status", json!({}));
    assert_eq!((&st["state"], &st["selected_height"]), (&json!("behind"), &json!(102)));
    chain.set("provisional", None);
    assert_eq!(a.ok("paycore.chain.status", json!({})), seen);
    chain.set("selected", None);
    chain.set("behind", Some(""));
    chain.set("k_conf", Some("7"));
    chain.set("time", None);
    chain.set("rp-unauthenticated", Some(""));
    assert_eq!(
        a.ok("paycore.chain.status", json!({})),
        json!({"state": "behind", "k_conf": 7, "rangeproofs_authenticated": false, "selected_height": null,
               "confirmed_time": null, "tip_height": 102})
    );
    // a layer that asks for no confirmations at all is not taken at its word
    chain.set("k_conf", Some("0"));
    assert_eq!(a.ok("paycore.chain.status", json!({}))["k_conf"], 10);
    chain.set("behind", None);
    chain.set("selected", Some(""));
    chain.set("k_conf", Some("3"));
    chain.set("time", Some("1000"));
    chain.set("rp-unauthenticated", None);
    assert_eq!(a.ok("paycore.chain.status", json!({})), seen);
    wait_for("the news of the chain", || {
        a.events.lock().unwrap().iter().any(|e| e["params"]["source"] == "chain" && e["params"]["event"]["tip_height"] == 102)
    });

    // a pays b
    wait_for("the search of a", || a.ok("paycore.search.status", json!({}))["state"] == "done");
    assert_eq!(a.ok("paycore.balance", json!({}))["incomplete"], json!(false));
    let ida = a.ok("paycore.identity.create", json!({}));
    let idb = b.ok("paycore.identity.create", json!({}));
    a.ok("paycore.contacts.set", json!({"key": idb["public"], "name": "b"}));
    b.ok("paycore.contacts.set", json!({"key": ida["public"], "name": "a"}));
    wait_for("both transports", || a.phase() == "ready" && b.phase() == "ready");
    b.ok("paycore.receive.set_auto", json!({"on": true}));
    let p = a.ok("paycore.send.prepare", json!({"amount": GRIN.to_string(), "deliver_to": idb["public"]}));
    wait_for("the reply to be held", || {
        a.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e["params"]["event"]["kind"] == "reply_held" && e["params"]["event"]["op"] == p["op"])
    });
    // Once the payment is signed, the handler hands the transaction to
    // the chain layer by itself. A broadcast whose fate the layer cannot
    // name is recorded as unknown and a refused one as refused; the wallet
    // makes up neither.
    chain.set("post-mode", Some("lost"));
    let fin = a.ok("paycore.send.finalize_held", json!({"op": p["op"]}));
    wait_for("the handler to hand the transaction over", || {
        a.events.lock().unwrap().iter().any(|e| {
            e["params"]["source"] == "broadcast" && e["params"]["event"]["op"] == p["op"] && e["params"]["event"]["outcome"] == "unknown"
        })
    });
    assert!(chain.posted().is_empty());
    // the interface may ask at once; the handler itself asks again only after a while
    chain.set("post-mode", Some("rejected"));
    assert_eq!(a.ok("paycore.send.broadcast", json!({"op": p["op"]}))["outcome"], "rejected");
    assert!(chain.posted().is_empty());
    chain.set("post-mode", None);
    assert_eq!(a.ok("paycore.send.broadcast", json!({"op": p["op"]}))["outcome"], "accepted");
    // the chain process was handed the signed transaction, byte for byte
    let posted = chain.posted();
    assert_eq!(posted.len(), 1);
    let hex: String = posted[0].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(fin["tx"], hex.as_str());
    let st = a.ok("paycore.send.status", json!({"op": p["op"]}));
    assert_eq!(
        (&st["state"], &st["broadcasts"]),
        (&json!("finalized"), &json!({"accepted": 1, "rejected": 1, "unknown": 1}))
    );
    assert_eq!(b.spendable(), "0", "accepted for broadcast is not in a block");

    // a block includes it: both wallets see it there
    let included = chain.mine(13, block_of(&posted[0]));
    wait_for("the confirmation", || a.ok("paycore.send.status", json!({"op": p["op"]}))["state"] == "confirmed");
    wait_for("the money of b", || b.spendable() == GRIN.to_string());
    assert_eq!(a.tip(), included);
    let change: u64 = a.spendable().parse().unwrap();
    assert!(change < 7 * GRIN && change > 6 * GRIN, "eight, less one paid and the fee: {change}");

    // the chain reorganises the block away. While the layer is rearranging
    // it says that it does not know, and nothing is concluded from that.
    chain.set("dark", Some(""));
    wait_for("the layer to go dark", || a.ok("paycore.chain.sync", json!({}))["unknown"] == true);
    // both chain processes have stopped reading blocks before any is removed
    wait_for("the layer of b to go dark", || b.ok("paycore.chain.sync", json!({}))["unknown"] == true);
    assert_eq!(
        (a.ok("paycore.send.status", json!({"op": p["op"]}))["state"].clone(), a.tip()),
        (json!("confirmed"), json!(included)),
        "unknown is not a rollback"
    );
    chain.cut(included);
    chain.empty(23);
    chain.empty(24);
    chain.set("dark", None);
    wait_for("the rollback at a", || a.ok("paycore.send.status", json!({"op": p["op"]}))["state"] == "finalized");
    wait_for("the rollback at b", || b.spendable() == "0");
    wait_for("the new blocks", || a.tip() == 104 && b.tip() == 104);
    assert!(a
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|e| e["params"]["source"] == "chain" && e["params"]["event"]["rolled_back"] == 1));
    // the same transaction gets into a later block
    chain.mine(25, block_of(&posted[0]));
    wait_for("the second confirmation", || a.ok("paycore.send.status", json!({"op": p["op"]}))["state"] == "confirmed");
    wait_for("the money of b again", || b.spendable() == GRIN.to_string());

    // what stands in the layer's way is shown to the user
    assert_eq!(a.status()["chain"]["problem"], Value::Null);
    chain.set("trouble", Some("only one peer answers"));
    wait_for("the problem", || a.status()["chain"]["problem"] == "only one peer answers");
    chain.set("trouble", None);
    wait_for("the problem to pass", || a.status()["chain"]["problem"] == Value::Null);

    // nothing of the wallet is in any file in readable form, and that
    // includes what the chain processes were given and what they keep
    let mut all = Vec::new();
    files(&t.0, &mut all);
    let words: Vec<&str> = phrase_a.split(' ').collect();
    for (path, content) in &all {
        let text = String::from_utf8_lossy(content);
        for secret in ["password of a", "password of b", &words[..3].join(" ")] {
            assert!(!text.contains(secret), "{secret:?} in {path:?}");
        }
    }
    assert!(only_dir(&t.0.join("a"), "chain-").is_dir(), "the chain process has a directory of its own");

    // locking ends the chain process of that profile and no other
    let before = chain.processes();
    a.ok("host.lock", json!({}));
    assert_eq!(a.chain_phase(), "none");
    wait_for("the chain process of a to end", || chain.processes().len() == 1);
    assert!(before.contains(&chain.processes()[0]));
    assert_eq!(b.chain_phase(), "ready");
    // while a was locked the chain moved on; it catches up after unlocking
    chain.empty(26);
    a.ok("host.unlock", json!({"password": "password of a"}));
    wait_for("a to catch up", || a.tip() == 106);
    assert_eq!(a.ok("paycore.send.status", json!({"op": p["op"]}))["state"], "confirmed");
    assert_eq!(a.end().0, 0);
    assert_eq!(b.end().0, 0);
    wait_for("every chain process to end", || chain.processes().is_empty());
}

/// A profile that followed the chain and was then away for longer than the
/// chain layer keeps blocks searches when it is back - from where it
/// stood: the chain layer is told which block that was, gives what was
/// there by then without range proofs, and the profile learns from it
/// what it still has; what came later it finds as a search does.
#[test]
fn a_profile_that_was_away_searches_from_where_it_stood() {
    let t = Temp::new("away");
    let mut chain = Chain::new(&t.0);
    let peer = chain.peer();
    let mut a = Proc::with_chain(HOST_TEST, &t.0, "a", None, &peer);
    let made = a.ok("host.profile.create", json!({"password": "password of a", "network": "automated"}));
    let phrase = made["mnemonic"].as_str().unwrap().to_string();
    let foreign = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let own = [coin(&phrase, 5 * GRIN, 0), coin(&phrase, 3 * GRIN, 1)];
    chain.mine(11, BlockFacts { outputs: own.to_vec(), ..BlockFacts::default() });
    chain.empty(12);
    a.ok("host.unlock", json!({"password": "password of a"}));
    wait_for("the tip", || a.tip() == 102);
    assert_eq!(a.spendable(), (8 * GRIN).to_string());
    assert_eq!(a.ok("paycore.search.status", json!({})), json!({"state": "none"}));
    a.ok("host.lock", json!({}));

    // While the profile is away its 3 is spent and a 7 comes in; the
    // chain layer starts again from block 200.
    let mut old = [coin(foreign, GRIN, 0), coin(&phrase, 5 * GRIN, 0), coin(&phrase, 7 * GRIN, 2)];
    old[0].pos = 1;
    old[1].pos = 2;
    old[2].pos = 9;
    chain.old(0, 3, old[..2].to_vec());
    chain.old(2, 3, old[2..].to_vec());
    chain.set("old-bare-below", Some("2"));
    chain.restart_at(200, 2, (102, 12));
    chain.empty(21);

    a.ok("host.unlock", json!({"password": "password of a"}));
    let done = json!({"state": "done", "next": null, "pieces": 3, "found": 1, "gone": 1, "since": 102});
    wait_for("the search", || a.ok("paycore.search.status", json!({})) == done);
    assert_eq!((a.spendable(), a.tip()), ((12 * GRIN).to_string(), json!(201)));
    // every piece was asked for with the block the profile stood at
    let noted = std::fs::read_to_string(chain.dir.join("old-since")).unwrap();
    assert_eq!(noted.lines().collect::<Vec<_>>(), ["0 102", "1 102", "2 102"]);
    // and it stays after the profile is locked and opened again
    a.ok("host.lock", json!({}));
    a.ok("host.unlock", json!({"password": "password of a"}));
    assert_eq!(a.ok("paycore.search.status", json!({})), done);
    assert_eq!(a.spendable(), (12 * GRIN).to_string());
    assert_eq!(a.end().0, 0);
}

/// A profile made from a phrase the user brought searches for what the
/// phrase was paid before the chain layer's first block; a profile with a
/// new phrase does not, until the user asks. What the search finds is
/// spendable and stays after the profile is locked and opened again.
#[test]
fn a_restored_profile_finds_its_old_outputs() {
    let t = Temp::new("old");
    let mut chain = Chain::new(&t.0);
    let peer = chain.peer();
    chain.empty(11);
    let mut a = Proc::with_chain(HOST_TEST, &t.0, "a", None, &peer);
    let made = a.ok("host.profile.create", json!({"password": "password of a", "network": "automated"}));
    let phrase = made["mnemonic"].as_str().unwrap().to_string();
    let foreign = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let mut old = [coin(foreign, GRIN, 0), coin(&phrase, 5 * GRIN, 0), coin(&phrase, 7 * GRIN, 1)];
    old[0].pos = 2;
    old[1].pos = 3;
    old[2].pos = 9;
    chain.old(0, 3, old[..2].to_vec());
    chain.old(2, 3, old[2..].to_vec());

    // the new profile: its phrase cannot have a history, nothing is searched
    a.ok("host.unlock", json!({"password": "password of a"}));
    wait_for("the tip", || a.tip() == 101);
    assert_eq!(a.ok("paycore.search.status", json!({})), json!({"state": "none"}));
    assert_eq!(a.spendable(), "0");

    // the same phrase brought to another device
    let mut b = Proc::with_chain(HOST_TEST, &t.0, "b", None, &peer);
    b.ok("host.profile.restore", json!({"password": "password of b", "network": "automated", "mnemonic": phrase}));
    b.ok("host.unlock", json!({"password": "password of b"}));
    let done = json!({"state": "done", "next": null, "pieces": 3, "found": 2, "gone": 0});
    wait_for("the search of b", || b.ok("paycore.search.status", json!({})) == done);
    assert_eq!((b.spendable(), b.tip()), ((12 * GRIN).to_string(), json!(101)));
    b.ok("host.lock", json!({}));
    b.ok("host.unlock", json!({"password": "password of b"}));
    assert_eq!(b.ok("paycore.search.status", json!({})), done);
    assert_eq!(b.spendable(), (12 * GRIN).to_string());

    // on the first device the user asks for the search
    assert_eq!(a.ok("paycore.search.start", json!({}))["state"], "reading");
    wait_for("the search of a", || a.ok("paycore.search.status", json!({})) == done);
    assert_eq!(a.spendable(), (12 * GRIN).to_string());
    // one of the found outputs is spent in a block: both see it
    chain.mine(12, BlockFacts { inputs: vec![old[1].commit], ..BlockFacts::default() });
    wait_for("the spend", || a.spendable() == (7 * GRIN).to_string() && b.spendable() == (7 * GRIN).to_string());

    // a chain layer that cannot give old outputs: the search waits, it
    // does not end with "nothing found"
    chain.set("old-pieces", None);
    assert_eq!(a.ok("paycore.search.start", json!({}))["state"], "reading");
    chain.empty(13);
    wait_for("the block", || a.tip() == 103);
    assert_eq!(a.ok("paycore.search.status", json!({})), json!({"state": "reading", "next": 0, "pieces": 0, "found": 0, "gone": 0}));
    assert_eq!(a.spendable(), (7 * GRIN).to_string());
    assert_eq!(a.end().0, 0);
    assert_eq!(b.end().0, 0);
}

/// The wallet never waits for the chain process: one that is slow to
/// start, refuses, talks nonsense or dies is reported and tried again
/// after a pause, and meanwhile the wallet says "unknown", never "nothing
/// new".
#[test]
fn the_wallet_does_not_depend_on_the_chain_being_up() {
    // a chain process that never becomes ready
    let t = Temp::new("chain-slow");
    let mut h = Proc::with_chain(HOST_TEST, &t.0, "p", None, "silent");
    create(&mut h, "pw", &[5 * GRIN]);
    let began = Instant::now();
    h.ok("host.unlock", json!({"password": "pw"}));
    assert!(began.elapsed() < Duration::from_secs(5), "unlocking does not wait for the chain");
    assert_eq!(h.chain_phase(), "starting");
    assert_eq!(h.ok("paycore.chain.sync", json!({})), json!({"chain": [], "tip_height": 2, "more": false, "unknown": true}));
    assert_eq!(
        h.ok("paycore.chain.status", json!({})),
        json!({"state": "unknown", "k_conf": 10, "rangeproofs_authenticated": false, "selected_height": null,
               "confirmed_time": null, "tip_height": 2})
    );
    // what the wallet already knew is still there
    assert_eq!(h.spendable(), (5 * GRIN).to_string());
    let began = Instant::now();
    h.ok("host.lock", json!({}));
    assert!(began.elapsed() < Duration::from_secs(5), "locking does not wait for the chain");
    assert_eq!(h.chain_phase(), "none");
    assert_eq!(h.end().0, 0);

    // one that refuses to start: reported, and tried again
    let t = Temp::new("chain-refuse");
    let mut h = Proc::with_chain(HOST_TEST, &t.0, "p", None, "refuse");
    create(&mut h, "pw", &[]);
    h.ok("host.unlock", json!({"password": "pw"}));
    wait_for("the refusal", || h.chain_phase() == "down");
    let st = h.status();
    assert_eq!(st["chain"]["error"], "the chain process did not start: no peer can be reached");
    let starts = st["chain"]["starts"].as_u64().unwrap();
    wait_for("another attempt", || h.status()["chain"]["starts"].as_u64().unwrap() > starts);
    assert_eq!(h.ok("paycore.chain.sync", json!({}))["unknown"], true);
    assert_eq!(h.end().0, 0);

    // one that does not speak the protocol
    let mut h = Proc::with_chain(HOST_TEST, &t.0, "g", None, "garbage");
    create(&mut h, "pw", &[]);
    h.ok("host.unlock", json!({"password": "pw"}));
    wait_for("the nonsense to be noticed", || h.chain_phase() == "down");
    assert_eq!(h.ok("paycore.chain.sync", json!({}))["unknown"], true);
    assert_eq!(h.end().0, 0);

    // a chain program that does not exist
    let mut command = Command::new(HOST_TEST);
    command
        .arg("--profile")
        .arg(t.0.join("q"))
        .arg("--guard-dir")
        .arg(t.0.join("q-guard"))
        .arg("--chain")
        .arg(t.0.join("no-such-program"));
    let mut q = Proc::spawn(command);
    create(&mut q, "pw", &[]);
    q.ok("host.unlock", json!({"password": "pw"}));
    assert_eq!(q.chain_phase(), "down");
    assert_eq!(q.status()["chain"]["error"], "the chain process could not be started");
    assert_eq!(q.end().0, 0);

    // one that dies is started again and the wallet goes on from where it was
    let t = Temp::new("chain-dies");
    let mut chain = Chain::new(&t.0);
    let mut h = Proc::with_chain(HOST_TEST, &t.0, "p", None, &chain.peer());
    let phrase = create(&mut h, "pw", &[]);
    h.ok("host.unlock", json!({"password": "pw"}));
    chain.mine(11, BlockFacts { outputs: vec![coin(&phrase, 2 * GRIN, 0)], ..BlockFacts::default() });
    wait_for("the first block", || h.tip() == 101);
    let first = chain.processes();
    assert_eq!((first.len(), h.status()["chain"]["starts"].as_u64()), (1, Some(1)));
    kill(first[0]);
    // the killed one could not remove its marker
    std::fs::remove_file(chain.dir.join(format!("{}.chain-alive", first[0]))).unwrap();
    chain.empty(12);
    wait_for("the chain process to return", || h.status()["chain"]["starts"].as_u64() == Some(2) && h.chain_phase() == "ready");
    wait_for("the next block", || h.tip() == 102);
    assert_eq!(h.spendable(), (2 * GRIN).to_string());
    assert_ne!(chain.processes(), first);

    // a layer that is alive and knows nothing: the position is kept
    chain.set("dark", Some(""));
    wait_for("the layer to go dark", || h.ok("paycore.chain.sync", json!({}))["unknown"] == true);
    chain.empty(13);
    assert_eq!(h.ok("paycore.chain.sync", json!({})), json!({"chain": [], "tip_height": 102, "more": false, "unknown": true}));
    assert_eq!((h.chain_phase().as_str(), h.spendable()), ("ready", (2 * GRIN).to_string()));
    assert_eq!(h.ok("paycore.chain.status", json!({}))["state"], "unknown");
    chain.set("dark", None);
    wait_for("the block that waited", || h.tip() == 103);
    assert_eq!(h.end().0, 0);
    wait_for("the chain process to end", || chain.processes().is_empty());
}

/// The host with the real transport program: Tor is brought up, a payment
/// is sealed and its publication to a relay that does not exist is tried.
/// Not part of the ordinary run: it uses the network. The transport
/// program is named by the environment variable FLY_MAILBOX_EXE.
#[test]
#[ignore = "bootstraps Tor over the network; needs FLY_MAILBOX_EXE"]
fn live_the_host_runs_the_real_transport() {
    let program = std::env::var("FLY_MAILBOX_EXE").expect("FLY_MAILBOX_EXE names the transport program");
    let t = Temp::new("live");
    let mut command = Command::new(HOST_TEST);
    command
        .arg("--profile")
        .arg(t.0.join("p"))
        .arg("--guard-dir")
        .arg(t.0.join("p-guard"))
        .arg("--transport")
        .arg(&program)
        .arg("--relay")
        .arg("wss://no-such-relay.invalid");
    let mut h = Proc::spawn(command);
    create(&mut h, "pw", &[5 * GRIN]);
    h.ok("host.unlock", json!({"password": "pw"}));
    let ready = |h: &mut Proc, what: &str| {
        let began = Instant::now();
        loop {
            let st = h.status();
            match st["transport"]["phase"].as_str().unwrap() {
                "ready" => break,
                "down" => panic!("{what}: the transport is down: {}", st["transport"]["error"]),
                _ => {}
            }
            assert!(began.elapsed() < Duration::from_secs(240), "{what}: not ready in four minutes");
            std::thread::sleep(Duration::from_millis(250));
        }
        println!("{what}: transport ready in {:.1} s", began.elapsed().as_secs_f32());
    };
    let began = Instant::now();
    h.ok("paycore.identity.create", json!({}));
    println!("identity created in {:.1} s", began.elapsed().as_secs_f32());
    ready(&mut h, "first start");
    // a new contact starts the transport again; Tor has its state on disk now
    h.ok("paycore.contacts.set", json!({"key": SOMEBODY, "name": "somebody"}));
    ready(&mut h, "second start");

    // sealed by the real transport, without any relay
    let began = Instant::now();
    let p = h.ok("paycore.send.prepare", json!({"amount": GRIN.to_string(), "deliver_to": SOMEBODY}));
    println!("payment sealed in {:.1} s", began.elapsed().as_secs_f32());
    assert_eq!(h.ok("paycore.balance", json!({}))["reserved"], (5 * GRIN).to_string());
    // the worker tries to publish it by itself
    let began = Instant::now();
    let mut outcome = Value::Null;
    while outcome.is_null() {
        assert!(began.elapsed() < Duration::from_secs(180), "no publication attempt was reported");
        std::thread::sleep(Duration::from_millis(250));
        outcome = h
            .events
            .lock()
            .unwrap()
            .iter()
            .find(|e| e["params"]["source"] == "published" && e["params"]["event"]["op"] == p["op"])
            .map(|e| e["params"]["event"]["delivery"].clone())
            .unwrap_or(Value::Null);
    }
    println!(
        "publication to a relay that does not exist: {outcome} after {:.1} s",
        began.elapsed().as_secs_f32()
    );
    assert_ne!(outcome, "relay_accepted");
    assert_eq!(h.ok("paycore.send.status", json!({"op": p["op"]}))["state"], "prepared");

    let began = Instant::now();
    h.ok("host.lock", json!({}));
    println!("locked in {:.1} s", began.elapsed().as_secs_f32());
    assert_eq!(h.phase(), "none");
    assert_eq!(h.end().0, 0);
}

/// A payment between two hosts over a real relay, through Tor: sealed,
/// published, answered by the other wallet, the answer held, and signed on
/// confirmation. The wallets are throw-away ones on the test chain; what
/// reaches the relay is two sealed messages. Not part of the ordinary run:
/// FLY_MAILBOX_EXE names the transport program, FLY_RELAY the relay.
#[test]
#[ignore = "publishes to a real relay through Tor; needs FLY_MAILBOX_EXE and FLY_RELAY"]
fn live_a_payment_crosses_a_real_relay() {
    let program = std::env::var("FLY_MAILBOX_EXE").expect("FLY_MAILBOX_EXE names the transport program");
    let relay = std::env::var("FLY_RELAY").expect("FLY_RELAY names the relay");
    println!("relay: {relay}");
    let t = Temp::new("relay");
    let start = |name: &str| {
        let mut command = Command::new(HOST_TEST);
        command
            .arg("--profile")
            .arg(t.0.join(name))
            .arg("--guard-dir")
            .arg(t.0.join(format!("{name}-guard")))
            .arg("--transport")
            .arg(&program)
            .arg("--relay")
            .arg(&relay);
        Proc::spawn(command)
    };
    let (mut a, mut b) = (start("a"), start("b"));
    create(&mut a, "pw a", &[5 * GRIN]);
    create(&mut b, "pw b", &[]);
    a.ok("host.unlock", json!({"password": "pw a"}));
    b.ok("host.unlock", json!({"password": "pw b"}));
    let ready = |a: &mut Proc, b: &mut Proc, what: &str| {
        let began = Instant::now();
        loop {
            let (sa, sb) = (a.status(), b.status());
            let phases = [&sa, &sb].map(|s| s["transport"]["phase"].as_str().unwrap().to_string());
            for s in [&sa, &sb] {
                assert_ne!(s["transport"]["phase"], "down", "{what}: {}", s["transport"]["error"]);
            }
            if phases.iter().all(|p| p == "ready") {
                break;
            }
            assert!(began.elapsed() < Duration::from_secs(300), "{what}: not ready in five minutes");
            std::thread::sleep(Duration::from_millis(250));
        }
        println!("{what}: both transports ready in {:.1} s", began.elapsed().as_secs_f32());
    };
    let ida = a.ok("paycore.identity.create", json!({}));
    let idb = b.ok("paycore.identity.create", json!({}));
    ready(&mut a, &mut b, "first start");
    a.ok("paycore.contacts.set", json!({"key": idb["public"], "name": "b"}));
    b.ok("paycore.contacts.set", json!({"key": ida["public"], "name": "a"}));
    ready(&mut a, &mut b, "second start");
    b.ok("paycore.receive.set_auto", json!({"on": true}));

    let began = Instant::now();
    let p = a.ok("paycore.send.prepare", json!({"amount": GRIN.to_string(), "deliver_to": idb["public"]}));
    println!("payment sealed in {:.1} s", began.elapsed().as_secs_f32());
    // what each side reports while the payment travels, each report once
    let mut told = (0, 0);
    let report = |who: &str, p: &Proc, seen: &mut usize| {
        let events = p.events.lock().unwrap();
        for e in events.iter().skip(*seen) {
            let (source, event) = (&e["params"]["source"], &e["params"]["event"]);
            println!(
                "{:6.1} s  {who}: {} {} {}",
                began.elapsed().as_secs_f32(),
                source.as_str().unwrap_or("?"),
                event["kind"].as_str().unwrap_or(""),
                event["delivery"].as_str().unwrap_or("")
            );
        }
        *seen = events.len();
    };
    let held = |a: &Proc| {
        a.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e["params"]["event"]["kind"] == "reply_held" && e["params"]["event"]["op"] == p["op"])
    };
    // and what each transport says is in its way, whenever that changes
    let mut said = (Value::Null, Value::Null);
    let tell = |who: &str, p: &mut Proc, last: &mut Value| {
        let now = p.status()["transport"]["problem"].clone();
        if now != *last {
            println!("{:6.1} s  {who}: the transport says: {now}", began.elapsed().as_secs_f32());
            *last = now;
        }
    };
    while !held(&a) {
        report("a", &a, &mut told.0);
        report("b", &b, &mut told.1);
        tell("a", &mut a, &mut said.0);
        tell("b", &mut b, &mut said.1);
        assert!(began.elapsed() < Duration::from_secs(600), "no answer came back in ten minutes");
        std::thread::sleep(Duration::from_millis(500));
    }
    report("a", &a, &mut told.0);
    report("b", &b, &mut told.1);
    println!("the answer came back in {:.1} s", began.elapsed().as_secs_f32());
    let st = a.ok("paycore.send.status", json!({"op": p["op"]}));
    assert_eq!((&st["state"], &st["reply_held"]), (&json!("prepared"), &json!(true)));
    let fin = a.ok("paycore.send.finalize_held", json!({"op": p["op"]}));
    assert!(fin["tx"].as_str().unwrap().len() > 100);
    assert_eq!(a.ok("paycore.send.status", json!({"op": p["op"]}))["state"], "finalized");
    println!("payment over a real relay: finalized");

    let began = Instant::now();
    a.ok("host.lock", json!({}));
    b.ok("host.lock", json!({}));
    println!("both locked in {:.1} s", began.elapsed().as_secs_f32());
    assert_eq!((a.end().0, b.end().0), (0, 0));
}

/// The host with the real chain program on the test network: the chain
/// process verifies headers, collects the state and applies the blocks,
/// and the wallet follows it block by block to the tip. Not part of the
/// ordinary run: it uses the network. The chain program is named by the
/// environment variable FLY_CHAIN_EXE. If FLY_CHAIN_SEED_DIR names a
/// directory with the files of an earlier run of that program, they are
/// put into the chain process's own directory first: the program trusts
/// none of them and checks each again, and it saves the downloading.
#[test]
#[ignore = "connects to Grin nodes of the test network; needs FLY_CHAIN_EXE"]
fn live_the_host_follows_the_real_chain() {
    let program = std::env::var("FLY_CHAIN_EXE").expect("FLY_CHAIN_EXE names the chain program");
    let seed = std::env::var("FLY_CHAIN_SEED_DIR").ok().map(std::path::PathBuf::from);
    let t = Temp::new("livechain");
    let start = |t: &Temp| {
        let mut command = Command::new(HOST);
        command.arg("--profile").arg(t.0.join("p")).arg("--guard-dir").arg(t.0.join("p-guard")).arg("--chain").arg(&program);
        Proc::spawn(command)
    };
    let mut h = start(&t);
    h.ok("host.profile.create", json!({"password": "pw", "network": "test"}));
    h.ok("host.unlock", json!({"password": "pw"}));
    if let Some(seed) = seed.filter(|dir| dir.join("headers.dat").exists()) {
        // the chain process's directory exists once the profile was opened;
        // stop everything, put the files there, start again
        wait_for("the chain directory", || std::fs::read_dir(t.0.join("p")).unwrap().flatten().any(|e| e.file_name().to_str().unwrap().starts_with("chain-")));
        let (code, _) = h.end();
        assert_eq!(code, 0, "the host ended in order");
        // the chain process ends when the host does, and lets go of its files
        std::thread::sleep(Duration::from_secs(3));
        let dir = only_dir(&t.0.join("p"), "chain-");
        let mut copied = 0u64;
        for name in ["headers.dat", "state.dat", "blocks.dat"] {
            if seed.join(name).exists() {
                copied += std::fs::copy(seed.join(name), dir.join(name)).unwrap();
            }
        }
        println!("files of an earlier run put in place: {copied} bytes");
        h = start(&t);
        h.ok("host.unlock", json!({"password": "pw"}));
    }
    let began = Instant::now();
    // where the chain process says its blocks end, once they end at the tip
    let at_tip = |h: &mut Proc| -> Option<u64> {
        let st = h.status();
        assert_ne!(st["chain"]["phase"], "down", "the chain process is down: {}", st["chain"]["error"]);
        let text = st["chain"]["problem"].as_str()?.to_string();
        let rest = text.split("blocks applied to the tip, ").nth(1)?;
        rest.chars().take_while(char::is_ascii_digit).collect::<String>().parse().ok()
    };
    let mut last = String::new();
    let mut shown = Instant::now();
    let tip = loop {
        assert!(began.elapsed() < Duration::from_secs(40 * 60), "the chain process did not reach the tip in forty minutes: {last}");
        if let Some(tip) = at_tip(&mut h) {
            break tip;
        }
        let now = h.status()["chain"]["problem"].as_str().unwrap_or("").to_string();
        if now != last && shown.elapsed() > Duration::from_secs(5) {
            println!("{:7.1}s chain: {now}", began.elapsed().as_secs_f32());
            shown = Instant::now();
        }
        last = now;
        std::thread::sleep(Duration::from_millis(500));
    };
    println!("chain process at the tip, {tip}, in {:.1} s", began.elapsed().as_secs_f32());

    // the wallet follows by itself, block by block
    let follow = Instant::now();
    let mut seen = Value::Null;
    loop {
        assert!(follow.elapsed() < Duration::from_secs(20 * 60), "the wallet did not reach the tip in twenty minutes: it is at {seen}");
        let now = h.tip();
        if now.as_u64().is_some_and(|height| height >= tip) {
            seen = now;
            break;
        }
        if now != seen && shown.elapsed() > Duration::from_secs(5) {
            println!("{:7.1}s wallet at {now}", began.elapsed().as_secs_f32());
            shown = Instant::now();
        }
        seen = now;
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("wallet at {seen} in {:.1} s after the chain process", follow.elapsed().as_secs_f32());

    // What the wallet is told about the chain. The layer follows the
    // heaviest valid chain it is shown and selects no tip: nothing it hands
    // over is more than preliminary.
    let st = h.ok("paycore.chain.status", json!({}));
    println!("chain status: {st}");
    assert_eq!((&st["state"], &st["selected_height"]), (&json!("behind"), &Value::Null));
    assert_eq!((&st["k_conf"], &st["rangeproofs_authenticated"], &st["confirmed_time"]), (&json!(10), &json!(true), &Value::Null));
    assert!(st["tip_height"].as_u64().is_some_and(|height| height >= tip));
    // a new wallet has nothing, and says so from verified blocks
    let balance = h.ok("paycore.balance", json!({}));
    println!("balance: {balance}");
    assert_eq!(balance["spendable"], "0");
}


/// A wallet restored from a phrase that has a history, with the real chain
/// program on a real network: the search for old outputs runs to its end.
/// Not part of the ordinary run. The phrase is read from the environment
/// variable FLY_RESTORE_PHRASE and is given to the host and to nothing
/// else: it is not printed, not in any message of this test, and the
/// profile made around it - sealed with a random password - is deleted
/// when the test ends. FLY_RESTORE_NETWORK is `test` (the default) or
/// `main`; FLY_CHAIN_EXE and FLY_CHAIN_SEED_DIR as in the test above.
/// FLY_CHAIN_PEERS, if set, names the nodes to use, separated by commas:
/// only they are asked then, not the seed names of the network.
/// Amounts are printed on lines that begin with `BALANCE`, so that
/// whoever runs the test can keep them out of a log.
#[test]
#[ignore = "connects to Grin nodes; needs FLY_CHAIN_EXE and FLY_RESTORE_PHRASE"]
fn live_a_restored_wallet_finds_its_outputs() {
    let program = std::env::var("FLY_CHAIN_EXE").expect("FLY_CHAIN_EXE names the chain program");
    let seed_dir = std::env::var("FLY_CHAIN_SEED_DIR").ok().map(std::path::PathBuf::from);
    let network = std::env::var("FLY_RESTORE_NETWORK").unwrap_or_else(|_| "test".to_string());
    assert!(network == "test" || network == "main", "FLY_RESTORE_NETWORK is test or main");
    let Ok(phrase) = std::env::var("FLY_RESTORE_PHRASE") else {
        panic!("FLY_RESTORE_PHRASE holds the recovery phrase");
    };
    let phrase = zeroize::Zeroizing::new(phrase);
    let mut random = [0u8; 24];
    getrandom::getrandom(&mut random).unwrap();
    let password: String = random.iter().map(|b| format!("{b:02x}")).collect();

    let peers: Vec<String> = std::env::var("FLY_CHAIN_PEERS")
        .map(|list| list.split(',').map(|peer| peer.trim().to_string()).filter(|peer| !peer.is_empty()).collect())
        .unwrap_or_default();
    if !peers.is_empty() {
        println!("nodes: {} (only these)", peers.join(", "));
    }
    let t = Temp::new("liverestore");
    let start = |t: &Temp| {
        let mut command = Command::new(HOST);
        command.arg("--profile").arg(t.0.join("p")).arg("--guard-dir").arg(t.0.join("p-guard")).arg("--chain").arg(&program);
        for peer in peers.iter() {
            command.arg("--chain-peer").arg(peer);
        }
        // the phrase is not for the processes started here
        command.env_remove("FLY_RESTORE_PHRASE");
        Proc::spawn(command)
    };
    let mut h = start(&t);
    // no part of the request or of the answer is printed
    let restored = h.call("host.profile.restore", json!({"password": password, "network": network, "mnemonic": phrase.as_str()}));
    drop(phrase);
    match restored {
        Ok(_) => println!("profile restored on the {network} network"),
        Err(e) => panic!("the phrase was not taken: {}", e["message"].as_str().unwrap_or("?")),
    }
    h.ok("host.unlock", json!({"password": password}));
    assert_eq!(h.ok("paycore.search.status", json!({}))["state"], "reading", "a restored profile searches");
    if let Some(seed) = seed_dir.filter(|dir| dir.join("headers.dat").exists()) {
        wait_for("the chain directory", || std::fs::read_dir(t.0.join("p")).unwrap().flatten().any(|e| e.file_name().to_str().unwrap().starts_with("chain-")));
        let (code, _) = h.end();
        assert_eq!(code, 0, "the host ended in order");
        std::thread::sleep(Duration::from_secs(3));
        let dir = only_dir(&t.0.join("p"), "chain-");
        let mut copied = 0u64;
        for name in ["headers.dat", "state.dat", "blocks.dat"] {
            if seed.join(name).exists() {
                copied += std::fs::copy(seed.join(name), dir.join(name)).unwrap();
            }
        }
        println!("files of an earlier run put in place: {copied} bytes");
        h = start(&t);
        h.ok("host.unlock", json!({"password": password}));
    }

    let began = Instant::now();
    let (mut shown, mut last) = (Instant::now(), String::new());
    // Where the time went, as the wallet process counts it: once when the
    // first piece has been read (everything before it is headers, state
    // and blocks) and once at the end. Counts and milliseconds only.
    let mut reading = false;
    let done = loop {
        assert!(began.elapsed() < Duration::from_secs(3 * 3600), "the search did not end in three hours: {last}");
        let st = h.status();
        assert_ne!(st["chain"]["phase"], "down", "the chain process is down: {}", st["chain"]["error"]);
        let search = h.ok("paycore.search.status", json!({}));
        if search["state"] == "done" {
            break search;
        }
        if !reading && search["next"].as_u64().is_some_and(|next| next > 0) {
            reading = true;
            println!("TIMING at {:.1} s, the first pieces read: {}", began.elapsed().as_secs_f32(), h.ok("paycore.chain.timing", json!({})));
        }
        let now = format!(
            "wallet at {}; search: piece {} of {}, found {}; chain: {}",
            h.tip(),
            search["next"],
            search["pieces"],
            search["found"],
            st["chain"]["problem"].as_str().unwrap_or("")
        );
        if now != last && shown.elapsed() > Duration::from_secs(10) {
            println!("{:7.1}s {now}", began.elapsed().as_secs_f32());
            shown = Instant::now();
        }
        last = now;
        std::thread::sleep(Duration::from_millis(500));
    };
    println!("search over in {:.1} s: pieces={} found={} gone={}", began.elapsed().as_secs_f32(), done["pieces"], done["found"], done["gone"]);
    println!("TIMING at {:.1} s, the search over: {}", began.elapsed().as_secs_f32(), h.ok("paycore.chain.timing", json!({})));
    assert_eq!(done["gone"], 0, "a new journal had nothing to lose");
    let balance = h.ok("paycore.balance", json!({}));
    let amount = |name: &str| balance[name].as_str().and_then(|a| a.parse::<u64>().ok()).unwrap();
    println!("something was found: {}", done["found"].as_u64().unwrap() > 0);
    println!("BALANCE spendable={} immature={} reserved={} (nanogrin)", amount("spendable"), amount("immature"), amount("reserved"));
    // what was found stays: locked and opened again, the same
    h.ok("host.lock", json!({}));
    h.ok("host.unlock", json!({"password": password}));
    assert_eq!(h.ok("paycore.search.status", json!({})), done);
    assert_eq!(h.ok("paycore.balance", json!({})), balance);
    assert_eq!(h.end().0, 0);
}

/// A payment between two wallets on a real network, from the phrase of a
/// funded wallet to a wallet made here, until it is in a block. Not part
/// of the ordinary run.
///
/// One computer, and a node takes one connection from an address: the two
/// hosts never run a chain process at the same time. The payer is
/// restored and finds its funds; it prepares the payment and is stopped.
/// The payee is made, put on the chain with a copy of the payer's chain
/// files, answers the payment and is stopped. The payer is started again
/// and signs; from there on nothing is asked of it: its handler hands the
/// transaction to the chain program, which sends it to one node as a stem
/// transaction, and the test waits until the wallet sees its kernel in a
/// block. Then the payee is started and must see the money.
///
/// FLY_RESTORE_PHRASE, FLY_RESTORE_NETWORK, FLY_CHAIN_EXE and
/// FLY_CHAIN_PEERS as in the test above; FLY_PAY_AMOUNT is the amount in
/// nanogrin (a tenth of a grin if not set). FLY_CHAIN_SEED_DIR, if it
/// holds chain files of an earlier run, saves collecting the state anew;
/// FLY_CHAIN_KEEP_DIR is where this run leaves its own for the next. The phrase is given to the
/// host and to nothing else. Amounts are on lines that begin with
/// `BALANCE` or `PAYMENT`.
#[test]
#[ignore = "connects to Grin nodes and SENDS A PAYMENT; needs FLY_CHAIN_EXE and FLY_RESTORE_PHRASE"]
fn live_a_payment_reaches_a_block() {
    let program = std::env::var("FLY_CHAIN_EXE").expect("FLY_CHAIN_EXE names the chain program");
    let network = std::env::var("FLY_RESTORE_NETWORK").unwrap_or_else(|_| "test".to_string());
    assert!(network == "test" || network == "main", "FLY_RESTORE_NETWORK is test or main");
    let Ok(phrase) = std::env::var("FLY_RESTORE_PHRASE") else {
        panic!("FLY_RESTORE_PHRASE holds the recovery phrase");
    };
    let phrase = zeroize::Zeroizing::new(phrase);
    let amount: u64 = std::env::var("FLY_PAY_AMOUNT").ok().and_then(|a| a.parse().ok()).unwrap_or(GRIN / 10);
    let peers: Vec<String> = std::env::var("FLY_CHAIN_PEERS")
        .map(|list| list.split(',').map(|peer| peer.trim().to_string()).filter(|peer| !peer.is_empty()).collect())
        .unwrap_or_default();
    let password = |tag: u8| {
        let mut random = [tag; 24];
        getrandom::getrandom(&mut random).unwrap();
        random.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let (pass_a, pass_b) = (password(1), password(2));
    let (ta, tb) = (Temp::new("livepayer"), Temp::new("livepayee"));
    let start = |t: &Temp| {
        let mut command = Command::new(HOST);
        command.arg("--profile").arg(t.0.join("p")).arg("--guard-dir").arg(t.0.join("p-guard")).arg("--chain").arg(&program);
        for peer in peers.iter() {
            command.arg("--chain-peer").arg(peer);
        }
        // the phrase is not for the processes started here
        command.env_remove("FLY_RESTORE_PHRASE");
        Proc::spawn(command)
    };
    let began = Instant::now();
    let say = |what: &str| println!("{:7.1}s {what}", began.elapsed().as_secs_f32());
    // wait, telling now and then where things stand
    let until = |h: &mut Proc, what: &str, minutes: u64, ready: &mut dyn FnMut(&mut Proc) -> bool| {
        let (from, mut shown) = (Instant::now(), Instant::now());
        while !ready(h) {
            assert!(from.elapsed() < Duration::from_secs(minutes * 60), "{what}: not in {minutes} minutes");
            if shown.elapsed() > Duration::from_secs(30) {
                let st = h.status();
                println!("{:7.1}s waiting for {what}; wallet at {}; chain: {}", began.elapsed().as_secs_f32(), h.tip(), st["chain"]["problem"].as_str().unwrap_or(""));
                shown = Instant::now();
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    };
    // The wallet has every block the chain program has when a round of
    // following ends with "nothing new". (`paycore.chain.status` says
    // "at_tip" only for a tip chosen by the acceptance rules, and the
    // chain program chooses none yet.)
    let at_tip = |h: &mut Proc| {
        h.call("paycore.chain.sync", json!({}))
            .is_ok_and(|r| r["more"] == false && r["unknown"] == false && !r["tip_height"].is_null())
    };
    // the chain files of an earlier run, to begin from; and where to leave this run's
    let seed_dir = std::env::var("FLY_CHAIN_SEED_DIR").ok().map(std::path::PathBuf::from).filter(|dir| dir.join("headers.dat").exists());
    let keep_dir = std::env::var("FLY_CHAIN_KEEP_DIR").ok().map(std::path::PathBuf::from);
    let chain_files = ["headers.dat", "state.dat", "blocks.dat"];
    let spendable = |h: &mut Proc| h.spendable().parse::<u64>().unwrap();

    // the payer: restored, and its funds found
    let mut a = start(&ta);
    let restored = a.call("host.profile.restore", json!({"password": pass_a, "network": network, "mnemonic": phrase.as_str()}));
    drop(phrase);
    if let Err(e) = restored {
        panic!("the phrase was not taken: {}", e["message"].as_str().unwrap_or("?"));
    }
    a.ok("host.unlock", json!({"password": pass_a}));
    if let Some(seed) = &seed_dir {
        wait_for("the payer's chain directory", || std::fs::read_dir(ta.0.join("p")).unwrap().flatten().any(|e| e.file_name().to_str().unwrap().starts_with("chain-")));
        assert_eq!(a.end().0, 0, "the host ended in order");
        std::thread::sleep(Duration::from_secs(3));
        let dir = only_dir(&ta.0.join("p"), "chain-");
        let mut copied = 0u64;
        for name in chain_files {
            if seed.join(name).exists() {
                copied += std::fs::copy(seed.join(name), dir.join(name)).unwrap();
            }
        }
        println!("files of an earlier run put in place: {copied} bytes");
        a = start(&ta);
        a.ok("host.unlock", json!({"password": pass_a}));
    }
    say("the payer is restored; it reads the chain and looks for its outputs");
    until(&mut a, "the payer's search", 180, &mut |h| h.ok("paycore.search.status", json!({}))["state"] == "done");
    let had = spendable(&mut a);
    println!("BALANCE payer before: spendable={had} (nanogrin)");
    assert!(had > amount, "the payer has less than the payment");
    assert_eq!(a.end().0, 0, "the payer's host ended in order");
    std::thread::sleep(Duration::from_secs(3));
    if let Some(keep) = &keep_dir {
        // for the next run: it need not collect the state again
        let from = only_dir(&ta.0.join("p"), "chain-");
        if std::fs::create_dir_all(keep).is_ok() {
            for name in chain_files {
                let _ = std::fs::copy(from.join(name), keep.join(name));
            }
            println!("chain files kept for the next run: {}", keep.display());
        }
    }

    // the payee: made here, put on the chain with the payer's chain files
    let mut b = start(&tb);
    b.ok("host.profile.create", json!({"password": pass_b, "network": network}));
    b.ok("host.unlock", json!({"password": pass_b}));
    wait_for("the payee's chain directory", || std::fs::read_dir(tb.0.join("p")).unwrap().flatten().any(|e| e.file_name().to_str().unwrap().starts_with("chain-")));
    assert_eq!(b.end().0, 0);
    std::thread::sleep(Duration::from_secs(3));
    let (from, to) = (only_dir(&ta.0.join("p"), "chain-"), only_dir(&tb.0.join("p"), "chain-"));
    for name in chain_files {
        if from.join(name).exists() {
            std::fs::copy(from.join(name), to.join(name)).unwrap();
        }
    }
    let mut b = start(&tb);
    b.ok("host.unlock", json!({"password": pass_b}));
    until(&mut b, "the payee to be at the tip", 60, &mut |h| at_tip(h));
    // Keep the payer unlocked from the first Slatepack through finalization.
    let mut a = start(&ta);
    a.ok("host.unlock", json!({"password": pass_a}));
    until(&mut a, "the payer to be at the tip again", 60, &mut |h| at_tip(h));
    let prepared = a.ok("paycore.send.prepare", json!({"amount": amount.to_string()}));
    say("the payment is prepared");
    let answered = b.ok("paycore.receive.draft", json!({"slate": prepared["slate"]}));
    say("the payee has answered");
    assert_eq!(b.end().0, 0, "the payee's host ended in order");
    std::thread::sleep(Duration::from_secs(3));

    // the payer signs; the rest is its handler's and the chain program's
    a.ok("paycore.send.finalize", json!({"op": prepared["op"], "slate": answered["slate"]}));
    let signed = Instant::now();
    say("the payment is signed; from here on nobody asks the wallet to send it");
    let mut told = String::new();
    until(&mut a, "the payment to be in a block", 60, &mut |h| {
        let st = h.ok("paycore.send.status", json!({"op": prepared["op"]}));
        let now = format!("state={} broadcasts={}", st["state"].as_str().unwrap_or("?"), st["broadcasts"]);
        if now != told {
            println!("{:7.1}s PAYMENT {now} ({:.0} s after it was signed)", began.elapsed().as_secs_f32(), signed.elapsed().as_secs_f32());
            told = now;
        }
        st["state"] == "confirmed"
    });
    println!("PAYMENT amount={amount} in a block {:.0} s after it was signed; wallet at {}", signed.elapsed().as_secs_f32(), a.tip());
    let left = spendable(&mut a);
    let balance = a.ok("paycore.balance", json!({}));
    println!("BALANCE payer after: spendable={left} immature={} reserved={} (nanogrin)", balance["immature"], balance["reserved"]);
    assert!(left < had, "the payer paid");
    assert_eq!(a.end().0, 0);
    std::thread::sleep(Duration::from_secs(3));

    // the payee sees the money in the block
    let mut b = start(&tb);
    b.ok("host.unlock", json!({"password": pass_b}));
    until(&mut b, "the payee's money", 60, &mut |h| spendable(h) == amount);
    println!("BALANCE payee: spendable={} (nanogrin)", spendable(&mut b));
    assert_eq!(b.end().0, 0);
}

/// Two spellings of a directory denote the same backup boundary.
#[cfg(any(windows, unix))]
#[test]
fn guard_placement_uses_directory_identity() -> std::io::Result<()> {
    let temp = Temp::new("guard-location");
    let profile = temp.0.join("Profile");
    std::fs::create_dir(&profile)?;
    #[cfg(unix)]
    let alias = {
        let link = temp.0.join("other-name");
        std::os::unix::fs::symlink(&profile, &link)?;
        link
    };
    #[cfg(windows)]
    let alias = {
        let other_case = temp.0.join("PROFILE");
        if !other_case.is_dir() {
            return Ok(()); // a case-sensitive directory has no such alias
        }
        other_case
    };
    let run = |guard: &Path| {
        Command::new(HOST)
            .arg("--profile").arg(&profile)
            .arg("--guard-dir").arg(guard)
            .stdin(Stdio::null()).output()
    };
    assert_eq!(run(&temp.0.join("external-guard"))?.status.code(), Some(0));
    let denied = run(&alias.join("guard"))?;
    assert_eq!(denied.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&denied.stderr).contains("outside the profile directory"));
    Ok(())
}

#[test]
fn active_network_stays_with_the_open_session() -> std::io::Result<()> {
    let t = Temp::new("active-network");
    let mut first = Proc::start(HOST_TEST, &t.0, "first", None);
    let mut other = Proc::start(HOST_TEST, &t.0, "other", None);
    for (proc, network) in [(&mut first, "test"), (&mut other, "main")] {
        proc.ok("host.profile.create", json!({"password": "fixture", "network": network}));
    }
    first.ok("host.unlock", json!({"password": "fixture"}));
    assert_eq!(first.status().get("network"), Some(&json!("test")));
    // An offline backup tool restores a different, valid profile file. The
    // already open wallet and its authenticated network do not change.
    std::fs::copy(t.0.join("other/profile.json"), t.0.join("first/profile.json"))?;
    assert_eq!(first.status().get("network"), Some(&json!("test")));
    first.ok("host.lock", json!({}));
    assert_eq!(first.status().get("network"), Some(&json!("main")));
    first.end();
    other.end();
    Ok(())
}

#[test]
fn backup_actions_belong_to_the_open_wallet() -> std::io::Result<()> {
    let t = Temp::new("backup-session");
    let mut opened = Proc::start(HOST_TEST, &t.0, "open", None);
    let mut second = Proc::start(HOST_TEST, &t.0, "second", None);
    for proc in [&mut opened, &mut second] {
        proc.ok("host.profile.create", json!({"password": "fixture", "network": "test"}));
    }
    opened.ok("host.unlock", json!({"password": "fixture"}));
    std::fs::copy(t.0.join("second/profile.json"), t.0.join("open/profile.json"))?;
    let backup_refused = opened.call("host.profile.mnemonic", json!({"password": "fixture"})).is_err();
    let rotation_refused = opened.call("host.profile.change_password",
        json!({"password": "fixture", "new_password": "new fixture"})).is_err();
    opened.end();
    second.end();
    // Assert only booleans: even a failed test must never print a mnemonic.
    assert!(backup_refused && rotation_refused);
    Ok(())
}

/// A host whose first line of input is the device's key, as the Android
/// service starts it.
#[cfg(not(windows))]
fn with_device_key(base: &Path, first_line: &str) -> Proc {
    let mut command = Command::new(HOST_TEST);
    command.arg("--profile").arg(base.join("p")).arg("--guard-dir").arg(base.join("p-guard")).arg("--device-key-stdin");
    let mut h = Proc::spawn(command);
    let stdin = h.stdin.as_mut().unwrap();
    stdin.write_all(first_line.as_bytes()).unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
    h
}

#[cfg(not(windows))]
fn device_key_line(key: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","method":"host.device_key","params":{{"key":"{key}"}}}}"#)
}

/// Where the device keeps a key for the guard (Android: the Keystore, on
/// whose behalf the service gives the host one line before any request),
/// the guard opens only with that key and the password together. The same
/// profile and guard directory under another device's key - a copy on
/// another phone - is not this wallet's guard: it does not open, is left as
/// it was, and is replaced only on request, with the wallet saying it
/// cannot vouch for its state. Without a device key the guard is tied to
/// the password alone, and the status says which it is. The key is not a
/// request: later it is not taken, and a host told to expect it starts with
/// nothing else.
#[cfg(not(windows))]
#[test]
fn the_device_key_binds_the_guard() {
    let t = Temp::new("device");
    let this = "11".repeat(32);
    let other = "22".repeat(32);
    let mut h = with_device_key(&t.0, &device_key_line(&this));
    assert_eq!(h.status()["guard_binding"], "device");
    create(&mut h, "pw", &[GRIN]);
    h.ok("host.unlock", json!({"password": "pw"}));
    h.ok("host.lock", json!({}));
    // the key is no request
    assert_eq!(h.kind("host.device_key", json!({"key": other})), "method_not_found");
    assert_eq!(h.end().0, 0);
    let key_file = only_dir(&t.0.join("p-guard"), "").join("guard.key");
    let kept = std::fs::read(&key_file).unwrap();

    // this device again
    let mut h = with_device_key(&t.0, &device_key_line(&this));
    assert_eq!(h.ok("host.unlock", json!({"password": "pw"})), json!({"guard": "match", "guard_key": "existing", "recovered": false}));
    assert_eq!(h.end().0, 0);

    // another device, and a device with no key of its own
    for (line, binding) in [(device_key_line(&other), "device"), (device_key_line(""), "password")] {
        let mut h = with_device_key(&t.0, &line);
        assert_eq!(h.status()["guard_binding"], binding);
        let e = h.call("host.unlock", json!({"password": "pw"})).unwrap_err();
        assert_eq!((&e["message"], &e["data"]["reason"]), (&json!("guard"), &json!("foreign")), "{binding}");
        assert_eq!(h.status()["profile"], "locked");
        assert_eq!(h.end().0, 0);
        assert_eq!(std::fs::read(&key_file).unwrap(), kept, "left as it was");
    }
    let mut h = Proc::start(HOST_TEST, &t.0, "p", None);
    assert_eq!(h.status()["guard_binding"], "password");
    assert_eq!(h.kind("host.unlock", json!({"password": "pw"})), "guard");
    assert_eq!(h.end().0, 0);

    // on the other device the guard is replaced only on request
    let mut h = with_device_key(&t.0, &device_key_line(&other));
    assert_eq!(
        h.ok("host.unlock", json!({"password": "pw", "reset_guard": true})),
        json!({"guard": "missing", "guard_key": "reset", "recovered": true})
    );
    assert_eq!(h.end().0, 0);
    let mut h = with_device_key(&t.0, &device_key_line(&this));
    assert_eq!(h.kind("host.unlock", json!({"password": "pw"})), "guard", "and is the other device's from then on");
    assert_eq!(h.end().0, 0);

    // a host told to expect the key takes nothing else for it
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"host.status","params":{}}"#;
    let upper = device_key_line(&"AB".repeat(32));
    let short = device_key_line(&"11".repeat(31));
    let spaced = device_key_line(&this).replace("\"params\":", "\"params\": ");
    for wrong in [request, "", upper.as_str(), short.as_str(), spaced.as_str()] {
        let (code, said) = with_device_key(&t.0, wrong).end();
        assert_eq!((code, said.trim()), (2, "fly-paycore-host: the first line must be the device key"), "{wrong}");
    }
    let mut command = Command::new(HOST_TEST);
    command.arg("--profile").arg(t.0.join("p")).arg("--guard-dir").arg(t.0.join("p-guard")).arg("--device-key-stdin");
    let (code, said) = Proc::spawn(command).end();
    assert_eq!((code, said.trim()), (2, "fly-paycore-host: the first line must be the device key"), "no line at all");
}
