//! The wallet process without threads: the same `host.*` and `paycore.*`
//! methods, answered on the caller's own thread.
//!
//! The wallet process ([`crate::run`]) keeps the payment core on a worker
//! thread and writes on another. Where there are no threads - the web
//! wallet, whose core runs in one browser worker - the same requests are
//! answered here, one at a time, and the round of delivery is run by the
//! caller ([`Inline::round`]). The profile, the journal, the guard and the
//! bridge are made by the same code as in the process; no helper program
//! is started, so the chain is what [`Setup::ports`] provides.
use crate::profile::{self, Network, ProfileError, Secrets};
use crate::session::{self, HostBridge, Places};
use crate::{
    answer, bad_params, fail, guard_name, origin_name, password, phrase_answer, private_dir, random, Head, HostFail, HostParams, HostRequest,
    Secret, Setup, HOST_API_VERSION,
};
use fly_paycore_bridge::MAX_REQUEST_LEN;
use serde_json::{json, Value};
use std::path::Path;
use zeroize::Zeroizing;

struct Open {
    bridge: HostBridge,
    network: Network,
    instance: [u8; 16],
}

/// One profile directory, served on the caller's thread.
pub struct Inline {
    setup: Setup,
    places: Places,
    open: Option<Open>,
    chain_report: crate::chain::SharedChainReport,
}

impl Inline {
    /// The profile in `profile`, its tail guard under `guard_root`. The
    /// guard directory must lie outside the profile directory, as for the
    /// process.
    pub fn new(setup: Setup, profile: &Path, guard_root: &Path) -> Result<Inline, String> {
        let profile = private_dir(profile).map_err(|_| "the profile directory cannot be used")?;
        let guard_root = private_dir(guard_root).map_err(|_| "the guard directory cannot be used")?;
        if guard_root.starts_with(&profile) {
            return Err("the guard directory must lie outside the profile directory".to_string());
        }
        if profile.to_str().is_none() {
            return Err("the profile path is not text".to_string());
        }
        Ok(Inline {
            setup,
            places: Places {
                profile,
                guard_root,
                launcher: None,
                chain: None,
                onion: None,
                device_key: None,
            },
            open: None,
            chain_report: Default::default(),
        })
    }

    /// The same with a chain layer: started when the profile is unlocked,
    /// ended when it is locked, started again if it stops - as the process
    /// does with the chain program.
    pub fn with_chain(mut self, chain: crate::chain::ChainProgram) -> Inline {
        self.places.chain = Some(chain);
        self
    }

    fn status(&self) -> Value {
        let state = if self.open.is_some() {
            "unlocked"
        } else if profile::exists(&self.places.profile) {
            "locked"
        } else {
            "none"
        };
        let network = match &self.open {
            Some(wallet) => Some(wallet.network),
            None => profile::network(&self.places.profile).ok(),
        }
        .map(Network::name);
        let idle = |configured: bool| json!({"configured": configured, "phase": "none", "error": "", "problem": "", "starts": 0});
        let chain = if self.places.chain.is_some() {
            let report = match self.chain_report.lock() {
                Ok(r) => r.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            };
            let phase = match report.phase {
                crate::transport::Phase::None => "none",
                crate::transport::Phase::Starting => "starting",
                crate::transport::Phase::Ready => "ready",
                crate::transport::Phase::Down => "down",
            };
            json!({"configured": true, "phase": phase, "error": report.error, "problem": report.problem, "starts": report.starts})
        } else {
            idle(false)
        };
        json!({
            "api_version": HOST_API_VERSION,
            "profile": state,
            "network": network,
            "guard_binding": session::guard_binding(&self.places),
            // where the rollback guards are kept, for the window to show: a
            // place on this computer, not a secret
            "guard_dir": self.places.guard_root.to_string_lossy(),
            "transport": idle(false),
            "onion": {"configured": false},
            "tor_bridges": {"lines": 0, "usable": true},
            "chain": chain,
        })
    }

    fn network(&self, p: &HostParams) -> Result<Network, HostFail> {
        let name = p.network.as_deref().ok_or_else(|| bad_params("network: missing"))?;
        match Network::from_name(name) {
            Some(Network::Automated) if !self.setup.allow_automated => Err(bad_params("network: unknown")),
            Some(network) => Ok(network),
            None => Err(bad_params("network: unknown")),
        }
    }

    /// As the process does it: sealed first, then the journal, then the
    /// profile file; the profile stays locked.
    fn make_profile(&mut self, p: &HostParams, seed: Zeroizing<Vec<u8>>, restored: bool) -> Result<(), HostFail> {
        if profile::exists(&self.places.profile) {
            return Err(ProfileError::Exists.into());
        }
        let pass = password(&p.password, "password")?;
        let secrets = Secrets {
            network: self.network(p)?,
            seed,
            root: random::<32>()?,
            guard_wrap: random::<32>()?,
            instance: *random::<16>()?,
            account: 0,
        };
        let text = Zeroizing::new(profile::seal(&secrets, &pass, self.setup.kdf_log_n)?);
        let extra = match self.setup.after_create {
            Some(_) => p.test.clone().unwrap_or(Value::Null),
            None => Value::Null,
        };
        session::create(&secrets, &self.places, &self.setup, &extra, restored)?;
        profile::write_new(&self.places.profile, &text)?;
        Ok(())
    }

    fn restore(&mut self, p: &HostParams) -> Result<(), HostFail> {
        let Some(Secret(phrase)) = &p.mnemonic else {
            return Err(bad_params("mnemonic: missing"));
        };
        if phrase.len() > 1024 {
            return Err(fail(-32046, "bad_mnemonic", ""));
        }
        let words = Zeroizing::new(phrase.to_lowercase());
        let seed = Zeroizing::new(grin_keychain::mnemonic::to_entropy(&words).map_err(|_| fail(-32046, "bad_mnemonic", ""))?);
        self.make_profile(p, seed, true)
    }

    fn profile_for_session(&self, pass: &[u8]) -> Result<Secrets, HostFail> {
        let secrets = profile::open(&self.places.profile, pass, self.setup.kdf_min_log_n)?;
        if self.open.as_ref().is_some_and(|wallet| wallet.instance != secrets.instance || wallet.network != secrets.network) {
            return Err(fail(-32049, "profile_io", "the open wallet and the profile file differ"));
        }
        Ok(secrets)
    }

    fn change_password(&mut self, p: &HostParams) -> Result<(), HostFail> {
        let old = password(&p.password, "password")?;
        let new = password(&p.new_password, "new_password")?;
        let secrets = self.profile_for_session(&old)?;
        let text = Zeroizing::new(profile::seal(&secrets, &new, self.setup.kdf_log_n)?);
        profile::replace(&self.places.profile, &text)?;
        Ok(())
    }

    /// Delete the wallet: as the process does (`Host::delete`).
    fn delete(&mut self, p: &HostParams) -> Result<(), HostFail> {
        let pass = password(&p.password, "password")?;
        let Some(crate::Secret(said)) = &p.words else {
            return Err(bad_params("words: missing"));
        };
        let secrets = self.profile_for_session(&pass)?;
        if !crate::words_match(&secrets.seed, said)? {
            return Err(fail(-32051, "wrong_words", ""));
        }
        // the bridge, the core and its keys end here
        self.open = None;
        session::forget(&self.places, &secrets.instance).map_err(|e| fail(-32049, "profile_io", &format!("{:?}", e.kind())))?;
        profile::remove(&self.places.profile)?;
        Ok(())
    }

    fn unlock(&mut self, p: &HostParams) -> Result<Value, HostFail> {
        if self.open.is_some() {
            return Err(fail(-32045, "already_unlocked", ""));
        }
        let pass = password(&p.password, "password")?;
        let secrets = profile::open(&self.places.profile, &pass, self.setup.kdf_min_log_n)?;
        if secrets.network == Network::Automated && !self.setup.allow_automated {
            return Err(ProfileError::Damaged("network").into());
        }
        let reset = p.reset_guard.unwrap_or(false);
        let (bridge, opened) = session::open(&secrets, &self.places, &self.setup, reset, &Default::default(), &self.chain_report)?;
        self.open = Some(Open {
            bridge,
            network: secrets.network,
            instance: secrets.instance,
        });
        Ok(json!({
            "guard": guard_name(opened.guard),
            "guard_key": origin_name(opened.guard_key),
            "recovered": opened.recovered,
        }))
    }

    fn host_call(&mut self, method: &str, id: &Value, line: &str) -> Zeroizing<String> {
        let request: HostRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => return answer(id, Err(bad_params("params"))),
        };
        let p = request.params.unwrap_or_default();
        let result = match method {
            "host.status" => Ok(self.status()),
            "host.profile.create" => match random::<32>() {
                Ok(seed) => {
                    let made = self.make_profile(&p, Zeroizing::new(seed.to_vec()), false);
                    match made.and_then(|()| phrase_answer(id, seed.as_ref())) {
                        Ok(line) => return line,
                        Err(e) => Err(e),
                    }
                }
                Err(e) => Err(e),
            },
            "host.profile.restore" => self.restore(&p).map(|()| json!({})),
            "host.profile.mnemonic" => {
                let shown = password(&p.password, "password")
                    .and_then(|pass| self.profile_for_session(&pass))
                    .and_then(|secrets: Secrets| phrase_answer(id, &secrets.seed));
                match shown {
                    Ok(line) => return line,
                    Err(e) => Err(e),
                }
            }
            "host.profile.change_password" => self.change_password(&p).map(|()| json!({})),
            "host.profile.delete" => self.delete(&p).map(|()| json!({})),
            "host.unlock" => self.unlock(&p),
            "host.lock" => {
                // the bridge, the core and its keys end here
                self.open = None;
                Ok(json!({}))
            }
            _ => Err(fail(-32601, "method_not_found", "")),
        };
        answer(id, result)
    }

    /// One request line in, one answer line out. A line longer than the
    /// process would read is refused unread.
    pub fn handle(&mut self, line: &str) -> Zeroizing<String> {
        if line.len() > MAX_REQUEST_LEN {
            return answer(&Value::Null, Err(fail(-32600, "invalid_request", "too long")));
        }
        let head: Head = match serde_json::from_str(line) {
            Ok(h) => h,
            Err(e) if e.is_data() => return answer(&Value::Null, Err(fail(-32600, "invalid_request", ""))),
            Err(_) => return answer(&Value::Null, Err(fail(-32700, "parse_error", ""))),
        };
        let id = head.id.unwrap_or(Value::Null);
        let valid_id = matches!(id, Value::Null | Value::Number(_) | Value::String(_));
        let (Some(method), true, Some("2.0")) = (head.method.as_deref(), valid_id, head.jsonrpc.as_deref()) else {
            return answer(&Value::Null, Err(fail(-32600, "invalid_request", "")));
        };
        if method.starts_with("host.") {
            return self.host_call(method, &id, line);
        }
        match &mut self.open {
            None => answer(&id, Err(fail(-32040, "locked", ""))),
            Some(wallet) => Zeroizing::new(wallet.bridge.call(line)),
        }
    }

    /// One round of the open wallet: follow the chain, publish what waits,
    /// take what arrived. Returns the notifications worth showing and
    /// whether there is more than one round takes. Nothing happens while
    /// the profile is locked.
    pub fn round(&mut self) -> (Vec<String>, bool) {
        match &mut self.open {
            Some(wallet) => fly_paycore_bridge::runner::round(&mut wallet.bridge),
            None => (Vec::new(), false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        let mut tag = [0u8; 8];
        let _ = getrandom::getrandom(&mut tag);
        std::env::temp_dir().join(format!("fly-inline-{name}-{}", tag.iter().map(|b| format!("{b:02x}")).collect::<String>()))
    }

    fn quick() -> Setup {
        // the cheapest key derivation the profile file takes: these are tests
        Setup { kdf_log_n: 15, ..Setup::product() }
    }

    fn call(host: &mut Inline, method: &str, params: Value) -> Value {
        let line = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
        serde_json::from_str(&host.handle(&line)).unwrap_or(Value::Null)
    }

    fn kind(reply: &Value) -> &str {
        reply.get("error").and_then(|e| e.get("message")).and_then(Value::as_str).unwrap_or("")
    }

    /// A wallet is created, locked and opened again on one thread; the
    /// words shown at creation restore the same address elsewhere; a wrong
    /// password opens nothing and the locked wallet answers nothing.
    #[test]
    fn a_wallet_lives_on_one_thread() {
        let root = temp("life");
        let mut host = Inline::new(quick(), &root.join("p"), &root.join("g")).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(call(&mut host, "host.status", json!({})).pointer("/result/profile"), Some(&json!("none")));
        // locked and absent: the core is not reached
        assert_eq!(kind(&call(&mut host, "paycore.address", json!({}))), "locked");
        let made = call(&mut host, "host.profile.create", json!({"password": "one", "network": "main"}));
        let words = made.pointer("/result/mnemonic").and_then(Value::as_str).unwrap_or("").to_string();
        assert_eq!(words.split(' ').count(), 24);
        assert_eq!(call(&mut host, "host.status", json!({})).pointer("/result/profile"), Some(&json!("locked")));
        // a refused second creation leaves nothing behind, not even a journal nobody refers to
        let entries = |dir: &Path| std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0);
        let before = entries(&root.join("p"));
        assert_eq!(kind(&call(&mut host, "host.profile.create", json!({"password": "one", "network": "main"}))), "profile_exists");
        assert_eq!(entries(&root.join("p")), before);
        assert_eq!(kind(&call(&mut host, "host.unlock", json!({"password": "two"}))), "wrong_password");
        assert_eq!(kind(&call(&mut host, "paycore.address", json!({}))), "locked");
        let opened = call(&mut host, "host.unlock", json!({"password": "one"}));
        assert!(opened.get("result").is_some(), "{opened}");
        assert_eq!(kind(&call(&mut host, "host.unlock", json!({"password": "one"}))), "already_unlocked");
        let status = call(&mut host, "host.status", json!({}));
        assert_eq!(status.pointer("/result/profile"), Some(&json!("unlocked")));
        assert_eq!(status.pointer("/result/network"), Some(&json!("main")));
        let address = call(&mut host, "paycore.address", json!({}));
        let address = address.pointer("/result/address").and_then(Value::as_str).unwrap_or("").to_string();
        assert!(address.len() == 64 && address.bytes().all(|b| b.is_ascii_hexdigit()), "{address}");
        // a round with no chain connected does no harm
        let (_, more) = host.round();
        assert!(!more);
        // the words are shown again only for the password
        assert_eq!(kind(&call(&mut host, "host.profile.mnemonic", json!({"password": "two"}))), "wrong_password");
        assert_eq!(call(&mut host, "host.profile.mnemonic", json!({"password": "one"})).pointer("/result/mnemonic"), Some(&json!(words)));
        assert!(call(&mut host, "host.lock", json!({})).get("result").is_some());
        assert_eq!(kind(&call(&mut host, "paycore.address", json!({}))), "locked");
        assert!(call(&mut host, "host.unlock", json!({"password": "one"})).get("result").is_some());
        let again = call(&mut host, "paycore.address", json!({}));
        assert_eq!(again.pointer("/result/address").and_then(Value::as_str), Some(address.as_str()));
        // the same words in another profile give the same address
        let mut other = Inline::new(quick(), &root.join("p2"), &root.join("g2")).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(kind(&call(&mut other, "host.profile.restore", json!({"password": "x", "network": "main", "mnemonic": "not the words"}))), "bad_mnemonic");
        assert!(call(&mut other, "host.profile.restore", json!({"password": "x", "network": "main", "mnemonic": words})).get("result").is_some());
        assert!(call(&mut other, "host.unlock", json!({"password": "x"})).get("result").is_some());
        let restored = call(&mut other, "paycore.address", json!({}));
        assert_eq!(restored.pointer("/result/address").and_then(Value::as_str), Some(address.as_str()));
        let _ = std::fs::remove_dir_all(root);
    }

    /// What is not a request is refused in the words of the process; the
    /// guard directory inside the profile is refused; a changed password
    /// is the only one that opens.
    #[test]
    fn requests_and_places_are_judged_as_in_the_process() {
        let root = temp("judge");
        assert!(Inline::new(quick(), &root.join("p"), &root.join("p").join("g")).is_err());
        let mut host = Inline::new(quick(), &root.join("p"), &root.join("g")).unwrap_or_else(|e| unreachable!("{e}"));
        let reply = |host: &mut Inline, line: &str| serde_json::from_str::<Value>(&host.handle(line)).unwrap_or(Value::Null);
        assert_eq!(kind(&reply(&mut host, "{")), "parse_error");
        assert_eq!(kind(&reply(&mut host, r#"{"jsonrpc":"1.0","id":1,"method":"host.status"}"#)), "invalid_request");
        assert_eq!(kind(&reply(&mut host, r#"{"jsonrpc":"2.0","id":[1],"method":"host.status"}"#)), "invalid_request");
        assert_eq!(kind(&reply(&mut host, r#"{"jsonrpc":"2.0","id":1,"method":"host.nothing"}"#)), "method_not_found");
        let long = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"host.status","params":{{"x":"{}"}}}}"#, "a".repeat(MAX_REQUEST_LEN));
        assert_eq!(kind(&reply(&mut host, &long)), "invalid_request");
        assert_eq!(kind(&call(&mut host, "host.profile.create", json!({"password": "one", "network": "automated"}))), "invalid_params");
        assert_eq!(kind(&call(&mut host, "host.profile.create", json!({"password": "", "network": "main"}))), "invalid_params");
        assert!(call(&mut host, "host.profile.create", json!({"password": "one", "network": "test"})).get("result").is_some());
        assert_eq!(kind(&call(&mut host, "host.profile.change_password", json!({"password": "no", "new_password": "two"}))), "wrong_password");
        assert!(call(&mut host, "host.profile.change_password", json!({"password": "one", "new_password": "two"})).get("result").is_some());
        assert_eq!(kind(&call(&mut host, "host.unlock", json!({"password": "one"}))), "wrong_password");
        assert!(call(&mut host, "host.unlock", json!({"password": "two"})).get("result").is_some());
        assert_eq!(call(&mut host, "host.status", json!({})).pointer("/result/network"), Some(&json!("test")));
        assert!(call(&mut host, "paycore.address", json!({})).pointer("/result/address").is_some());
        let _ = std::fs::remove_dir_all(root);
    }

    struct Quiet;
    impl fly_paycore_bridge::chain_port::ChainFeed for Quiet {
        fn status(&mut self) -> Option<fly_paycore_bridge::chain_port::Status> {
            None
        }
        fn next(&mut self, _: Option<fly_paycore_bridge::chain_port::Tip>) -> Result<fly_paycore_bridge::chain_port::Step, fly_paycore_bridge::chain_port::Unknown> {
            Err(fly_paycore_bridge::chain_port::Unknown)
        }
        fn post(&mut self, _: &[u8]) -> fly_paycore_bridge::chain_port::Posted {
            fly_paycore_bridge::chain_port::Posted::Unknown
        }
    }

    fn quiet_inside(config: &fly_paycore_bridge::chain_pipe::Config, timeout: std::time::Duration) -> Result<fly_paycore_bridge::chain_pipe::Starting, String> {
        crate::chain::serve_inside(config, timeout, |_| Ok(Quiet), || {})
    }

    /// With a chain layer inside the program the wallet on one thread has
    /// a chain as the process has: none while locked, started at the
    /// unlock for the profile's own network and directory, reported in the
    /// status, gone again at the lock.
    #[test]
    fn a_wallet_on_one_thread_starts_its_chain_layer_at_the_unlock() {
        let root = temp("chain");
        let chain = crate::chain::ChainProgram {
            inside: Some(quiet_inside),
            program: std::path::PathBuf::new(),
            peers: Vec::new(),
            retry: std::time::Duration::from_secs(3600),
            direct_post: false,
            tor_off: false,
        };
        let mut host = Inline::new(quick(), &root.join("p"), &root.join("g")).unwrap_or_else(|e| unreachable!("{e}")).with_chain(chain);
        let chain_of = |host: &mut Inline| call(host, "host.status", json!({})).pointer("/result/chain").cloned().unwrap_or(Value::Null);
        assert_eq!(chain_of(&mut host), json!({"configured": true, "phase": "none", "error": null, "problem": null, "starts": 0}));
        assert!(call(&mut host, "host.profile.create", json!({"password": "one", "network": "main"})).get("result").is_some());
        assert_eq!(chain_of(&mut host).get("starts"), Some(&json!(0)), "nothing is started for a locked profile");
        assert!(call(&mut host, "host.unlock", json!({"password": "one"})).get("result").is_some());
        assert_eq!(chain_of(&mut host).get("starts"), Some(&json!(1)));
        let began = std::time::Instant::now();
        while chain_of(&mut host).get("phase") != Some(&json!("ready")) && began.elapsed() < std::time::Duration::from_secs(20) {
            let _ = host.round();
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(chain_of(&mut host).get("phase"), Some(&json!("ready")));
        // its files are the profile's own: a directory beside the journal
        let dirs = std::fs::read_dir(root.join("p")).map(|d| d.filter_map(Result::ok).filter(|e| e.path().is_dir()).count()).unwrap_or(0);
        assert!(dirs >= 2, "{dirs}");
        assert!(call(&mut host, "host.lock", json!({})).get("result").is_some());
        assert_eq!(chain_of(&mut host), json!({"configured": true, "phase": "none", "error": null, "problem": null, "starts": 0}));
        let _ = std::fs::remove_dir_all(root);
    }

    /// A wallet is deleted only for its password and two of its words by
    /// number; then it is gone whole - its file, its journal, its guard -
    /// and nothing else is. Until every condition is met nothing is touched.
    #[test]
    fn a_wallet_is_deleted_for_its_password_and_two_of_its_words_and_no_other_way() {
        let root = temp("delete");
        let (profile, guard) = (root.join("p"), root.join("g"));
        let mut host = Inline::new(quick(), &profile, &guard).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(kind(&call(&mut host, "host.profile.delete", json!({"password": "one", "words": "1 a 2 b"}))), "no_profile");
        let made = call(&mut host, "host.profile.create", json!({"password": "one", "network": "main"}));
        let words: Vec<String> = made.pointer("/result/mnemonic").and_then(Value::as_str).unwrap_or("").split(' ').map(str::to_string).collect();
        assert_eq!(words.len(), 24);
        assert!(call(&mut host, "host.unlock", json!({"password": "one"})).get("result").is_some());
        let address = call(&mut host, "paycore.address", json!({})).pointer("/result/address").cloned();
        // a neighbour's file and a neighbour's directory in the same folders
        std::fs::write(profile.join("own-nodes.txt"), "kept").unwrap_or_else(|e| unreachable!("{e}"));
        std::fs::create_dir_all(profile.join("wallet-00112233445566778899aabbccddeeff")).unwrap_or_else(|e| unreachable!("{e}"));
        std::fs::create_dir_all(guard.join("00112233445566778899aabbccddeeff")).unwrap_or_else(|e| unreachable!("{e}"));
        let entries = |dir: &std::path::Path| std::fs::read_dir(dir).map(|d| d.filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().into_owned()).collect::<Vec<_>>()).unwrap_or_default();
        let before = (entries(&profile).len(), entries(&guard).len());
        assert!(before.0 >= 4 && before.1 == 2, "{before:?}");
        let w = |at: usize| words.get(at).cloned().unwrap_or_default();
        let said = |a: usize, b: usize| format!("{} {} {} {}", a.saturating_add(1), w(a), b.saturating_add(1), w(b));
        let refused = [
            (json!({"password": "two", "words": said(6, 18)}), "wrong_password"),
            (json!({"password": "one"}), "invalid_params"),
            (json!({"password": "one", "words": ""}), "invalid_params"),
            (json!({"password": "one", "words": format!("7 {}", w(6))}), "invalid_params"),
            (json!({"password": "one", "words": format!("7 {} 7 {}", w(6), w(6))}), "invalid_params"),
            (json!({"password": "one", "words": format!("0 {} 19 {}", w(6), w(18))}), "invalid_params"),
            (json!({"password": "one", "words": format!("25 {} 19 {}", w(6), w(18))}), "invalid_params"),
            (json!({"password": "one", "words": format!("x {} 19 {}", w(6), w(18))}), "invalid_params"),
            (json!({"password": "one", "words": format!("7 {} 19 {} 3 {}", w(6), w(18), w(2))}), "invalid_params"),
            (json!({"password": "one", "words": format!("7 {} 19 nothing", w(6))}), "wrong_words"),
            (json!({"password": "one", "words": format!("7 nothing 19 {}", w(18))}), "wrong_words"),
            // the right words at the wrong places
            (json!({"password": "one", "words": format!("19 {} 7 {}", w(6), w(18))}), if w(6) == w(18) { "" } else { "wrong_words" }),
            (json!({"words": said(6, 18)}), "invalid_params"),
        ];
        for (params, expected) in refused {
            if expected.is_empty() {
                continue;
            }
            assert_eq!(kind(&call(&mut host, "host.profile.delete", params.clone())), expected, "{params}");
            assert_eq!((entries(&profile).len(), entries(&guard).len()), before, "{params}");
            assert_eq!(call(&mut host, "paycore.address", json!({})).pointer("/result/address").cloned(), address, "the wallet is still open: {params}");
        }
        // the words as a person types them: capitals and extra spaces
        let typed = format!("  7  {}   19 {} ", w(6).to_uppercase(), w(18));
        assert!(call(&mut host, "host.profile.delete", json!({"password": "one", "words": typed})).get("result").is_some());
        assert_eq!(call(&mut host, "host.status", json!({})).pointer("/result/profile"), Some(&json!("none")));
        assert_eq!(kind(&call(&mut host, "paycore.address", json!({}))), "locked");
        let mut left = entries(&profile);
        left.sort();
        assert_eq!(left.iter().filter(|n| !n.contains("lock")).collect::<Vec<_>>(), ["own-nodes.txt", "wallet-00112233445566778899aabbccddeeff"], "{left:?}");
        assert_eq!(entries(&guard), ["00112233445566778899aabbccddeeff"]);
        // nothing of it can be opened, and a new wallet can be made in its place
        assert_eq!(kind(&call(&mut host, "host.unlock", json!({"password": "one"}))), "no_profile");
        assert!(call(&mut host, "host.profile.create", json!({"password": "new", "network": "main"})).get("result").is_some());
        let _ = std::fs::remove_dir_all(root);
    }
}
