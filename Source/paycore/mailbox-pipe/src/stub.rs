#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, missing_docs)]
//! A stand-in transport process for the tests of the process boundary
//! (feature "stub"; never part of a product build).
//! "Relay" is a directory both stubs can see: one file per message.
//! Two contact keys make it misbehave on purpose: sealing for `[0xDD; 32]`
//! kills the process, sealing for `[0xCC; 32]` never answers.
use fly_paycore_mailbox::{Envelope, Incoming, Mailbox, Published};
use crate::{serve, Config};
use std::collections::BTreeSet;
use std::path::PathBuf;

/// id, from, to, text
type Message = ([u8; 32], [u8; 32], [u8; 32], String);

struct Stub {
    me: [u8; 32],
    dir: PathBuf,
    sealed: u64,
    done: BTreeSet<[u8; 32]>,
    round: BTreeSet<[u8; 32]>,
}
fn key(b: &[u8], at: usize) -> [u8; 32] {
    let mut k = [0u8; 32];
    if let Some(s) = b.get(at..at.saturating_add(32)) {
        k.copy_from_slice(s);
    }
    k
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
impl Stub {
    /// A file named "trouble" in the shared directory makes the "relay"
    /// refuse every publication; its text is what the relay "said".
    fn trouble(&self) -> Option<String> {
        std::fs::read(self.dir.join("trouble"))
            .ok()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    }
    fn messages(&self) -> Vec<Message> {
        let mut out = Vec::new();
        let Ok(dir) = std::fs::read_dir(&self.dir) else { return out };
        let mut names: Vec<PathBuf> = dir.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "msg")).collect();
        names.sort();
        for p in names {
            let Ok(b) = std::fs::read(&p) else { continue };
            if b.len() < 96 {
                continue;
            }
            out.push((
                key(&b, 0),
                key(&b, 32),
                key(&b, 64),
                String::from_utf8_lossy(b.get(96..).unwrap_or_default()).into_owned(),
            ));
        }
        out
    }
}
impl Mailbox for Stub {
    fn seal(&mut self, to: &[u8; 32], text: &str) -> Result<Envelope, String> {
        if *to == [0xDD; 32] {
            std::process::exit(3);
        }
        if *to == [0xCC; 32] {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        if text.is_empty() {
            return Err("nothing to seal".into());
        }
        self.sealed = self.sealed.wrapping_add(1);
        let mut event_id = self.me;
        for (slot, byte) in event_id.iter_mut().zip(self.sealed.to_le_bytes()) {
            *slot = byte;
        }
        let mut bytes = self.me.to_vec();
        bytes.extend_from_slice(to);
        bytes.extend_from_slice(text.as_bytes());
        Ok(Envelope { event_id, bytes, expires_at: 4_000_000_000 })
    }
    fn publish(&mut self, e: &Envelope) -> Published {
        if e.bytes.len() < 64 || self.trouble().is_some() {
            return Published::Unknown;
        }
        let mut file = e.event_id.to_vec();
        file.extend_from_slice(&e.bytes);
        let path = self.dir.join(format!("{}.msg", hex(&e.event_id)));
        match std::fs::write(path, file) {
            Ok(()) => Published::Accepted,
            Err(_) => Published::Busy,
        }
    }
    fn next_incoming(&mut self) -> Option<Incoming> {
        let found = self
            .messages()
            .into_iter()
            .find(|m| m.2 == self.me && !self.done.contains(&m.0) && !self.round.contains(&m.0));
        match found {
            Some((id, from, _, text)) => {
                self.round.insert(id);
                Some(Incoming { id, from, text })
            }
            None => {
                self.round.clear();
                None
            }
        }
    }
    fn resend_reply(&mut self, _incoming: &[u8; 32]) -> Option<Published> {
        None
    }
    fn reply(&mut self, incoming: &[u8; 32], text: &str) -> Published {
        let Some(to) = self.messages().into_iter().find(|m| m.0 == *incoming).map(|m| m.1) else {
            return Published::Unknown;
        };
        match self.seal(&to, text) {
            Ok(e) => self.publish(&e),
            Err(_) => Published::Unknown,
        }
    }
    fn done(&mut self, incoming: &[u8; 32]) {
        self.done.insert(*incoming);
    }
    fn problem(&mut self) -> Option<String> {
        self.trouble()
    }
}

/// Entry point of a stand-in transport process.
pub fn run() {
    let mut alive = None;
    let result = serve(&mut std::io::stdin().lock(), &mut std::io::stdout().lock(), |config: Config| {
        if config.relay == "refuse" {
            return Err("the relay address is not usable".to_string());
        }
        if config.relay == "silent" {
            // never becomes ready
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        if config.relay == "garbage" {
            use std::io::Write;
            let _ = std::io::stdout().write_all(b"this is not a frame at all, just text\n");
            let _ = std::io::stdout().flush();
            std::process::exit(0);
        }
        // "dir:<path>" as the relay: one directory shared by processes that
        // each have their own data directory
        let dir = match config.relay.strip_prefix("dir:") {
            Some(shared) => PathBuf::from(shared),
            None => PathBuf::from(&config.data_dir),
        };
        // Tor bridges it was given, kept for the tests to look at
        if !config.tor_bridges.is_empty() {
            let _ = std::fs::create_dir_all(&config.data_dir);
            let _ = std::fs::write(PathBuf::from(&config.data_dir).join("tor-bridges.seen"), &config.tor_bridges);
        }
        let marker = dir.join(format!("{}.alive", std::process::id()));
        std::fs::write(&marker, b"").map_err(|e| e.to_string())?;
        alive = Some(marker);
        Ok(Stub {
            me: config.identity_public,
            dir,
            sealed: 0,
            done: BTreeSet::new(),
            round: BTreeSet::new(),
        })
    });
    // a clean end (the wallet closed the pipe) removes the marker
    if result.is_ok() {
        if let Some(marker) = alive {
            let _ = std::fs::remove_file(marker);
        }
    }
}
