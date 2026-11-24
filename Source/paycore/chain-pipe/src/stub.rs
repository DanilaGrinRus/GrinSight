//! A stand-in chain process for tests (feature "stub"). The "chain" is a
//! directory that the test fills:
//!
//! * `anchor` - 40 bytes: height (little-endian) and header hash of the
//!   block the chain starts from;
//! * `blocks/<height, 20 digits>.blk` - a block in its wire form;
//! * `time`, `k_conf` - numbers as text; `selected` - present if the tip
//!   counts as selected; `provisional` - present if it stands on something
//!   nobody vouches for; `behind` - present if the layer is not at the tip;
//! * `post-mode` - `accepted` (default), `rejected`, `unknown`, or `lost`
//!   (unknown, and the transaction is not kept); posted transactions land
//!   in `posted/<n>.tx`;
//! * `trouble` - text the layer reports as its problem;
//! * `old-pieces` - how many pieces the old outputs have (absent: the layer
//!   cannot give old outputs); `old/<piece, 20 digits>.blk` - the outputs
//!   of a piece, in the wire form of a block (absent: an empty piece);
//! * `old-known` - 40 bytes, as `anchor`: a block from before the anchor
//!   that the layer still vouches for; a wallet that names it as the block
//!   it knew its outputs up to gets the pieces below `old-bare-below` (a
//!   number as text) without range proofs. Every request that names a
//!   block is noted in `old-since`: a line "piece height";
//! * `dark` - present: the layer knows nothing (no status, unknown steps).
//!
//! What the process was told at its start is left in `told` in its data
//! directory.
//!
//! The directory is the first peer if it is written `dir:<path>` (so two
//! chain processes can serve the same chain), else the data directory.
//! Peers named `silent`, `refuse` and `garbage` make a chain process that
//! never reports ready, refuses to start, or talks nonsense.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, missing_docs)]
use crate::{serve, wire, Config};
use fly_paycore_chain_port::{ChainFeed, Level, OldOutputs, Posted, Status, Step, Tip, Unknown};
use std::path::PathBuf;

pub struct Stub {
    dir: PathBuf,
}

impl Stub {
    fn text(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.dir.join(name)).ok().map(|t| t.trim().to_string())
    }
    fn has(&self, name: &str) -> bool {
        self.dir.join(name).exists()
    }
    fn anchor(&self) -> Option<Tip> {
        self.saved_tip("anchor")
    }
    fn saved_tip(&self, name: &str) -> Option<Tip> {
        let b = std::fs::read(self.dir.join(name)).ok()?;
        (b.len() == 40).then(|| Tip {
            height: u64::from_le_bytes(b[..8].try_into().unwrap()),
            hash: b[8..].try_into().unwrap(),
        })
    }
    fn block(&self, height: u64) -> Option<fly_paycore_chain_port::BlockFacts> {
        let bytes = std::fs::read(self.dir.join("blocks").join(format!("{height:020}.blk"))).ok()?;
        wire::decode_block(&bytes).filter(|b| b.height == height)
    }
    /// The highest block reachable from the anchor without a gap.
    fn tip(&self) -> Option<Tip> {
        let mut tip = self.anchor()?;
        while let Some(b) = self.block(tip.height + 1) {
            tip = Tip { height: b.height, hash: b.hash };
        }
        Some(tip)
    }
    fn hash_at(&self, height: u64) -> Option<[u8; 32]> {
        let anchor = self.anchor()?;
        if height == anchor.height {
            return Some(anchor.hash);
        }
        self.block(height).map(|b| b.hash)
    }
}

impl ChainFeed for Stub {
    fn status(&mut self) -> Option<Status> {
        if self.has("dark") {
            return None;
        }
        let tip = self.tip();
        Some(Status {
            level: match (tip, self.has("behind")) {
                (None, _) => Level::Unknown,
                (Some(_), true) => Level::Behind,
                (Some(_), false) => Level::AtTip,
            },
            tip,
            selected: tip.filter(|_| self.has("selected")),
            confirmed_time: self.text("time").and_then(|t| t.parse().ok()),
            k_conf: self.text("k_conf").and_then(|t| t.parse().ok()).unwrap_or(3),
            rangeproofs_authenticated: !self.has("rp-unauthenticated"),
            provisional: self.has("provisional"),
        })
    }

    fn next(&mut self, at: Option<Tip>) -> Result<Step, Unknown> {
        if self.has("dark") {
            return Err(Unknown);
        }
        let (anchor, tip) = (self.anchor().ok_or(Unknown)?, self.tip().ok_or(Unknown)?);
        let Some(at) = at else {
            return Ok(Step::Reanchor(anchor));
        };
        if at.height < anchor.height {
            return Ok(if self.saved_tip("old-known") == Some(at) {
                Step::ReanchorExtending(anchor)
            } else {
                Step::Reanchor(anchor)
            });
        }
        if at.height > tip.height {
            // the wallet is ahead of what this layer has: it cannot say
            return Err(Unknown);
        }
        match self.hash_at(at.height) {
            Some(hash) if hash == at.hash => match self.block(at.height + 1) {
                Some(block) => Ok(Step::Block(Box::new(block))),
                None => Ok(Step::Nothing),
            },
            _ if at.height > anchor.height => Ok(Step::Rollback { to: at.height - 1 }),
            _ => Ok(Step::Reanchor(anchor)),
        }
    }

    fn post(&mut self, tx: &[u8]) -> Posted {
        let mode = self.text("post-mode").unwrap_or_else(|| "accepted".into());
        if mode != "lost" && mode != "rejected" {
            let dir = self.dir.join("posted");
            let _ = std::fs::create_dir_all(&dir);
            let n = std::fs::read_dir(&dir).map(|d| d.count()).unwrap_or(0);
            let _ = std::fs::write(dir.join(format!("{n:06}.tx")), tx);
        }
        match mode.as_str() {
            "accepted" => Posted::Accepted,
            "rejected" => Posted::Rejected,
            _ => Posted::Unknown,
        }
    }

    fn problem(&mut self) -> Option<String> {
        self.text("trouble")
    }
    fn old_outputs(&mut self, piece: u64) -> Result<OldOutputs, Unknown> {
        if self.has("dark") {
            return Err(Unknown);
        }
        let pieces: u64 = self.text("old-pieces").and_then(|t| t.parse().ok()).ok_or(Unknown)?;
        let outputs = match std::fs::read(self.dir.join("old").join(format!("{piece:020}.blk"))) {
            Ok(bytes) => wire::decode_block(&bytes).ok_or(Unknown)?.outputs,
            Err(_) => Vec::new(),
        };
        Ok(OldOutputs {
            outputs,
            at: self.tip().ok_or(Unknown)?,
            before: self.anchor().ok_or(Unknown)?.height,
            next: Some(piece + 1).filter(|next| *next < pieces),
            pieces,
            bare: false,
        })
    }
    fn old_outputs_since(&mut self, piece: u64, since: Tip) -> Result<OldOutputs, Unknown> {
        use std::io::Write;
        if let Ok(mut noted) = std::fs::OpenOptions::new().create(true).append(true).open(self.dir.join("old-since")) {
            let _ = writeln!(noted, "{piece} {}", since.height);
        }
        let mut old = self.old_outputs(piece)?;
        let known = self.saved_tip("old-known");
        let below: u64 = self.text("old-bare-below").and_then(|t| t.parse().ok()).unwrap_or(0);
        if known == Some(since) && piece < below {
            old.outputs.iter_mut().for_each(|o| o.proof.clear());
            old.bare = true;
        }
        Ok(old)
    }
}

/// Entry point of a stand-in chain process.
pub fn run() {
    let mut alive = None;
    let result = serve(&mut std::io::stdin().lock(), &mut std::io::stdout().lock(), |config: Config| {
        let first = config.peers.first().cloned().unwrap_or_default();
        match first.as_str() {
            "refuse" => return Err("no peer can be reached".to_string()),
            "silent" => loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            },
            "garbage" => {
                use std::io::Write;
                let _ = std::io::stdout().write_all(b"this is not a frame at all, just text\n");
                let _ = std::io::stdout().flush();
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(3600));
                }
            }
            _ => {}
        }
        let dir = match first.strip_prefix("dir:") {
            Some(shared) => PathBuf::from(shared),
            None => PathBuf::from(&config.data_dir),
        };
        // what this process was told, for the tests of whoever started it
        let genesis: String = config.genesis.iter().map(|b| format!("{b:02x}")).collect();
        let told = format!(
            "network={}\ngenesis={genesis}\npeers={}\ndirect_post={}\n",
            config.network,
            config.peers.join(","),
            u8::from(config.direct_post)
        );
        let _ = std::fs::write(PathBuf::from(&config.data_dir).join("told"), told);
        // Tor bridges it was given, kept apart for the tests to look at
        if !config.tor_bridges.is_empty() {
            let _ = std::fs::write(PathBuf::from(&config.data_dir).join("tor-bridges.seen"), &config.tor_bridges);
        }
        let marker = dir.join(format!("{}.chain-alive", std::process::id()));
        std::fs::write(&marker, b"").map_err(|_| "the directory cannot be written".to_string())?;
        alive = Some(marker);
        Ok(Stub { dir })
    });
    if let Some(marker) = alive {
        let _ = std::fs::remove_file(marker);
    }
    if result.is_err() {
        std::process::exit(2);
    }
}
