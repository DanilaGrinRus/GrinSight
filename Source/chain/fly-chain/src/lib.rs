//! The chain process of GrinSight.
//!
//! So far it does two things. It follows the *header* chain: it connects to
//! Grin nodes with the node's own network code, verifies every header from
//! a starting point compiled into the program, keeps the verified chain in
//! a file and follows the branch with the most work among those it is
//! shown. And it collects the *state* at the header where nodes give their
//! state out - the unspent outputs and the ends of the three trees a
//! header commits to - checking every piece against that verified header.
//!
//! Then it follows the chain with *blocks*: every block from that header to
//! the tip is applied to the state under its verified header, and the
//! wallet process is answered from what has been applied. It names no
//! selected tip and cannot broadcast yet; what it has reached it reports in
//! words.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    missing_docs
)]

pub mod accept;
pub mod adapter;
mod bootstrap;
pub use bootstrap::check_exported_pair;
pub use bootstrap::import_checkpoint;
pub use bootstrap::{import_checkpoint_file, pack_checkpoint, pack_profile_checkpoint};
pub mod feed;
pub mod follow;
pub mod net;
pub mod node;
pub mod old;
pub mod post;
pub mod probe;
pub mod schedule;
pub mod send;
pub mod state;

use adapter::Event;
use fly_chain_headers::Net;
use node::{Settings, SharedView, View};
use std::sync::mpsc::SyncSender;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// Name of the file a test build reads its starting point from.
pub const TEST_START_FILE: &str = "start.json";

/// Name of the file in the data directory that holds a starting point the
/// user gave the program in place of the compiled-in one.
pub const OWN_POINT_FILE: &str = "own-point.json";

/// Who vouches for the starting point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PointKind {
    /// Taken from a node while the program was written: nobody.
    #[default]
    Development,
    /// Made for this release and named, when it was made, by public
    /// nodes of two operators on different networks: the maker of the
    /// release.
    Release,
    /// Given to the program by the user: the user.
    Own,
    /// Imported from two files after checking an exact GSHP1 history sample.
    Imported,
    /// Reconstructed by local sequential verification beginning at the exact network genesis.
    Genesis,
    /// Reopened a local compact record previously made after autonomous verification.
    LocalGenesis,
}

impl PointKind {
    /// What is said wherever the starting point is mentioned.
    pub fn note(self) -> &'static str {
        match self {
            PointKind::Development => "development starting point: nobody vouches for it",
            PointKind::Release => "release starting point: public nodes of two operators named it when it was made",
            PointKind::Genesis => "local starting point: headers checked from network genesis",
            PointKind::LocalGenesis => "locally saved point: headers checked from network genesis",
            PointKind::Own => "starting point you gave this program",
            PointKind::Imported => "imported starting point: GSHP1 sample verified for this checkpoint",
        }
    }
    /// Whether what is selected on top of the point is provisional.
    pub fn provisional(self) -> bool {
        self == PointKind::Development
    }
    pub(crate) fn autonomous(self) -> bool {
        matches!(self, Self::Genesis | Self::LocalGenesis)
    }
}

/// The starting point the program goes from, and who vouches for it.
#[derive(Clone, Debug)]
pub struct Point {
    /// The record, for the header chain.
    pub record: Vec<u8>,
    /// Who vouches for it.
    pub kind: PointKind,
}

/// The starting point this program uses for `net`.
///
/// The record of a starting point made from a verified header chain, at
/// the header nodes give their state out at now: a wallet that starts
/// from it can collect the state at once, and the header is too deep to
/// be taken back (K188). The record has to pass the check a starting
/// point passes when the program starts, and to be of that height; why
/// none can be made is said in words for the user.
pub fn point_from(chain: &fly_chain_headers::chain::HeaderChain, made: u64) -> Result<Vec<u8>, String> {
    // K202: a point is made only of a chain that does not lose the proof
    // of the program's point, and has to carry that proof itself
    if refused(chain.start()) {
        return Err("no starting point of your own is made from this chain: it began at a point the proof in this program does not reach; clear your own point first".to_string());
    }
    let tip = chain.tip().height;
    let at = node::archive_height(tip);
    let record = match chain.record_at(at, made) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return Err(format!(
                "no new starting point can be made yet: it would be at block {at}, and it has to be at least three above the point this program started from ({}); the tip is {tip}",
                chain.start().height()
            ))
        }
        Err(_) => return Err("the header file cannot be read".to_string()),
    };
    match fly_chain_headers::checkpoint::check(&record, chain.net()) {
        Ok(start) if start.height() == at && !refused(&start) => Ok(record),
        _ => Err("the starting point made does not pass its own check".to_string()),
    }
}

/// Whether the proof of history this program carries for the network of
/// `start` does not reach it; `false` when it carries none (K202).
#[cfg(feature = "history-proof")]
fn refused(start: &fly_chain_headers::checkpoint::Start) -> bool {
    matches!(fly_chain_headers::proof::history_of(start), fly_chain_headers::proof::History::Refused(_))
}

#[cfg(not(feature = "history-proof"))]
fn refused(_start: &fly_chain_headers::checkpoint::Start) -> bool {
    false
}

/// A point the user left in the data directory (`own-point.json`) comes
/// first; if it is there and does not pass its check, nothing is started -
/// the user meant to use it. Otherwise, for the two real networks, the
/// point compiled in, which is a release point if what the build says
/// about it vouches for it and a development point otherwise. The network
/// of automated tests has none compiled in; a test build reads one from
/// the data directory.
pub fn starting_point(net: Net, data_dir: &Path) -> Result<Point, String> {
    use fly_chain_headers::checkpoint::{self, MAX_RECORD_LEN};
    use std::io::Read;
    if net == Net::Automated && !cfg!(feature = "test-net") {
        return Err("the network of automated tests is not served by this program".to_string());
    }
    if let Some(record) = bootstrap::imported(net, data_dir)
        .map_err(|e| format!("the imported GSHP1 checkpoint cannot be verified: {e}"))?
    {
        return Ok(Point { record, kind: PointKind::Imported });
    }
    match std::fs::File::open(data_dir.join(OWN_POINT_FILE)) {
        Ok(file) => {
            let mut record = Vec::new();
            let limit = u64::try_from(MAX_RECORD_LEN).unwrap_or(u64::MAX).saturating_add(1);
            file.take(limit)
                .read_to_end(&mut record)
                .map_err(|_| "your own starting point cannot be read".to_string())?;
            return match checkpoint::check(&record, net) {
                Ok(_) => Ok(Point {
                    record,
                    kind: PointKind::Own,
                }),
                Err(checkpoint::CheckError::Network) => Err("your own starting point is for another network".to_string()),
                Err(_) => Err("your own starting point does not pass its check".to_string()),
            };
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // A dangling user-selected record still expresses an explicit choice.
            match std::fs::symlink_metadata(data_dir.join(OWN_POINT_FILE)) {
                Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err("your own starting point cannot be read".to_string()),
            }
        }
        Err(_) => return Err("your own starting point cannot be read".to_string()),
    }
    match net {
        Net::Main | Net::Test => {
            let baked = fly_chain_headers::baked_point(net).ok_or("no starting point for this network")?;
            let vouched = checkpoint::check(baked.record, net).ok().is_some_and(|start| {
                fly_chain_headers::origin::Origin::read(baked.origin).is_some_and(|origin| origin.vouches_for(&start))
            });
            Ok(Point {
                record: baked.record.to_vec(),
                kind: if vouched { PointKind::Release } else { PointKind::Development },
            })
        }
        Net::Automated => std::fs::read(data_dir.join(TEST_START_FILE))
            .map(|record| Point {
                record,
                kind: PointKind::Development,
            })
            .map_err(|_| "the test network needs a starting point in the data directory".to_string()),
    }
}
/// How the user wants transactions sent.
#[derive(Clone, Debug, Default)]
pub struct Sending {
    /// The user agreed that a transaction Tor fails to send goes out from
    /// this computer's address.
    pub direct_post: bool,
    /// The user switched Tor off (K189).
    pub tor_off: bool,
    /// Tor bridges the user chose, one a line; empty for none.
    pub tor_bridges: String,
}

fn startup_point(net: Net, data_dir: &Path) -> Result<Point, String> {
    if net == Net::Automated && !cfg!(feature = "test-net") {
        return Err("the network of automated tests is not served by this program".into());
    }
    let explicit = fly_paycore_chain_port::bootstrap::selected(data_dir, net.tag()).map_err(|e| e.to_string())?;
    if explicit || bootstrap::has_autonomous_state(data_dir).map_err(|e| e.to_string())? {
        // A legacy journal does not name its network in its filename. Persist
        // its choice only after prepare has validated the correct network.
        return Ok(Point { record: Vec::new(), kind: PointKind::Genesis });
    }
    starting_point(net, data_dir)
}

/// Start the node on a thread of its own. `genesis` is the genesis hash the
/// caller expects for `net`; a mismatch means caller and program disagree
/// about the chain, and nothing is started.
///
/// Makes `net` the chain type of the whole process: one process, one chain.
pub fn start(
    net: Net,
    genesis: [u8; 32],
    data_dir: PathBuf,
    peers: Vec<String>,
    sending: Sending,
    stop: Arc<AtomicBool>,
) -> Result<(SharedView, SyncSender<Event>, JoinHandle<()>), String> {
    if genesis != net.genesis_hash() {
        return Err("the wallet names another genesis than this program has for that network".to_string());
    }
    let point = startup_point(net, &data_dir)?;
    grin_core::global::init_global_chain_type(net.chain_type());
    if grin_core::global::get_chain_type() != net.chain_type() {
        return Err("this process already serves another network".to_string());
    }
    let view: SharedView = Arc::new(Mutex::new(View::default()));
    let settings = Settings {
        net,
        tips: accept::Setup::of(net, &data_dir),
        data_dir,
        peers,
        record: point.record,
        point: point.kind,
        direct_post: sending.direct_post,
        tor_off: sending.tor_off,
        tor_bridges: sending.tor_bridges,
    };
    let shared = view.clone();
    let (events, inbox) = std::sync::mpsc::sync_channel::<Event>(256);
    let to_node = events.clone();
    let handle = std::thread::Builder::new()
        .name("fly-chain-node".into())
        .spawn(move || node::run(settings, shared, stop, events, inbox))
        .map_err(|_| "the node thread could not be started".to_string())?;
    Ok((view, to_node, handle))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod startup_tests {
    use super::*;
    use fly_paycore_chain_port::bootstrap as choice;
    use std::fs;

    struct Folder(PathBuf);
    impl Folder {
        fn new() -> Self {
            let mut random = [0; 8];
            getrandom::getrandom(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!("fly-startup-{}", u64::from_le_bytes(random)));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Folder {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn normal_selection_uses_the_release_then_honours_a_users_point() {
        let dir = Folder::new();
        for net in [Net::Main, Net::Test] {
            let point = startup_point(net, &dir.0).unwrap();
            assert_eq!(point.kind, PointKind::Release);
            assert_eq!(point.record, fly_chain_headers::baked_point(net).unwrap().record);
            #[cfg(feature = "history-proof")]
            {
                use fly_chain_headers::proof::{history_of, History};
                let checked = fly_chain_headers::checkpoint::check(&point.record, net).unwrap();
                match net {
                    Net::Main => assert!(matches!(history_of(&checked), History::Sampled(_))),
                    Net::Test => assert!(matches!(history_of(&checked), History::Unproved)),
                    Net::Automated => unreachable!(),
                }
            }
        }
        fs::write(dir.0.join(OWN_POINT_FILE), fly_chain_headers::baked_point(Net::Main).unwrap().record).unwrap();
        assert_eq!(startup_point(Net::Main, &dir.0).unwrap().kind, PointKind::Own);
        assert!(startup_point(Net::Test, &dir.0).is_err());
        fs::write(dir.0.join(OWN_POINT_FILE), b"broken").unwrap();
        assert!(startup_point(Net::Main, &dir.0).is_err());
        choice::schedule(&dir.0, Net::Main.tag()).unwrap();
        assert_eq!(startup_point(Net::Main, &dir.0).unwrap().kind, PointKind::Genesis);
        assert!(startup_point(Net::Test, &dir.0).is_err());
    }

    #[test]
    fn existing_autonomous_files_select_local_verification_across_restarts() {
        for file in ["autonomous-headers-v1.bin", "autonomous-compact-v1.bin", "autonomous-active-v1.copy"] {
            let dir = Folder::new();
            let selected = dir.0.join(file);
            fs::write(&selected, b"existing bytes are for the autonomous reader to verify").unwrap();
            assert_eq!(startup_point(Net::Main, &dir.0).unwrap().kind, PointKind::Genesis, "{file}");
            assert!(!choice::selected(&dir.0, Net::Main.tag()).unwrap());
            assert_eq!(startup_point(Net::Main, &dir.0).unwrap().kind, PointKind::Genesis);
        }
        let dir = Folder::new();
        fs::create_dir(dir.0.join("genesis-main-v1.intent")).unwrap();
        assert!(startup_point(Net::Main, &dir.0).is_err());
    }

    #[cfg(feature = "history-proof")]
    #[test]
    fn import_exact_gshp1_pair_on_the_second_wallet() {
        let input = Folder::new();
        let dst = Folder::new();
        let net = Net::Main;
        let point = fly_chain_headers::baked_point(net).unwrap().record;
        let sample = fly_chain_headers::proof::baked_history(net).unwrap();
        let point_file = input.0.join("my checkpoint.json");
        let history_file = input.0.join("gs export.proof");
        fs::write(&point_file, point).unwrap();
        fs::write(&history_file, sample).unwrap();
        let partial = dst.0.join("import-gshp1.partial");
        fs::create_dir(&partial).unwrap();
        fs::write(partial.join("checkpoint.json"), b"partial from an interrupted import").unwrap();
        assert_eq!(startup_point(net, &dst.0).unwrap().kind, PointKind::Release);
        fs::write(dst.0.join("headers.dat"), b"pre-existing release cache").unwrap();
        let passed = import_checkpoint(net, &dst.0, &point_file, &history_file).unwrap();
        assert_eq!(passed, import_checkpoint(net, &dst.0, &point_file, &history_file).unwrap());
        assert!(!partial.exists());
        assert_eq!(fs::read(dst.0.join("headers.dat")).unwrap(), b"pre-existing release cache");
        let activated = startup_point(net, &dst.0).unwrap();
        assert_eq!(activated.kind, PointKind::Imported);
        assert_eq!(activated.record, point);
        assert_eq!(fly_chain_headers::checkpoint::check(&activated.record, net).unwrap().hash(), passed.hash);
        assert_eq!(passed.points, fly_chain_headers::proof::POINTS);

        // Changing the selected source after import cannot change the installed pair.
        fs::write(&history_file, b"incomplete").unwrap();
        assert!(import_checkpoint(net, &dst.0, &point_file, &history_file).is_err());
        assert_eq!(startup_point(net, &dst.0).unwrap().kind, PointKind::Imported);
        assert!(startup_point(Net::Test, &dst.0).is_err());
        let imported_proof = dst.0.join("imported-gshp1-v1/history.proof");
        fs::write(&imported_proof, b"incomplete").unwrap();
        assert!(startup_point(net, &dst.0).is_err());
        fs::remove_file(imported_proof).unwrap();
        assert!(startup_point(net, &dst.0).is_err());
    }

    #[cfg(feature = "history-proof")]
    #[test]
    fn import_cannot_replace_an_explicit_start_or_install_a_wrong_network() {
        let input = Folder::new();
        let dst = Folder::new();
        let net = Net::Main;
        let point = input.0.join("point");
        let proof = input.0.join("proof");
        let record = fly_chain_headers::baked_point(net).unwrap().record;
        fs::write(&point, record).unwrap();
        fs::write(&proof, fly_chain_headers::proof::baked_history(net).unwrap()).unwrap();
        assert!(import_checkpoint(Net::Test, &dst.0, &point, &proof).is_err());
        fs::write(dst.0.join(OWN_POINT_FILE), record).unwrap();
        assert!(import_checkpoint(net, &dst.0, &point, &proof).is_err());
        assert_eq!(startup_point(net, &dst.0).unwrap().kind, PointKind::Own);
        fs::remove_file(dst.0.join(OWN_POINT_FILE)).unwrap();
        choice::schedule(&dst.0, net.tag()).unwrap();
        assert!(import_checkpoint(net, &dst.0, &point, &proof).is_err());
        assert_eq!(startup_point(net, &dst.0).unwrap().kind, PointKind::Genesis);
        assert!(!dst.0.join("imported-gshp1-v1").exists());
    }
}
