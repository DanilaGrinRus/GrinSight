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
pub mod feed;
pub mod follow;
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
}

impl PointKind {
    /// What is said wherever the starting point is mentioned.
    pub fn note(self) -> &'static str {
        match self {
            PointKind::Development => "development starting point: nobody vouches for it",
            PointKind::Release => "release starting point: public nodes of two operators named it when it was made",
            PointKind::Own => "starting point you gave this program",
        }
    }
    /// Whether what is selected on top of the point is provisional.
    pub fn provisional(self) -> bool {
        self == PointKind::Development
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
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
    direct_post: bool,
    tor_bridges: String,
    stop: Arc<AtomicBool>,
) -> Result<(SharedView, SyncSender<Event>, JoinHandle<()>), String> {
    let point = starting_point(net, &data_dir)?;
    if genesis != net.genesis_hash() {
        return Err("the wallet names another genesis than this program has for that network".to_string());
    }
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
        direct_post,
        tor_bridges,
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
