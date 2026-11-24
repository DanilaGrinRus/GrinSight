//! The header chain of Grin, followed from a built-in starting point.
//!
//! Nothing here speaks to the network and nothing here knows about a wallet.
//! The crate answers one question: given a starting point that somebody
//! vouches for and headers that anybody may have supplied, which headers
//! follow from that point by the rules of the chain?
//!
//! * [`checkpoint`] reads the record of a starting point and checks that
//!   everything in it hangs on one header hash.
//! * [`origin`] reads what a build says about where its compiled-in point
//!   comes from, and decides whether that amounts to vouching for it.
//! * [`peaks`] keeps the peaks of the header MMR, which is all that is
//!   needed to check the next header's commitment to the headers before it.
//! * [`rules`] checks one more header with the functions the node itself
//!   uses: version, time, sizes, proof of work, difficulty.
//! * [`chain`] holds the verified headers in a file, verifies the whole file
//!   again whenever it is opened, extends the chain and changes branch only
//!   for more work.
//!
//! What follows from a starting point is no more trustworthy than the point:
//! a header chain verified here is "the heaviest valid chain this process
//! was shown from that point", not "the chain". Rules for choosing among
//! sources belong to a later layer.
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

pub mod chain;
pub mod checkpoint;
pub mod origin;
pub mod peaks;
pub mod rules;
#[cfg(feature = "testkit")]
pub mod testkit;

use grin_core::core::hash::Hashed;
use grin_core::core::BlockHeader;
use grin_core::global::{self, ChainTypes};
use grin_core::ser::{self, DeserializationMode, ProtocolVersion};

/// Longest serialized header accepted anywhere in this crate. A header with
/// a 42-nonce proof at 32 edge bits takes 415 bytes; larger graphs add a few.
pub const MAX_HEADER_LEN: usize = 1024;

/// The chain a header belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Net {
    /// Mainnet.
    Main,
    /// The public test network (Floonet).
    Test,
    /// The network of automated tests: tiny proofs of work, hard forks every
    /// three blocks. Never a network of a product.
    Automated,
}

impl Net {
    /// The byte this network has in records and on the pipe to the wallet.
    pub fn tag(self) -> u8 {
        match self {
            Net::Main => 1,
            Net::Test => 2,
            Net::Automated => 3,
        }
    }
    /// The network of a tag.
    pub fn from_tag(tag: u8) -> Option<Net> {
        match tag {
            1 => Some(Net::Main),
            2 => Some(Net::Test),
            3 => Some(Net::Automated),
            _ => None,
        }
    }
    /// The same network as the Grin code names it.
    pub fn chain_type(self) -> ChainTypes {
        match self {
            Net::Main => ChainTypes::Mainnet,
            Net::Test => ChainTypes::Testnet,
            Net::Automated => ChainTypes::AutomatedTesting,
        }
    }
    /// Make this network the one the Grin code uses on the calling thread.
    /// Every entry point of this crate does it first: the consensus
    /// functions read the network from the thread.
    pub fn enter(self) {
        global::set_local_chain_type(self.chain_type());
    }
    /// Hash of the genesis header of this network.
    pub fn genesis_hash(self) -> [u8; 32] {
        self.enter();
        let genesis = match self {
            Net::Main => grin_core::genesis::genesis_main(),
            Net::Test => grin_core::genesis::genesis_test(),
            Net::Automated => grin_core::genesis::genesis_dev(),
        };
        hash_bytes(&genesis.header)
    }
}

/// The hash of a header as plain bytes.
pub fn hash_bytes(header: &BlockHeader) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (to, from) in out.iter_mut().zip(header.hash().as_bytes()) {
        *to = *from;
    }
    out
}

/// Read one header from exactly these bytes, in the form headers have in
/// records and in the file. The network must have been entered.
pub fn read_header(raw: &[u8]) -> Option<BlockHeader> {
    if raw.is_empty() || raw.len() > MAX_HEADER_LEN {
        return None;
    }
    let mut reader = raw;
    let header: BlockHeader = ser::deserialize(&mut reader, ProtocolVersion::local_db(), DeserializationMode::Full).ok()?;
    reader.is_empty().then_some(header)
}

/// The bytes [`read_header`] reads.
pub fn write_header(header: &BlockHeader) -> Option<Vec<u8>> {
    ser::ser_vec(header, ProtocolVersion::local_db())
        .ok()
        .filter(|raw| raw.len() <= MAX_HEADER_LEN)
}

/// A starting point compiled into this crate: its record and what the
/// build says about where it comes from.
#[derive(Clone, Copy, Debug)]
pub struct Baked {
    /// The record, for [`checkpoint::check`].
    pub record: &'static [u8],
    /// The origin, for [`origin::Origin::read`].
    pub origin: &'static [u8],
}

/// The starting point compiled in for `net`.
///
/// The two files of a network are replaced together when a release point
/// is made (`fly-chain point --kind release`). Until then they hold a
/// development point: taken from a node while the program was written,
/// vouched for by nobody. Which of the two a build has is decided by
/// [`origin::Origin::vouches_for`], never by the caller's hopes: a program
/// must say what its point is whenever it speaks of it.
pub fn baked_point(net: Net) -> Option<Baked> {
    match net {
        Net::Main => Some(Baked {
            record: include_bytes!("../points/main.json"),
            origin: include_bytes!("../points/main.origin.json"),
        }),
        Net::Test => Some(Baked {
            record: include_bytes!("../points/test.json"),
            origin: include_bytes!("../points/test.origin.json"),
        }),
        Net::Automated => None,
    }
}
