//! Where a compiled-in starting point comes from.
//!
//! A record of a starting point proves that everything in it hangs on one
//! header hash, and nothing about that hash. Whether somebody vouches for
//! the hash is said in a second file that a build carries beside the
//! record: who made the point, when, from which nodes, and which public
//! nodes of named operators gave the same hash for that height.
//!
//! The file is a statement of whoever made the build, exactly as the
//! record is, and it is believed exactly as far as the build is. What this
//! module adds is strictness about its form: an origin that does not name
//! the very header of the record, or names fewer than two operators on
//! different networks, vouches for nothing, and the point is then a
//! development point whatever the file calls it.
use crate::checkpoint::Start;
use serde::{Deserialize, Serialize};

/// Longest origin read.
pub const MAX_ORIGIN_LEN: usize = 16 * 1024;
/// Most confirmations in an origin.
pub const MAX_CONFIRMED: usize = 16;
/// Longest text in an origin.
pub const MAX_TEXT: usize = 256;
/// How many operators on different networks have to have given the hash.
pub const MIN_INDEPENDENT: usize = 2;

/// What the maker of a build says the point is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Taken from a node while the program was written. Nobody vouches
    /// for it.
    Development,
    /// Made for a release and compared with public nodes.
    Release,
}

/// A public node that gave the point's hash for the point's height.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Confirmed {
    /// The operator.
    pub group: String,
    /// The name the node was reached under.
    pub host: String,
    /// The network (autonomous system) the node is in.
    pub asn: u32,
}

/// The origin of a starting point.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    /// Version of this form: 1.
    pub version: u8,
    /// What the point is said to be.
    pub kind: Kind,
    /// The network's tag, as in the record.
    pub network: u8,
    /// Height of the starting header.
    pub height: u64,
    /// Hash of the starting header: 64 lower-case hexadecimal digits.
    pub hash: String,
    /// When the point was made, in Unix seconds.
    pub made: u64,
    /// Where the headers came from, in words.
    pub from: String,
    /// The public nodes that gave the same hash.
    pub confirmed: Vec<Confirmed>,
}

fn plain(text: &str) -> bool {
    text.len() <= MAX_TEXT && text.bytes().all(|b| b == b' ' || b.is_ascii_graphic())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Origin {
    /// An origin for the header of `start`.
    pub fn of(kind: Kind, start: &Start, made: u64, from: &str, confirmed: Vec<Confirmed>) -> Origin {
        Origin {
            version: 1,
            kind,
            network: start.net.tag(),
            height: start.height(),
            hash: hex(&start.hash()),
            made,
            from: from.to_string(),
            confirmed,
        }
    }

    fn well_formed(&self) -> bool {
        self.version == 1
            && self.hash.len() == 64
            && self.hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && plain(&self.from)
            && self.confirmed.len() <= MAX_CONFIRMED
            && self
                .confirmed
                .iter()
                .all(|c| plain(&c.group) && plain(&c.host) && !c.group.is_empty() && !c.host.is_empty())
    }

    /// Read an origin. Nothing if the bytes are not one in every detail.
    pub fn read(bytes: &[u8]) -> Option<Origin> {
        if bytes.is_empty() || bytes.len() > MAX_ORIGIN_LEN {
            return None;
        }
        let origin: Origin = serde_json::from_slice(bytes).ok()?;
        origin.well_formed().then_some(origin)
    }

    /// The bytes [`Origin::read`] reads, laid out for a person to read.
    /// Nothing if this origin would not be read back.
    pub fn write(&self) -> Option<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self).ok()?;
        bytes.push(b'\n');
        (Origin::read(&bytes).as_ref() == Some(self)).then_some(bytes)
    }

    /// Whether this origin is about the header of `start` and no other.
    pub fn names(&self, start: &Start) -> bool {
        self.network == start.net.tag() && self.height == start.height() && self.hash == hex(&start.hash())
    }

    /// Whether two of the confirmations are of different operators on
    /// different networks.
    pub fn independent(&self) -> bool {
        self.confirmed
            .iter()
            .any(|a| self.confirmed.iter().any(|b| a.group != b.group && a.asn != b.asn))
    }

    /// Whether the maker of the build vouches for `start`: the origin calls
    /// the point a release point, names this very header and lists public
    /// nodes of two operators on different networks that gave its hash.
    pub fn vouches_for(&self, start: &Start) -> bool {
        self.kind == Kind::Release && self.names(start) && self.independent()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn sample() -> Origin {
        Origin {
            version: 1,
            kind: Kind::Release,
            network: 1,
            height: 4_114_000,
            hash: "00".repeat(31) + "af",
            made: 1_795_000_000,
            from: "nodes found through the network's seed names".to_string(),
            confirmed: vec![
                Confirmed {
                    group: "One".to_string(),
                    host: "one.example".to_string(),
                    asn: 1,
                },
                Confirmed {
                    group: "Two".to_string(),
                    host: "two.example".to_string(),
                    asn: 2,
                },
            ],
        }
    }

    #[test]
    fn an_origin_is_read_back_as_written() {
        let origin = sample();
        let bytes = origin.write().unwrap();
        assert_eq!(Origin::read(&bytes), Some(origin));
        assert!(String::from_utf8(bytes).unwrap().contains("\"kind\": \"release\""));
    }

    #[test]
    fn what_is_not_an_origin() {
        let good = serde_json::to_value(sample()).unwrap();
        assert!(Origin::read(&serde_json::to_vec(&good).unwrap()).is_some());
        let bent = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut value = good.clone();
            change(&mut value);
            Origin::read(&serde_json::to_vec(&value).unwrap())
        };
        assert_eq!(bent(&|v| v["version"] = 2.into()), None);
        assert_eq!(bent(&|v| v["kind"] = "final".into()), None);
        assert_eq!(bent(&|v| v["kind"] = "Release".into()), None);
        assert_eq!(bent(&|v| v["hash"] = "00".repeat(31).into()), None);
        assert_eq!(bent(&|v| v["hash"] = ("00".repeat(31) + "AF").into()), None);
        assert_eq!(bent(&|v| v["hash"] = ("00".repeat(31) + "ag").into()), None);
        assert_eq!(bent(&|v| v["from"] = "line\nbreak".into()), None);
        assert_eq!(bent(&|v| v["from"] = "x".repeat(MAX_TEXT + 1).into()), None);
        assert_eq!(bent(&|v| v["confirmed"][0]["group"] = "".into()), None);
        assert_eq!(bent(&|v| v["confirmed"][0]["host"] = "".into()), None);
        assert_eq!(bent(&|v| v["confirmed"][1]["host"] = "t\u{e9}st".into()), None);
        assert_eq!(bent(&|v| v["confirmed"][0]["asn"] = serde_json::Value::Null), None);
        assert_eq!(bent(&|v| v["extra"] = 1.into()), None);
        assert_eq!(bent(&|v| v["confirmed"][0]["extra"] = 1.into()), None);
        assert_eq!(bent(&|v| { v.as_object_mut().unwrap().remove("made"); }), None);
        let many = vec![good["confirmed"][0].clone(); MAX_CONFIRMED + 1];
        assert_eq!(bent(&|v| v["confirmed"] = many.clone().into()), None);
        assert!(bent(&|v| v["confirmed"] = many[..MAX_CONFIRMED].to_vec().into()).is_some());
        assert!(bent(&|v| v["from"] = "x".repeat(MAX_TEXT).into()).is_some());
        assert_eq!(Origin::read(b""), None);
        let mut padded = serde_json::to_vec(&good).unwrap();
        padded.resize(MAX_ORIGIN_LEN, b' ');
        assert!(Origin::read(&padded).is_some());
        padded.push(b' ');
        assert_eq!(Origin::read(&padded), None, "one byte too long");
    }

    #[test]
    fn two_operators_on_two_networks() {
        let mut origin = sample();
        assert!(origin.independent());
        origin.confirmed[1].asn = 1;
        assert!(!origin.independent(), "one network");
        origin.confirmed[1].asn = 2;
        origin.confirmed[1].group = "One".to_string();
        assert!(!origin.independent(), "one operator");
        origin.confirmed.truncate(1);
        assert!(!origin.independent(), "one node");
        origin.confirmed.clear();
        assert!(!origin.independent());
        // a third that differs from one of two alike is enough
        let mut origin = sample();
        origin.confirmed[1] = origin.confirmed[0].clone();
        origin.confirmed.push(Confirmed {
            group: "Three".to_string(),
            host: "three.example".to_string(),
            asn: 3,
        });
        assert!(origin.independent());
    }
}
