//! Whom the program asks.
//!
//! A *source* is a node's own API reached over HTTPS under a name. Who
//! runs the node is not something the program can work out from the
//! network: it is a fact written down when the program is released, with
//! the place where the operator said so. Two sources count as two voices
//! only if that record names different operators and different networks
//! (autonomous systems) for them. A source the user adds is asked like any
//! other and never counts as an independent voice.

/// The path of a node's public API.
pub const FOREIGN: &str = "/v2/foreign";

/// One node asked about the tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The operator, as recorded at release. Empty for a source the user
    /// added.
    pub group: String,
    /// The autonomous system the service was seen in when the record was
    /// made. Unknown is not different from anything.
    pub asn: Option<u32>,
    /// The name the node is reached and authenticated under.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The path of the API.
    pub path: String,
}

impl Source {
    /// A source of the built-in list.
    pub fn listed(group: &str, asn: Option<u32>, host: &str) -> Source {
        Source {
            group: group.to_string(),
            asn,
            host: host.to_string(),
            port: 443,
            path: FOREIGN.to_string(),
        }
    }

    /// A source the user names, as `https://host`, `https://host:port` or
    /// either with a path. Nothing else is taken: no other scheme, no
    /// user name, no query.
    pub fn own(url: &str) -> Option<Source> {
        let rest = url.strip_prefix("https://")?;
        let (at, path) = match rest.find('/') {
            Some(i) => (rest.get(..i)?, rest.get(i..)?),
            None => (rest, FOREIGN),
        };
        let path = if path == "/" { FOREIGN } else { path };
        let (host, port) = match at.rsplit_once(':') {
            Some((host, port)) => {
                if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                (host, port.parse::<u16>().ok()?)
            }
            None => (at, 443),
        };
        let host_ok = !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
            && !host.starts_with(['.', '-'])
            && !host.ends_with(['.', '-'])
            && !host.contains("..");
        let path_ok = path.len() <= 128
            && path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'));
        if !host_ok || !path_ok || port == 0 {
            return None;
        }
        Some(Source {
            group: String::new(),
            asn: None,
            host: host.to_string(),
            port,
            path: path.to_string(),
        })
    }

    /// Whether this source can be one of two independent voices together
    /// with `other`: both are recorded with an operator and a network, and
    /// both the operators and the networks differ.
    pub fn independent_of(&self, other: &Source) -> bool {
        match (self.asn, other.asn) {
            (Some(a), Some(b)) => {
                a != b && !self.group.is_empty() && !other.group.is_empty() && self.group != other.group
            }
            _ => false,
        }
    }
}

/// How many operators recorded with a network the Mainnet list has to
/// have for any quorum to be possible.
pub const MAINNET_GROUPS: usize = 3;

/// The same for Testnet. Only two operators run a public node there, so
/// both of them have to confirm; coins of the test network are worth
/// nothing, and this keeps the same code at work on both networks.
pub const TESTNET_GROUPS: usize = 2;

/// The version of the built-in lists. A changed list is a new version.
pub const LIST_VERSION: u32 = 2;

/// The built-in list for Mainnet: public nodes of five operators who each
/// said in public that the node is theirs.
///
/// The networks are the ones the nodes' addresses were seen in when the
/// list was checked on 23 November 2026. Two of the five stand in the
/// same network and so are not independent of each other; for a service
/// behind a proxy the network is the proxy's.
pub fn mainnet() -> Vec<Source> {
    vec![
        Source::listed("Grincoin.org", Some(24940), "grincoin.org"),
        Source::listed("Grinffindor", Some(9145), "mainnet.grinffindor.org"),
        Source::listed("Grin.money", Some(13335), "api.grin.money"),
        Source::listed("Raubritter", Some(16276), "main.grin.raubritter.org"),
        Source::listed("Grin Coffee", Some(16276), "mainnet.grin-coffee.com"),
    ]
}

/// The built-in list for Testnet: the public nodes of the two operators
/// who run one there, with the networks their addresses were seen in on
/// 23 November 2026.
pub fn testnet() -> Vec<Source> {
    vec![
        Source::listed("Grinffindor", Some(9145), "testnet.grinffindor.org"),
        Source::listed("Grin.money", Some(13335), "testapi.grin.money"),
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn a_source_the_user_names() {
        let plain = Source::own("https://node.example").unwrap();
        assert_eq!((plain.host.as_str(), plain.port, plain.path.as_str()), ("node.example", 443, FOREIGN));
        assert_eq!((plain.group.as_str(), plain.asn), ("", None));
        let full = Source::own("https://10.0.0.7:3413/v2/foreign").unwrap();
        assert_eq!((full.host.as_str(), full.port), ("10.0.0.7", 3413));
        assert_eq!(Source::own("https://node.example/").unwrap().path, FOREIGN);
        assert_eq!(Source::own("https://node.example/api/v2").unwrap().path, "/api/v2");
    }

    #[test]
    fn what_is_not_taken_for_a_source() {
        for bad in [
            "",
            "node.example",
            "http://node.example",
            "https://",
            "https://user@node.example",
            "https://user:pass@node.example",
            "https://node.example?x=1",
            "https://node.example/v2/foreign?x=1",
            "https://node.example/v2/foreign#x",
            "https://node.example:0",
            "https://node.example:65536",
            "https://node.example:",
            "https://node.example:44a",
            "https://Node.Example",
            "https://node..example",
            "https://-node.example",
            "https://node.example.",
            "https://node.example/a b",
            "https://node.example/\r\nX: y",
            "https://[::1]:3413",
        ] {
            assert_eq!(Source::own(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn who_is_independent_of_whom() {
        let a = Source::listed("A", Some(1), "a.example");
        let b = Source::listed("B", Some(2), "b.example");
        assert!(a.independent_of(&b) && b.independent_of(&a));
        // The same operator on another network, another operator on the
        // same network, a network nobody recorded, a source of the user.
        assert!(!a.independent_of(&Source::listed("A", Some(2), "a2.example")));
        assert!(!a.independent_of(&Source::listed("B", Some(1), "b.example")));
        assert!(!a.independent_of(&Source::listed("B", None, "b.example")));
        assert!(!Source::listed("A", None, "a.example").independent_of(&b));
        let mut own = Source::own("https://mine.example").unwrap();
        assert!(!a.independent_of(&own));
        own.asn = Some(3);
        assert!(!a.independent_of(&own) && !own.independent_of(&a));
        assert!(!a.independent_of(&a));
    }

    #[test]
    fn the_built_in_lists() {
        let list = mainnet();
        let seen: Vec<(&str, Option<u32>, &str)> = list
            .iter()
            .map(|s| (s.group.as_str(), s.asn, s.host.as_str()))
            .collect();
        assert_eq!(
            seen,
            [
                ("Grincoin.org", Some(24940), "grincoin.org"),
                ("Grinffindor", Some(9145), "mainnet.grinffindor.org"),
                ("Grin.money", Some(13335), "api.grin.money"),
                ("Raubritter", Some(16276), "main.grin.raubritter.org"),
                ("Grin Coffee", Some(16276), "mainnet.grin-coffee.com"),
            ]
        );
        // Every pair is independent but the two that share a network.
        let mut pairs = Vec::new();
        for (i, a) in list.iter().enumerate() {
            for b in list.iter().skip(i + 1) {
                if !a.independent_of(b) {
                    pairs.push((a.group.as_str(), b.group.as_str()));
                }
            }
        }
        assert_eq!(pairs, [("Raubritter", "Grin Coffee")]);

        let test = testnet();
        let seen: Vec<(&str, Option<u32>, &str)> = test
            .iter()
            .map(|s| (s.group.as_str(), s.asn, s.host.as_str()))
            .collect();
        assert_eq!(
            seen,
            [
                ("Grinffindor", Some(9145), "testnet.grinffindor.org"),
                ("Grin.money", Some(13335), "testapi.grin.money"),
            ]
        );
        // The two are a pair: on Testnet both have to confirm.
        assert!(test[0].independent_of(&test[1]));
        assert_eq!(LIST_VERSION, 2);
        for s in list.iter().chain(&test) {
            assert!(s.port == 443 && s.path == FOREIGN);
            assert_eq!(Source::own(&format!("https://{}", s.host)).map(|o| o.host), Some(s.host.clone()));
        }
        // No node of one network is in the list of the other.
        assert!(list.iter().all(|m| test.iter().all(|t| t.host != m.host)));
    }
}
