//! Frames and the start-up message.
use fly_paycore_pipe_link::Cut;

/// Largest frame in either direction, checked before anything is allocated.
pub const MAX_FRAME: usize = 256 * 1024;
/// Version of this protocol; the two sides must agree exactly.
pub const VERSION: u8 = 3;

// requests
pub(crate) const SEAL: u8 = 0x01;
pub(crate) const PUBLISH: u8 = 0x02;
pub(crate) const NEXT: u8 = 0x03;
pub(crate) const RESEND: u8 = 0x04;
pub(crate) const REPLY: u8 = 0x05;
pub(crate) const DONE: u8 = 0x06;
pub(crate) const PROBLEM: u8 = 0x07;
// answers
pub(crate) const SEALED: u8 = 0x81;
pub(crate) const NOT_SEALED: u8 = 0x82;
pub(crate) const PUBLISHED: u8 = 0x83;
pub(crate) const INCOMING: u8 = 0x84;
pub(crate) const NOTHING: u8 = 0x85;
pub(crate) const NO_REPLY: u8 = 0x86;
pub(crate) const OK: u8 = 0x87;
pub(crate) const TEXT: u8 = 0x88;

/// What the transport process needs to start. It crosses the pipe once, as
/// the first frame; nothing of it is put on a command line or in the
/// environment, where other processes could read it.
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    /// Secret key of the profile's transport identity.
    pub identity_secret: [u8; 32],
    /// The public key that belongs to it. The transport checks that the two
    /// match before it starts.
    pub identity_public: [u8; 32],
    /// Key under which the transport keeps replies on disk.
    pub store_key: [u8; 32],
    /// Address of the relay.
    pub relay: String,
    /// Directory for the transport's own files (Tor state, stored replies).
    pub data_dir: String,
    /// Contacts the mailbox talks to.
    pub contacts: Vec<[u8; 32]>,
    /// How long a sealed message may wait at relays, in seconds.
    pub delivery_window_secs: u32,
    /// Longest wait for a relay to acknowledge, in milliseconds.
    pub publish_timeout_ms: u32,
    /// How long one contact is polled for a message, in milliseconds.
    pub poll_ms: u32,
    /// Longest wait for the network layer to come up, in seconds.
    pub start_timeout_secs: u32,
    /// Tor bridges the user chose, one a line; empty for none. The
    /// transport reads and checks them; with any, Tor is reached through
    /// them only.
    pub tor_bridges: String,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // never the secrets, and not who the contacts are
        write!(f, "Config {{ contacts: {}, .. }}", self.contacts.len())
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        for b in self.identity_secret.iter_mut().chain(self.store_key.iter_mut()) {
            *b = 0;
        }
        // keep the wipe from being optimised away
        std::hint::black_box(&self.identity_secret);
        std::hint::black_box(&self.store_key);
    }
}

impl Config {
    pub(crate) fn encode(&self) -> Option<Vec<u8>> {
        let mut out = vec![VERSION];
        out.extend_from_slice(&self.identity_secret);
        out.extend_from_slice(&self.identity_public);
        out.extend_from_slice(&self.store_key);
        for text in [&self.relay, &self.data_dir] {
            out.extend_from_slice(&u16::try_from(text.len()).ok()?.to_le_bytes());
            out.extend_from_slice(text.as_bytes());
        }
        out.extend_from_slice(&u16::try_from(self.contacts.len()).ok()?.to_le_bytes());
        for c in &self.contacts {
            out.extend_from_slice(c);
        }
        for n in [
            self.delivery_window_secs,
            self.publish_timeout_ms,
            self.poll_ms,
            self.start_timeout_secs,
        ] {
            out.extend_from_slice(&n.to_le_bytes());
        }
        out.extend_from_slice(&u16::try_from(self.tor_bridges.len()).ok()?.to_le_bytes());
        out.extend_from_slice(self.tor_bridges.as_bytes());
        (out.len() < MAX_FRAME).then_some(out)
    }

    pub(crate) fn decode(payload: &[u8]) -> Option<Config> {
        let mut c = Cut(payload);
        if c.take(1)? != [VERSION] {
            return None;
        }
        let identity_secret = c.array::<32>()?;
        let identity_public = c.array::<32>()?;
        let store_key = c.array::<32>()?;
        let relay = c.short_text()?;
        let data_dir = c.short_text()?;
        let n = usize::from(c.u16()?);
        let mut contacts = Vec::new();
        for _ in 0..n {
            contacts.push(c.array::<32>()?);
        }
        let config = Config {
            identity_secret,
            identity_public,
            store_key,
            relay,
            data_dir,
            contacts,
            delivery_window_secs: c.u32()?,
            publish_timeout_ms: c.u32()?,
            poll_ms: c.u32()?,
            start_timeout_secs: c.u32()?,
            tor_bridges: c.short_text()?,
        };
        c.done().then_some(config)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod config_tests {
    use super::*;

    fn config(bridges: &str) -> Config {
        Config {
            identity_secret: [1; 32],
            identity_public: [2; 32],
            store_key: [3; 32],
            relay: "wss://relay.example".into(),
            data_dir: "d".into(),
            contacts: vec![[4; 32]],
            delivery_window_secs: 900,
            publish_timeout_ms: 1000,
            poll_ms: 100,
            start_timeout_secs: 10,
            tor_bridges: bridges.into(),
        }
    }

    /// Tor bridges cross in the start-up message as they were given; none
    /// is an empty text; more than the message carries does not cross.
    #[test]
    fn tor_bridges_cross_in_the_start_up_message() {
        let lines = "obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=abc iat-mode=0\n198.51.100.25:443 7DD62766BF2052432051D7B7E08A22F7E34A4543";
        let wire = config(lines).encode().unwrap();
        assert_eq!(Config::decode(&wire).map(|c| c.tor_bridges.clone()), Some(lines.to_string()));
        assert_eq!(Config::decode(&config("").encode().unwrap()).map(|c| c.tor_bridges.clone()), Some(String::new()));
        assert_ne!(wire, config("").encode().unwrap());
        assert!(config(&"a".repeat(70_000)).encode().is_none());
        // every byte is accounted for, and another version is not read
        assert!(Config::decode(wire.split_last().unwrap().1).is_none());
        let mut longer = wire.clone();
        longer.push(0);
        assert!(Config::decode(&longer).is_none());
        let mut other = wire;
        *other.first_mut().unwrap() = VERSION.wrapping_add(1);
        assert!(Config::decode(&other).is_none());
    }
}
