//! Tor bridges for the Tor clients of GrinSight (the chain process, the
//! message transport, the address process).
//!
//! A bridge is a Tor relay that is not in the public list; a pluggable
//! transport (obfs4, Snowflake, ...) hides that the traffic is Tor at all.
//! The user picks bridges in the window; here the picked lines are checked
//! and bounded and put into an Arti configuration.
//!
//! Two things are fixed here and never come from outside:
//!
//! * the program that speaks the transports is the one that stands next to
//!   the process's own program ([`program_beside`]); no line and no setting
//!   names a program to start;
//! * once bridges are given, Tor is reached through them only. A bridge
//!   that does not answer is a failure to connect, never a reason to go to
//!   the public relays directly.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Bridges taken at once. The built-in obfs4 list of Tor Browser is about
/// a dozen lines.
pub const MAX_LINES: usize = 32;
/// Longest line, in bytes. A Snowflake line is under a thousand.
pub const MAX_LINE: usize = 2048;
/// Longest text of bridge lines taken at once, in bytes: what one start-up
/// message of a helper process carries.
pub const MAX_TEXT: usize = 60_000;

/// Why the bridges cannot be used. Names no line: a line may hold what the
/// user would rather not see in a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeError {
    /// More lines than [`MAX_LINES`].
    TooMany,
    /// A line longer than [`MAX_LINE`].
    TooLong,
    /// A line with characters a bridge line never has.
    NotPlain,
    /// A line that is not a bridge line.
    NotABridge,
    /// A transport is asked for and its program is not next to this one.
    NoProgram,
    /// Arti did not take the configuration.
    Refused,
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            BridgeError::TooMany => "too many bridge lines",
            BridgeError::TooLong => "a bridge line is too long",
            BridgeError::NotPlain => "a bridge line has characters it cannot have",
            BridgeError::NotABridge => "a line is not a bridge line",
            BridgeError::NoProgram => "the program for Tor bridges is not next to this one",
            BridgeError::Refused => "Tor did not take the bridges",
        })
    }
}

/// Bridge lines that passed the checks, in the user's order. Empty means
/// "no bridges": Tor is reached the ordinary way.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct TorBridges {
    lines: Vec<String>,
}

impl std::fmt::Debug for TorBridges {
    /// The count only: the lines stay out of logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TorBridges({})", self.lines.len())
    }
}

/// The transport a line asks for, or nothing for a bridge reached plainly.
fn transport_of(line: &str) -> Option<&str> {
    let mut words = line.split_ascii_whitespace();
    let mut first = words.next()?;
    if first.eq_ignore_ascii_case("bridge") {
        first = words.next()?;
    }
    if first.parse::<SocketAddr>().is_ok() {
        return None;
    }
    Some(first)
}

impl TorBridges {
    /// No bridges.
    pub fn none() -> TorBridges {
        TorBridges::default()
    }

    /// Reads bridge lines, one a line. Empty lines and lines that begin
    /// with `#` are skipped. Every other line has to be a bridge line as
    /// Tor writes them, with or without the leading word `Bridge`.
    pub fn parse(text: &str) -> Result<TorBridges, BridgeError> {
        if text.len() > MAX_TEXT {
            return Err(BridgeError::TooLong);
        }
        let mut lines = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if lines.len() >= MAX_LINES {
                return Err(BridgeError::TooMany);
            }
            if line.len() > MAX_LINE {
                return Err(BridgeError::TooLong);
            }
            if !line.bytes().all(|b| b == b' ' || b.is_ascii_graphic()) {
                return Err(BridgeError::NotPlain);
            }
            if line.parse::<BridgeConfigBuilder>().is_err() {
                return Err(BridgeError::NotABridge);
            }
            lines.push(line.to_string());
        }
        Ok(TorBridges { lines })
    }

    /// Whether there are no bridges.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// How many bridges there are.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// The lines, one a line, as [`TorBridges::parse`] reads them back.
    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    /// The transports the lines ask for, each once.
    pub fn transports(&self) -> BTreeSet<String> {
        self.lines.iter().filter_map(|l| transport_of(l)).map(str::to_string).collect()
    }

    /// Puts the bridges into `config`. With no bridges nothing changes.
    /// With bridges Tor is told to use them and nothing else, and to start
    /// `program` for the transports they ask for; a transport without the
    /// program is an error here, before anything connects.
    pub fn apply(&self, config: &mut TorClientConfigBuilder, program: &Path) -> Result<(), BridgeError> {
        if self.lines.is_empty() {
            return Ok(());
        }
        let transports = self.transports();
        if !transports.is_empty() && !program.is_file() {
            return Err(BridgeError::NoProgram);
        }
        for line in &self.lines {
            let bridge: BridgeConfigBuilder = line.parse().map_err(|_| BridgeError::NotABridge)?;
            config.bridges().bridges().push(bridge);
        }
        // bridges or nothing: never the public relays directly
        config.bridges().enabled(tor_config::BoolOrAuto::Explicit(true));
        if !transports.is_empty() {
            let mut names = Vec::new();
            for name in &transports {
                names.push(name.parse().map_err(|_| BridgeError::NotABridge)?);
            }
            let mut transport = TransportConfigBuilder::default();
            // the path is taken as it is, never as Arti's variables
            transport.protocols(names).path(CfgPath::new_literal(program)).run_on_startup(false);
            config.bridges().transports().push(transport);
        }
        Ok(())
    }
}

/// Name of the pluggable transport program as the packages carry it.
#[cfg(target_os = "android")]
pub const PROGRAM: &str = "liblyrebird.so";
/// Name of the pluggable transport program as the packages carry it.
#[cfg(all(windows, not(target_os = "android")))]
pub const PROGRAM: &str = "lyrebird.exe";
/// Name of the pluggable transport program as the packages carry it.
#[cfg(all(not(windows), not(target_os = "android")))]
pub const PROGRAM: &str = "lyrebird";

/// Where the pluggable transport program is looked for: next to the
/// program `own`, under the fixed name [`PROGRAM`].
pub fn program_beside(own: &Path) -> Option<PathBuf> {
    Some(own.parent()?.join(PROGRAM))
}

/// The pluggable transport program next to this process's own program.
/// A path that leads nowhere when the process cannot say where it is: then
/// a transport is refused with [`BridgeError::NoProgram`].
pub fn own_program() -> PathBuf {
    std::env::current_exe().ok().and_then(|own| program_beside(&own)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Made-up bridges in the shape of real ones (documentation addresses).
    const OBFS4: &str = "obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=YXJlIGZyZXF1ZW50bHkgZnVsbCBvZiBsaXR0bGUgbWVzc2FnZXMgeW91IGNhbiBmaW5kLg iat-mode=0";
    const SNOWFLAKE: &str = "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://broker.example/ fronts=front.example ice=stun:stun.example:3478 utls-imitate=hellorandomizedalpn";
    const PLAIN: &str = "198.51.100.25:443 7DD62766BF2052432051D7B7E08A22F7E34A4543";

    fn built(config: &TorClientConfigBuilder) -> bool {
        config.clone().build().is_ok()
    }

    fn here() -> PathBuf {
        // any file that is there stands in for the program
        std::env::current_exe().unwrap_or_default()
    }

    #[test]
    fn lines_are_read_as_tor_writes_them() {
        let text = format!("# mine\n\n  Bridge {OBFS4}  \r\n{SNOWFLAKE}\n{PLAIN}\n");
        let b = TorBridges::parse(&text);
        assert!(b.is_ok());
        let b = b.unwrap_or_default();
        assert_eq!(b.len(), 3);
        assert_eq!(b.transports().into_iter().collect::<Vec<_>>(), vec!["obfs4".to_string(), "snowflake".to_string()]);
        // what is kept reads back as the same bridges
        assert_eq!(TorBridges::parse(&b.text()), Ok(b.clone()));
        assert!(TorBridges::parse("").unwrap_or_default().is_empty());
        assert!(TorBridges::parse("# nothing\n\n").unwrap_or_default().is_empty());
        assert_eq!(TorBridges::none().len(), 0);
    }

    #[test]
    fn what_is_not_a_bridge_line_is_refused_whole() {
        for bad in [
            "hello",
            "obfs4",
            "obfs4 192.0.2.55:38114",
            "obfs4 192.0.2.55:38114 nothex cert=x",
            "ClientTransportPlugin obfs4 exec /bin/sh",
            "192.0.2.55",
        ] {
            assert_eq!(TorBridges::parse(bad), Err(BridgeError::NotABridge), "{bad}");
            // one bad line spoils the lot: no half of a list is used
            assert_eq!(TorBridges::parse(&format!("{PLAIN}\n{bad}")), Err(BridgeError::NotABridge), "{bad}");
        }
        assert_eq!(TorBridges::parse(&format!("{PLAIN} \u{1}")), Err(BridgeError::NotPlain));
        assert_eq!(TorBridges::parse(&format!("{PLAIN} мост")), Err(BridgeError::NotPlain));
        assert_eq!(TorBridges::parse(&format!("{PLAIN}\tx=1")), Err(BridgeError::NotPlain));
    }

    #[test]
    fn the_count_and_the_length_are_bounded() {
        let many = vec![PLAIN; MAX_LINES].join("\n");
        assert_eq!(TorBridges::parse(&many).map(|b| b.len()), Ok(MAX_LINES));
        assert_eq!(TorBridges::parse(&format!("{many}\n{PLAIN}")), Err(BridgeError::TooMany));
        let pad = MAX_LINE.saturating_sub(OBFS4.len()).saturating_sub(3);
        let long = format!("{OBFS4} x={}", "a".repeat(pad));
        assert_eq!(long.len(), MAX_LINE);
        assert!(TorBridges::parse(&long).is_ok());
        assert_eq!(TorBridges::parse(&format!("{long}a")), Err(BridgeError::TooLong));
        // the whole text is bounded too, whatever it is made of
        assert!(TorBridges::parse(&"\n".repeat(MAX_TEXT)).is_ok());
        assert_eq!(TorBridges::parse(&"\n".repeat(MAX_TEXT.saturating_add(1))), Err(BridgeError::TooLong));
    }

    #[test]
    fn no_bridges_leave_the_configuration_alone() {
        let mut config = TorClientConfigBuilder::default();
        assert_eq!(TorBridges::none().apply(&mut config, Path::new("")), Ok(()));
        let made = config.build();
        assert!(made.is_ok());
        assert_eq!(format!("{:?}", made.ok().map(|c| format!("{c:?}").contains("192.0.2."))), "Some(false)");
    }

    #[test]
    fn bridges_go_into_the_configuration_with_the_program_beside() {
        let b = TorBridges::parse(&format!("{OBFS4}\n{SNOWFLAKE}\n{PLAIN}")).unwrap_or_default();
        let mut config = TorClientConfigBuilder::default();
        assert_eq!(b.apply(&mut config, &here()), Ok(()));
        assert!(built(&config));
        let shown = format!("{config:?}");
        // bridges are insisted on, and one program serves both transports
        assert!(shown.contains("Explicit(true)"), "{shown}");
        assert!(shown.contains("obfs4") && shown.contains("snowflake"));
        assert_eq!(shown.matches("TransportConfigBuilder").count(), 1, "{shown}");
    }

    #[test]
    fn a_transport_without_its_program_is_refused_before_anything_connects() {
        let b = TorBridges::parse(OBFS4).unwrap_or_default();
        let mut config = TorClientConfigBuilder::default();
        let nowhere = Path::new("no-such-folder").join(PROGRAM);
        assert_eq!(b.apply(&mut config, &nowhere), Err(BridgeError::NoProgram));
        assert_eq!(b.apply(&mut config, Path::new("")), Err(BridgeError::NoProgram));
        // a folder is not a program
        assert_eq!(b.apply(&mut config, &std::env::temp_dir()), Err(BridgeError::NoProgram));
        // a bridge reached plainly needs no program
        let plain = TorBridges::parse(PLAIN).unwrap_or_default();
        let mut config = TorClientConfigBuilder::default();
        assert_eq!(plain.apply(&mut config, &nowhere), Ok(()));
        assert!(built(&config));
        assert!(!format!("{config:?}").contains("TransportConfigBuilder {"));
    }

    #[test]
    fn the_program_is_the_one_next_to_this_one_under_a_fixed_name() {
        let own = Path::new("some").join("where").join("fly-chain");
        assert_eq!(program_beside(&own), Some(Path::new("some").join("where").join(PROGRAM)));
        assert_eq!(program_beside(Path::new("")), None);
        assert_eq!(own_program().file_name().and_then(|n| n.to_str()), Some(PROGRAM));
        assert!(PROGRAM.contains("lyrebird"));
    }

    #[test]
    fn the_lines_stay_out_of_what_is_printed() {
        let b = TorBridges::parse(&format!("{OBFS4}\n{PLAIN}")).unwrap_or_default();
        assert_eq!(format!("{b:?}"), "TorBridges(2)");
        for e in [BridgeError::TooMany, BridgeError::TooLong, BridgeError::NotPlain, BridgeError::NotABridge, BridgeError::NoProgram, BridgeError::Refused] {
            let said = e.to_string();
            assert!(!said.is_empty() && !said.contains("192.0.2") && !said.contains("cert="));
        }
    }
}
