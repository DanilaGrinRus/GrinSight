//! How Tor is reached: directly or through bridges (decision of the
//! author, 24.11: obfs4 and Snowflake, the bridges at hand in a couple of
//! clicks).
//!
//! The window only writes down the user's choice: a file of bridge lines
//! next to the profile folder, named to the wallet process, which hands
//! its text to every process that uses Tor. Those processes read and check
//! the lines for real; what is checked here is only that a line looks like
//! a bridge line, so that a slip is said at once and not at the next
//! start. No file, or a file without lines, is "directly".
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Name of the file, next to the profile folder.
pub(crate) const FILE: &str = "tor-bridges.txt";
/// Bridges taken at once, and the longest line: the bounds of the
/// processes that read them.
pub(crate) const MAX_LINES: usize = 32;
pub(crate) const MAX_LINE: usize = 2048;

/// The built-in bridges of Tor Browser, as the Tor Expert Bundle has them.
const BUILT_IN: &str = include_str!("../tor/pt_config.json");
/// The first line of the file says which choice wrote it.
const HEAD: &str = "# GrinSight: ";

/// The user's choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// The ordinary way, no bridges.
    Direct,
    /// The built-in obfs4 bridges.
    Obfs4,
    /// Snowflake.
    Snowflake,
    /// Lines the user gave.
    Own,
}

impl Mode {
    /// The choice by its number in the window.
    pub(crate) fn of(index: i32) -> Option<Mode> {
        match index {
            0 => Some(Mode::Direct),
            1 => Some(Mode::Obfs4),
            2 => Some(Mode::Snowflake),
            3 => Some(Mode::Own),
            _ => None,
        }
    }

    /// Its number in the window.
    pub(crate) fn index(self) -> i32 {
        match self {
            Mode::Direct => 0,
            Mode::Obfs4 => 1,
            Mode::Snowflake => 2,
            Mode::Own => 3,
        }
    }

    fn word(self) -> &'static str {
        match self {
            Mode::Direct => "direct",
            Mode::Obfs4 => "obfs4",
            Mode::Snowflake => "snowflake",
            Mode::Own => "own",
        }
    }
}

/// Why the user's lines are not taken. `usize` is the number of the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnError {
    /// No line at all.
    Empty,
    /// More than [`MAX_LINES`].
    TooMany,
    /// A line longer than [`MAX_LINE`].
    TooLong(usize),
    /// A line that does not look like a bridge line.
    NotABridge(usize),
}

/// The built-in bridges of one kind (`obfs4`, `snowflake`).
pub(crate) fn built_in(kind: &str) -> Vec<String> {
    let Ok(all) = serde_json::from_str::<serde_json::Value>(BUILT_IN) else { return Vec::new() };
    let lines = all.get("bridges").and_then(|b| b.get(kind)).and_then(|k| k.as_array()).cloned().unwrap_or_default();
    lines.iter().filter_map(|l| l.as_str()).filter(|l| looks_like_a_bridge(l)).map(str::to_string).collect()
}

/// Whether a line has the shape of a bridge line: an optional word
/// `Bridge`, an optional transport name, `address:port`, a fingerprint of
/// 40 hexadecimal digits, then `key=value` words. Plain characters only.
pub(crate) fn looks_like_a_bridge(line: &str) -> bool {
    if !line.bytes().all(|b| b == b' ' || b.is_ascii_graphic()) {
        return false;
    }
    let mut words = line.split(' ').filter(|w| !w.is_empty()).peekable();
    if words.peek().is_some_and(|w| w.eq_ignore_ascii_case("bridge")) {
        words.next();
    }
    let Some(mut word) = words.next() else { return false };
    if word.parse::<SocketAddr>().is_err() {
        // a transport name, then the address
        let named = word.bytes().enumerate().all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()));
        if !named {
            return false;
        }
        match words.next() {
            Some(next) => word = next,
            None => return false,
        }
    }
    if word.parse::<SocketAddr>().is_err() {
        return false;
    }
    let Some(print) = words.next() else { return false };
    if print.len() != 40 || !print.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    words.all(|w| w.split_once('=').is_some_and(|(key, _)| !key.is_empty()))
}

/// The user's lines, tidied: one bridge a line, nothing else. Empty lines
/// and lines that begin with `#` are dropped.
pub(crate) fn check_own(text: &str) -> Result<Vec<String>, OwnError> {
    let mut lines = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let number = n.saturating_add(1);
        if lines.len() >= MAX_LINES {
            return Err(OwnError::TooMany);
        }
        if line.len() > MAX_LINE {
            return Err(OwnError::TooLong(number));
        }
        if !looks_like_a_bridge(line) {
            return Err(OwnError::NotABridge(number));
        }
        lines.push(line.to_string());
    }
    if lines.is_empty() {
        return Err(OwnError::Empty);
    }
    Ok(lines)
}

/// The text of the file for a choice: its first line names the choice, the
/// bridges follow. For "directly" there is nothing to write.
pub(crate) fn file_text(mode: Mode, own: &str) -> Result<String, OwnError> {
    let lines = match mode {
        Mode::Direct => return Ok(String::new()),
        Mode::Obfs4 => built_in("obfs4"),
        Mode::Snowflake => built_in("snowflake"),
        Mode::Own => check_own(own)?,
    };
    if lines.is_empty() {
        return Err(OwnError::Empty);
    }
    Ok(format!("{HEAD}{}\n{}\n", mode.word(), lines.join("\n")))
}

/// What a file says: the choice, and the user's own lines when it is
/// theirs. A file with bridges and no first line of ours is the user's own.
pub(crate) fn read_text(text: &str) -> (Mode, String) {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    if lines.is_empty() {
        return (Mode::Direct, String::new());
    }
    let named = text.lines().next().and_then(|first| first.trim().strip_prefix(HEAD));
    match named {
        Some("obfs4") if lines == built_in("obfs4") => (Mode::Obfs4, String::new()),
        Some("snowflake") if lines == built_in("snowflake") => (Mode::Snowflake, String::new()),
        _ => (Mode::Own, lines.join("\n")),
    }
}

/// The file for the wallet whose profile folder is `profile`.
pub(crate) fn file(profile: &Path) -> Option<PathBuf> {
    Some(profile.parent()?.join(FILE))
}

/// Writes the choice down. "Directly" leaves a file without lines: the
/// wallet process takes no file and an empty one the same way.
pub(crate) fn save(path: &Path, mode: Mode, own: &str) -> Result<Result<(), OwnError>, std::io::Error> {
    let text = match file_text(mode, own) {
        Ok(text) => text,
        Err(e) => return Ok(Err(e)),
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, text)?;
    Ok(Ok(()))
}

/// The choice that is written down at `path`; "directly" when nothing is.
pub(crate) fn load(path: &Path) -> (Mode, String) {
    match std::fs::read(path) {
        Ok(bytes) if bytes.len() <= 60_000 => read_text(&String::from_utf8_lossy(&bytes)),
        // too long a file is not ours; shown as the user's own, to be put right
        Ok(_) => (Mode::Own, String::new()),
        Err(_) => (Mode::Direct, String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBFS4: &str = "obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=YXJlIGZyZXF1ZW50bHkgZnVsbCBvZiBsaXR0bGUgbWVzc2FnZXMgeW91IGNhbiBmaW5kLg iat-mode=0";
    const PLAIN: &str = "198.51.100.25:443 7DD62766BF2052432051D7B7E08A22F7E34A4543";

    #[test]
    fn the_built_in_bridges_are_those_of_the_bundle() {
        // the file of Tor Expert Bundle 16.0.1, unchanged
        assert_eq!(BUILT_IN.len(), 2668);
        let (obfs4, snowflake) = (built_in("obfs4"), built_in("snowflake"));
        assert_eq!((obfs4.len(), snowflake.len()), (7, 2));
        assert!(obfs4.iter().all(|l| l.starts_with("obfs4 ") && l.contains(" cert=") && l.contains(" iat-mode=")));
        assert!(snowflake.iter().all(|l| l.starts_with("snowflake ") && l.contains(" url=https://") && l.contains(" ice=stun:")));
        assert!(built_in("no-such-kind").is_empty());
        // no line of the lists names a program to start
        assert!(obfs4.iter().chain(snowflake.iter()).all(|l| !l.contains("exec") && !l.contains("ClientTransportPlugin")));
    }

    #[test]
    fn a_line_is_told_from_what_is_not_a_bridge_line() {
        for good in [OBFS4, PLAIN, "Bridge 198.51.100.25:443 7DD62766BF2052432051D7B7E08A22F7E34A4543", "webtunnel [2001:db8::1]:443 7DD62766BF2052432051D7B7E08A22F7E34A4543 url=https://example.org/path ver=0.0.1"] {
            assert!(looks_like_a_bridge(good), "{good}");
        }
        for bad in [
            "",
            "hello",
            "obfs4",
            "obfs4 192.0.2.55:38114",
            "192.0.2.55 7DD62766BF2052432051D7B7E08A22F7E34A4543",
            "198.51.100.25:443 7DD62766BF2052432051D7B7E08A22F7E34A45",
            "198.51.100.25:443 7DD62766BF2052432051D7B7E08A22F7E34A454Z",
            "198.51.100.25:443 7DD62766BF2052432051D7B7E08A22F7E34A4543 loose",
            "ClientTransportPlugin obfs4 exec /bin/sh",
            "4bad 198.51.100.25:443 7DD62766BF2052432051D7B7E08A22F7E34A4543",
            "198.51.100.25:443 7DD62766BF2052432051D7B7E08A22F7E34A4543 мост=1",
            "198.51.100.25:443\t7DD62766BF2052432051D7B7E08A22F7E34A4543",
        ] {
            assert!(!looks_like_a_bridge(bad), "{bad}");
        }
    }

    #[test]
    fn the_users_lines_are_tidied_or_refused_with_the_number_of_the_line() {
        let text = format!("# from the site\n\n  {OBFS4}  \r\n{PLAIN}\n");
        assert_eq!(check_own(&text), Ok(vec![OBFS4.to_string(), PLAIN.to_string()]));
        assert_eq!(check_own(""), Err(OwnError::Empty));
        assert_eq!(check_own("# nothing\n\n"), Err(OwnError::Empty));
        assert_eq!(check_own(&format!("{PLAIN}\nnot a bridge\n{PLAIN}")), Err(OwnError::NotABridge(2)));
        let long = format!("{PLAIN} x={}", "a".repeat(MAX_LINE));
        assert_eq!(check_own(&format!("{PLAIN}\n\n{long}")), Err(OwnError::TooLong(3)));
        assert_eq!(check_own(&vec![PLAIN; MAX_LINES].join("\n")).map(|l| l.len()), Ok(MAX_LINES));
        assert_eq!(check_own(&vec![PLAIN; MAX_LINES.saturating_add(1)].join("\n")), Err(OwnError::TooMany));
    }

    #[test]
    fn a_choice_is_written_down_and_read_back() {
        assert_eq!(file_text(Mode::Direct, "anything"), Ok(String::new()));
        assert_eq!(read_text(""), (Mode::Direct, String::new()));
        assert_eq!(read_text("# GrinSight: obfs4\n"), (Mode::Direct, String::new()));
        for mode in [Mode::Obfs4, Mode::Snowflake] {
            let text = file_text(mode, "").unwrap_or_default();
            assert!(text.starts_with("# GrinSight: "));
            assert_eq!(read_text(&text), (mode, String::new()));
            assert_eq!(Mode::of(mode.index()), Some(mode));
        }
        assert_eq!(file_text(Mode::Obfs4, "").map(|t| t.lines().count()), Ok(8));
        assert_eq!(file_text(Mode::Snowflake, "").map(|t| t.lines().count()), Ok(3));
        let own = file_text(Mode::Own, &format!("{PLAIN}\n{OBFS4}")).unwrap_or_default();
        assert_eq!(read_text(&own), (Mode::Own, format!("{PLAIN}\n{OBFS4}")));
        assert_eq!(file_text(Mode::Own, "no"), Err(OwnError::NotABridge(1)));
        // a file somebody changed by hand is shown as the user's own lines
        let changed = format!("# GrinSight: obfs4\n{PLAIN}\n");
        assert_eq!(read_text(&changed), (Mode::Own, PLAIN.to_string()));
        assert_eq!(read_text(PLAIN), (Mode::Own, PLAIN.to_string()));
        assert_eq!(Mode::of(4), None);
        assert_eq!(Mode::of(-1), None);
    }

    #[test]
    fn the_file_is_next_to_the_profile_and_directly_leaves_it_without_lines() {
        let base = std::env::temp_dir().join(format!("fly-ui-tor-{}", std::process::id()));
        let path = file(&base.join("profile")).unwrap_or_default();
        assert_eq!(path, base.join(FILE));
        assert_eq!(load(&path), (Mode::Direct, String::new()));
        assert!(matches!(save(&path, Mode::Snowflake, ""), Ok(Ok(()))));
        assert_eq!(load(&path), (Mode::Snowflake, String::new()));
        // a refused choice changes nothing
        assert!(matches!(save(&path, Mode::Own, "not a bridge"), Ok(Err(OwnError::NotABridge(1)))));
        assert_eq!(load(&path), (Mode::Snowflake, String::new()));
        assert!(matches!(save(&path, Mode::Own, PLAIN), Ok(Ok(()))));
        assert_eq!(load(&path), (Mode::Own, PLAIN.to_string()));
        assert!(matches!(save(&path, Mode::Direct, ""), Ok(Ok(()))));
        assert_eq!(std::fs::read_to_string(&path).unwrap_or_else(|_| "?".into()), "");
        assert_eq!(load(&path), (Mode::Direct, String::new()));
    }
}
