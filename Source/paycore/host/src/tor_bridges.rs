//! Tor bridges the user chose, as the host hands them to the processes
//! that use Tor (the chain process, the message transport, the address
//! process).
//!
//! The host does not know what a bridge line is and has no Tor in it: it
//! reads the file named by `--tor-bridges` and passes its text on in the
//! start-up message of each process, which reads and checks the lines.
//! The file is read anew at every start of a process, so a change is taken
//! up when a process is next started.
//!
//! One thing is the host's to keep: a file that is there and cannot be
//! used is never the same as no file. No file means "no bridges"; a file
//! that cannot be read, is too long or is not text is passed on as
//! [`UNUSABLE`], which is not a bridge line, so the processes refuse to
//! start Tor instead of reaching it directly against the user's choice.
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Longest file taken, in bytes: what the start-up message carries.
pub const MAX_FILE: usize = 60_000;
/// What is passed on for a file that is there and cannot be used.
pub const UNUSABLE: &str = "unusable";

static FILE: OnceLock<PathBuf> = OnceLock::new();

/// Names the file, once, at start.
pub(crate) fn set_file(path: PathBuf) {
    let _ = FILE.set(path);
}

/// The text to pass on now: nothing when no file was named.
pub fn text() -> String {
    FILE.get().map(|path| read(path)).unwrap_or_default()
}

/// The text of the file `path` to pass on: nothing when there is no such
/// file, [`UNUSABLE`] when it is there and cannot be used.
pub fn read(path: &Path) -> String {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return String::new(),
        Err(_) => return UNUSABLE.to_string(),
    };
    let limit = u64::try_from(MAX_FILE).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    if file.take(limit).read_to_end(&mut bytes).is_err() || bytes.len() > MAX_FILE {
        return UNUSABLE.to_string();
    }
    match String::from_utf8(bytes) {
        // the start-up message carries plain text only
        Ok(text) if !text.contains('\0') => text,
        _ => UNUSABLE.to_string(),
    }
}

/// How many lines of `text` are bridge lines to the eye: not empty and
/// not a remark. For the interface; the processes do the real reading.
pub fn count(text: &str) -> usize {
    text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).count()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fly-host-bridges-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn no_file_is_no_bridges_and_a_file_is_passed_on_as_it_is() {
        let dir = temp("plain");
        let file = dir.join("tor-bridges.txt");
        assert_eq!(read(&file), "");
        let lines = "# mine\nobfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=abc iat-mode=0\n\n198.51.100.25:443 7DD62766BF2052432051D7B7E08A22F7E34A4543\n";
        std::fs::write(&file, lines).unwrap();
        assert_eq!(read(&file), lines);
        assert_eq!(count(&read(&file)), 2);
        std::fs::write(&file, "").unwrap();
        assert_eq!(read(&file), "");
        assert_eq!(count(""), 0);
    }

    #[test]
    fn a_file_that_cannot_be_used_is_never_taken_for_no_bridges() {
        let dir = temp("unusable");
        // a folder in the file's place
        assert_eq!(read(&dir), UNUSABLE);
        let file = dir.join("tor-bridges.txt");
        std::fs::write(&file, "a".repeat(MAX_FILE)).unwrap();
        assert_eq!(read(&file).len(), MAX_FILE);
        std::fs::write(&file, "a".repeat(MAX_FILE.saturating_add(1))).unwrap();
        assert_eq!(read(&file), UNUSABLE);
        std::fs::write(&file, [0xff, 0xfe, 0x00]).unwrap();
        assert_eq!(read(&file), UNUSABLE);
        std::fs::write(&file, "obfs4\0x").unwrap();
        assert_eq!(read(&file), UNUSABLE);
        // what is passed on then is not empty and is one line that no
        // reader of bridge lines takes
        assert_eq!(count(UNUSABLE), 1);
        assert!(!UNUSABLE.is_empty() && !UNUSABLE.contains(' '));
    }
}
