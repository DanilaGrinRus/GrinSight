//! Slatepack text as a file: the wallet's own folder `slatepack`, next to
//! the profile folder (decision of the author, 24.11: no system file
//! window, one folder of the wallet's own).
//!
//! What is saved is the text the window shows, nothing else. What is read
//! is anybody's file: only a regular file of this folder, of a bounded
//! size, and its text goes the same way as pasted text - the wallet reads
//! and checks it; nothing here decides what it is.
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Name of the folder, next to the profile folder.
pub(crate) const FOLDER: &str = "slatepack";
/// Largest file read, in bytes. A Slatepack text is a few kilobytes.
pub(crate) const MAX_FILE: u64 = 256 * 1024;
/// Files offered at once, the newest first.
pub(crate) const MAX_LISTED: usize = 12;

/// Why a file was not written or read. The words name no path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileError {
    /// There is no text to save.
    Empty,
    /// The folder cannot be made or used.
    Folder,
    /// The file could not be written.
    Write,
    /// The file is gone, is not a plain file or could not be read.
    Read,
    /// The file is larger than a Slatepack text can be.
    Large,
    /// The file is not text.
    NotText,
}

/// The folder for Slatepack files of the wallet whose profile folder is
/// `profile`.
pub(crate) fn folder(profile: &Path) -> Option<PathBuf> {
    Some(profile.parent()?.join(FOLDER))
}

/// The civil date and time of a moment, UTC: year, month, day, hour,
/// minute, second.
fn civil(secs: u64) -> (i64, i64, i64, u64, u64, u64) {
    let days = i64::try_from(secs.checked_div(86_400).unwrap_or(0)).unwrap_or(0);
    let rest = secs.checked_rem(86_400).unwrap_or(0);
    // days since 1970-01-01 to a date of the Gregorian calendar
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = doe
        .saturating_sub(doe.div_euclid(1_460))
        .saturating_add(doe.div_euclid(36_524))
        .saturating_sub(doe.div_euclid(146_096))
        .div_euclid(365);
    let doy = doe.saturating_sub(yoe.saturating_mul(365).saturating_add(yoe.div_euclid(4)).saturating_sub(yoe.div_euclid(100)));
    let mp = doy.saturating_mul(5).saturating_add(2).div_euclid(153);
    let day = doy.saturating_sub(mp.saturating_mul(153).saturating_add(2).div_euclid(5)).saturating_add(1);
    let month = if mp < 10 { mp.saturating_add(3) } else { mp.saturating_sub(9) };
    let year = yoe.saturating_add(era.saturating_mul(400)).saturating_add(i64::from(month <= 2));
    (year, month, day, rest.checked_div(3_600).unwrap_or(0), rest.checked_rem(3_600).unwrap_or(0).checked_div(60).unwrap_or(0), rest.checked_rem(60).unwrap_or(0))
}

/// The name a text saved at `secs` (seconds since 1970, UTC) gets.
pub(crate) fn name_at(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = civil(secs);
    format!("slatepack-{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}.txt")
}

fn plain_dir(dir: &Path) -> Result<(), FileError> {
    match std::fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(FileError::Folder),
    }
    let meta = std::fs::symlink_metadata(dir).map_err(|_| FileError::Folder)?;
    if !meta.file_type().is_dir() {
        return Err(FileError::Folder);
    }
    Ok(())
}

/// Save `text` as a new file of `dir`. Nothing is ever written over.
pub(crate) fn save(dir: &Path, text: &str, now: SystemTime) -> Result<PathBuf, FileError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(FileError::Empty);
    }
    plain_dir(dir)?;
    let secs = now.duration_since(SystemTime::UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs();
    // two texts in one second: the next second's name, and so on
    for step in 0..60u64 {
        let path = dir.join(name_at(secs.saturating_add(step)));
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                use std::io::Write;
                return file.write_all(text.as_bytes()).and_then(|()| file.write_all(b"\n")).map(|()| path).map_err(|_| FileError::Write);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(FileError::Write),
        }
    }
    Err(FileError::Write)
}

fn offered(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.ends_with(".txt") || lower.ends_with(".slatepack")
}

/// The files of `dir` a text can be taken from: plain files with the
/// endings `.txt` and `.slatepack`, not larger than [`MAX_FILE`], the
/// newest first, [`MAX_LISTED`] at most.
pub(crate) fn list(dir: &Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<(SystemTime, String, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let path = entry.path();
            // a link is not followed
            let meta = std::fs::symlink_metadata(&path).ok()?;
            (meta.file_type().is_file() && meta.len() <= MAX_FILE && offered(&name)).then(|| (meta.modified().unwrap_or(SystemTime::UNIX_EPOCH), name, path))
        })
        .collect();
    found.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    found.into_iter().take(MAX_LISTED).map(|(_, name, path)| (name, path)).collect()
}

/// The text of a file, for the box a text is pasted into.
pub(crate) fn load(path: &Path) -> Result<String, FileError> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| FileError::Read)?;
    if !meta.file_type().is_file() {
        return Err(FileError::Read);
    }
    if meta.len() > MAX_FILE {
        return Err(FileError::Large);
    }
    let bytes = std::fs::read(path).map_err(|_| FileError::Read)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE {
        return Err(FileError::Large);
    }
    String::from_utf8(bytes).map(|text| text.trim().to_string()).map_err(|_| FileError::NotText)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("fly-files-{tag}-{nanos}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn names_carry_the_date_and_time() {
        assert_eq!(name_at(0), "slatepack-19700101-000000.txt");
        // 2026-11-24 07:12:05 UTC
        assert_eq!(name_at(1_795_504_325), "slatepack-20261124-071205.txt");
        // a leap day and the last second of a year
        assert_eq!(name_at(1_709_208_000), "slatepack-20240229-120000.txt");
        assert_eq!(name_at(1_735_689_599), "slatepack-20241231-235959.txt");
    }

    #[test]
    fn the_folder_is_next_to_the_profile() {
        assert_eq!(folder(Path::new("/data/profile")), Some(PathBuf::from("/data/slatepack")));
        assert_eq!(folder(Path::new("/")), None);
    }

    /// A text is saved as a new file and read back the same; nothing is
    /// written over, an empty text is not saved.
    #[test]
    fn a_text_is_saved_as_a_new_file_and_read_back() {
        let dir = temp("save").join(FOLDER);
        let now = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(1_795_504_325)).unwrap();
        let first = save(&dir, "  BEGINSLATEPACK. one. ENDSLATEPACK.\n", now).unwrap();
        assert_eq!(first.file_name().unwrap(), "slatepack-20261124-071205.txt");
        assert_eq!(load(&first).unwrap(), "BEGINSLATEPACK. one. ENDSLATEPACK.");
        // the same second again: another file, the first is as it was
        let second = save(&dir, "BEGINSLATEPACK. two. ENDSLATEPACK.", now).unwrap();
        assert_eq!(second.file_name().unwrap(), "slatepack-20261124-071206.txt");
        assert_eq!(load(&first).unwrap(), "BEGINSLATEPACK. one. ENDSLATEPACK.");
        assert_eq!(save(&dir, " \n ", now), Err(FileError::Empty));
        assert_eq!(list(&dir).len(), 2);
        // a file where the folder should be
        let other = temp("blocked");
        std::fs::write(other.join(FOLDER), b"x").unwrap();
        assert_eq!(save(&other.join(FOLDER), "text", now), Err(FileError::Folder));
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
        let _ = std::fs::remove_dir_all(&other);
    }

    /// Only plain text files of a bounded size are offered and read, the
    /// newest first; a folder, a huge file, another ending and bytes that
    /// are not text are not taken.
    #[test]
    fn only_plain_bounded_text_files_are_offered() {
        let dir = temp("list");
        let old = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(1_000_000)).unwrap();
        for (name, body) in [("a.txt", "A"), ("b.SLATEPACK", "B"), ("c.exe", "C"), ("d.txt.bak", "D")] {
            std::fs::write(dir.join(name), body).unwrap();
        }
        std::fs::File::options().write(true).open(dir.join("a.txt")).unwrap().set_modified(old).unwrap();
        std::fs::create_dir(dir.join("folder.txt")).unwrap();
        std::fs::write(dir.join("huge.txt"), vec![b'x'; usize::try_from(MAX_FILE).unwrap().saturating_add(1)]).unwrap();
        std::fs::write(dir.join("binary.txt"), [0xff, 0xfe, 0x00]).unwrap();
        let names: Vec<String> = list(&dir).into_iter().map(|(name, _)| name).collect();
        assert_eq!(names.len(), 3, "{names:?}");
        assert_eq!(names.last().map(String::as_str), Some("a.txt"), "the oldest is last");
        assert!(names.contains(&"b.SLATEPACK".to_string()) && names.contains(&"binary.txt".to_string()));
        assert_eq!(load(&dir.join("a.txt")).as_deref(), Ok("A"));
        assert_eq!(load(&dir.join("binary.txt")), Err(FileError::NotText));
        assert_eq!(load(&dir.join("huge.txt")), Err(FileError::Large));
        assert_eq!(load(&dir.join("folder.txt")), Err(FileError::Read));
        assert_eq!(load(&dir.join("missing.txt")), Err(FileError::Read));
        // no more than the bound are offered
        for n in 0..20 {
            std::fs::write(dir.join(format!("more-{n}.txt")), "M").unwrap();
        }
        assert_eq!(list(&dir).len(), MAX_LISTED);
        assert!(list(&dir.join("nowhere")).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A link is not a file of the folder: it is neither offered nor
    /// followed, wherever it leads.
    #[cfg(unix)]
    #[test]
    fn a_link_is_neither_offered_nor_followed() {
        let dir = temp("link");
        let outside = temp("link-target").join("secret.txt");
        std::fs::write(&outside, "elsewhere").unwrap();
        let link = dir.join("link.txt");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        // the link does lead to a text
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "elsewhere");
        assert!(list(&dir).is_empty());
        assert_eq!(load(&link), Err(FileError::Read));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
