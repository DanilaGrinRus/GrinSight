//! The wallet host and the chain process share one durable network-bound startup preference.
use std::{fs, io, path::Path};

const INTENTS: [(u8, &str); 3] = [
    (1, "genesis-main-v1.intent"),
    (2, "genesis-test-v1.intent"),
    (3, "genesis-automated-v1.intent"),
];

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the saved genesis verification choice is damaged or belongs to another network",
    )
}

/// Check the persisted choice. An unreadable, incorrectly typed or cross-network
/// marker must never route a previously autonomous wallet to a release point.
pub fn selected(folder: &Path, network: u8) -> io::Result<bool> {
    if !INTENTS.iter().any(|&(tag, _)| tag == network) {
        return Err(invalid());
    }
    let mut found = false;
    for (tag, name) in INTENTS {
        match fs::symlink_metadata(folder.join(name)) {
            Ok(file) if tag == network && file.is_file() && file.len() == 0 => found = true,
            Ok(_) => return Err(invalid()),
            Err(why) if why.kind() == io::ErrorKind::NotFound => {}
            Err(why) => return Err(why),
        }
    }
    Ok(found)
}

/// Atomically schedule the next startup in this chain directory. The filename
/// binds the network and version; the marker is intentionally empty, so no
/// intermediate partially written value exists, including on portable media.
pub fn schedule(folder: &Path, network: u8) -> io::Result<()> {
    if selected(folder, network)? {
        return Ok(());
    }
    let (_, name) = INTENTS
        .iter()
        .find(|&&(tag, _)| tag == network)
        .ok_or_else(invalid)?;
    fs::create_dir_all(folder)?;
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(folder.join(name))
    {
        Ok(_) => {}
        Err(why) if why.kind() == io::ErrorKind::AlreadyExists => {}
        Err(why) => return Err(why),
    }
    if selected(folder, network)? {
        Ok(())
    } else {
        Err(invalid())
    }
}
