//! Research create-only store for encrypted incoming and outgoing records.
//! The caller must provide a trusted, stable directory and stable ancestors.
//! This does not defend against directory swaps, rollback or loss of directory
//! updates after power loss; it is not yet a production or payment queue.
use std::{fs::{self, OpenOptions}, io::{Read, Write}, path::{Path, PathBuf}};
use super::{contact_session::PreparedMessage, queue_record::{self, QueueIdentity, QueueKey, MAX_RECORD}};
use nostr_sdk::Event;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError { InvalidRecord, BeforePublication, Indeterminate, Capacity, Busy }

const MAX_DIRECTORY_ENTRIES: usize = 8192;
const MAX_INBOX_ENTRIES: usize = 512;
const MAX_INBOX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_OUTBOX_ENTRIES: usize = 512;
const MAX_OUTBOX_BYTES: u64 = 64 * 1024 * 1024;

pub(super) fn safe_metadata(md: &fs::Metadata) -> bool {
    if md.file_type().is_symlink() { return false; }
    #[cfg(windows)] {
        use std::os::windows::fs::MetadataExt;
        if md.file_attributes() & 0x400 != 0 { return false; }
    }
    true
}
pub(super) fn check_dir(dir: &Path) -> Result<(), StoreError> {
    let md = fs::symlink_metadata(dir).map_err(|_| StoreError::BeforePublication)?;
    if !safe_metadata(&md) || !md.is_dir() { return Err(StoreError::BeforePublication); }
    Ok(())
}
fn target(dir: &Path, identity: &QueueIdentity) -> Result<PathBuf, StoreError> {
    if identity.slot.iter().all(|x| *x == 0) { return Err(StoreError::InvalidRecord); }
    let name: String = identity.slot.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(dir.join(format!("out-{name}.flyq")))
}
fn ack_target(dir: &Path, identity: &QueueIdentity) -> Result<PathBuf, StoreError> {
    if identity.slot.iter().all(|x| *x == 0) { return Err(StoreError::InvalidRecord); }
    let name: String = identity.slot.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(dir.join(format!("ack-{name}.flyq")))
}
fn incoming_target(dir: &Path, identity: &QueueIdentity) -> Result<PathBuf, StoreError> {
    if identity.slot.iter().all(|x| *x == 0) { return Err(StoreError::InvalidRecord); }
    let name: String = identity.slot.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(dir.join(format!("in-{name}.flyi")))
}

/// Bounded discovery only: slots are untrusted file-name hints. Every record
/// must still be opened with the right wallet/contact key and reauthenticated.
/// A full or malformed directory fails rather than returning a partial list.
pub fn discover_incoming(dir: &Path) -> Result<Vec<[u8; 16]>, StoreError> {
    discover_incoming_bounded(dir, MAX_DIRECTORY_ENTRIES, MAX_INBOX_ENTRIES)
}

/// Find possible outgoing records after a restart. Names are only untrusted
/// hints: the caller must recover the authenticated operation context and open
/// each record with its own key before retrying. Concurrent writers may add a
/// record after this scan; a later scan is required. This is not a scheduler.
pub fn discover_outgoing(dir: &Path) -> Result<Vec<[u8; 16]>, StoreError> {
    discover_outgoing_bounded(dir, MAX_DIRECTORY_ENTRIES, MAX_INBOX_ENTRIES)
}

fn discover_outgoing_bounded(dir: &Path, max_directory: usize, max_outgoing: usize) -> Result<Vec<[u8; 16]>, StoreError> {
    check_dir(dir)?;
    let mut count = 0usize;
    let mut slots = Vec::new();
    for entry in fs::read_dir(dir).map_err(|_| StoreError::InvalidRecord)? {
        count = count.checked_add(1).ok_or(StoreError::InvalidRecord)?;
        if count > max_directory { return Err(StoreError::InvalidRecord); }
        let entry = entry.map_err(|_| StoreError::InvalidRecord)?;
        let os_name = entry.file_name();
        let name = os_name.to_str().ok_or(StoreError::InvalidRecord)?;
        if !name.to_ascii_lowercase().starts_with("out-") { continue; }
        let hex = name.strip_prefix("out-").and_then(|v| v.strip_suffix(".flyq"))
            .filter(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            .ok_or(StoreError::InvalidRecord)?;
        if slots.len() >= max_outgoing { return Err(StoreError::InvalidRecord); }
        let md = fs::symlink_metadata(entry.path()).map_err(|_| StoreError::InvalidRecord)?;
        if !safe_metadata(&md) || !md.is_file() || md.len() < 48 || md.len() > MAX_RECORD as u64 {
            return Err(StoreError::InvalidRecord);
        }
        let mut slot = [0u8; 16];
        for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            let value = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            slot[i] = value(pair[0]) * 16 + value(pair[1]);
        }
        if slot.iter().all(|b| *b == 0) { return Err(StoreError::InvalidRecord); }
        slots.push(slot);
    }
    slots.sort_unstable();
    Ok(slots)
}

fn discover_incoming_bounded(dir: &Path, max_directory: usize, max_inbox: usize) -> Result<Vec<[u8; 16]>, StoreError> {
    check_dir(dir)?;
    let mut count = 0usize;
    let mut slots = Vec::new();
    for entry in fs::read_dir(dir).map_err(|_| StoreError::InvalidRecord)? {
        count = count.checked_add(1).ok_or(StoreError::InvalidRecord)?;
        if count > max_directory { return Err(StoreError::InvalidRecord); }
        let entry = entry.map_err(|_| StoreError::InvalidRecord)?;
        let os_name = entry.file_name();
        let name = os_name.to_str().ok_or(StoreError::InvalidRecord)?;
        let folded = name.to_ascii_lowercase();
        if !folded.starts_with("in-") && !folded.ends_with(".flyi") { continue; }
        let hex = name.strip_prefix("in-").and_then(|v| v.strip_suffix(".flyi"))
            .filter(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            .ok_or(StoreError::InvalidRecord)?;
        if slots.len() >= max_inbox { return Err(StoreError::InvalidRecord); }
        let md = fs::symlink_metadata(entry.path()).map_err(|_| StoreError::InvalidRecord)?;
        if !safe_metadata(&md) || !md.is_file() || md.len() < 48 || md.len() > MAX_RECORD as u64 {
            return Err(StoreError::InvalidRecord);
        }
        let mut slot = [0u8; 16];
        for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            let value = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            slot[i] = value(pair[0]) * 16 + value(pair[1]);
        }
        if slot.iter().all(|b| *b == 0) { return Err(StoreError::InvalidRecord); }
        slots.push(slot);
    }
    slots.sort_unstable();
    Ok(slots)
}
pub(super) fn read_options() -> OpenOptions {
    let mut options = OpenOptions::new(); options.read(true);
    #[cfg(windows)] {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    #[cfg(any(target_os = "linux", target_os = "android"))] {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x2_0000 | 0x800); // O_NOFOLLOW | O_NONBLOCK
    }
    options
}

/// Create an encrypted record once: stage, sync file, then create-only link.
/// An indeterminate result requires inspecting the existing slot, never creating
/// a new event blindly. Publication does not imply durable directory metadata.
pub fn persist(dir: &Path, key: &QueueKey, identity: &QueueIdentity, prepared: &PreparedMessage, now: u64)
    -> Result<(), StoreError> {
    persist_inner(dir, key, identity, prepared, now, || {}, || {})
}

/// Publish a single encrypted S1 binding and reply in the create-only slot.
/// The caller must validate and authenticate the request before generating the
/// reply. An indeterminate result requires readback, never a second signature.
pub fn persist_bound_reply(dir: &Path, key: &QueueKey, identity: &QueueIdentity,
    slate_id: &[u8; 16], request: &str, prepared: &PreparedMessage, now: u64) -> Result<(), StoreError> {
    persist_bound_reply_inner(dir, key, identity, slate_id, request, prepared, now, || {}, || {})
}

/// Store an outgoing envelope and its encrypted recipient in one create-only
/// record. It is suitable for a reply to an unknown sender; it stores no S1.
pub fn persist_recoverable(dir: &Path, key: &QueueKey, identity: &QueueIdentity,
    prepared: &PreparedMessage, now: u64) -> Result<(), StoreError> {
    persist_recoverable_bounded(dir, key, identity, prepared, now, MAX_OUTBOX_ENTRIES, MAX_OUTBOX_BYTES)
}

fn persist_recoverable_bounded(dir: &Path, key: &QueueKey, identity: &QueueIdentity,
    prepared: &PreparedMessage, now: u64, max_entries: usize, max_bytes: u64) -> Result<(), StoreError> {
    persist_recoverable_bounded_inner(dir, key, identity, prepared, now, max_entries, max_bytes, || {}, || {})
}

/// Materialize the exact ciphertext previously committed with a sender reservation.
/// The caller must check that the operation is still authorized to publish.
/// An existing copy is accepted only if byte-identical to the authenticated journal.
pub fn restore_committed_outgoing(
    dir: &Path, key: &QueueKey, expected: &QueueIdentity, sealed: &[u8], now: u64,
) -> Result<(), StoreError> {
    if !sealed.starts_with(b"FLYR0001") { return Err(StoreError::InvalidRecord); }
    let (recovered, _) = queue_record::open_recoverable(
        key, expected.network, &expected.wallet_id, &expected.slot, expected.sender, sealed, now,
    ).map_err(|_| StoreError::InvalidRecord)?;
    if recovered.recipient != expected.recipient { return Err(StoreError::InvalidRecord); }
    check_dir(dir)?;
    let path = target(dir, expected)?;
    match persist_outbox_bytes(dir, &path, sealed, MAX_OUTBOX_ENTRIES, MAX_OUTBOX_BYTES, ".flyr-", || {}, || {}) {
        Err(StoreError::Indeterminate) => {
            if read_outgoing(dir, expected)?.as_slice() == sealed { Ok(()) } else { Err(StoreError::Indeterminate) }
        }
        outcome => outcome,
    }
}

fn persist_recoverable_bounded_inner(dir: &Path, key: &QueueKey, identity: &QueueIdentity,
    prepared: &PreparedMessage, now: u64, max_entries: usize, max_bytes: u64,
    after_sync: impl FnOnce(), after_link: impl FnOnce()) -> Result<(), StoreError> {
    check_dir(dir)?;
    let destination = target(dir, identity)?;
    let bytes = queue_record::seal_recoverable(key, identity, prepared, now)
        .map_err(|_| StoreError::InvalidRecord)?;
    persist_outbox_bytes(dir, &destination, &bytes, max_entries, max_bytes, ".flyr-", after_sync, after_link)
}

/// Save the outgoing reply bound to the authenticated source event. Stores no
/// incoming payment operation; the source ID is inside encrypted transport data.
pub fn persist_correlated_recoverable(dir: &Path, key: &QueueKey, identity: &QueueIdentity,
    prepared: &PreparedMessage, now: u64, source: &[u8;32]) -> Result<(), StoreError> {
    persist_correlated_inner(dir, key, identity, prepared, now, source, || {}, || {})
}

fn persist_correlated_inner(dir: &Path, key: &QueueKey, identity: &QueueIdentity,
    prepared: &PreparedMessage, now: u64, source: &[u8;32],
    after_sync: impl FnOnce(), after_link: impl FnOnce()) -> Result<(), StoreError> {
    check_dir(dir)?;
    let destination = target(dir, identity)?;
    let bytes = queue_record::seal_correlated_recoverable(key, identity, prepared, now, source)
        .map_err(|_| StoreError::InvalidRecord)?;
    persist_outbox_bytes(dir, &destination, &bytes, MAX_OUTBOX_ENTRIES, MAX_OUTBOX_BYTES, ".flyr-", after_sync, after_link)
}

fn persist_outbox_bytes(dir: &Path, destination: &Path, bytes: &[u8], max_entries: usize,
    max_bytes: u64, stage_prefix: &str, after_sync: impl FnOnce(), after_link: impl FnOnce()) -> Result<(), StoreError> {
    let _lock = outbox_lock(dir)?;
    match fs::symlink_metadata(destination) {
        Ok(_) => return Err(StoreError::Indeterminate),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(StoreError::BeforePublication),
    }
    let (count, used) = outbox_usage(dir)?;
    let needed = (bytes.len() as u64).checked_add(80).ok_or(StoreError::Capacity)?;
    if count >= max_entries || used.checked_add(needed).is_none_or(|total| total > max_bytes) {
        return Err(StoreError::Capacity);
    }
    publish_bytes(dir, destination, bytes, stage_prefix, after_sync, after_link)
}

fn persist_bound_reply_inner(dir: &Path, key: &QueueKey, identity: &QueueIdentity,
    slate_id: &[u8; 16], request: &str, prepared: &PreparedMessage, now: u64,
    after_sync: impl FnOnce(), after_link: impl FnOnce()) -> Result<(), StoreError> {
    check_dir(dir)?;
    let destination = target(dir, identity)?;
    let bytes = queue_record::seal_bound_reply(key, identity, slate_id, request, prepared, now)
        .map_err(|_| StoreError::InvalidRecord)?;
    persist_outbox_bytes(dir, &destination, &bytes, MAX_OUTBOX_ENTRIES, MAX_OUTBOX_BYTES, ".flyb-", after_sync, after_link)
}

/// Reopen the original reply only when the full request binding matches.
pub fn load_bound_reply(dir: &Path, key: &QueueKey, identity: &QueueIdentity,
    slate_id: &[u8; 16], request: &str, now: u64) -> Result<PreparedMessage, StoreError> {
    let bytes = read_outgoing(dir, identity)?;
    queue_record::open_bound_reply(key, identity, slate_id, request, &bytes, now)
        .map_err(|_| StoreError::InvalidRecord)
}

fn persist_inner(dir: &Path, key: &QueueKey, identity: &QueueIdentity, prepared: &PreparedMessage, now: u64,
    after_sync: impl FnOnce(), after_link: impl FnOnce()) -> Result<(), StoreError> {
    check_dir(dir)?;
    let destination = target(dir, identity)?;
    let bytes = queue_record::seal(key, identity, prepared, now).map_err(|_| StoreError::InvalidRecord)?;
    persist_outbox_bytes(dir, &destination, &bytes, MAX_OUTBOX_ENTRIES, MAX_OUTBOX_BYTES, ".flyq-", after_sync, after_link)
}

pub(super) fn publish_bytes(dir: &Path, destination: &Path, bytes: &[u8], stage_prefix: &str, after_sync: impl FnOnce(), after_link: impl FnOnce())
    -> Result<(), StoreError> {
    let mut after_sync = Some(after_sync);
    let mut after_link = Some(after_link);
    for _ in 0..16 {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).map_err(|_| StoreError::BeforePublication)?;
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let path = dir.join(format!("{stage_prefix}{suffix}.tmp"));
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(StoreError::BeforePublication),
        };
        file.write_all(bytes).map_err(|_| StoreError::BeforePublication)?;
        file.sync_all().map_err(|_| StoreError::BeforePublication)?;
        drop(file);
        after_sync.take().expect("single stage")();
        let result = fs::hard_link(&path, destination);
        if result.is_ok() { after_link.take().expect("single link")(); }
        // Only our unique encrypted stage is removed, under the trusted-directory
        // assumption. A crash may leave it behind; no automatic scanning/deletion.
        let _ = fs::remove_file(&path);
        return result.map_err(|_| StoreError::Indeterminate);
    }
    Err(StoreError::BeforePublication)
}

pub(super) fn persist_incoming(dir: &Path, key: &QueueKey, identity: &QueueIdentity, event: &Event)
    -> Result<(), StoreError> {
    persist_incoming_bounded(dir, key, identity, event, MAX_INBOX_ENTRIES, MAX_INBOX_BYTES)
}

// Cooperating processes lock the same stable file for inventory and publish.
// Caller must keep the directory/ancestors and lock file trusted and stable.
pub(super) fn inbox_lock(dir: &Path) -> Result<std::fs::File, StoreError> {
    directory_lock(dir, ".inbox.lock")
}
fn outbox_lock(dir: &Path) -> Result<std::fs::File, StoreError> {
    directory_lock(dir, ".outbox.lock")
}
fn directory_lock(dir: &Path, name: &str) -> Result<std::fs::File, StoreError> {
    let mut options = OpenOptions::new(); options.read(true).write(true).create(true);
    #[cfg(windows)] {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    #[cfg(any(target_os = "linux", target_os = "android"))] {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x2_0000 | 0x800); // O_NOFOLLOW | O_NONBLOCK
    }
    let file = options.open(dir.join(name)).map_err(|_| StoreError::BeforePublication)?;
    let md = file.metadata().map_err(|_| StoreError::BeforePublication)?;
    if !safe_metadata(&md) || !md.is_file() || md.len() != 0 { return Err(StoreError::BeforePublication); }
    file.try_lock().map_err(|_| StoreError::Busy)?;
    Ok(file)
}

// Counts all discovered outgoing records, reserves space for their ack, and
// conservatively counts existing ack files and encrypted leftover stages too.
// Only writers honoring outbox_lock are covered by the concurrency guarantee.
fn outbox_usage(dir: &Path) -> Result<(usize, u64), StoreError> {
    let slots = discover_outgoing(dir)?;
    let mut bytes = 0u64;
    for slot in &slots {
        let name: String = slot.iter().map(|b| format!("{b:02x}")).collect();
        let md = fs::symlink_metadata(dir.join(format!("out-{name}.flyq"))).map_err(|_| StoreError::InvalidRecord)?;
        if !safe_metadata(&md) || !md.is_file() { return Err(StoreError::InvalidRecord); }
        bytes = bytes.checked_add(md.len()).and_then(|n| n.checked_add(80)).ok_or(StoreError::Capacity)?;
    }
    let mut scanned = 0usize;
    for entry in fs::read_dir(dir).map_err(|_| StoreError::InvalidRecord)? {
        scanned += 1; if scanned > MAX_DIRECTORY_ENTRIES { return Err(StoreError::InvalidRecord); }
        let entry = entry.map_err(|_| StoreError::InvalidRecord)?;
        let os_name = entry.file_name(); let name = os_name.to_str().ok_or(StoreError::InvalidRecord)?;
        let lower = name.to_ascii_lowercase();
        if !lower.starts_with("ack-") && !lower.starts_with(".flyr-")
            && !lower.starts_with(".flyq-") && !lower.starts_with(".flyb-") { continue; }
        let (prefix, suffix) = if lower.starts_with("ack-") { ("ack-", ".flyq") }
            else if lower.starts_with(".flyr-") { (".flyr-", ".tmp") }
            else if lower.starts_with(".flyq-") { (".flyq-", ".tmp") } else { (".flyb-", ".tmp") };
        name.strip_prefix(prefix).and_then(|v| v.strip_suffix(suffix))
            .filter(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            .ok_or(StoreError::InvalidRecord)?;
        let md = fs::symlink_metadata(entry.path()).map_err(|_| StoreError::InvalidRecord)?;
        if !safe_metadata(&md) || !md.is_file() || md.len() > MAX_RECORD as u64 { return Err(StoreError::InvalidRecord); }
        bytes = bytes.checked_add(md.len()).ok_or(StoreError::Capacity)?;
    }
    Ok((slots.len(), bytes))
}

fn inbox_usage(dir: &Path) -> Result<(usize, u64), StoreError> {
    let slots = discover_incoming(dir)?;
    let mut bytes = 0u64;
    for slot in &slots {
        let name: String = slot.iter().map(|b| format!("{b:02x}")).collect();
        let md = fs::symlink_metadata(dir.join(format!("in-{name}.flyi"))).map_err(|_| StoreError::InvalidRecord)?;
        if !safe_metadata(&md) || !md.is_file() { return Err(StoreError::InvalidRecord); }
        bytes = bytes.checked_add(md.len()).ok_or(StoreError::Capacity)?;
    }
    // Leftover stages are encrypted, but still consume the quota. Never delete
    // them automatically: their publication outcome may be unknown.
    let mut scanned = 0usize;
    for entry in fs::read_dir(dir).map_err(|_| StoreError::InvalidRecord)? {
        scanned += 1;
        if scanned > MAX_DIRECTORY_ENTRIES { return Err(StoreError::InvalidRecord); }
        let entry = entry.map_err(|_| StoreError::InvalidRecord)?;
        let os_name = entry.file_name(); let name = os_name.to_str().ok_or(StoreError::InvalidRecord)?;
        if !name.to_ascii_lowercase().starts_with(".flyi-") { continue; }
        let suffix = name.strip_prefix(".flyi-").and_then(|v| v.strip_suffix(".tmp"))
            .filter(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            .ok_or(StoreError::InvalidRecord)?;
        let _ = suffix;
        let md = fs::symlink_metadata(entry.path()).map_err(|_| StoreError::InvalidRecord)?;
        if !safe_metadata(&md) || !md.is_file() || md.len() > MAX_RECORD as u64 { return Err(StoreError::InvalidRecord); }
        bytes = bytes.checked_add(md.len()).ok_or(StoreError::Capacity)?;
    }
    Ok((slots.len(), bytes))
}

fn persist_incoming_bounded(dir: &Path, key: &QueueKey, identity: &QueueIdentity, event: &Event,
    max_entries: usize, max_bytes: u64) -> Result<(), StoreError> {
    check_dir(dir)?;
    let path = incoming_target(dir, identity)?;
    let bytes = queue_record::seal_incoming(key, identity, event).map_err(|_| StoreError::InvalidRecord)?;
    let _lock = inbox_lock(dir)?;
    match fs::symlink_metadata(&path) {
        Ok(_) => return Err(StoreError::Indeterminate),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(StoreError::BeforePublication),
    }
    let (count, used) = inbox_usage(dir)?;
    if count >= max_entries || used.checked_add(bytes.len() as u64).is_none_or(|total| total > max_bytes) {
        return Err(StoreError::Capacity);
    }
    publish_bytes(dir, &path, &bytes, ".flyi-", || {}, || {})
}

pub(super) fn load_incoming(dir: &Path, key: &QueueKey, identity: &QueueIdentity) -> Result<Event, StoreError> {
    check_dir(dir)?;
    let path = incoming_target(dir, identity)?;
    let md = fs::symlink_metadata(&path).map_err(|_| StoreError::InvalidRecord)?;
    if !safe_metadata(&md) || !md.is_file() || md.len() > MAX_RECORD as u64 { return Err(StoreError::InvalidRecord); }
    let file = read_options().open(&path).map_err(|_| StoreError::InvalidRecord)?;
    let md = file.metadata().map_err(|_| StoreError::InvalidRecord)?;
    if !safe_metadata(&md) || !md.is_file() || md.len() > MAX_RECORD as u64 { return Err(StoreError::InvalidRecord); }
    let mut bytes = Vec::new();
    file.take((MAX_RECORD + 1) as u64).read_to_end(&mut bytes).map_err(|_| StoreError::InvalidRecord)?;
    queue_record::open_incoming(key, identity, &bytes).map_err(|_| StoreError::InvalidRecord)
}

/// A missing acknowledgement differs from a damaged or unauthenticated one.
pub(super) fn acknowledged(dir: &Path, key: &QueueKey, identity: &QueueIdentity, event: &PreparedMessage)
    -> Result<bool, StoreError> {
    acknowledged_id(dir, key, identity, event.event.id.as_bytes())
}

fn acknowledged_id(dir: &Path, key: &QueueKey, identity: &QueueIdentity, event_id: &[u8;32])
    -> Result<bool, StoreError> {
    check_dir(dir)?;
    let path = ack_target(dir, identity)?;
    let md = match fs::symlink_metadata(&path) {
        Ok(md) => md,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(StoreError::InvalidRecord),
    };
    if !safe_metadata(&md) || !md.is_file() || md.len() != 80 { return Err(StoreError::InvalidRecord); }
    let file = read_options().open(&path).map_err(|_| StoreError::InvalidRecord)?;
    let md = file.metadata().map_err(|_| StoreError::InvalidRecord)?;
    if !safe_metadata(&md) || !md.is_file() || md.len() != 80 { return Err(StoreError::InvalidRecord); }
    let mut bytes = Vec::new();
    file.take(81).read_to_end(&mut bytes).map_err(|_| StoreError::InvalidRecord)?;
    queue_record::verify_ack(key, identity, &bytes, event_id).map_err(|_| StoreError::InvalidRecord)?;
    Ok(true)
}

pub(super) fn mark_acknowledged(dir: &Path, key: &QueueKey, identity: &QueueIdentity, event: &PreparedMessage)
    -> Result<(), StoreError> {
    check_dir(dir)?;
    let _lock = outbox_lock(dir)?;
    let path = ack_target(dir, identity)?;
    if acknowledged(dir, key, identity, event)? { return Ok(()); }
    let out = fs::symlink_metadata(target(dir, identity)?).map_err(|_| StoreError::InvalidRecord)?;
    if !safe_metadata(&out) || !out.is_file() { return Err(StoreError::InvalidRecord); }
    let (_, used) = outbox_usage(dir)?;
    // outbox_usage reserves 80 bytes for an acknowledgement per record.
    if used > MAX_OUTBOX_BYTES { return Err(StoreError::Capacity); }
    let bytes = queue_record::seal_ack(key, identity, event.event.id.as_bytes()).map_err(|_| StoreError::InvalidRecord)?;
    match publish_bytes(dir, &path, &bytes, ".flyq-", || {}, || {}) {
        Ok(()) => Ok(()),
        Err(StoreError::Indeterminate) if acknowledged(dir, key, identity, event)? => Ok(()),
        Err(e) => Err(e),
    }
}

/// Reopen and authenticate the record; missing, corrupt and expired all fail.
fn read_outgoing(dir: &Path, identity: &QueueIdentity) -> Result<Vec<u8>, StoreError> {
    check_dir(dir)?;
    let path = target(dir, identity)?;
    let md = fs::symlink_metadata(&path).map_err(|_| StoreError::InvalidRecord)?;
    if !safe_metadata(&md) || !md.is_file() || md.len() > MAX_RECORD as u64 { return Err(StoreError::InvalidRecord); }
    let file = read_options().open(&path).map_err(|_| StoreError::InvalidRecord)?;
    let md = file.metadata().map_err(|_| StoreError::InvalidRecord)?;
    if !safe_metadata(&md) || !md.is_file() || md.len() > MAX_RECORD as u64 { return Err(StoreError::InvalidRecord); }
    let mut bytes = Vec::new();
    file.take((MAX_RECORD + 1) as u64).read_to_end(&mut bytes).map_err(|_| StoreError::InvalidRecord)?;
    Ok(bytes)
}

pub fn load(dir: &Path, key: &QueueKey, identity: &QueueIdentity, now: u64) -> Result<PreparedMessage, StoreError> {
    let bytes = read_outgoing(dir, identity)?;
    queue_record::open(key, identity, &bytes, now).map_err(|_| StoreError::InvalidRecord)
}

/// Recover an unknown recipient from the authenticated record, using only a
/// trusted wallet identity, local sender key and discovered slot. A missing,
/// expired or damaged record is an error, never an instruction to resend anew.
pub fn load_recoverable(dir: &Path, key: &QueueKey, network: queue_record::Network,
    wallet_id: &[u8; 32], slot: &[u8; 16], sender: nostr_sdk::PublicKey, now: u64)
    -> Result<(QueueIdentity, PreparedMessage), StoreError> {
    let lookup = QueueIdentity { network, wallet_id: *wallet_id, slot: *slot, sender, recipient: sender };
    let bytes = read_outgoing(dir, &lookup)?;
    queue_record::open_recoverable(key, network, wallet_id, slot, sender, &bytes, now)
        .map_err(|_| StoreError::InvalidRecord)
}

/// Reopen optional encrypted local history without creating a publishable
/// event. The caller must keep the returned text in trusted native memory.
pub fn load_recoverable_history(dir: &Path, key: &QueueKey, network: queue_record::Network,
    wallet_id: &[u8;32], slot: &[u8;16], sender: nostr_sdk::PublicKey)
    -> Result<(QueueIdentity, queue_record::OutgoingHistory), StoreError> {
    let lookup = QueueIdentity { network, wallet_id:*wallet_id, slot:*slot, sender, recipient:sender };
    let bytes = read_outgoing(dir, &lookup)?;
    queue_record::open_recoverable_history(key, network, wallet_id, slot, sender, &bytes)
        .map_err(|_| StoreError::InvalidRecord)
}

pub fn load_correlated_recoverable(dir: &Path, key: &QueueKey, network: queue_record::Network,
    wallet_id: &[u8;32], slot: &[u8;16], sender: nostr_sdk::PublicKey, source: &[u8;32], now: u64)
    -> Result<(QueueIdentity, PreparedMessage), StoreError> {
    let lookup = QueueIdentity { network, wallet_id: *wallet_id, slot: *slot, sender, recipient: sender };
    let bytes = read_outgoing(dir, &lookup)?;
    queue_record::open_correlated_recoverable(key, network, wallet_id, slot, sender, source, &bytes, now)
        .map_err(|_| StoreError::InvalidRecord)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageRecovery { Restored, AlreadyPresent }

/// Recover a single authenticated FLYR0002 stage after a process crash. The
/// original event must be re-presented and the same slot derived again. All
/// cooperating writers must honor outbox_lock; directory ancestry must stay
/// trusted. Zero or multiple matching stages fail closed. The encrypted stage
/// is retained; this cannot prove directory durability or defeat rollback.
pub fn recover_correlated_stage(dir: &Path, key: &QueueKey, identity: &QueueIdentity,
    source: &[u8;32], now: u64) -> Result<StageRecovery, StoreError> {
    check_dir(dir)?;
    if queue_record::incoming_event_reply_slot(key, identity.network, &identity.wallet_id, identity.sender, source)
        .map_err(|_| StoreError::InvalidRecord)? != identity.slot { return Err(StoreError::InvalidRecord); }
    let destination = target(dir, identity)?;
    let _lock = outbox_lock(dir)?;
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            let (stored, _) = load_correlated_recoverable(dir, key, identity.network, &identity.wallet_id,
                &identity.slot, identity.sender, source, now)?;
            return if stored.recipient == identity.recipient { Ok(StageRecovery::AlreadyPresent) }
                else { Err(StoreError::InvalidRecord) };
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(StoreError::BeforePublication),
    }
    let mut scanned = 0usize; let mut candidates = 0usize; let mut stage_bytes = 0u64;
    let mut matched: Option<PathBuf> = None;
    for entry in fs::read_dir(dir).map_err(|_| StoreError::InvalidRecord)? {
        scanned += 1; if scanned > MAX_DIRECTORY_ENTRIES { return Err(StoreError::InvalidRecord); }
        let entry = entry.map_err(|_| StoreError::InvalidRecord)?;
        let os_name = entry.file_name(); let name = os_name.to_str().ok_or(StoreError::InvalidRecord)?;
        if !name.to_ascii_lowercase().starts_with(".flyr-") { continue; }
        name.strip_prefix(".flyr-").and_then(|v| v.strip_suffix(".tmp"))
            .filter(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            .ok_or(StoreError::InvalidRecord)?;
        candidates += 1; if candidates > MAX_OUTBOX_ENTRIES { return Err(StoreError::Capacity); }
        let md = fs::symlink_metadata(entry.path()).map_err(|_| StoreError::InvalidRecord)?;
        if !safe_metadata(&md) || !md.is_file() || md.len() > MAX_RECORD as u64 { return Err(StoreError::InvalidRecord); }
        stage_bytes = stage_bytes.checked_add(md.len()).ok_or(StoreError::Capacity)?;
        if stage_bytes > MAX_OUTBOX_BYTES { return Err(StoreError::Capacity); }
        let file = read_options().open(entry.path()).map_err(|_| StoreError::InvalidRecord)?;
        let md = file.metadata().map_err(|_| StoreError::InvalidRecord)?;
        if !safe_metadata(&md) || !md.is_file() || md.len() > MAX_RECORD as u64 { return Err(StoreError::InvalidRecord); }
        let mut bytes = Vec::new(); file.take((MAX_RECORD + 1) as u64).read_to_end(&mut bytes).map_err(|_| StoreError::InvalidRecord)?;
        if let Ok((stored, _)) = queue_record::open_correlated_recoverable(key, identity.network, &identity.wallet_id,
            &identity.slot, identity.sender, source, &bytes, now) {
            if stored.recipient != identity.recipient || matched.is_some() { return Err(StoreError::Indeterminate); }
            matched = Some(entry.path());
        }
    }
    let path = matched.ok_or(StoreError::InvalidRecord)?;
    let (count, used) = outbox_usage(dir)?;
    let mut options = read_options(); options.write(true);
    let file = options.open(&path).map_err(|_| StoreError::InvalidRecord)?;
    let md = file.metadata().map_err(|_| StoreError::InvalidRecord)?;
    if !safe_metadata(&md) || !md.is_file() || md.len() > MAX_RECORD as u64 { return Err(StoreError::InvalidRecord); }
    let mut bytes = Vec::new(); (&file).take((MAX_RECORD + 1) as u64).read_to_end(&mut bytes).map_err(|_| StoreError::InvalidRecord)?;
    let (stored, _) = queue_record::open_correlated_recoverable(key, identity.network, &identity.wallet_id,
        &identity.slot, identity.sender, source, &bytes, now).map_err(|_| StoreError::InvalidRecord)?;
    if stored.recipient != identity.recipient { return Err(StoreError::InvalidRecord); }
    let needed = md.len().checked_add(80).ok_or(StoreError::Capacity)?;
    if count >= MAX_OUTBOX_ENTRIES || used.checked_add(needed).is_none_or(|n| n > MAX_OUTBOX_BYTES) { return Err(StoreError::Capacity); }
    file.sync_all().map_err(|_| StoreError::BeforePublication)?;
    fs::hard_link(&path, &destination).map_err(|_| StoreError::Indeterminate)?;
    Ok(StageRecovery::Restored)
}

/// Read explicitly retained local text even after network delivery expiry.
/// This returns no event suitable for publication.
pub fn load_history(dir: &Path, key: &QueueKey, identity: &QueueIdentity) -> Result<queue_record::OutgoingHistory, StoreError> {
    let bytes = read_outgoing(dir, identity)?;
    queue_record::open_history(key, identity, &bytes).map_err(|_| StoreError::InvalidRecord)
}

/// Relay acceptance is not proof of recipient delivery. Missing acknowledgement
/// is not proof of rejection: the send or the local acknowledgement write may
/// have completed without an observed response. Expiry is based on caller time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutgoingStatus {
    RelayAccepted { delivery_window_expired: bool },
    Unacknowledged { delivery_window_expired: bool },
}

/// Authenticated status and recipient, including after expiry. Relay acceptance
/// is not recipient delivery, and a damaged acknowledgement fails closed.
pub fn recoverable_status(dir: &Path, key: &QueueKey, network: queue_record::Network,
    wallet_id: &[u8; 32], slot: &[u8; 16], sender: nostr_sdk::PublicKey, now: u64)
    -> Result<(QueueIdentity, OutgoingStatus), StoreError> {
    let lookup = QueueIdentity { network, wallet_id: *wallet_id, slot: *slot, sender, recipient: sender };
    let bytes = read_outgoing(dir, &lookup)?;
    let (identity, metadata) = queue_record::recoverable_metadata(key, network, wallet_id, slot, sender, &bytes)
        .map_err(|_| StoreError::InvalidRecord)?;
    let expired = now >= metadata.expires_at;
    let status = if acknowledged_id(dir, key, &identity, metadata.event_id.as_bytes())? {
        OutgoingStatus::RelayAccepted { delivery_window_expired: expired }
    } else { OutgoingStatus::Unacknowledged { delivery_window_expired: expired } };
    Ok((identity, status))
}

/// Read-only status, including after expiry; it does not return publishable
/// event bytes or prevent replays after storage rollback.
pub fn outgoing_status(dir: &Path, key: &QueueKey, identity: &QueueIdentity, now: u64)
    -> Result<OutgoingStatus, StoreError> {
    let bytes = read_outgoing(dir, identity)?;
    let metadata = queue_record::open_metadata(key, identity, &bytes).map_err(|_| StoreError::InvalidRecord)?;
    let expired = now >= metadata.expires_at;
    if acknowledged_id(dir, key, identity, metadata.event_id.as_bytes())? {
        Ok(OutgoingStatus::RelayAccepted { delivery_window_expired:expired })
    } else {
        Ok(OutgoingStatus::Unacknowledged { delivery_window_expired:expired })
    }
}

/// Status remains readable after expiry, but a changed S1 or peer is rejected.
/// Relay acknowledgement is not recipient delivery or payment confirmation.
pub fn bound_reply_status(dir: &Path, key: &QueueKey, identity: &QueueIdentity,
    slate_id: &[u8; 16], request: &str, now: u64) -> Result<OutgoingStatus, StoreError> {
    let bytes = read_outgoing(dir, identity)?;
    let metadata = queue_record::open_bound_metadata(key, identity, slate_id, request, &bytes)
        .map_err(|_| StoreError::InvalidRecord)?;
    let expired = now >= metadata.expires_at;
    if acknowledged_id(dir, key, identity, metadata.event_id.as_bytes())? {
        Ok(OutgoingStatus::RelayAccepted { delivery_window_expired: expired })
    } else {
        Ok(OutgoingStatus::Unacknowledged { delivery_window_expired: expired })
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::{os::windows::fs::MetadataExt, sync::{Arc, Barrier}, time::Duration};
    use nostr_sdk::{Event, EventBuilder, JsonUtil, Keys, Kind, PublicKey, Tag, Timestamp};
    use super::super::queue_record::Network;
    fn directory() -> PathBuf {
        let root = PathBuf::from(std::env::var_os("FLY_ROOT").expect("FLY_ROOT required"));
        assert_eq!(fs::canonicalize(&root).unwrap(), fs::canonicalize(r"C:\DHW\GrinSight\FlyClient").unwrap());
        let tmp = root.join(".tmp");
        assert_eq!(fs::canonicalize(std::env::temp_dir()).unwrap(), fs::canonicalize(&tmp).unwrap());
        for p in [&root, &tmp] { assert_eq!(fs::symlink_metadata(p).unwrap().file_attributes() & 0x400, 0); }
        let mut random = [0u8; 16]; getrandom::getrandom(&mut random).unwrap();
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let dir = tmp.join(format!("fly-queue-store-test-{suffix}"));
        fs::create_dir(&dir).unwrap(); dir
    }

    #[test]
    fn inbox_discovery_is_bounded_and_rejects_suspicious_names() {
        let dir = directory();
        fs::write(dir.join("in-bad"), [0u8; 48]).unwrap();
        assert_eq!(discover_incoming(&dir), Err(StoreError::InvalidRecord));
        let clean = directory();
        fs::write(clean.join("in-01010101010101010101010101010101.flyi"), [0u8; 48]).unwrap();
        fs::write(clean.join("in-02020202020202020202020202020202.flyi"), [0u8; 48]).unwrap();
        fs::write(clean.join("unrelated"), b"test").unwrap();
        assert_eq!(discover_incoming_bounded(&clean, 3, 2).unwrap(), vec![[1; 16], [2; 16]]);
        assert_eq!(discover_incoming_bounded(&clean, 3, 1), Err(StoreError::InvalidRecord));
        assert_eq!(discover_incoming_bounded(&clean, 2, 2), Err(StoreError::InvalidRecord));
        let uppercase = directory();
        fs::write(uppercase.join("IN-01010101010101010101010101010101.FLYI"), [0u8; 48]).unwrap();
        assert_eq!(discover_incoming(&uppercase), Err(StoreError::InvalidRecord));
    }
    #[tokio::test]
    async fn outgoing_discovery_requires_authenticated_readback() {
        let dir = directory(); let (identity, prepared, _) = fixture().await;
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        persist(&dir, &key, &identity, &prepared, 1000).unwrap();
        fs::write(dir.join(".flyq-unfinished.tmp"), b"stage").unwrap();
        fs::write(dir.join("ack-unrelated.flyq"), b"ack").unwrap();
        assert_eq!(discover_outgoing(&dir).unwrap(), vec![identity.slot]);
        assert_eq!(outgoing_status(&dir, &key, &identity, 1000), Ok(OutgoingStatus::Unacknowledged { delivery_window_expired:false }));
        let other = QueueKey::derive(&[8; 32], &identity).unwrap();
        assert!(outgoing_status(&dir, &other, &identity, 1000).is_err());
        assert_eq!(discover_outgoing_bounded(&dir, 2, 5), Err(StoreError::InvalidRecord));
        assert_eq!(discover_outgoing_bounded(&dir, 3, 0), Err(StoreError::InvalidRecord));
        fs::write(dir.join("OUT-bad.flyq"), [0u8; 48]).unwrap();
        assert_eq!(discover_outgoing(&dir), Err(StoreError::InvalidRecord));
    }
    async fn fixture() -> (QueueIdentity, PreparedMessage, PreparedMessage) {
        let alice = Keys::generate(); let bob = Keys::generate();
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [7; 32], slot: [3; 16], sender: alice.public_key(), recipient: bob.public_key() };
        let rumor = EventBuilder::new(Kind::PrivateDirectMessage, "synthetic queue test")
            .tag(Tag::public_key(identity.recipient)).build(identity.sender);
        let event1 = EventBuilder::gift_wrap(&alice, &identity.recipient, rumor.clone(), [Tag::expiration(Timestamp::from(1900))]).await.unwrap();
        let event2 = EventBuilder::gift_wrap(&alice, &identity.recipient, rumor, [Tag::expiration(Timestamp::from(1900))]).await.unwrap();
        let prepared = |event| PreparedMessage { event, sender: identity.sender, recipient: identity.recipient, expires_at: 1900, local_history: None };
        (identity, prepared(event1), prepared(event2))
    }

    #[tokio::test]
    async fn committed_delivery_only_reopens_the_exact_record_in_its_window() {
        let dir = directory();
        let (id, first, second) = fixture().await;
        let key = QueueKey::derive(&[9; 32], &id).unwrap();
        let a = queue_record::seal_recoverable(&key, &id, &first, 1000).unwrap();
        let b = queue_record::seal_recoverable(&key, &id, &second, 1000).unwrap();
        let mut wrong = id;
        wrong.recipient = Keys::generate().public_key();
        assert_eq!(restore_committed_outgoing(&dir, &key, &wrong, &a, 1000), Err(StoreError::InvalidRecord));
        assert!(discover_outgoing(&dir).unwrap().is_empty());
        restore_committed_outgoing(&dir, &key, &id, &a, 1000).unwrap();
        restore_committed_outgoing(&dir, &key, &id, &a, 1001).unwrap();
        assert_eq!(restore_committed_outgoing(&dir, &key, &id, &b, 1002), Err(StoreError::Indeterminate));
        assert_eq!(restore_committed_outgoing(&dir, &key, &id, &a, 1900), Err(StoreError::InvalidRecord));
        assert!(read_outgoing(&dir, &id).unwrap() == a);
    }

    #[tokio::test]
    async fn outgoing_status_distinguishes_acknowledgement_and_expiry() {
        let dir = directory(); let (identity, mut prepared, _) = fixture().await;
        prepared.local_history = Some(zeroize::Zeroizing::new("synthetic queue test".to_owned()));
        let key = QueueKey::derive(&[9;32], &identity).unwrap();
        persist(&dir, &key, &identity, &prepared, 1000).unwrap();
        assert_eq!(outgoing_status(&dir, &key, &identity, 1000), Ok(OutgoingStatus::Unacknowledged { delivery_window_expired:false }));
        assert_eq!(outgoing_status(&dir, &key, &identity, 1900), Ok(OutgoingStatus::Unacknowledged { delivery_window_expired:true }));
        mark_acknowledged(&dir, &key, &identity, &prepared).unwrap();
        assert_eq!(outgoing_status(&dir, &key, &identity, 1000), Ok(OutgoingStatus::RelayAccepted { delivery_window_expired:false }));
        assert_eq!(outgoing_status(&dir, &key, &identity, 1900), Ok(OutgoingStatus::RelayAccepted { delivery_window_expired:true }));
        let other = QueueKey::derive(&[8;32], &identity).unwrap();
        assert!(outgoing_status(&dir, &other, &identity, 1900).is_err());
        let path = ack_target(&dir, &identity).unwrap();
        let mut bytes = fs::read(&path).unwrap(); let last=bytes.len()-1; bytes[last]^=1;
        fs::write(path, bytes).unwrap();
        assert!(outgoing_status(&dir, &key, &identity, 1900).is_err());
    }

    #[tokio::test]
    async fn incoming_quota_refuses_new_items_without_replacing_existing() {
        let dir = directory(); let (base, first, second) = fixture().await;
        let mut a = base; a.slot.copy_from_slice(&first.event.id.as_bytes()[..16]);
        let mut b = base; b.slot.copy_from_slice(&second.event.id.as_bytes()[..16]);
        assert_ne!(a.slot, b.slot);
        let key = QueueKey::derive(&[9; 32], &a).unwrap();
        assert_eq!(persist_incoming_bounded(&dir, &key, &a, &first.event, 1, MAX_INBOX_BYTES), Ok(()));
        assert_eq!(persist_incoming_bounded(&dir, &key, &b, &second.event, 1, MAX_INBOX_BYTES), Err(StoreError::Capacity));
        assert_eq!(load_incoming(&dir, &key, &a).unwrap().id, first.event.id);
        assert_eq!(discover_incoming(&dir).unwrap(), vec![a.slot]);
        assert_eq!(persist_incoming_bounded(&dir, &key, &a, &first.event, 1, MAX_INBOX_BYTES), Err(StoreError::Indeterminate));
        let busy = inbox_lock(&dir).unwrap();
        assert_eq!(persist_incoming_bounded(&dir, &key, &b, &second.event, 2, MAX_INBOX_BYTES), Err(StoreError::Busy));
        drop(busy);

        let staged = directory();
        fs::write(staged.join(".flyi-01010101010101010101010101010101.tmp"), [0u8; 100]).unwrap();
        assert_eq!(persist_incoming_bounded(&staged, &key, &b, &second.event, 2, 100), Err(StoreError::Capacity));
        assert!(discover_incoming(&staged).unwrap().is_empty());
    }

    #[tokio::test]
    async fn recoverable_outbox_quota_preserves_existing_and_counts_stages() {
        let dir = directory(); let (a, first, second) = fixture().await;
        let mut b = a; b.slot = [4;16];
        let key = QueueKey::derive(&[9;32], &a).unwrap();
        assert_eq!(persist_recoverable_bounded(&dir, &key, &a, &first, 1000, 1, MAX_OUTBOX_BYTES), Ok(()));
        assert_eq!(persist_recoverable_bounded(&dir, &key, &b, &second, 1000, 1, MAX_OUTBOX_BYTES), Err(StoreError::Capacity));
        assert_eq!(persist_recoverable_bounded(&dir, &key, &a, &second, 1000, 1, MAX_OUTBOX_BYTES), Err(StoreError::Indeterminate));
        assert_eq!(load_recoverable(&dir, &key, a.network, &a.wallet_id, &a.slot, a.sender, 1000).unwrap().1.event.id, first.event.id);
        let lock = outbox_lock(&dir).unwrap();
        assert_eq!(persist_recoverable_bounded(&dir, &key, &b, &second, 1000, 2, MAX_OUTBOX_BYTES), Err(StoreError::Busy));
        drop(lock);
        let staged = directory();
        fs::write(staged.join(".flyr-01010101010101010101010101010101.tmp"), [0u8;100]).unwrap();
        assert_eq!(persist_recoverable_bounded(&staged, &key, &b, &second, 1000, 2, 100), Err(StoreError::Capacity));
        assert!(discover_outgoing(&staged).unwrap().is_empty());
    }

    #[tokio::test]
    async fn all_outgoing_formats_share_the_same_capacity_boundary() {
        let dir = directory(); let (base, prepared, _) = fixture().await;
        let key = QueueKey::derive(&[9;32], &base).unwrap();
        for index in 1u16..=MAX_OUTBOX_ENTRIES as u16 {
            let mut slot = [0u8;16]; slot[14..].copy_from_slice(&index.to_be_bytes());
            let name: String = slot.iter().map(|b| format!("{b:02x}")).collect();
            fs::write(dir.join(format!("out-{name}.flyq")), [0u8;48]).unwrap();
        }
        let mut ordinary = base; ordinary.slot = [4;16];
        assert_eq!(persist(&dir, &key, &ordinary, &prepared, 1000), Err(StoreError::Capacity));
        let mut recoverable = base; recoverable.slot = [5;16];
        assert_eq!(persist_recoverable(&dir, &key, &recoverable, &prepared, 1000), Err(StoreError::Capacity));
        let mut bound = base; let slate_id = [10;16];
        bound.slot = queue_record::payment_operation_slot(&key, &bound, &slate_id, queue_record::PaymentStage::Standard1).unwrap();
        assert_eq!(persist_bound_reply(&dir, &key, &bound, &slate_id, "BEGINSLATEPACK. synthetic ENDSLATEPACK.", &prepared, 1000), Err(StoreError::Capacity));
        let mut correlated = base; correlated.slot = [6;16];
        assert_eq!(persist_correlated_recoverable(&dir, &key, &correlated, &prepared, 1000, &[0x51;32]), Err(StoreError::Capacity));
        assert_eq!(discover_outgoing(&dir).unwrap().len(), MAX_OUTBOX_ENTRIES);
    }

    #[tokio::test]
    async fn mixed_formats_cannot_both_take_last_slot_concurrently() {
        let dir = directory(); let (a, first, second) = fixture().await;
        let mut b = a; b.slot = [4;16];
        let key = QueueKey::derive(&[9;32], &a).unwrap();
        let ordinary = queue_record::seal(&key, &a, &first, 1000).unwrap();
        let correlated = queue_record::seal_correlated_recoverable(&key, &b, &second, 1000, &[0x51;32]).unwrap();
        let first_path = target(&dir, &a).unwrap(); let second_path = target(&dir, &b).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let results = std::thread::scope(|scope| {
            let first_barrier = barrier.clone(); let second_barrier = barrier.clone(); let d = &dir;
            let one = scope.spawn(move || { first_barrier.wait(); persist_outbox_bytes(d, &first_path, &ordinary, 1, MAX_OUTBOX_BYTES, ".flyq-", || {}, || {}) });
            let two = scope.spawn(move || { second_barrier.wait(); persist_outbox_bytes(d, &second_path, &correlated, 1, MAX_OUTBOX_BYTES, ".flyr-", || {}, || {}) });
            [one.join().unwrap(), two.join().unwrap()]
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| matches!(result, Err(StoreError::Busy | StoreError::Capacity))).count(), 1);
        assert_eq!(discover_outgoing(&dir).unwrap().len(), 1);
    }

    #[test]
    fn outbox_quota_child() {
        use std::io::Read;
        let Some(which) = std::env::var_os("FLY_OUTBOX_QUOTA_CHILD") else { return; };
        let which = which.to_str().unwrap(); assert!(matches!(which, "a" | "b"));
        let dir = PathBuf::from(std::env::var_os("FLY_OUTBOX_QUOTA_DIR").unwrap());
        let root = PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        assert_eq!(fs::canonicalize(dir.parent().unwrap()).unwrap(), fs::canonicalize(root.join(".tmp")).unwrap());
        assert!(dir.file_name().unwrap().to_string_lossy().starts_with("fly-queue-store-test-"));
        assert!(safe_metadata(&fs::symlink_metadata(&dir).unwrap()));
        let sender = PublicKey::parse(&std::env::var("FLY_OUTBOX_QUOTA_SENDER").unwrap()).unwrap();
        let recipient = PublicKey::parse(&std::env::var("FLY_OUTBOX_QUOTA_RECIPIENT").unwrap()).unwrap();
        let event = Event::from_json(std::env::var("FLY_OUTBOX_QUOTA_EVENT").unwrap()).unwrap();
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [7;32],
            slot: if which == "a" { [1;16] } else { [2;16] }, sender, recipient };
        let prepared = PreparedMessage { event, sender, recipient, expires_at:1900, local_history:None };
        let key = QueueKey::derive(&[9;32], &identity).unwrap();
        OpenOptions::new().write(true).create_new(true).open(dir.join(format!("outbox-ready-{which}"))).unwrap();
        let mut signal = [0u8;1]; std::io::stdin().read_exact(&mut signal).unwrap(); assert_eq!(signal, [1]);
        match persist_recoverable_bounded(&dir, &key, &identity, &prepared, 1000, 1, MAX_OUTBOX_BYTES) {
            Ok(()) => println!("SYNTHETIC_OUTBOX_STORED"),
            Err(StoreError::Busy | StoreError::Capacity) => println!("SYNTHETIC_OUTBOX_REFUSED"),
            Err(error) => panic!("unexpected synthetic outbox result: {error:?}"),
        }
    }

    #[tokio::test]
    async fn recoverable_outbox_quota_two_processes_do_not_overfill() {
        use std::{io::Write, process::{Command, Stdio}};
        let dir = directory(); let (base, first, second) = fixture().await;
        let mut children = Vec::new();
        for (which, item) in [("a", first), ("b", second)] {
            children.push(Command::new(std::env::current_exe().unwrap())
                .args(["nostr::queue_store::tests::outbox_quota_child", "--exact", "--nocapture", "--test-threads=1"])
                .env("FLY_OUTBOX_QUOTA_CHILD", which).env("FLY_OUTBOX_QUOTA_DIR", &dir)
                .env("FLY_OUTBOX_QUOTA_SENDER", base.sender.to_string())
                .env("FLY_OUTBOX_QUOTA_RECIPIENT", base.recipient.to_string())
                .env("FLY_OUTBOX_QUOTA_EVENT", item.event.as_json())
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap());
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !(dir.join("outbox-ready-a").exists() && dir.join("outbox-ready-b").exists()) {
            if std::time::Instant::now() >= deadline {
                for child in &mut children { let _ = child.kill(); let _ = child.wait(); }
                panic!("synthetic outbox children not ready");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        for child in &mut children { child.stdin.take().unwrap().write_all(&[1]).unwrap(); }
        let mut outputs = Vec::new();
        for mut child in children {
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            loop {
                if child.try_wait().unwrap().is_some() { break; }
                if std::time::Instant::now() >= deadline { let _ = child.kill(); let _ = child.wait(); panic!("synthetic outbox child timed out"); }
                std::thread::sleep(Duration::from_millis(20));
            }
            let output = child.wait_with_output().unwrap(); assert!(output.status.success());
            outputs.push(String::from_utf8_lossy(&output.stdout).into_owned());
        }
        assert_eq!(outputs.iter().filter(|out| out.contains("SYNTHETIC_OUTBOX_STORED")).count(), 1);
        assert_eq!(outputs.iter().filter(|out| out.contains("SYNTHETIC_OUTBOX_REFUSED")).count(), 1);
        assert_eq!(discover_outgoing(&dir).unwrap().len(), 1);
    }

    #[test]
    fn inbox_quota_child() {
        use std::io::Read;
        let Some(which) = std::env::var_os("FLY_INBOX_QUOTA_CHILD") else { return; };
        let which = which.to_str().unwrap(); assert!(matches!(which, "a" | "b"));
        let dir = PathBuf::from(std::env::var_os("FLY_INBOX_QUOTA_DIR").unwrap());
        let root = PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        assert_eq!(fs::canonicalize(&root).unwrap(), fs::canonicalize(r"C:\DHW\GrinSight\FlyClient").unwrap());
        assert_eq!(fs::canonicalize(dir.parent().unwrap()).unwrap(), fs::canonicalize(root.join(".tmp")).unwrap());
        assert!(dir.file_name().unwrap().to_string_lossy().starts_with("fly-queue-store-test-"));
        assert!(safe_metadata(&fs::symlink_metadata(&dir).unwrap()));
        let event = Event::from_json(std::env::var("FLY_INBOX_QUOTA_EVENT").unwrap()).unwrap();
        let sender = PublicKey::parse(&std::env::var("FLY_INBOX_QUOTA_SENDER").unwrap()).unwrap();
        let recipient = PublicKey::parse(&std::env::var("FLY_INBOX_QUOTA_RECIPIENT").unwrap()).unwrap();
        let mut slot = [0u8; 16]; slot.copy_from_slice(&event.id.as_bytes()[..16]);
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [7; 32], slot, sender, recipient };
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        OpenOptions::new().write(true).create_new(true).open(dir.join(format!("quota-ready-{which}"))).unwrap();
        let mut signal = [0u8; 1]; std::io::stdin().read_exact(&mut signal).unwrap(); assert_eq!(signal, [1]);
        match persist_incoming_bounded(&dir, &key, &identity, &event, 1, MAX_INBOX_BYTES) {
            Ok(()) => println!("SYNTHETIC_QUOTA_STORED"),
            Err(StoreError::Busy | StoreError::Capacity) => println!("SYNTHETIC_QUOTA_REFUSED"),
            Err(error) => panic!("unexpected synthetic quota result: {error:?}"),
        }
    }

    #[tokio::test]
    async fn incoming_quota_two_processes_do_not_overfill() {
        use std::{io::Write, process::{Command, Stdio}};
        let dir = directory(); let (base, first, second) = fixture().await;
        let mut children = Vec::new();
        for (which, item) in [("a", first), ("b", second)] {
            children.push(Command::new(std::env::current_exe().unwrap())
                .args(["nostr::queue_store::tests::inbox_quota_child", "--exact", "--nocapture", "--test-threads=1"])
                .env("FLY_INBOX_QUOTA_CHILD", which).env("FLY_INBOX_QUOTA_DIR", &dir)
                .env("FLY_INBOX_QUOTA_SENDER", base.sender.to_string())
                .env("FLY_INBOX_QUOTA_RECIPIENT", base.recipient.to_string())
                .env("FLY_INBOX_QUOTA_EVENT", item.event.as_json())
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap());
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !(dir.join("quota-ready-a").exists() && dir.join("quota-ready-b").exists()) {
            if std::time::Instant::now() >= deadline {
                for child in &mut children { let _ = child.kill(); let _ = child.wait(); }
                panic!("synthetic inbox children not ready");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        for child in &mut children { child.stdin.take().unwrap().write_all(&[1]).unwrap(); }
        let mut outputs = Vec::new();
        for mut child in children {
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            loop {
                if child.try_wait().unwrap().is_some() { break; }
                if std::time::Instant::now() >= deadline { let _ = child.kill(); let _ = child.wait(); panic!("synthetic inbox child timed out"); }
                std::thread::sleep(Duration::from_millis(20));
            }
            let output = child.wait_with_output().unwrap(); assert!(output.status.success());
            outputs.push(String::from_utf8_lossy(&output.stdout).into_owned());
        }
        assert_eq!(outputs.iter().filter(|out| out.contains("SYNTHETIC_QUOTA_STORED")).count(), 1);
        assert_eq!(outputs.iter().filter(|out| out.contains("SYNTHETIC_QUOTA_REFUSED")).count(), 1);
        assert_eq!(discover_incoming(&dir).unwrap().len(), 1);
    }
    #[tokio::test]
    async fn create_only_reopen_and_corruption_fail_closed() {
        let dir = directory(); let (identity, first, second) = fixture().await;
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        persist(&dir, &key, &identity, &first, 1000).unwrap();
        assert_eq!(load(&dir, &key, &identity, 1000).unwrap().event.id, first.event.id);
        assert_eq!(persist(&dir, &key, &identity, &second, 1000), Err(StoreError::Indeterminate));
        assert_eq!(load(&dir, &key, &identity, 1000).unwrap().event.id, first.event.id);
        let path = target(&dir, &identity).unwrap();
        let mut bytes = fs::read(&path).unwrap(); let last = bytes.len() - 1; bytes[last] ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(matches!(load(&dir, &key, &identity, 1000), Err(StoreError::InvalidRecord)));
    }
    #[tokio::test]
    async fn acknowledgement_is_bound_to_identity_and_event_and_corruption_fails() {
        let dir = directory(); let (identity, first, second) = fixture().await;
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        assert_eq!(acknowledged(&dir, &key, &identity, &first), Ok(false));
        assert_eq!(mark_acknowledged(&dir, &key, &identity, &first), Err(StoreError::InvalidRecord));
        persist(&dir, &key, &identity, &first, 1000).unwrap();
        mark_acknowledged(&dir, &key, &identity, &first).unwrap();
        assert_eq!(acknowledged(&dir, &key, &identity, &first), Ok(true));
        assert!(matches!(acknowledged(&dir, &key, &identity, &second), Err(StoreError::InvalidRecord)));
        assert!(mark_acknowledged(&dir, &key, &identity, &first).is_ok());
        let mut wrong = identity; wrong.sender = Keys::generate().public_key();
        assert!(matches!(acknowledged(&dir, &key, &wrong, &first), Err(StoreError::InvalidRecord)));
        let path = ack_target(&dir, &identity).unwrap();
        let mut bytes = fs::read(&path).unwrap(); bytes[79] ^= 1; fs::write(path, bytes).unwrap();
        assert!(matches!(acknowledged(&dir, &key, &identity, &first), Err(StoreError::InvalidRecord)));
    }
    #[tokio::test]
    async fn competing_writers_publish_at_most_one_complete_record() {
        let dir = directory(); let (identity, first, second) = fixture().await;
        let first_id = first.event.id; let second_id = second.event.id;
        let barrier = Arc::new(Barrier::new(2));
        let results = std::thread::scope(|scope| {
            let spawn = |item: PreparedMessage| {
                let b = barrier.clone(); let d = &dir; let i = identity;
                scope.spawn(move || {
                    let key = QueueKey::derive(&[9; 32], &i).unwrap();
                    b.wait(); persist(d, &key, &i, &item, 1000)
                })
            };
            let a = spawn(first); let b = spawn(second);
            [a.join().unwrap(), b.join().unwrap()]
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|r| matches!(r, Err(StoreError::Indeterminate | StoreError::Busy))).count(), 1);
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        let loaded = load(&dir, &key, &identity, 1000).unwrap().event.id;
        assert!(loaded == first_id || loaded == second_id);
    }

    #[test]
    fn reopen_child() {
        let Some(dir) = std::env::var_os("FLY_QUEUE_REOPEN_DIR") else { return; };
        let dir = PathBuf::from(dir);
        let root = PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        let tmp = root.join(".tmp");
        assert_eq!(fs::canonicalize(&root).unwrap(), fs::canonicalize(r"C:\DHW\GrinSight\FlyClient").unwrap());
        assert_eq!(fs::canonicalize(dir.parent().unwrap()).unwrap(), fs::canonicalize(&tmp).unwrap());
        assert!(dir.file_name().unwrap().to_string_lossy().starts_with("fly-queue-store-test-"));
        assert!(safe_metadata(&fs::symlink_metadata(&dir).unwrap()));
        let sender = PublicKey::parse(&std::env::var("FLY_QUEUE_TEST_SENDER").unwrap()).unwrap();
        let recipient = PublicKey::parse(&std::env::var("FLY_QUEUE_TEST_RECIPIENT").unwrap()).unwrap();
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [7; 32], slot: [3; 16], sender, recipient };
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        let recovered = load(&dir, &key, &identity, 1000).unwrap();
        assert_eq!(recovered.event.id.to_string(), std::env::var("FLY_QUEUE_TEST_EVENT").unwrap());
        if std::env::var("FLY_QUEUE_EXPECT_ACK").as_deref() == Ok("1") {
            assert_eq!(acknowledged(&dir, &key, &identity, &recovered), Ok(true));
        }
    }

    #[tokio::test]
    async fn persisted_record_reopens_in_new_process() {
        let dir = directory(); let (identity, first, _) = fixture().await;
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        persist(&dir, &key, &identity, &first, 1000).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["nostr::queue_store::tests::reopen_child", "--exact", "--test-threads=1"])
            .env("FLY_QUEUE_REOPEN_DIR", &dir)
            .env("FLY_QUEUE_TEST_SENDER", identity.sender.to_string())
            .env("FLY_QUEUE_TEST_RECIPIENT", identity.recipient.to_string())
            .env("FLY_QUEUE_TEST_EVENT", first.event.id.to_string())
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
            .spawn().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if child.try_wait().unwrap().is_some() { break; }
            if std::time::Instant::now() >= deadline { let _ = child.kill(); let _ = child.wait(); panic!("synthetic child timed out"); }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }

    #[test]
    fn reopen_recoverable_child() {
        let Some(dir) = std::env::var_os("FLY_RECOVERABLE_TEST_DIR") else { return; };
        let dir = PathBuf::from(dir);
        let root = PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        assert_eq!(fs::canonicalize(dir.parent().unwrap()).unwrap(), fs::canonicalize(root.join(".tmp")).unwrap());
        assert!(dir.file_name().unwrap().to_string_lossy().starts_with("fly-queue-store-test-"));
        let sender = PublicKey::parse(&std::env::var("FLY_QUEUE_TEST_SENDER").unwrap()).unwrap();
        let key = QueueKey::derive_for_wallet_entropy(&[9;32], Network::Floonet, &[7;32]).unwrap();
        let slots = discover_outgoing(&dir).unwrap(); assert_eq!(slots, vec![[3;16]]);
        let (identity, message) = load_recoverable(&dir, &key, Network::Floonet, &[7;32], &slots[0], sender, 1000).unwrap();
        assert_eq!(identity.recipient.to_string(), std::env::var("FLY_QUEUE_TEST_RECIPIENT").unwrap());
        assert_eq!(message.event.id.to_string(), std::env::var("FLY_QUEUE_TEST_EVENT").unwrap());
        assert!(load_recoverable(&dir, &key, Network::Floonet, &[7;32], &slots[0], sender, 1900).is_err());
    }

    #[test]
    fn reopen_correlated_child() {
        let Some(dir) = std::env::var_os("FLY_CORRELATED_TEST_DIR") else { return; };
        let dir = PathBuf::from(dir);
        let root = PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        assert_eq!(fs::canonicalize(dir.parent().unwrap()).unwrap(), fs::canonicalize(root.join(".tmp")).unwrap());
        assert!(dir.file_name().unwrap().to_string_lossy().starts_with("fly-queue-store-test-"));
        let sender = PublicKey::parse(&std::env::var("FLY_QUEUE_TEST_SENDER").unwrap()).unwrap();
        let key = QueueKey::derive_for_wallet_entropy(&[9;32], Network::Floonet, &[7;32]).unwrap();
        let source = [0x51;32];
        let slot = queue_record::incoming_event_reply_slot(&key, Network::Floonet, &[7;32], sender, &source).unwrap();
        let (identity, message) = load_correlated_recoverable(&dir, &key, Network::Floonet, &[7;32], &slot, sender, &source, 1000).unwrap();
        assert_eq!(identity.recipient.to_string(), std::env::var("FLY_QUEUE_TEST_RECIPIENT").unwrap());
        assert_eq!(message.event.id.to_string(), std::env::var("FLY_QUEUE_TEST_EVENT").unwrap());
        assert!(load_correlated_recoverable(&dir, &key, Network::Floonet, &[7;32], &slot, sender, &[0x52;32], 1000).is_err());
    }

    #[tokio::test]
    async fn correlated_reply_recovers_in_new_process_from_source_event() {
        let dir = directory(); let (mut identity, prepared, _) = fixture().await;
        let key = QueueKey::derive_from_wallet_entropy(&[9;32], &identity).unwrap();
        let source = [0x51;32];
        identity.slot = queue_record::incoming_event_reply_slot(&key, identity.network, &identity.wallet_id, identity.sender, &source).unwrap();
        persist_correlated_recoverable(&dir, &key, &identity, &prepared, 1000, &source).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["nostr::queue_store::tests::reopen_correlated_child", "--exact", "--test-threads=1"])
            .env("FLY_CORRELATED_TEST_DIR", &dir)
            .env("FLY_QUEUE_TEST_SENDER", identity.sender.to_string())
            .env("FLY_QUEUE_TEST_RECIPIENT", identity.recipient.to_string())
            .env("FLY_QUEUE_TEST_EVENT", prepared.event.id.to_string())
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
            .spawn().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if child.try_wait().unwrap().is_some() { break; }
            if std::time::Instant::now() >= deadline { let _ = child.kill(); let _ = child.wait(); panic!("synthetic child timed out"); }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }

    #[tokio::test]
    async fn recoverable_record_reopens_in_new_process_without_recipient_hint() {
        let dir = directory(); let (identity, prepared, _) = fixture().await;
        let key = QueueKey::derive_from_wallet_entropy(&[9;32], &identity).unwrap();
        persist_recoverable(&dir, &key, &identity, &prepared, 1000).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["nostr::queue_store::tests::reopen_recoverable_child", "--exact", "--test-threads=1"])
            .env("FLY_RECOVERABLE_TEST_DIR", &dir)
            .env("FLY_QUEUE_TEST_SENDER", identity.sender.to_string())
            .env("FLY_QUEUE_TEST_RECIPIENT", identity.recipient.to_string())
            .env("FLY_QUEUE_TEST_EVENT", prepared.event.id.to_string())
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
            .spawn().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if child.try_wait().unwrap().is_some() { break; }
            if std::time::Instant::now() >= deadline { let _ = child.kill(); let _ = child.wait(); panic!("synthetic child timed out"); }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }

    #[tokio::test]
    async fn recoverable_status_distinguishes_expiry_ack_and_corruption() {
        let dir = directory(); let (identity, prepared, _) = fixture().await;
        let key = QueueKey::derive_from_wallet_entropy(&[9;32], &identity).unwrap();
        persist_recoverable(&dir, &key, &identity, &prepared, 1000).unwrap();
        let status = |now| recoverable_status(&dir, &key, identity.network, &identity.wallet_id,
            &identity.slot, identity.sender, now).map(|(_, status)| status);
        assert_eq!(status(1000), Ok(OutgoingStatus::Unacknowledged { delivery_window_expired: false }));
        assert_eq!(status(1900), Ok(OutgoingStatus::Unacknowledged { delivery_window_expired: true }));
        mark_acknowledged(&dir, &key, &identity, &prepared).unwrap();
        assert_eq!(status(1900), Ok(OutgoingStatus::RelayAccepted { delivery_window_expired: true }));
        let path = ack_target(&dir, &identity).unwrap();
        let mut bytes = fs::read(&path).unwrap(); let last = bytes.len() - 1; bytes[last] ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(status(1900).is_err());
    }

    #[tokio::test]
    async fn recoverable_history_is_readable_after_expiry_but_cannot_be_republished() {
        let dir = directory(); let (identity, mut prepared, _) = fixture().await;
        prepared.local_history = Some(zeroize::Zeroizing::new("synthetic retained S1".to_owned()));
        let key = QueueKey::derive_from_wallet_entropy(&[9;32], &identity).unwrap();
        persist_recoverable(&dir, &key, &identity, &prepared, 1000).unwrap();
        assert!(load_recoverable(&dir, &key, identity.network, &identity.wallet_id, &identity.slot, identity.sender, 1900).is_err());
        let (recovered, history) = load_recoverable_history(&dir, &key, identity.network, &identity.wallet_id, &identity.slot, identity.sender).unwrap();
        assert_eq!(recovered.recipient, identity.recipient); assert_eq!(history.event_id, prepared.event.id);
        assert_eq!(history.text(), "synthetic retained S1");
        let wrong = QueueKey::derive_from_wallet_entropy(&[8;32], &identity).unwrap();
        assert!(load_recoverable_history(&dir, &wrong, identity.network, &identity.wallet_id, &identity.slot, identity.sender).is_err());
        assert!(load_recoverable_history(&dir, &key, Network::Mainnet, &identity.wallet_id, &identity.slot, identity.sender).is_err());
    }

    #[tokio::test]
    async fn acknowledgement_survives_new_process() {
        let dir = directory(); let (identity, first, _) = fixture().await;
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        persist(&dir, &key, &identity, &first, 1000).unwrap();
        mark_acknowledged(&dir, &key, &identity, &first).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["nostr::queue_store::tests::reopen_child", "--exact", "--test-threads=1"])
            .env("FLY_QUEUE_REOPEN_DIR", &dir).env("FLY_QUEUE_EXPECT_ACK", "1")
            .env("FLY_QUEUE_TEST_SENDER", identity.sender.to_string())
            .env("FLY_QUEUE_TEST_RECIPIENT", identity.recipient.to_string())
            .env("FLY_QUEUE_TEST_EVENT", first.event.id.to_string())
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
            .spawn().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if child.try_wait().unwrap().is_some() { break; }
            if std::time::Instant::now() >= deadline { let _ = child.kill(); let _ = child.wait(); panic!("synthetic child timed out"); }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }

    #[cfg(feature = "repo-linked-tests")]
    #[test]
    fn vault_queue_reopen_child() {
        use fly_vault_research::{Network as VaultNetwork, WalletIdentity};
        let Some(dir) = std::env::var_os("FLY_VAULT_QUEUE_DIR") else { return; };
        let dir = PathBuf::from(dir);
        let root = PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        assert_eq!(fs::canonicalize(&root).unwrap(), fs::canonicalize(r"C:\DHW\GrinSight\FlyClient").unwrap());
        assert_eq!(fs::canonicalize(dir.parent().unwrap()).unwrap(), fs::canonicalize(root.join(".tmp")).unwrap());
        assert!(dir.file_name().unwrap().to_string_lossy().starts_with("fly-queue-store-test-"));
        assert!(safe_metadata(&fs::symlink_metadata(&dir).unwrap()));
        let sender = PublicKey::parse(&std::env::var("FLY_QUEUE_TEST_SENDER").unwrap()).unwrap();
        let recipient = PublicKey::parse(&std::env::var("FLY_QUEUE_TEST_RECIPIENT").unwrap()).unwrap();
        let hex = std::env::var("FLY_QUEUE_TEST_WALLET_ID").unwrap();
        assert_eq!(hex.len(), 64);
        let mut wallet_id = [0u8; 32];
        for (i, byte) in wallet_id.iter_mut().enumerate() { *byte = u8::from_str_radix(&hex[i*2..i*2+2], 16).unwrap(); }
        let identity = QueueIdentity { network: Network::Floonet, wallet_id, slot: [3; 16], sender, recipient };
        let container = fs::read(dir.join("synthetic-seed.vault")).unwrap();
        assert!(container.len() <= 16 * 1024);
        let vault_id = WalletIdentity { network: VaultNetwork::Floonet, wallet_id: identity.wallet_id };
        let entropy = fly_vault_research::verified_wallet::open_wallet(&container, "synthetic-password", &vault_id).unwrap();
        let actual = fly_core::wallet_identity_research::from_entropy(&entropy, fly_core::wallet_identity_research::Network::Floonet).unwrap();
        assert_eq!(actual, identity.wallet_id);
        let key = QueueKey::derive_from_wallet_entropy(&entropy, &identity).unwrap();
        let recovered = load(&dir, &key, &identity, 1000).unwrap();
        assert_eq!(recovered.event.id.to_string(), std::env::var("FLY_QUEUE_TEST_EVENT").unwrap());
        assert!(load(&dir, &key, &identity, 1900).is_err());
        let history = load_history(&dir, &key, &identity).unwrap();
        assert_eq!(history.event_id, recovered.event.id);
        assert_eq!(history.text(), "synthetic queue test");
    }

    #[cfg(feature = "repo-linked-tests")]
    #[tokio::test]
    async fn vault_backed_queue_reopens_in_new_process() {
        use fly_vault_research::{Network as VaultNetwork, WalletIdentity};
        use zeroize::Zeroizing;
        let dir = directory(); let (mut identity, mut first, _) = fixture().await;
        first.local_history = Some(Zeroizing::new("synthetic queue test".to_owned()));
        let seed = Zeroizing::new([0x42u8; 16]);
        identity.wallet_id = fly_core::wallet_identity_research::from_entropy(&*seed, fly_core::wallet_identity_research::Network::Floonet).unwrap();
        let vault_id = WalletIdentity { network: VaultNetwork::Floonet, wallet_id: identity.wallet_id };
        let sealed = fly_vault_research::verified_wallet::seal_wallet(&*seed, "synthetic-password", VaultNetwork::Floonet).unwrap();
        assert_eq!(sealed.identity, vault_id);
        let container = sealed.container;
        let vault_path = dir.join("synthetic-seed.vault");
        OpenOptions::new().write(true).create_new(true).open(vault_path).unwrap().write_all(&container).unwrap();
        let entropy = fly_vault_research::verified_wallet::open_wallet(&container, "synthetic-password", &vault_id).unwrap();
        let key = QueueKey::derive_from_wallet_entropy(&entropy, &identity).unwrap();
        persist(&dir, &key, &identity, &first, 1000).unwrap();
        drop(key); drop(entropy); drop(seed);
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["nostr::queue_store::tests::vault_queue_reopen_child", "--exact", "--test-threads=1"])
            .env("FLY_VAULT_QUEUE_DIR", &dir)
            .env("FLY_QUEUE_TEST_SENDER", identity.sender.to_string())
            .env("FLY_QUEUE_TEST_RECIPIENT", identity.recipient.to_string())
            .env("FLY_QUEUE_TEST_WALLET_ID", identity.wallet_id.iter().map(|b| format!("{b:02x}")).collect::<String>())
            .env("FLY_QUEUE_TEST_EVENT", first.event.id.to_string())
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
            .spawn().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if child.try_wait().unwrap().is_some() { break; }
            if std::time::Instant::now() >= deadline { let _ = child.kill(); let _ = child.wait(); panic!("synthetic child timed out"); }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }

    #[test]
    fn race_child() {
        use std::io::Read;
        let Some(which) = std::env::var_os("FLY_QUEUE_RACE_CHILD") else { return; };
        let which = which.to_str().unwrap();
        assert!(matches!(which, "a" | "b"));
        let dir = PathBuf::from(std::env::var_os("FLY_QUEUE_RACE_DIR").unwrap());
        let root = PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        assert_eq!(fs::canonicalize(&root).unwrap(), fs::canonicalize(r"C:\DHW\GrinSight\FlyClient").unwrap());
        assert_eq!(fs::canonicalize(dir.parent().unwrap()).unwrap(), fs::canonicalize(root.join(".tmp")).unwrap());
        assert!(dir.file_name().unwrap().to_string_lossy().starts_with("fly-queue-store-test-"));
        assert!(safe_metadata(&fs::symlink_metadata(&dir).unwrap()));
        let sender = PublicKey::parse(&std::env::var("FLY_QUEUE_TEST_SENDER").unwrap()).unwrap();
        let recipient = PublicKey::parse(&std::env::var("FLY_QUEUE_TEST_RECIPIENT").unwrap()).unwrap();
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [7; 32], slot: [3; 16], sender, recipient };
        let event = Event::from_json(std::env::var("FLY_QUEUE_TEST_ENVELOPE").unwrap()).unwrap();
        let prepared = PreparedMessage { event, sender, recipient, expires_at: 1900, local_history: None };
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        OpenOptions::new().write(true).create_new(true).open(dir.join(format!("ready-{which}"))).unwrap();
        let mut signal = [0u8; 1]; std::io::stdin().read_exact(&mut signal).unwrap();
        assert_eq!(signal, [1]);
        match persist(&dir, &key, &identity, &prepared, 1000) {
            Ok(()) => println!("SYNTHETIC_RACE_WON"),
            Err(StoreError::Indeterminate | StoreError::Busy) => println!("SYNTHETIC_RACE_REFUSED"),
            Err(error) => panic!("unexpected synthetic store error: {error:?}"),
        }
    }

    #[tokio::test]
    async fn separate_process_writers_do_not_replace_each_other() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let dir = directory(); let (identity, first, second) = fixture().await;
        let first_id = first.event.id; let second_id = second.event.id;
        let mut children = Vec::new();
        for (which, item) in [("a", first), ("b", second)] {
            children.push(Command::new(std::env::current_exe().unwrap())
                .args(["nostr::queue_store::tests::race_child", "--exact", "--nocapture", "--test-threads=1"])
                .env("FLY_QUEUE_RACE_CHILD", which).env("FLY_QUEUE_RACE_DIR", &dir)
                .env("FLY_QUEUE_TEST_SENDER", identity.sender.to_string())
                .env("FLY_QUEUE_TEST_RECIPIENT", identity.recipient.to_string())
                .env("FLY_QUEUE_TEST_ENVELOPE", item.event.as_json())
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap());
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !(dir.join("ready-a").exists() && dir.join("ready-b").exists()) {
            if std::time::Instant::now() >= deadline {
                for child in &mut children { let _ = child.kill(); let _ = child.wait(); }
                panic!("synthetic race children did not become ready");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        for child in &mut children { child.stdin.take().unwrap().write_all(&[1]).unwrap(); }
        let mut outputs = Vec::new();
        for mut child in children {
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            loop {
                if child.try_wait().unwrap().is_some() { break; }
                if std::time::Instant::now() >= deadline { let _ = child.kill(); let _ = child.wait(); panic!("synthetic race child timed out"); }
                std::thread::sleep(Duration::from_millis(20));
            }
            let output = child.wait_with_output().unwrap(); assert!(output.status.success());
            outputs.push(String::from_utf8_lossy(&output.stdout).to_string());
        }
        assert_eq!(outputs.iter().filter(|s| s.contains("SYNTHETIC_RACE_WON")).count(), 1);
        assert_eq!(outputs.iter().filter(|s| s.contains("SYNTHETIC_RACE_REFUSED")).count(), 1);
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        let loaded = load(&dir, &key, &identity, 1000).unwrap().event.id;
        assert!(loaded == first_id || loaded == second_id);
    }

    #[test]
    fn crash_child() {
        use std::io::Read;
        let Ok(stage) = std::env::var("FLY_QUEUE_CRASH_STAGE") else { return; };
        assert!(matches!(stage.as_str(), "sync" | "link"));
        let dir = PathBuf::from(std::env::var_os("FLY_QUEUE_RACE_DIR").unwrap());
        let root = PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        assert_eq!(fs::canonicalize(&root).unwrap(), fs::canonicalize(r"C:\DHW\GrinSight\FlyClient").unwrap());
        assert_eq!(fs::canonicalize(dir.parent().unwrap()).unwrap(), fs::canonicalize(root.join(".tmp")).unwrap());
        assert!(dir.file_name().unwrap().to_string_lossy().starts_with("fly-queue-store-test-"));
        assert!(safe_metadata(&fs::symlink_metadata(&dir).unwrap()));
        let sender = PublicKey::parse(&std::env::var("FLY_QUEUE_TEST_SENDER").unwrap()).unwrap();
        let recipient = PublicKey::parse(&std::env::var("FLY_QUEUE_TEST_RECIPIENT").unwrap()).unwrap();
        let mut identity = QueueIdentity { network: Network::Floonet, wallet_id: [7; 32], slot: [3; 16], sender, recipient };
        let event = Event::from_json(std::env::var("FLY_QUEUE_TEST_ENVELOPE").unwrap()).unwrap();
        let prepared = PreparedMessage { event, sender, recipient, expires_at: 1900, local_history: None };
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        let pause = || {
            OpenOptions::new().write(true).create_new(true).open(dir.join("crash-ready")).unwrap();
            let mut signal = [0u8; 1]; let _ = std::io::stdin().read_exact(&mut signal);
        };
        if std::env::var_os("FLY_QUEUE_CORRELATED_CRASH").is_some() {
            let source = [0x51;32];
            identity.slot = queue_record::incoming_event_reply_slot(&key, identity.network, &identity.wallet_id, identity.sender, &source).unwrap();
            let _ = persist_correlated_inner(&dir, &key, &identity, &prepared, 1000, &source,
                || if stage == "sync" { pause(); }, || if stage == "link" { pause(); });
        } else if std::env::var_os("FLY_QUEUE_RECOVERABLE_CRASH").is_some() {
            let _ = persist_recoverable_bounded_inner(&dir, &key, &identity, &prepared, 1000,
                MAX_OUTBOX_ENTRIES, MAX_OUTBOX_BYTES,
                || if stage == "sync" { pause(); }, || if stage == "link" { pause(); });
        } else if std::env::var_os("FLY_QUEUE_BOUND_CRASH").is_some() {
            let slate_id = [10; 16];
            identity.slot = queue_record::payment_operation_slot(&key, &identity, &slate_id,
                queue_record::PaymentStage::Standard1).unwrap();
            let _ = persist_bound_reply_inner(&dir, &key, &identity, &slate_id,
                "BEGINSLATEPACK. original ENDSLATEPACK.", &prepared, 1000,
                || if stage == "sync" { pause(); }, || if stage == "link" { pause(); });
        } else {
            let _ = persist_inner(&dir, &key, &identity, &prepared, 1000,
                || if stage == "sync" { pause(); }, || if stage == "link" { pause(); });
        }
    }

    #[tokio::test]
    async fn killed_process_preserves_publication_boundary() {
        use std::process::{Command, Stdio};
        for stage in ["sync", "link"] {
            let dir = directory(); let (identity, prepared, _) = fixture().await;
            let expected = prepared.event.id;
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["nostr::queue_store::tests::crash_child", "--exact", "--test-threads=1"])
                .env("FLY_QUEUE_CRASH_STAGE", stage).env("FLY_QUEUE_RACE_DIR", &dir)
                .env("FLY_QUEUE_TEST_SENDER", identity.sender.to_string())
                .env("FLY_QUEUE_TEST_RECIPIENT", identity.recipient.to_string())
                .env("FLY_QUEUE_TEST_ENVELOPE", prepared.event.as_json())
                .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while !dir.join("crash-ready").exists() {
                if child.try_wait().unwrap().is_some() { panic!("synthetic child ended before pause"); }
                if std::time::Instant::now() >= deadline { let _ = child.kill(); let _ = child.wait(); panic!("synthetic child timed out"); }
                std::thread::sleep(Duration::from_millis(20));
            }
            child.kill().unwrap(); child.wait().unwrap();
            let key = QueueKey::derive(&[9; 32], &identity).unwrap();
            if stage == "sync" {
                assert!(matches!(load(&dir, &key, &identity, 1000), Err(StoreError::InvalidRecord)));
                persist(&dir, &key, &identity, &prepared, 1000).unwrap();
            }
            assert_eq!(load(&dir, &key, &identity, 1000).unwrap().event.id, expected);
        }
    }

    #[tokio::test]
    async fn killed_process_preserves_bound_reply_and_request_binding() {
        use std::process::{Command, Stdio};
        for stage in ["sync", "link"] {
            let dir = directory();
            let (mut identity, prepared, _) = fixture().await;
            let key = QueueKey::derive(&[9; 32], &identity).unwrap();
            let slate_id = [10; 16];
            identity.slot = queue_record::payment_operation_slot(&key, &identity, &slate_id,
                queue_record::PaymentStage::Standard1).unwrap();
            let request = "BEGINSLATEPACK. original ENDSLATEPACK.";
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["nostr::queue_store::tests::crash_child", "--exact", "--test-threads=1"])
                .env("FLY_QUEUE_CRASH_STAGE", stage).env("FLY_QUEUE_BOUND_CRASH", "1")
                .env("FLY_QUEUE_RACE_DIR", &dir)
                .env("FLY_QUEUE_TEST_SENDER", identity.sender.to_string())
                .env("FLY_QUEUE_TEST_RECIPIENT", identity.recipient.to_string())
                .env("FLY_QUEUE_TEST_ENVELOPE", prepared.event.as_json())
                .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while !dir.join("crash-ready").exists() {
                if child.try_wait().unwrap().is_some() { panic!("synthetic child ended before pause"); }
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill(); let _ = child.wait(); panic!("synthetic child timed out");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            child.kill().unwrap();
            child.wait().unwrap();
            if stage == "sync" {
                assert!(load_bound_reply(&dir, &key, &identity, &slate_id, request, 1000).is_err());
                persist_bound_reply(&dir, &key, &identity, &slate_id, request, &prepared, 1000).unwrap();
            }
            assert_eq!(load_bound_reply(&dir, &key, &identity, &slate_id, request, 1000).unwrap().event.id,
                prepared.event.id);
            assert!(load_bound_reply(&dir, &key, &identity, &slate_id,
                "BEGINSLATEPACK. changed ENDSLATEPACK.", 1000).is_err());
            assert!(matches!(persist_bound_reply(&dir, &key, &identity, &slate_id, request, &prepared, 1000),
                Err(StoreError::Indeterminate)));
        }
    }

    #[tokio::test]
    async fn killed_process_preserves_recoverable_reply_boundary() {
        use std::process::{Command, Stdio};
        for stage in ["sync", "link"] {
            let dir = directory(); let (identity, prepared, _) = fixture().await;
            let key = QueueKey::derive(&[9;32], &identity).unwrap();
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["nostr::queue_store::tests::crash_child", "--exact", "--test-threads=1"])
                .env("FLY_QUEUE_CRASH_STAGE", stage).env("FLY_QUEUE_RECOVERABLE_CRASH", "1")
                .env("FLY_QUEUE_RACE_DIR", &dir)
                .env("FLY_QUEUE_TEST_SENDER", identity.sender.to_string())
                .env("FLY_QUEUE_TEST_RECIPIENT", identity.recipient.to_string())
                .env("FLY_QUEUE_TEST_ENVELOPE", prepared.event.as_json())
                .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while !dir.join("crash-ready").exists() {
                if child.try_wait().unwrap().is_some() { panic!("synthetic child ended before pause"); }
                if std::time::Instant::now() >= deadline { let _ = child.kill(); let _ = child.wait(); panic!("synthetic child timed out"); }
                std::thread::sleep(Duration::from_millis(20));
            }
            child.kill().unwrap(); child.wait().unwrap();
            if stage == "sync" {
                assert!(load_recoverable(&dir, &key, identity.network, &identity.wallet_id, &identity.slot, identity.sender, 1000).is_err());
                persist_recoverable(&dir, &key, &identity, &prepared, 1000).unwrap();
            }
            let (recovered, event) = load_recoverable(&dir, &key, identity.network, &identity.wallet_id,
                &identity.slot, identity.sender, 1000).unwrap();
            assert_eq!(recovered.recipient, identity.recipient);
            assert_eq!(event.event.id, prepared.event.id);
            assert_eq!(persist_recoverable(&dir, &key, &identity, &prepared, 1000), Err(StoreError::Indeterminate));
        }
    }

    #[tokio::test]
    async fn killed_process_recovers_correlated_stage_without_new_signature() {
        use std::process::{Command, Stdio};
        for stage in ["sync", "link"] {
            let dir = directory(); let (mut identity, prepared, _) = fixture().await;
            let key = QueueKey::derive(&[9;32], &identity).unwrap(); let source = [0x51;32];
            identity.slot = queue_record::incoming_event_reply_slot(&key, identity.network, &identity.wallet_id, identity.sender, &source).unwrap();
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["nostr::queue_store::tests::crash_child", "--exact", "--test-threads=1"])
                .env("FLY_QUEUE_CRASH_STAGE", stage).env("FLY_QUEUE_CORRELATED_CRASH", "1")
                .env("FLY_QUEUE_RACE_DIR", &dir)
                .env("FLY_QUEUE_TEST_SENDER", identity.sender.to_string())
                .env("FLY_QUEUE_TEST_RECIPIENT", identity.recipient.to_string())
                .env("FLY_QUEUE_TEST_ENVELOPE", prepared.event.as_json())
                .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while !dir.join("crash-ready").exists() {
                if child.try_wait().unwrap().is_some() { panic!("synthetic child ended before pause"); }
                if std::time::Instant::now() >= deadline { let _ = child.kill(); let _ = child.wait(); panic!("synthetic child timed out"); }
                std::thread::sleep(Duration::from_millis(20));
            }
            child.kill().unwrap(); child.wait().unwrap();
            assert!(recover_correlated_stage(&dir, &key, &identity, &[0x52;32], 1000).is_err());
            let mut wrong = identity; wrong.recipient = Keys::generate().public_key();
            assert!(recover_correlated_stage(&dir, &key, &wrong, &source, 1000).is_err());
            assert_eq!(recover_correlated_stage(&dir, &key, &identity, &source, 1000).unwrap(),
                if stage == "sync" { StageRecovery::Restored } else { StageRecovery::AlreadyPresent });
            let (recovered, event) = load_correlated_recoverable(&dir, &key, identity.network, &identity.wallet_id,
                &identity.slot, identity.sender, &source, 1000).unwrap();
            assert_eq!(recovered.recipient, identity.recipient); assert_eq!(event.event.id, prepared.event.id);
            assert_eq!(recover_correlated_stage(&dir, &key, &identity, &source, 1000).unwrap(), StageRecovery::AlreadyPresent);
        }
    }

    #[tokio::test]
    async fn ambiguous_correlated_stages_are_not_published() {
        let dir = directory(); let (mut identity, prepared, _) = fixture().await;
        let key = QueueKey::derive(&[9;32], &identity).unwrap(); let source = [0x51;32];
        identity.slot = queue_record::incoming_event_reply_slot(&key, identity.network, &identity.wallet_id, identity.sender, &source).unwrap();
        for suffix in ["01".repeat(16), "02".repeat(16)] {
            let record = queue_record::seal_correlated_recoverable(&key, &identity, &prepared, 1000, &source).unwrap();
            fs::write(dir.join(format!(".flyr-{suffix}.tmp")), record).unwrap();
        }
        assert_eq!(recover_correlated_stage(&dir, &key, &identity, &source, 1000), Err(StoreError::Indeterminate));
        assert!(!target(&dir, &identity).unwrap().exists());
    }
}
