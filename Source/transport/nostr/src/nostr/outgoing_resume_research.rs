//! Bounded, read-before-send recovery for experimental FLYR0001 records.
//! Not a scheduler, payment authority, durable directory or rollback defense.
use std::{future::Future, path::Path, sync::atomic::{AtomicBool, Ordering}, time::Duration};
use fly_tor::SharedTor;
use nostr_sdk::{Keys, PublicKey, Timestamp};
use super::{contact_session::{ContactSession, Publication, SessionError},
    queue_record::{Network, QueueKey}, queue_store::{self, OutgoingStatus}};

/// States describe a relay or local storage, never recipient or chain status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeState {
    RelayAccepted { delivery_window_expired: bool },
    Expired,
    Pending,
    Deferred,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResumeEntry { pub slot: [u8; 16], pub state: ResumeState }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeBatch {
    pub entries: Vec<ResumeEntry>,
    /// Pass this to the next run to rotate past the last attempted slot.
    /// Not persisted; losing it after restart affects fairness, not identity.
    pub next_after: Option<[u8; 16]>,
}

/// A single in-process recovery supervisor for one unlocked profile. The owner
/// must keep it unique across the application and use a separate instance only
/// after lock/reopen. It is not a cross-process lock or rollback protection.
pub struct ResumeSupervisor {
    network: Network,
    wallet_id: [u8; 32],
    sender: PublicKey,
    active: AtomicBool,
    cursor: tokio::sync::Mutex<Option<[u8; 16]>>,
}

impl ResumeSupervisor {
    pub fn new(network: Network, wallet_id: [u8; 32], sender: PublicKey) -> Result<Self, SessionError> {
        if wallet_id.iter().all(|b| *b == 0) { return Err(SessionError::InvalidInput); }
        Ok(Self { network, wallet_id, sender, active: AtomicBool::new(true), cursor: tokio::sync::Mutex::new(None) })
    }

    /// Stop starting new sends, then wait for any active pass to finish. A send
    /// already in flight can complete; after this method returns this supervisor
    /// cannot send again. The caller must await it before dropping unlocked keys.
    pub async fn stop_and_wait(&self) {
        self.active.store(false, Ordering::SeqCst);
        let _guard = self.cursor.lock().await;
    }

    pub async fn run_via_tor(&self, tor: SharedTor, keys: Keys, relay: &str, dir: &Path,
        key: &QueueKey, timeout: Duration, max_attempts: u8) -> Result<ResumeBatch, SessionError> {
        if keys.public_key() != self.sender { return Err(SessionError::InvalidInput); }
        self.run_with(dir, key, timeout, max_attempts, |recipient| {
            let tor = tor.clone(); let keys = keys.clone(); let relay = relay.to_owned();
            async move { ContactSession::connect(tor, keys, recipient, &relay, timeout).await }
        }).await
    }

    pub(super) async fn run_with<F, Fut>(&self, dir: &Path, key: &QueueKey, timeout: Duration,
        max_attempts: u8, connect: F) -> Result<ResumeBatch, SessionError>
    where F: FnMut(PublicKey) -> Fut, Fut: Future<Output = Result<ContactSession, SessionError>> {
        if !self.active.load(Ordering::SeqCst) { return Err(SessionError::Closed); }
        let mut cursor = self.cursor.try_lock().map_err(|_| SessionError::StorageBusy)?;
        if !self.active.load(Ordering::SeqCst) { return Err(SessionError::Closed); }
        let batch = resume_with(dir, key, self.network, &self.wallet_id, self.sender, timeout,
            max_attempts, *cursor, Some(&self.active), connect).await?;
        *cursor = batch.next_after;
        Ok(batch)
    }
}

/// Native-only unlocked recovery context for one catalog profile. It retains
/// the messaging and queue keys in native memory, never returns them to UI,
/// and must be stopped and dropped before the profile is considered locked.
/// The application must ensure one context per profile across the process.
#[cfg(all(windows, feature = "windows-vault-queue-research", feature = "messaging-identity-research"))]
pub struct ProfileRecovery {
    directory: std::path::PathBuf,
    keys: Keys,
    key: QueueKey,
    supervisor: ResumeSupervisor,
}

/// Latest transport state only. A relay acknowledgement never confirms a
/// payment. Updates are snapshots, so a slow observer can miss transitions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryWorkerState { Starting, Running, Finished(ResumeBatch), Error(SessionError), Stopped }

#[cfg(all(windows, feature = "windows-vault-queue-research", feature = "messaging-identity-research"))]
pub struct RecoveryWorker {
    stop: tokio::sync::watch::Sender<bool>,
    state: tokio::sync::watch::Receiver<RecoveryWorkerState>,
    task: Option<tokio::task::JoinHandle<()>>,
    profile: std::sync::Arc<ProfileRecovery>,
}

#[cfg(all(windows, feature = "windows-vault-queue-research", feature = "messaging-identity-research"))]
impl RecoveryWorker {
    pub fn state(&self) -> tokio::sync::watch::Receiver<RecoveryWorkerState> { self.state.clone() }

    /// Stop starting new sends, wait for the current pass and background task,
    /// and only then release this worker's unlocked profile. Already started
    /// relay operations may complete. Caller must not retain other contexts.
    pub async fn stop(mut self) -> Result<(), SessionError> {
        self.stop.send_replace(true);
        self.profile.stop_and_wait().await;
        if let Some(task) = self.task.take() { task.await.map_err(|_| SessionError::StorageUnavailable)?; }
        Ok(())
    }
}

#[cfg(all(windows, feature = "windows-vault-queue-research", feature = "messaging-identity-research"))]
impl Drop for RecoveryWorker {
    fn drop(&mut self) {
        // Nonblocking best effort only. An owner locking a profile must call
        // and await stop(), otherwise unlocked keys may remain until task exit.
        self.stop.send_replace(true);
        self.profile.supervisor.active.store(false, Ordering::SeqCst);
    }
}

pub(super) async fn worker_loop<F, Fut>(mut stop: tokio::sync::watch::Receiver<bool>,
    state: tokio::sync::watch::Sender<RecoveryWorkerState>, interval: Duration, mut pass: F)
where F: FnMut() -> Fut, Fut: Future<Output = Result<ResumeBatch, SessionError>> {
    loop {
        if *stop.borrow() { break; }
        state.send_replace(RecoveryWorkerState::Running);
        match pass().await {
            Ok(batch) => { state.send_replace(RecoveryWorkerState::Finished(batch)); }
            Err(error) => { state.send_replace(RecoveryWorkerState::Error(error)); }
        }
        if *stop.borrow() { break; }
        tokio::select! {
            _ = tokio::time::sleep(interval) => (),
            changed = stop.changed() => { if changed.is_err() || *stop.borrow() { break; } }
        }
    }
    state.send_replace(RecoveryWorkerState::Stopped);
}

#[cfg(all(windows, feature = "windows-vault-queue-research", feature = "messaging-identity-research"))]
impl ProfileRecovery {
    pub async fn open(catalog_root: &Path, profile_id: &str, password: &str) -> Result<Self, SessionError> {
        let (profile, identity) = super::windows_vault_queue_research::resolve_catalog_profile(catalog_root, profile_id)
            .map_err(|_| SessionError::StorageUnavailable)?;
        Self::from_profile(&profile, password, &identity).await
    }

    pub(super) async fn from_profile(profile: &Path, password: &str,
        identity: &super::contact_book_research::BookIdentity) -> Result<Self, SessionError> {
        let directory = profile.join("messages");
        queue_store::check_dir(&directory).map_err(|_| SessionError::StorageUnavailable)?;
        let (keys, key) = super::windows_vault_queue_research::open_messaging_and_queue_async(profile, password, identity).await
            .map_err(|error| match error {
                super::windows_vault_queue_research::AsyncProfileError::Busy => SessionError::StorageBusy,
                super::windows_vault_queue_research::AsyncProfileError::Unavailable => SessionError::StorageUnavailable,
            })?;
        let supervisor = ResumeSupervisor::new(identity.network, identity.wallet_id, keys.public_key())?;
        Ok(Self { directory, keys, key, supervisor })
    }

    pub async fn run(&self, tor: SharedTor, relay: &str, timeout: Duration, max_attempts: u8)
        -> Result<ResumeBatch, SessionError> {
        self.supervisor.run_via_tor(tor, self.keys.clone(), relay, &self.directory, &self.key, timeout, max_attempts).await
    }

    /// Wait before dropping this context; an in-flight send can finish first.
    pub async fn stop_and_wait(&self) { self.supervisor.stop_and_wait().await; }

    /// Start one bounded periodic loop, consuming this unlocked context. A
    /// single loop uses a single relay; other formats remain unavailable.
    /// The app must await RecoveryWorker::stop before reporting profile lock.
    pub fn start(self, tor: SharedTor, relay: &str, interval: Duration, timeout: Duration,
        max_attempts: u8) -> Result<RecoveryWorker, SessionError> {
        if interval < Duration::from_secs(5) || interval > Duration::from_secs(3600)
            || timeout.is_zero() || timeout > Duration::from_secs(120) || max_attempts == 0 || max_attempts > 16 {
            return Err(SessionError::InvalidInput);
        }
        let parsed = nostr_sdk::Url::parse(relay).map_err(|_| SessionError::InvalidInput)?;
        super::tor_transport::destination(&parsed, timeout).map_err(|_| SessionError::InvalidInput)?;
        let profile = std::sync::Arc::new(self);
        let runner = profile.clone(); let relay = relay.to_owned();
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let (state, state_receiver) = tokio::sync::watch::channel(RecoveryWorkerState::Starting);
        let task = tokio::spawn(async move {
            worker_loop(receiver, state, interval, move || {
                let profile = runner.clone(); let tor = tor.clone(); let relay = relay.clone();
                async move { profile.run(tor, &relay, timeout, max_attempts).await }
            }).await;
        });
        Ok(RecoveryWorker { stop, state: state_receiver, task: Some(task), profile })
    }
}

/// One pass, sequentially over at most 512 discovered records and at most 16
/// network attempts. The caller must own the process-wide supervisor and the
/// trusted profile/key; concurrent passes may send an identical event twice.
/// Old formats and corrupt records are returned as Unavailable, never ignored
/// or overwritten. Missing files and rollback cannot be distinguished here.
pub async fn resume_via_tor(tor: SharedTor, keys: Keys, relay: &str, dir: &Path,
    key: &QueueKey, network: Network, wallet_id: &[u8; 32], timeout: Duration,
    max_attempts: u8, start_after: Option<[u8; 16]>) -> Result<ResumeBatch, SessionError> {
    let sender = keys.public_key();
    resume_with(dir, key, network, wallet_id, sender, timeout, max_attempts, start_after, None, |recipient| {
        let tor = tor.clone(); let keys = keys.clone(); let relay = relay.to_owned();
        async move { ContactSession::connect(tor, keys, recipient, &relay, timeout).await }
    }).await
}

pub(super) async fn resume_with<F, Fut>(dir: &Path, key: &QueueKey, network: Network,
    wallet_id: &[u8; 32], sender: PublicKey, timeout: Duration, max_attempts: u8,
    start_after: Option<[u8; 16]>, active: Option<&AtomicBool>, mut connect: F) -> Result<ResumeBatch, SessionError>
where F: FnMut(PublicKey) -> Fut, Fut: Future<Output = Result<ContactSession, SessionError>> {
    if timeout.is_zero() || timeout > Duration::from_secs(120) || max_attempts == 0 || max_attempts > 16 {
        return Err(SessionError::InvalidInput);
    }
    let mut slots = queue_store::discover_outgoing(dir).map_err(|_| SessionError::StorageUnavailable)?;
    if let Some(last) = start_after {
        let pivot = slots.partition_point(|slot| *slot <= last);
        slots.rotate_left(pivot);
    }
    let mut attempts = 0u8;
    let mut next_after = start_after;
    let mut result = Vec::with_capacity(slots.len());
    for slot in slots {
        let now = Timestamp::now().as_secs();
        let state = match queue_store::recoverable_status(dir, key, network, wallet_id, &slot, sender, now) {
            Err(_) => ResumeState::Unavailable,
            Ok((_, OutgoingStatus::RelayAccepted { delivery_window_expired })) => ResumeState::RelayAccepted { delivery_window_expired },
            Ok((_, OutgoingStatus::Unacknowledged { delivery_window_expired: true })) => ResumeState::Expired,
            Ok((identity, OutgoingStatus::Unacknowledged { delivery_window_expired: false })) => {
                if attempts >= max_attempts || active.is_some_and(|value| !value.load(Ordering::SeqCst)) { ResumeState::Deferred } else {
                    attempts += 1;
                    next_after = Some(slot);
                    match connect(identity.recipient).await {
                        Err(_) => ResumeState::Pending,
                        Ok(session) => {
                            let sent = if active.is_some_and(|value| !value.load(Ordering::SeqCst)) {
                                Err(SessionError::Closed)
                            } else { session.publish_recoverable_payment(dir, key, network, wallet_id, &slot, timeout).await };
                            let _ = tokio::time::timeout(timeout, session.close()).await;
                            match sent {
                                Ok(Publication::RelayAccepted) => ResumeState::RelayAccepted { delivery_window_expired: false },
                                Ok(Publication::Unknown) => ResumeState::Pending,
                                Err(SessionError::Expired) => ResumeState::Expired,
                                Err(SessionError::StorageUnavailable | SessionError::InvalidInput) => ResumeState::Unavailable,
                                Err(SessionError::Closed) if active.is_some_and(|value| !value.load(Ordering::SeqCst)) => ResumeState::Deferred,
                                Err(_) => ResumeState::Pending,
                            }
                        }
                    }
                }
            }
        };
        result.push(ResumeEntry { slot, state });
    }
    Ok(ResumeBatch { entries: result, next_after })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

    #[tokio::test]
    async fn periodic_worker_finishes_inflight_pass_and_stops_without_retry() {
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let (state, state_receiver) = tokio::sync::watch::channel(RecoveryWorkerState::Starting);
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let task_started = started.clone(); let task_release = release.clone(); let task_calls = calls.clone();
        let worker = tokio::spawn(async move {
            worker_loop(receiver, state, Duration::from_millis(10), move || {
                let started = task_started.clone(); let release = task_release.clone(); let calls = task_calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    started.notify_one();
                    release.notified().await;
                    Ok(ResumeBatch { entries: vec![], next_after: None })
                }
            }).await;
        });
        tokio::time::timeout(Duration::from_secs(2), started.notified()).await.unwrap();
        assert_eq!(*state_receiver.borrow(), RecoveryWorkerState::Running);
        stop.send_replace(true);
        assert!(!worker.is_finished());
        release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), worker).await.unwrap().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(*state_receiver.borrow(), RecoveryWorkerState::Stopped);
    }
}
