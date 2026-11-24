//! Experimental Windows bridge from an identity-anchored profile to its
//! encrypted message queue. No secret is returned to Flutter or logged.
//! The caller must own a stable trusted profile directory and identity;
//! coordinated rollback/replacement of the vault and anchor is not detected.
use std::path::Path;
use fly_vault_research::{identity_anchor_research, verified_wallet, Network as VaultNetwork};
use super::{contact_book_research::{BookIdentity, BookKey}, queue_record::{Network, OutgoingHistory, QueueIdentity, QueueKey}, queue_store::{self, OutgoingStatus}};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileQueueError;

/// Unlock, compare the separately protected identity and derive only the
/// purpose-separated queue key. The temporary entropy is zeroized on drop by
/// the vault; callers must not expose the returned key to untrusted code.
pub fn open_queue_key(directory: &Path, password: &str, identity: &QueueIdentity)
    -> Result<QueueKey, ProfileQueueError> {
    let network = match identity.network { Network::Mainnet => VaultNetwork::Mainnet, Network::Floonet => VaultNetwork::Floonet };
    let anchor = identity_anchor_research::read(directory, network).map_err(|_| ProfileQueueError)?;
    if anchor.wallet_id != identity.wallet_id { return Err(ProfileQueueError); }
    let entropy = verified_wallet::open_published(directory, password, &anchor).map_err(|_| ProfileQueueError)?;
    QueueKey::derive_from_wallet_entropy(&entropy, identity).map_err(|_| ProfileQueueError)
}

/// Derive a distinct contact-book key without exporting wallet entropy.
/// As with the queue, the anchor does not detect coordinated rollback.
pub fn open_book_key(directory: &Path, password: &str, identity: &BookIdentity)
    -> Result<BookKey, ProfileQueueError> {
    let network = match identity.network { Network::Mainnet => VaultNetwork::Mainnet, Network::Floonet => VaultNetwork::Floonet };
    let anchor = identity_anchor_research::read(directory, network).map_err(|_| ProfileQueueError)?;
    if anchor.wallet_id != identity.wallet_id { return Err(ProfileQueueError); }
    let entropy = verified_wallet::open_published(directory, password, &anchor).map_err(|_| ProfileQueueError)?;
    BookKey::derive_from_wallet_entropy(&entropy, identity).map_err(|_| ProfileQueueError)
}

/// Explicit one-time creation; a missing or uncertain result never triggers
/// automatic recreation. Returns only the messaging public key.
#[cfg(feature = "messaging-identity-research")]
pub fn create_messaging_identity(directory:&Path,password:&str,identity:&BookIdentity)
    -> Result<nostr_sdk::PublicKey, ProfileQueueError> {
    let network=match identity.network { Network::Mainnet=>VaultNetwork::Mainnet, Network::Floonet=>VaultNetwork::Floonet };
    let anchor=identity_anchor_research::read(directory,network).map_err(|_|ProfileQueueError)?;
    if anchor.wallet_id!=identity.wallet_id { return Err(ProfileQueueError); }
    let entropy=verified_wallet::open_published(directory,password,&anchor).map_err(|_|ProfileQueueError)?;
    super::messaging_identity_research::create_once(directory,&entropy,password,identity).map_err(|_|ProfileQueueError)
}

/// Reopen the existing independent identity only; never create a replacement.
/// The returned key object stays inside trusted native code.
#[cfg(feature = "messaging-identity-research")]
pub fn open_messaging_identity(directory:&Path,password:&str,identity:&BookIdentity)
    -> Result<nostr_sdk::Keys, ProfileQueueError> {
    let network=match identity.network { Network::Mainnet=>VaultNetwork::Mainnet, Network::Floonet=>VaultNetwork::Floonet };
    let anchor=identity_anchor_research::read(directory,network).map_err(|_|ProfileQueueError)?;
    if anchor.wallet_id!=identity.wallet_id { return Err(ProfileQueueError); }
    let entropy=verified_wallet::open_published(directory,password,&anchor).map_err(|_|ProfileQueueError)?;
    super::messaging_identity_research::open(directory,&entropy,password,identity).map_err(|_|ProfileQueueError)
}

/// Unlock the profile once, then reopen its independent Nostr identity and
/// derive its contact-book key inside native Rust. Neither secret is a UI API.
#[cfg(feature = "messaging-identity-research")]
pub fn open_messaging_and_book(directory:&Path,password:&str,identity:&BookIdentity)
    -> Result<(nostr_sdk::Keys,BookKey),ProfileQueueError> {
    let network=match identity.network { Network::Mainnet=>VaultNetwork::Mainnet, Network::Floonet=>VaultNetwork::Floonet };
    let anchor=identity_anchor_research::read(directory,network).map_err(|_|ProfileQueueError)?;
    if anchor.wallet_id!=identity.wallet_id { return Err(ProfileQueueError); }
    let entropy=verified_wallet::open_published(directory,password,&anchor).map_err(|_|ProfileQueueError)?;
    let book=BookKey::derive_from_wallet_entropy(&entropy,identity).map_err(|_|ProfileQueueError)?;
    let keys=super::messaging_identity_research::open(directory,&entropy,password,identity).map_err(|_|ProfileQueueError)?;
    Ok((keys,book))
}

/// Open the independent messaging identity and wallet-scoped queue key in one
/// authenticated unlock, without requiring a known recipient. The caller must
/// retain these only in native memory and must stop the supervisor before lock.
#[cfg(feature = "messaging-identity-research")]
pub fn open_messaging_and_queue(directory:&Path,password:&str,identity:&BookIdentity)
    -> Result<(nostr_sdk::Keys,QueueKey),ProfileQueueError> {
    let network=match identity.network { Network::Mainnet=>VaultNetwork::Mainnet, Network::Floonet=>VaultNetwork::Floonet };
    let anchor=identity_anchor_research::read(directory,network).map_err(|_|ProfileQueueError)?;
    if anchor.wallet_id!=identity.wallet_id { return Err(ProfileQueueError); }
    let entropy=verified_wallet::open_published(directory,password,&anchor).map_err(|_|ProfileQueueError)?;
    let queue=QueueKey::derive_for_wallet_entropy(&entropy,identity.network,&identity.wallet_id).map_err(|_|ProfileQueueError)?;
    let keys=super::messaging_identity_research::open(directory,&entropy,password,identity).map_err(|_|ProfileQueueError)?;
    Ok((keys,queue))
}

/// Return an encrypted NIP-49 backup only after opening the anchored profile.
/// The caller must protect and clear its own UI/clipboard copies.
#[cfg(feature = "messaging-identity-research")]
pub fn export_messaging_backup(directory:&Path,password:&str,identity:&BookIdentity)
    -> Result<zeroize::Zeroizing<String>,ProfileQueueError> {
    let network=match identity.network { Network::Mainnet=>VaultNetwork::Mainnet, Network::Floonet=>VaultNetwork::Floonet };
    let anchor=identity_anchor_research::read(directory,network).map_err(|_|ProfileQueueError)?;
    if anchor.wallet_id!=identity.wallet_id { return Err(ProfileQueueError); }
    let entropy=verified_wallet::open_published(directory,password,&anchor).map_err(|_|ProfileQueueError)?;
    super::messaging_identity_research::export_backup(directory,&entropy,password,identity).map_err(|_|ProfileQueueError)
}

/// Explicit import into an empty identity slot. Never replaces an existing or
/// indeterminate file, and returns only the Nostr public key.
#[cfg(feature = "messaging-identity-research")]
pub fn import_messaging_backup(directory:&Path,password:&str,identity:&BookIdentity,backup:&str,backup_password:&str)
    -> Result<nostr_sdk::PublicKey,ProfileQueueError> {
    let network=match identity.network { Network::Mainnet=>VaultNetwork::Mainnet, Network::Floonet=>VaultNetwork::Floonet };
    let anchor=identity_anchor_research::read(directory,network).map_err(|_|ProfileQueueError)?;
    if anchor.wallet_id!=identity.wallet_id { return Err(ProfileQueueError); }
    let entropy=verified_wallet::open_published(directory,password,&anchor).map_err(|_|ProfileQueueError)?;
    super::messaging_identity_research::import_backup_once(directory,&entropy,password,identity,backup,backup_password).map_err(|_|ProfileQueueError)
}

#[cfg(feature = "messaging-identity-research")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncProfileError { Busy, Unavailable }

#[cfg(feature = "messaging-identity-research")]
async fn run_profile_job<T:Send+'static>(job:impl FnOnce()->T+Send+'static)->Result<T,AsyncProfileError> {
    use std::sync::{Arc,OnceLock};
    static LIMIT:OnceLock<Arc<tokio::sync::Semaphore>>=OnceLock::new();
    let permit=LIMIT.get_or_init(||Arc::new(tokio::sync::Semaphore::new(1))).clone()
        .try_acquire_owned().map_err(|_|AsyncProfileError::Busy)?;
    tokio::task::spawn_blocking(move || { let _permit=permit; job() }).await.map_err(|_|AsyncProfileError::Unavailable)
}

/// Run password KDFs off the async executor, with at most one active profile
/// unlock in this process. Cancellation drops the caller's future but cannot
/// interrupt a KDF already running; the worker retains its permit until exit.
#[cfg(feature = "messaging-identity-research")]
pub async fn open_messaging_and_book_async(directory:&Path,password:&str,identity:&BookIdentity)
    -> Result<(nostr_sdk::Keys,BookKey),AsyncProfileError> {
    if password.is_empty() || password.len()>1024 { return Err(AsyncProfileError::Unavailable); }
    let path=directory.to_owned(); let password=zeroize::Zeroizing::new(password.to_owned()); let identity=*identity;
    run_profile_job(move ||open_messaging_and_book(&path,&password,&identity)).await?
        .map_err(|_|AsyncProfileError::Unavailable)
}

#[cfg(feature = "messaging-identity-research")]
pub async fn open_messaging_and_queue_async(directory:&Path,password:&str,identity:&BookIdentity)
    -> Result<(nostr_sdk::Keys,QueueKey),AsyncProfileError> {
    if password.is_empty() || password.len()>1024 { return Err(AsyncProfileError::Unavailable); }
    let path=directory.to_owned(); let password=zeroize::Zeroizing::new(password.to_owned()); let identity=*identity;
    run_profile_job(move ||open_messaging_and_queue(&path,&password,&identity)).await?
        .map_err(|_|AsyncProfileError::Unavailable)
}

/// Unlock and read retained text without returning the seed or queue key.
/// Both directories and the contact identity must be independently trusted.
/// This read is not a proof of delivery, completeness, or rollback safety.
pub fn read_outgoing_history(profile_directory: &Path, queue_directory: &Path, password: &str,
    identity: &QueueIdentity) -> Result<OutgoingHistory, ProfileQueueError> {
    let key = open_queue_key(profile_directory, password, identity)?;
    queue_store::load_history(queue_directory, &key, identity).map_err(|_| ProfileQueueError)
}

/// Return only locally authenticated relay-acknowledgement/expiry state.
/// The caller's clock may be wrong; relay acceptance is not user delivery.
pub fn read_outgoing_status(profile_directory: &Path, queue_directory: &Path, password: &str,
    identity: &QueueIdentity, now: u64) -> Result<OutgoingStatus, ProfileQueueError> {
    let key = open_queue_key(profile_directory, password, identity)?;
    queue_store::outgoing_status(queue_directory, &key, identity, now).map_err(|_| ProfileQueueError)
}

/// Select the profile by catalog ID and use its fixed messages directory.
/// The root and contact identity must come from trusted application state;
/// this does not create directories, authenticate contacts or prevent rollback.
pub fn read_catalog_history(catalog_root: &Path, profile_id: &str, password: &str,
    identity: &QueueIdentity) -> Result<OutgoingHistory, ProfileQueueError> {
    let catalog = fly_wallet::windows_catalog_research::Catalog::new(catalog_root).map_err(|_| ProfileQueueError)?;
    catalog.with_profile(profile_id, |profile, network| {
        let matches = matches!((network, identity.network),
            (fly_wallet::address::Network::Mainnet, Network::Mainnet) |
            (fly_wallet::address::Network::Floonet, Network::Floonet));
        if !matches { return Err(ProfileQueueError); }
        read_outgoing_history(profile, &profile.join("messages"), password, identity)
    }).map_err(|_| ProfileQueueError)?
}

/// Resolve only a catalog ID and obtain its separately protected identity.
/// Caller must keep the catalog root and all ancestors stable through use;
/// this identifies a profile but does not verify its password or contacts.
pub fn resolve_catalog_profile(catalog_root:&Path,profile_id:&str)
    -> Result<(std::path::PathBuf,BookIdentity),ProfileQueueError> {
    let catalog=fly_wallet::windows_catalog_research::Catalog::new(catalog_root).map_err(|_|ProfileQueueError)?;
    catalog.with_profile(profile_id,|profile,network| {
        let (network,vault_network)=match network {
            fly_wallet::address::Network::Mainnet=>(Network::Mainnet,VaultNetwork::Mainnet),
            fly_wallet::address::Network::Floonet=>(Network::Floonet,VaultNetwork::Floonet),
        };
        let anchor=identity_anchor_research::read(profile,vault_network).map_err(|_|ProfileQueueError)?;
        Ok((profile.to_path_buf(),BookIdentity { network,wallet_id:anchor.wallet_id }))
    }).map_err(|_|ProfileQueueError)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::{EventBuilder, Keys, Kind, Tag, Timestamp};
    use super::super::contact_session::PreparedMessage;
    use zeroize::Zeroizing;

    #[tokio::test]
    async fn synthetic_profile_unlocks_only_its_own_outgoing_history() {
        let root = std::path::PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        assert_eq!(std::fs::canonicalize(&root).unwrap(), std::fs::canonicalize(r"C:\DHW\GrinSight\FlyClient").unwrap());
        let tmp = root.join(".tmp");
        assert_eq!(std::fs::canonicalize(std::env::temp_dir()).unwrap(), std::fs::canonicalize(&tmp).unwrap());
        let mut random = [0u8; 16]; getrandom::getrandom(&mut random).unwrap();
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let dir = tmp.join(format!("fly-vault-queue-synthetic-{suffix}"));
        std::fs::create_dir(&dir).unwrap();
        let seed = Zeroizing::new([42u8; 16]);
        let anchor = verified_wallet::create_once(&dir, &*seed, "synthetic-password", VaultNetwork::Floonet).unwrap();
        identity_anchor_research::publish_once(&dir, &anchor).unwrap();
        let alice = Keys::generate(); let bob = Keys::generate();
        let identity = QueueIdentity { network:Network::Floonet, wallet_id:anchor.wallet_id,
            slot:[3;16], sender:alice.public_key(), recipient:bob.public_key() };
        let rumor = EventBuilder::new(Kind::PrivateDirectMessage, "SYNTHETIC")
            .tag(Tag::public_key(bob.public_key())).build(alice.public_key());
        let event = EventBuilder::gift_wrap(&alice, &bob.public_key(), rumor,
            [Tag::expiration(Timestamp::from(1900))]).await.unwrap();
        let prepared = PreparedMessage { event, sender:identity.sender, recipient:identity.recipient,
            expires_at:1900, local_history:Some(Zeroizing::new("SYNTHETIC".to_owned())) };
        let key = open_queue_key(&dir, "synthetic-password", &identity).unwrap();
        queue_store::persist(&dir, &key, &identity, &prepared, 1000).unwrap();
        drop(key); drop(seed);
        let history = read_outgoing_history(&dir, &dir, "synthetic-password", &identity).unwrap();
        assert_eq!(history.text(), "SYNTHETIC");
        assert_eq!(read_outgoing_status(&dir, &dir, "synthetic-password", &identity, 1900),
            Ok(OutgoingStatus::Unacknowledged { delivery_window_expired:true }));
        assert!(read_outgoing_history(&dir, &dir, "wrong", &identity).is_err());
        let key = open_queue_key(&dir, "synthetic-password", &identity).unwrap();
        assert!(queue_store::load(&dir, &key, &identity, 1900).is_err());
        assert!(open_queue_key(&dir, "wrong", &identity).is_err());
        let contacts=dir.join("contacts"); std::fs::create_dir(&contacts).unwrap();
        let book_identity=BookIdentity { network:Network::Floonet, wallet_id:identity.wallet_id };
        let book_key=open_book_key(&dir,"synthetic-password",&book_identity).unwrap();
        let contact=super::super::contact_book_research::Contact::new("Synthetic",bob.public_key()).unwrap();
        super::super::contact_book_research::create(&contacts,&book_key,&book_identity,&[4;16],&contact).unwrap();
        drop(book_key);
        let book_key=open_book_key(&dir,"synthetic-password",&book_identity).unwrap();
        assert_eq!(super::super::contact_book_research::read(&contacts,&book_key,&book_identity,&[4;16]).unwrap().public_key,bob.public_key());
        assert!(open_book_key(&dir,"wrong",&book_identity).is_err());
        #[cfg(feature = "messaging-identity-research")]
        {
            assert!(open_messaging_identity(&dir,"synthetic-password",&book_identity).is_err());
            let public=create_messaging_identity(&dir,"synthetic-password",&book_identity).unwrap();
            assert_eq!(open_messaging_identity(&dir,"synthetic-password",&book_identity).unwrap().public_key(),public);
            let (keys,book)=open_messaging_and_book(&dir,"synthetic-password",&book_identity).unwrap();
            assert_eq!(keys.public_key(),public);
            assert_eq!(super::super::contact_book_research::read(&contacts,&book,&book_identity,&[4;16]).unwrap().public_key,bob.public_key());
            assert!(open_messaging_and_book(&dir,"wrong",&book_identity).is_err());
            let (keys,book)=open_messaging_and_book_async(&dir,"synthetic-password",&book_identity).await.unwrap();
            assert_eq!(keys.public_key(),public);
            assert_eq!(super::super::contact_book_research::read(&contacts,&book,&book_identity,&[4;16]).unwrap().public_key,bob.public_key());
            assert!(matches!(open_messaging_and_book_async(&dir,"wrong",&book_identity).await,Err(AsyncProfileError::Unavailable)));
            let (keys,queue)=open_messaging_and_queue(&dir,"synthetic-password",&book_identity).unwrap();
            assert_eq!(keys.public_key(),public);
            assert_eq!(queue_store::load(&dir,&queue,&identity,1000).unwrap().event.id,prepared.event.id);
            assert!(open_messaging_and_queue(&dir,"wrong",&book_identity).is_err());
            let (keys,queue)=open_messaging_and_queue_async(&dir,"synthetic-password",&book_identity).await.unwrap();
            assert_eq!(keys.public_key(),public);
            assert_eq!(queue_store::load(&dir,&queue,&identity,1000).unwrap().event.id,prepared.event.id);
            assert!(matches!(open_messaging_and_queue_async(&dir,"wrong",&book_identity).await,Err(AsyncProfileError::Unavailable)));
            assert!(super::super::outgoing_resume_research::ProfileRecovery::from_profile(&dir,"synthetic-password",&book_identity).await.is_err());
            std::fs::create_dir(dir.join("messages")).unwrap();
            assert!(super::super::outgoing_resume_research::ProfileRecovery::from_profile(&dir,"wrong",&book_identity).await.is_err());
            let recovery=super::super::outgoing_resume_research::ProfileRecovery::from_profile(&dir,"synthetic-password",&book_identity).await.unwrap();
            recovery.stop_and_wait().await;
            drop(recovery);
            assert!(create_messaging_identity(&dir,"synthetic-password",&book_identity).is_err());
            assert!(open_messaging_identity(&dir,"wrong",&book_identity).is_err());
            let backup=export_messaging_backup(&dir,"synthetic-password",&book_identity).unwrap();
            assert!(export_messaging_backup(&dir,"wrong",&book_identity).is_err());
            let other_dir=dir.join("synthetic-restore"); std::fs::create_dir(&other_dir).unwrap();
            let other_seed=zeroize::Zeroizing::new([43u8;16]);
            let other_anchor=verified_wallet::create_once(&other_dir,&*other_seed,"new-password",VaultNetwork::Floonet).unwrap();
            identity_anchor_research::publish_once(&other_dir,&other_anchor).unwrap();
            let other=BookIdentity { network:Network::Floonet,wallet_id:other_anchor.wallet_id };
            assert!(import_messaging_backup(&other_dir,"new-password",&other,&backup,"wrong").is_err());
            assert_eq!(import_messaging_backup(&other_dir,"new-password",&other,&backup,"synthetic-password"),Ok(public));
            assert_eq!(open_messaging_identity(&other_dir,"new-password",&other).unwrap().public_key(),public);
            assert!(import_messaging_backup(&other_dir,"new-password",&other,&backup,"synthetic-password").is_err());
        }
        let mut wrong = identity; wrong.wallet_id[0] ^= 1;
        assert!(open_queue_key(&dir, "synthetic-password", &wrong).is_err());
        wrong = identity; wrong.network = Network::Mainnet;
        assert!(open_queue_key(&dir, "synthetic-password", &wrong).is_err());
    }

    #[tokio::test]
    async fn catalog_profile_reads_only_its_fixed_message_directory() {
        use fly_wallet::{address::Network as WalletNetwork, windows_catalog_research::Catalog,
            windows_profile_research::prepare_generated};
        let root = std::path::PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        assert_eq!(std::fs::canonicalize(&root).unwrap(), std::fs::canonicalize(r"C:\DHW\GrinSight\FlyClient").unwrap());
        let tmp = root.join(".tmp");
        assert_eq!(std::fs::canonicalize(std::env::temp_dir()).unwrap(), std::fs::canonicalize(&tmp).unwrap());
        let mut random=[0u8;16]; getrandom::getrandom(&mut random).unwrap();
        let suffix:String=random.iter().map(|b|format!("{b:02x}")).collect();
        let catalog_root=tmp.join(format!("fly-catalog-queue-synthetic-{suffix}"));
        std::fs::create_dir(&catalog_root).unwrap();
        let catalog=Catalog::new(&catalog_root).unwrap();
        let pending=prepare_generated(WalletNetwork::Floonet,12).unwrap();
        let created=catalog.create("Synthetic",pending.confirm_backup(),"synthetic-password").unwrap();
        let profile=catalog_root.join(&created.id);
        let (resolved,resolved_identity)=resolve_catalog_profile(&catalog_root,&created.id).unwrap();
        assert_eq!(std::fs::canonicalize(resolved).unwrap(),std::fs::canonicalize(&profile).unwrap());
        assert_eq!(resolved_identity.wallet_id,created.profile.identity.wallet_id);
        assert!(resolve_catalog_profile(&catalog_root,"../outside").is_err());
        let messages=profile.join("messages"); std::fs::create_dir(&messages).unwrap();
        #[cfg(feature = "messaging-identity-research")]
        {
            assert!(super::super::outgoing_resume_research::ProfileRecovery::open(&catalog_root,&created.id,"synthetic-password").await.is_err());
            create_messaging_identity(&profile,"synthetic-password",&resolved_identity).unwrap();
            assert!(super::super::outgoing_resume_research::ProfileRecovery::open(&catalog_root,"../outside","synthetic-password").await.is_err());
            assert!(super::super::outgoing_resume_research::ProfileRecovery::open(&catalog_root,&created.id,"wrong").await.is_err());
            let recovery=super::super::outgoing_resume_research::ProfileRecovery::open(&catalog_root,&created.id,"synthetic-password").await.unwrap();
            recovery.stop_and_wait().await;
            drop(recovery);
        }
        let alice=Keys::generate(); let bob=Keys::generate();
        let identity=QueueIdentity { network:Network::Floonet, wallet_id:created.profile.identity.wallet_id,
            slot:[3;16], sender:alice.public_key(), recipient:bob.public_key() };
        let rumor=EventBuilder::new(Kind::PrivateDirectMessage,"SYNTHETIC")
            .tag(Tag::public_key(bob.public_key())).build(alice.public_key());
        let event=EventBuilder::gift_wrap(&alice,&bob.public_key(),rumor,[Tag::expiration(Timestamp::from(1900))]).await.unwrap();
        let prepared=PreparedMessage { event, sender:identity.sender, recipient:identity.recipient,
            expires_at:1900, local_history:Some(Zeroizing::new("SYNTHETIC".to_owned())) };
        let key=open_queue_key(&profile,"synthetic-password",&identity).unwrap();
        queue_store::persist(&messages,&key,&identity,&prepared,1000).unwrap();
        drop(key);
        assert_eq!(read_catalog_history(&catalog_root,&created.id,"synthetic-password",&identity).unwrap().text(),"SYNTHETIC");
        assert!(read_catalog_history(&catalog_root,"../outside","synthetic-password",&identity).is_err());
        assert!(read_catalog_history(&catalog_root,&created.id,"wrong",&identity).is_err());
        let mut other=identity; other.network=Network::Mainnet;
        assert!(read_catalog_history(&catalog_root,&created.id,"synthetic-password",&other).is_err());
    }

    #[cfg(feature = "messaging-identity-research")]
    #[tokio::test]
    async fn blocking_profile_work_does_not_block_executor_or_allow_parallel_unlocks() {
        use std::time::Duration;
        let (started_tx,started_rx)=tokio::sync::oneshot::channel();
        let (release_tx,release_rx)=std::sync::mpsc::sync_channel::<()>(1);
        let task=tokio::spawn(async move {
            run_profile_job(move || {
                let _=started_tx.send(());
                release_rx.recv_timeout(Duration::from_secs(3)).is_ok()
            }).await
        });
        tokio::time::timeout(Duration::from_secs(2),started_rx).await.unwrap().unwrap();
        assert!(matches!(run_profile_job(||()).await,Err(AsyncProfileError::Busy)));
        release_tx.send(()).unwrap();
        assert_eq!(task.await.unwrap(),Ok(true));
        assert_eq!(run_profile_job(||42).await,Ok(42));
        let (started_tx,started_rx)=tokio::sync::oneshot::channel();
        let (release_tx,release_rx)=std::sync::mpsc::sync_channel::<()>(1);
        let cancelled=tokio::spawn(async move {
            run_profile_job(move || { let _=started_tx.send(()); let _=release_rx.recv_timeout(Duration::from_secs(3)); }).await
        });
        tokio::time::timeout(Duration::from_secs(2),started_rx).await.unwrap().unwrap();
        cancelled.abort();
        assert!(matches!(run_profile_job(||()).await,Err(AsyncProfileError::Busy)));
        release_tx.send(()).unwrap();
        let deadline=tokio::time::Instant::now()+Duration::from_secs(2);
        loop {
            match run_profile_job(||()).await {
                Ok(())=>break,
                Err(AsyncProfileError::Busy) if tokio::time::Instant::now()<deadline=>tokio::time::sleep(Duration::from_millis(10)).await,
                other=>panic!("worker permit not released: {other:?}"),
            }
        }
    }
}
