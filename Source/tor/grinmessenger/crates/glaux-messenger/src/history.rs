// SPDX-License-Identifier: MIT OR Apache-2.0
//! Encrypted conversation history (M2).
//!
//! The caller supplies a 32-byte key (the app will derive it from the wallet
//! password with Argon2id once phase 3 lands). Each record is a JSON object
//! encrypted with ChaCha20-Poly1305 and stored as `peer/<uuid>.msg`; the peer
//! address is the only visible metadata. The key is zeroized on drop.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::address::Address;
use crate::envelope::{unix_now, MessageKind};
use crate::error::{Error, Result};

const AAD_DOMAIN: &[u8] = b"glaux-messenger-history-v1";
const QUOTA_AAD: &[u8] = b"glaux-history-quota-index-v1";

#[derive(Default, Serialize, Deserialize)]
struct QuotaIndex { dirty: bool, text: usize, slate: usize }

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Incoming,
    Outgoing,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MessageRecord {
    pub id: String,
    pub direction: Direction,
    /// True only after the sender signature was verified before storage.
    #[serde(default)]
    pub signature_verified: bool,
    pub kind: MessageKind,
    pub created_at: u64,
    /// Unix timestamp after which the local history record may be deleted.
    /// `None` keeps legacy records (and messages without an explicit expiry).
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// Explicit local policy; old records default to false.
    #[serde(default)]
    pub local_expiry_opt_in: bool,
}

pub struct History {
    root: PathBuf,
    key: Zeroizing<[u8; 32]>,
    max_per_peer: usize,
    lock: Mutex<()>,
    seen_cache: Mutex<std::collections::HashMap<String, SeenCache>>,
    #[cfg(debug_assertions)] pub seen_full_reloads: std::sync::atomic::AtomicUsize,
    #[cfg(test)] scans: std::sync::atomic::AtomicUsize,
    #[cfg(debug_assertions)] pub payment_full_scans: std::sync::atomic::AtomicUsize,
}

#[derive(Serialize, Deserialize, Default)]
struct PaymentCheckpoint { version: u8, review: Vec<(String,String,Vec<u8>)>, processed: Vec<(String,String,Vec<u8>)> }

pub struct PaymentScan { root:PathBuf, items: Vec<(String,String)>, cursor: usize, index: std::collections::HashMap<(String,String),(bool,Vec<u8>)>, log_len:u64, log_head:[u8;32] }


struct SeenCache { entries:std::collections::BTreeMap<String,Vec<u8>>, base_hash:[u8;32], len:u64, head:[u8;32], base_modified:Option<std::time::SystemTime>, base_len:u64, log_modified:Option<std::time::SystemTime> }

impl History {
    pub fn open(root: impl Into<PathBuf>, key: [u8; 32]) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| Error::Store(format!("history: {e}")))?;
        Ok(Self {
            root,
            key: Zeroizing::new(key),
            max_per_peer: 2_000,
            lock: Mutex::new(()),
            seen_cache: Mutex::new(std::collections::HashMap::new()),
            #[cfg(debug_assertions)] seen_full_reloads: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)] scans: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(debug_assertions)] payment_full_scans: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    pub fn with_limit(mut self, max_per_peer: usize) -> Self {
        self.max_per_peer = max_per_peer;
        self
    }

    fn guard(&self) -> Result<(std::sync::MutexGuard<'_, ()>, fs::File)> {
        let started=std::time::Instant::now();
        let guard = loop {
            match self.lock.try_lock() {
                Ok(g) => break g,
                Err(std::sync::TryLockError::WouldBlock) if started.elapsed() < std::time::Duration::from_secs(3) => std::thread::sleep(std::time::Duration::from_millis(20)),
                Err(std::sync::TryLockError::WouldBlock) => return Err(Error::Store("history lock timed out".into())),
                Err(_) => return Err(Error::Store("history poisoned".into())),
            }
        };
        let file = fs::OpenOptions::new().read(true).write(true).create(true).open(self.root.join("history.lock"))
            .map_err(|e| Error::Store(format!("history lock open: {e}")))?;
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) if started.elapsed() < std::time::Duration::from_secs(3) => std::thread::sleep(std::time::Duration::from_millis(20)),
                Err(std::fs::TryLockError::WouldBlock) => return Err(Error::Store("history lock timed out".into())),
                Err(e) => return Err(Error::Store(format!("history lock: {e}"))),
            }
        }
        Ok((guard, file))
    }

    fn peer_dir(&self, peer: &Address) -> PathBuf {
        self.root.join(peer.to_string())
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.key[..]))
    }

    fn write_quota(&self, peer: &Address, index: &QuotaIndex) -> Result<()> {
        let plain=serde_json::to_vec(index).map_err(|e|Error::Store(format!("quota index encode: {e}")))?;
        let mut nonce=[0u8;12];getrandom::getrandom(&mut nonce).map_err(|e|Error::Crypto(format!("quota index RNG: {e}")))?;
        let mut aad=QUOTA_AAD.to_vec();aad.extend_from_slice(peer.to_string().as_bytes());
        let cipher=self.cipher().encrypt(Nonce::from_slice(&nonce),Payload{msg:&plain,aad:&aad}).map_err(|_|Error::Crypto("quota index encrypt".into()))?;
        let mut bytes=nonce.to_vec();bytes.extend_from_slice(&cipher);write_atomic(&self.peer_dir(peer).join("quota-index.enc"),&bytes)
    }

    fn scan_quota(&self, peer: &Address) -> Result<QuotaIndex> {
        let mut index=QuotaIndex::default();
        for item in self.read_records(peer)? { if matches!(item.kind,MessageKind::Slatepack { .. }) { index.slate+=1; } else { index.text+=1; } }
        Ok(index)
    }

    /// Caller holds the history OS lock. A dirty WAL is recovered by one scan.
    fn load_quota(&self, peer: &Address) -> Result<QuotaIndex> {
        let dir=self.peer_dir(peer);fs::create_dir_all(&dir).map_err(|e|Error::Store(format!("quota directory: {e}")))?;
        let path=dir.join("quota-index.enc");let sentinel=dir.join("quota-index.initialized");
        let mut marker_aad=b"glaux-quota-marker-v1".to_vec();marker_aad.extend_from_slice(peer.to_string().as_bytes());
        if !path.exists() {
            if sentinel.exists() {return Err(Error::Store("quota index missing after migration".into()));}
            let index=self.scan_quota(peer)?;self.write_quota(peer,&index)?;
            let mut nonce=[0u8;12];getrandom::getrandom(&mut nonce).map_err(|e|Error::Crypto(format!("quota marker RNG: {e}")))?;
            let cipher=self.cipher().encrypt(Nonce::from_slice(&nonce),Payload{msg:b"quota-v1",aad:&marker_aad}).map_err(|_|Error::Crypto("quota marker encrypt".into()))?;
            let mut bytes=nonce.to_vec();bytes.extend_from_slice(&cipher);write_atomic(&sentinel,&bytes)?;
            return Ok(index);
        }
        if !sentinel.exists() { return Err(Error::Store("quota migration marker missing".into())); }
        let marker=fs::read(sentinel).map_err(|e|Error::Store(format!("quota marker read: {e}")))?;
        if marker.len()<28 {return Err(Error::Store("quota migration marker truncated".into()));}
        let plain=self.cipher().decrypt(Nonce::from_slice(&marker[..12]),Payload{msg:&marker[12..],aad:&marker_aad}).map_err(|_|Error::Crypto("quota migration marker authentication".into()))?;
        if plain!=b"quota-v1" {return Err(Error::Store("quota migration marker invalid".into()));}
        let bytes=fs::read(path).map_err(|e|Error::Store(format!("quota index read: {e}")))?;
        if bytes.len()<28 {return Err(Error::Store("quota index truncated".into()));}
        let mut aad=QUOTA_AAD.to_vec();aad.extend_from_slice(peer.to_string().as_bytes());
        let plain=self.cipher().decrypt(Nonce::from_slice(&bytes[..12]),Payload{msg:&bytes[12..],aad:&aad}).map_err(|_|Error::Crypto("quota index authentication".into()))?;
        let index:QuotaIndex=serde_json::from_slice(&plain).map_err(|e|Error::Store(format!("quota index decode: {e}")))?;
        if index.dirty {let recovered=self.scan_quota(peer)?;self.write_quota(peer,&recovered)?;return Ok(recovered);}
        Ok(index)
    }

    fn aad(peer: &Address, id: &str) -> Vec<u8> {
        let mut out = AAD_DOMAIN.to_vec();
        out.extend_from_slice(peer.to_string().as_bytes());
        out.push(0);
        out.extend_from_slice(id.as_bytes());
        out
    }

    pub fn record(&self, peer: &Address, record: &MessageRecord) -> Result<()> {
        let _guard = self.guard()?;
        if uuid::Uuid::parse_str(&record.id).is_err() {
            return Err(Error::Envelope("history id должен быть UUID".into()));
        }
        let dir = self.peer_dir(peer);
        fs::create_dir_all(&dir).map_err(|e| Error::Store(format!("history: {e}")))?;
        let path = dir.join(format!("{}.msg", record.id));
        if let Some(expected)=self.seen_lookup_locked(peer,&record.id)? {
            if expected!=Self::replay_digest(record)? {return Err(Error::Crypto("history replay identity conflict".into()));}
            if !path.exists() && !self.marker_path(peer,&record.id).exists() {return Err(Error::Crypto("indexed seen marker missing".into()));}
            if !path.exists() {self.check_marker_locked(peer,&record.id,&expected)?;return Err(Error::Store("history record already deleted".into()));}
        }
        if self.marker_path(peer, &record.id).exists() {
            self.check_marker_locked(peer, &record.id, &Self::replay_digest(record)?)?;
            return Err(Error::Store("history record already deleted".into()));
        }
        if path.exists() {
            let old = self.read_record_path(peer, &record.id, &path)?;
            if Self::replay_digest(&old)? != Self::replay_digest(record)? { return Err(Error::Store("history replay identity conflict".into())); }
            return Ok(());
        }
        let mut quota = self.load_quota(peer)?;
        let is_slate = matches!(record.kind, MessageKind::Slatepack { .. });
        let used = if is_slate { quota.slate } else { quota.text };
        let limit = if is_slate { 256 } else { self.max_per_peer };
        if used >= limit {
            return Err(Error::Store(if is_slate { "payment message storage full; no payment request was deleted" } else { "text history full; payment message reserve remains available" }.into()));
        }
        // Generation advances before the durable message: a crash may cause
        // an unnecessary scan, but never an invisible new payment.
        if record.direction==Direction::Incoming && matches!(&record.kind,MessageKind::Slatepack{..}) {self.bump_payment_generation_locked()?;}
        let plaintext = Zeroizing::new(
            serde_json::to_vec(record)
                .map_err(|e| Error::Envelope(format!("history json: {e}")))?,
        );
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| Error::Crypto(format!("history RNG: {e}")))?;
        let ciphertext = self
            .cipher()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &Self::aad(peer, &record.id),
                },
            )
            .map_err(|_| Error::Crypto("history encrypt".into()))?;

        let mut bytes = Vec::with_capacity(12 + ciphertext.len());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);
        quota.dirty=true;self.write_quota(peer,&quota)?;
        write_atomic(&dir.join(format!("{}.msg", record.id)), &bytes)?;
        if is_slate { quota.slate+=1; } else { quota.text+=1; }
        quota.dirty=false;self.write_quota(peer,&quota)?;
        Ok(())
    }

    pub fn list(&self, peer: &Address, limit: usize) -> Result<Vec<MessageRecord>> {
        let _guard = self.guard()?;
        self.cleanup_peer_locked(peer, unix_now());
        let mut records = self.read_records(peer)?;
        records.sort_by_key(|record| record.created_at);
        // Keep the newest page, then return it chronologically. Taking the
        // first N made new messages invisible once a peer passed the limit.
        let keep = limit.max(1).min(records.len());
        let start = records.len() - keep;
        Ok(records.split_off(start))
    }

    /// Persistent dedup probe: the record file is the durable "seen" marker,
    /// so a relay replay after a restart is not surfaced as a new message.
    pub fn contains(&self, peer: &Address, id: &str) -> Result<bool> {
        let _guard = self.guard()?;
        if uuid::Uuid::parse_str(id).is_err() {
            return Ok(false);
        }
        Ok(self.peer_dir(peer).join(format!("{id}.msg")).is_file())
    }

    fn replay_digest(record: &MessageRecord) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(&(record.direction, &record.id, &record.kind, record.created_at))
            .map_err(|e| Error::Envelope(format!("history fingerprint: {e}")))?;
        Ok(Sha256::digest(bytes).to_vec())
    }

    fn marker_aad(peer: &Address, id: &str) -> Vec<u8> {
        let mut aad = b"glaux-history-replay-v2\0".to_vec();
        aad.extend_from_slice(&Self::aad(peer, id));
        aad
    }

    /// Persist an exact transport token before rejecting an unopenable event.
    pub fn quarantine_event(&self, token: &str) -> Result<()> {
        let _guard=self.guard()?;
        if token.is_empty() || token.len()>128 || !token.bytes().all(|b| b.is_ascii_hexdigit() || b==b':' || b==b'-') {
            return Err(Error::Store("invalid quarantine token".into()));
        }
        let name=data_encoding::HEXLOWER.encode(&Sha256::digest(token.as_bytes()));
        let dir=self.root.join("quarantine");fs::create_dir_all(&dir).map_err(|e|Error::Store(format!("quarantine: {e}")))?;
        let path=dir.join(format!("{name}.bad"));let aad=b"glaux-quarantine-v2";
        if path.exists() {
            let bytes=fs::read(path).map_err(|e|Error::Store(format!("quarantine read: {e}")))?;
            if bytes.len()<28 {return Err(Error::Store("quarantine truncated".into()));}
            let plain=self.cipher().decrypt(Nonce::from_slice(&bytes[..12]),Payload{msg:&bytes[12..],aad}).map_err(|_|Error::Crypto("quarantine authentication".into()))?;
            if plain!=token.as_bytes() {return Err(Error::Store("quarantine conflict".into()));}return Ok(());
        }
        let count=fs::read_dir(&dir).map_err(|e|Error::Store(format!("quarantine: {e}")))?.filter_map(|e|e.ok()).filter(|e|e.path().extension().is_some_and(|x|x=="bad")).count();
        if count>=1000 {return Err(Error::Quota("quarantine full; message not acknowledged".into()));}
        let mut nonce=[0u8;12];getrandom::getrandom(&mut nonce).map_err(|e|Error::Crypto(format!("quarantine RNG: {e}")))?;
        let data=self.cipher().encrypt(Nonce::from_slice(&nonce),Payload{msg:token.as_bytes(),aad}).map_err(|_|Error::Crypto("quarantine encrypt".into()))?;
        let mut bytes=nonce.to_vec();bytes.extend_from_slice(&data);write_atomic(&path,&bytes)
    }

    fn marker_path(&self, peer: &Address, id: &str) -> PathBuf {
        self.peer_dir(peer).join(format!("{id}.seen"))
    }

    fn seen_index_aad(peer:&Address)->Vec<u8> {let mut a=b"glaux-seen-index-v1\0".to_vec();a.extend_from_slice(peer.to_string().as_bytes());a}
    fn write_seen_index_locked(&self,peer:&Address,index:&std::collections::BTreeMap<String,Vec<u8>>)->Result<()> {
        let plain=serde_json::to_vec(index).map_err(|e|Error::Store(format!("seen index: {e}")))?;
        if plain.len()>16*1024*1024{return Err(Error::Store("seen index full".into()));}
        let mut nonce=[0u8;12];getrandom::getrandom(&mut nonce).map_err(|e|Error::Crypto(format!("seen index RNG: {e}")))?;
        let cipher=self.cipher().encrypt(Nonce::from_slice(&nonce),Payload{msg:&plain,aad:&Self::seen_index_aad(peer)}).map_err(|_|Error::Crypto("seen index encryption".into()))?;
        let mut bytes=nonce.to_vec();bytes.extend(cipher);write_atomic(&self.peer_dir(peer).join(".seen-index-v1"),&bytes)
    }
    fn load_seen_base_locked(&self,peer:&Address)->Result<std::collections::BTreeMap<String,Vec<u8>>> {
        let dir=self.peer_dir(peer);fs::create_dir_all(&dir).map_err(|e|Error::Store(format!("seen index directory: {e}")))?;
        let path=dir.join(".seen-index-v1");let marker=dir.join(".seen-index-initialized");
        let present=|p:&Path| -> Result<bool> {match fs::metadata(p) {Ok(meta) if meta.is_file()=>Ok(true),Ok(_)=>Err(Error::Store("seen index path is not a file".into())),Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(false),Err(e)=>Err(Error::Store(format!("seen index metadata: {e}")))}};
        match (present(&path)?,present(&marker)?) {
            (false,false)=>{
                // Conservative legacy migration: authenticate every extant marker.
                // Markers lost before migration are inherently unknowable.
                let mut index=std::collections::BTreeMap::new();
                for e in fs::read_dir(&dir).map_err(|e|Error::Store(format!("seen migration: {e}")))? {
                    let path=e.map_err(|e|Error::Store(format!("seen migration: {e}")))?.path();
                    if path.extension().and_then(|x|x.to_str())!=Some("seen"){continue;}
                    let id=path.file_stem().and_then(|x|x.to_str()).ok_or_else(||Error::Store("bad seen filename".into()))?;
                    if uuid::Uuid::parse_str(id).is_err(){return Err(Error::Store("bad seen id".into()));}
                    let raw=fs::read(&path).map_err(|e|Error::Store(format!("seen migration: {e}")))?;
                    if raw.len()<28{return Err(Error::Crypto("seen marker truncated".into()));}
                    let digest=self.cipher().decrypt(Nonce::from_slice(&raw[..12]),Payload{msg:&raw[12..],aad:&Self::marker_aad(peer,id)}).map_err(|_|Error::Crypto("seen marker authentication".into()))?;
                    if digest.len()!=32 || index.insert(id.to_string(),digest).is_some(){return Err(Error::Crypto("seen index invalid".into()));}
                }
                self.write_seen_index_locked(peer,&index)?;
                let mut nonce=[0u8;12];getrandom::getrandom(&mut nonce).map_err(|e|Error::Crypto(format!("seen marker RNG: {e}")))?;
                let cipher=self.cipher().encrypt(Nonce::from_slice(&nonce),Payload{msg:b"initialized",aad:&Self::seen_index_aad(peer)}).map_err(|_|Error::Crypto("seen marker encryption".into()))?;
                let mut bytes=nonce.to_vec();bytes.extend(cipher);write_atomic(&marker,&bytes)?;Ok(index)
            },
            (true,true)=>{
                let tag=fs::read(&marker).map_err(|e|Error::Store(format!("seen marker: {e}")))?;
                if tag.len()<28 || self.cipher().decrypt(Nonce::from_slice(&tag[..12]),Payload{msg:&tag[12..],aad:&Self::seen_index_aad(peer)}).map_err(|_|Error::Crypto("seen marker authentication".into()))?!=b"initialized" {return Err(Error::Crypto("seen marker invalid".into()));}
                let bytes=read_capped(&path,16*1024*1024)?;
                if bytes.len()<28 || bytes.len()>16*1024*1024{return Err(Error::Crypto("seen index damaged".into()));}
                let plain=self.cipher().decrypt(Nonce::from_slice(&bytes[..12]),Payload{msg:&bytes[12..],aad:&Self::seen_index_aad(peer)}).map_err(|_|Error::Crypto("seen index authentication".into()))?;
                let index:std::collections::BTreeMap<String,Vec<u8>>=serde_json::from_slice(&plain).map_err(|_|Error::Crypto("seen index invalid".into()))?;
                if index.iter().any(|(id,d)|uuid::Uuid::parse_str(id).is_err()||d.len()!=32){return Err(Error::Crypto("seen index invalid".into()));}Ok(index)
            },
            _=>Err(Error::Crypto("seen index migration incomplete or deleted".into())),
        }
    }

    fn seen_v2_aad(peer:&Address,base:&[u8;32],domain:&[u8])->Vec<u8>{let mut a=domain.to_vec();a.extend_from_slice(peer.to_string().as_bytes());a.extend_from_slice(base);a}
    fn write_seen_anchor_locked(&self,peer:&Address,base:&[u8;32],len:u64,head:&[u8;32])->Result<()> {
        let plain=serde_json::to_vec(&(1u8,len,head.to_vec())).map_err(|e|Error::Store(format!("seen anchor: {e}")))?;
        let mut nonce=[0u8;12];getrandom::getrandom(&mut nonce).map_err(|e|Error::Crypto(format!("seen anchor RNG: {e}")))?;
        let cipher=self.cipher().encrypt(Nonce::from_slice(&nonce),Payload{msg:&plain,aad:&Self::seen_v2_aad(peer,base,b"seen-anchor-v2")}).map_err(|_|Error::Crypto("seen anchor encryption".into()))?;
        let mut raw=nonce.to_vec();raw.extend(cipher);write_atomic(&self.peer_dir(peer).join(".seen-anchor-v2"),&raw)
    }
    fn read_seen_anchor_locked(&self,peer:&Address,base:&[u8;32])->Result<(u64,[u8;32])> {
        let raw=fs::read(self.peer_dir(peer).join(".seen-anchor-v2")).map_err(|e|Error::Store(format!("seen anchor: {e}")))?;
        if raw.len()<28 || raw.len()>4096{return Err(Error::Crypto("seen anchor invalid".into()));}
        let plain=self.cipher().decrypt(Nonce::from_slice(&raw[..12]),Payload{msg:&raw[12..],aad:&Self::seen_v2_aad(peer,base,b"seen-anchor-v2")}).map_err(|_|Error::Crypto("seen anchor authentication".into()))?;
        let (version,len,head):(u8,u64,Vec<u8>)=serde_json::from_slice(&plain).map_err(|_|Error::Crypto("seen anchor invalid".into()))?;
        if version!=1||head.len()!=32{return Err(Error::Crypto("seen anchor invalid".into()));}let mut h=[0;32];h.copy_from_slice(&head);Ok((len,h))
    }
    fn ensure_seen_cache_locked(&self,peer:&Address,cache:&mut std::collections::HashMap<String,SeenCache>)->Result<()> {
        let dir=self.peer_dir(peer);let key=peer.to_string();
        // Always verify that migration sentinel remains present, even on a cache hit.
        let meta=fs::metadata(dir.join(".seen-index-v1")).ok();
        if let (Some(current),Some(meta))=(cache.get(&key),meta.as_ref()) {
            if current.base_modified.is_some() && current.log_modified.is_some() && fs::metadata(dir.join(".seen-index-initialized")).is_ok() && meta.len()==current.base_len && meta.modified().ok()==current.base_modified {
                let v1=fs::read(dir.join(".seen-index-initialized")).map_err(|e|Error::Store(format!("seen marker: {e}")))?;
                if v1.len()<28 || self.cipher().decrypt(Nonce::from_slice(&v1[..12]),Payload{msg:&v1[12..],aad:&Self::seen_index_aad(peer)}).map_err(|_|Error::Crypto("seen marker authentication".into()))?!=b"initialized" {return Err(Error::Crypto("seen marker invalid".into()));}
                let v2=fs::read(dir.join(".seen-v2-ready")).map_err(|e|Error::Store(format!("seen ready: {e}")))?;
                if v2.len()<28 || self.cipher().decrypt(Nonce::from_slice(&v2[..12]),Payload{msg:&v2[12..],aad:&Self::seen_v2_aad(peer,&current.base_hash,b"seen-ready-v2")}).map_err(|_|Error::Crypto("seen ready authentication".into()))?!=b"ready" {return Err(Error::Crypto("seen ready invalid".into()));}
                let (len,head)=self.read_seen_anchor_locked(peer,&current.base_hash)?;
                let mut log=fs::File::open(dir.join(".seen-events-v2")).map_err(|e|Error::Store(format!("seen journal: {e}")))?;
                let log_meta=log.metadata().map_err(|e|Error::Store(format!("seen journal: {e}")))?;
                if log_meta.len()==len && log_meta.modified().ok()==current.log_modified && len==current.len && head==current.head {
                    log.seek(SeekFrom::End(-32)).map_err(|e|Error::Store(format!("seen journal: {e}")))?;let mut tail=[0;32];log.read_exact(&mut tail).map_err(|e|Error::Store(format!("seen journal: {e}")))?;
                    if tail==head{return Ok(());}
                }
            }
        }
        #[cfg(debug_assertions)] self.seen_full_reloads.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
        let mut entries=self.load_seen_base_locked(peer)?;
        if entries.len()>100_000{return Err(Error::Store("seen registry full".into()));}
        let base_path=dir.join(".seen-index-v1");let base=read_capped(&base_path,16*1024*1024)?;
        let base_hash:[u8;32]=Sha256::digest(&base).into();let base_meta=fs::metadata(&base_path).map_err(|e|Error::Store(format!("seen base: {e}")))?;
        let log_path=dir.join(".seen-events-v2");let anchor_path=dir.join(".seen-anchor-v2");let ready=dir.join(".seen-v2-ready");
        let present=|p:&Path|->Result<bool>{match fs::metadata(p){Ok(m) if m.is_file()=>Ok(true),Ok(_)=>Err(Error::Store("seen journal path invalid".into())),Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(false),Err(e)=>Err(Error::Store(format!("seen journal metadata: {e}")))}};
        match (present(&log_path)?,present(&anchor_path)?,present(&ready)?) {
            (false,false,false)=>{
                let mut f=fs::OpenOptions::new().write(true).create_new(true).open(&log_path).map_err(|e|Error::Store(format!("seen journal init: {e}")))?;
                f.write_all(&[0;32]).and_then(|_|f.sync_all()).map_err(|e|Error::Store(format!("seen journal init: {e}")))?;
                self.write_seen_anchor_locked(peer,&base_hash,32,&[0;32])?;
                let mut nonce=[0u8;12];getrandom::getrandom(&mut nonce).map_err(|e|Error::Crypto(format!("seen ready RNG: {e}")))?;
                let cipher=self.cipher().encrypt(Nonce::from_slice(&nonce),Payload{msg:b"ready",aad:&Self::seen_v2_aad(peer,&base_hash,b"seen-ready-v2")}).map_err(|_|Error::Crypto("seen ready encryption".into()))?;
                let mut bytes=nonce.to_vec();bytes.extend(cipher);write_atomic(&ready,&bytes)?;
            },
            (true,true,true)=>{},
            _=>return Err(Error::Crypto("seen journal initialization incomplete or missing".into())),
        }
        let ready_bytes=fs::read(&ready).map_err(|e|Error::Store(format!("seen ready: {e}")))?;
        if ready_bytes.len()<28 || self.cipher().decrypt(Nonce::from_slice(&ready_bytes[..12]),Payload{msg:&ready_bytes[12..],aad:&Self::seen_v2_aad(peer,&base_hash,b"seen-ready-v2")}).map_err(|_|Error::Crypto("seen ready authentication".into()))?!=b"ready" {return Err(Error::Crypto("seen ready invalid".into()));}
        let log=read_capped(&log_path,32*1024*1024)?;
        if log.len()<32 || log.len()>32*1024*1024 || log[..32]!=[0u8;32] {return Err(Error::Crypto("seen journal invalid".into()));}
        let (anchor_len,anchor_head)=self.read_seen_anchor_locked(peer,&base_hash)?;
        if anchor_len<32||anchor_len>log.len() as u64{return Err(Error::Crypto("seen journal truncated".into()));}
        let mut pos=32usize;let mut head=[0u8;32];let mut anchor_seen=anchor_len==32&&anchor_head==head;
        while pos<log.len(){
            if log.len()-pos<4{return Err(Error::Crypto("seen journal truncated".into()));}
            let n=u32::from_le_bytes(log[pos..pos+4].try_into().unwrap()) as usize;pos+=4;
            if n<28||n>4096||log.len()-pos<n+32{return Err(Error::Crypto("seen journal truncated".into()));}
            let frame=&log[pos..pos+n];pos+=n;let digest=&log[pos..pos+32];pos+=32;
            let mut hash=Sha256::new();hash.update(head);hash.update(frame);let next:[u8;32]=hash.finalize().into();if digest!=next{return Err(Error::Crypto("seen journal chain mismatch".into()));}
            let mut aad=Self::seen_v2_aad(peer,&base_hash,b"seen-event-v2");aad.extend_from_slice(&head);
            let plain=self.cipher().decrypt(Nonce::from_slice(&frame[..12]),Payload{msg:&frame[12..],aad:&aad}).map_err(|_|Error::Crypto("seen event authentication".into()))?;
            let (id,value):(String,Vec<u8>)=serde_json::from_slice(&plain).map_err(|_|Error::Crypto("seen event invalid".into()))?;
            if uuid::Uuid::parse_str(&id).is_err()||value.len()!=32{return Err(Error::Crypto("seen event invalid".into()));}
            if entries.insert(id,value.clone()).is_some_and(|old|old!=value){return Err(Error::Crypto("seen identity conflict".into()));}
            if entries.len()>100_000{return Err(Error::Store("seen registry full".into()));}head=next;
            if pos as u64==anchor_len{if head!=anchor_head{return Err(Error::Crypto("seen anchor mismatch".into()));}anchor_seen=true;}
        }
        if !anchor_seen{return Err(Error::Crypto("seen anchor not on event boundary".into()));}
        if anchor_len<log.len() as u64 {self.write_seen_anchor_locked(peer,&base_hash,log.len() as u64,&head)?;}
        if cache.len()>=8&&!cache.contains_key(&key){cache.clear();}
        cache.insert(key,SeenCache{entries,base_hash,len:log.len() as u64,head,base_modified:base_meta.modified().ok(),base_len:base_meta.len(),log_modified:fs::metadata(&log_path).ok().and_then(|m|m.modified().ok())});Ok(())
    }
    fn seen_lookup_locked(&self,peer:&Address,id:&str)->Result<Option<Vec<u8>>> {
        let mut cache=self.seen_cache.lock().map_err(|_|Error::Store("seen cache poisoned".into()))?;self.ensure_seen_cache_locked(peer,&mut cache)?;
        Ok(cache.get(&peer.to_string()).and_then(|c|c.entries.get(id)).cloned())
    }
    fn seen_remember_locked(&self,peer:&Address,id:&str,digest:&[u8])->Result<()> {
        let mut cache=self.seen_cache.lock().map_err(|_|Error::Store("seen cache poisoned".into()))?;self.ensure_seen_cache_locked(peer,&mut cache)?;
        let c=cache.get_mut(&peer.to_string()).ok_or_else(||Error::Store("seen cache unavailable".into()))?;
        if let Some(old)=c.entries.get(id) {if old!=digest{return Err(Error::Crypto("seen identity conflict".into()));}return Ok(());}
        if c.entries.len()>=100_000{return Err(Error::Store("seen registry full".into()));}
        let mut nonce=[0u8;12];getrandom::getrandom(&mut nonce).map_err(|e|Error::Crypto(format!("seen event RNG: {e}")))?;
        let plain=serde_json::to_vec(&(id,digest)).map_err(|e|Error::Store(format!("seen event: {e}")))?;
        let mut aad=Self::seen_v2_aad(peer,&c.base_hash,b"seen-event-v2");aad.extend_from_slice(&c.head);
        let cipher=self.cipher().encrypt(Nonce::from_slice(&nonce),Payload{msg:&plain,aad:&aad}).map_err(|_|Error::Crypto("seen event encryption".into()))?;
        let mut frame=nonce.to_vec();frame.extend(cipher);let mut hash=Sha256::new();hash.update(c.head);hash.update(&frame);let head:[u8;32]=hash.finalize().into();
        let mut entry=(frame.len() as u32).to_le_bytes().to_vec();entry.extend(frame);entry.extend(head);
        if c.len.saturating_add(entry.len() as u64)>32*1024*1024{return Err(Error::Store("seen journal full".into()));}
        let mut file=fs::OpenOptions::new().append(true).open(self.peer_dir(peer).join(".seen-events-v2")).map_err(|e|Error::Store(format!("seen journal: {e}")))?;
        file.write_all(&entry).and_then(|_|file.sync_all()).map_err(|e|Error::Store(format!("seen journal write: {e}")))?;
        #[cfg(test)]
        if let Ok(path)=std::env::var("GS_SEEN_PAUSE_AFTER_APPEND") {
            let mut marker=fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(|e|Error::Store(format!("test marker: {e}")))?;
            marker.write_all(b"journal-synced").and_then(|_|marker.sync_all()).map_err(|e|Error::Store(format!("test marker: {e}")))?;
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
        self.write_seen_anchor_locked(peer,&c.base_hash,c.len+entry.len() as u64,&head)?;
        #[cfg(test)]
        if let Ok(path)=std::env::var("GS_SEEN_PAUSE_AFTER_ANCHOR") {
            let mut marker=fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(|e|Error::Store(format!("test marker: {e}")))?;
            marker.write_all(b"anchor-synced").and_then(|_|marker.sync_all()).map_err(|e|Error::Store(format!("test marker: {e}")))?;
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
        c.len+=entry.len() as u64;c.head=head;c.log_modified=fs::metadata(self.peer_dir(peer).join(".seen-events-v2")).ok().and_then(|m|m.modified().ok());c.entries.insert(id.to_string(),digest.to_vec());Ok(())
    }

    fn save_marker_locked(&self, peer: &Address, record: &MessageRecord) -> Result<()> {
        let path = self.marker_path(peer, &record.id);
        let expected = Self::replay_digest(record)?;
        self.seen_remember_locked(peer,&record.id,&expected)?;
        if path.exists() {
            return self.check_marker_locked(peer, &record.id, &expected);
        }
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| Error::Crypto(format!("history RNG: {e}")))?;
        let cipher = self.cipher().encrypt(Nonce::from_slice(&nonce), Payload { msg: &expected, aad: &Self::marker_aad(peer, &record.id) })
            .map_err(|_| Error::Crypto("history marker encrypt".into()))?;
        let mut data = nonce.to_vec();
        data.extend_from_slice(&cipher);
        write_atomic(&path, &data)
    }

    fn check_marker_locked(&self, peer: &Address, id: &str, expected: &[u8]) -> Result<()> {
        let data = fs::read(self.marker_path(peer, id)).map_err(|e| Error::Store(format!("history marker read: {e}")))?;
        if data.len() < 28 { return Err(Error::Store("history marker truncated".into())); }
        let got = self.cipher().decrypt(Nonce::from_slice(&data[..12]), Payload { msg: &data[12..], aad: &Self::marker_aad(peer, id) })
            .map_err(|_| Error::Crypto("history marker authentication".into()))?;
        if got != expected { return Err(Error::Store("history replay identity conflict".into())); }
        Ok(())
    }

    /// Authenticate the existing record or retained tombstone before ACK.
    pub fn contains_record(&self, peer: &Address, incoming: &MessageRecord) -> Result<bool> {
        let _guard = self.guard()?;
        self.load_quota(peer)?;
        if uuid::Uuid::parse_str(&incoming.id).is_err() { return Err(Error::Envelope("invalid history id".into())); }
        let expected = Self::replay_digest(incoming)?;
        let indexed=self.seen_lookup_locked(peer,&incoming.id)?;
        let marker = self.marker_path(peer, &incoming.id);
        let path = self.peer_dir(peer).join(format!("{}.msg", incoming.id));
        if let Some(saved)=indexed {
            if saved!=expected{return Err(Error::Crypto("history replay identity conflict".into()));}
            if marker.exists(){self.check_marker_locked(peer,&incoming.id,&expected)?;return Ok(true);}
            if !path.exists(){return Err(Error::Crypto("indexed seen marker missing".into()));}
            // A crash between index and marker is safe while original record exists.
        } else if marker.exists(){return Err(Error::Crypto("seen index missing marker identity".into()));}
        if !path.exists() { return Ok(false); }
        let saved = self.read_record_path(peer, &incoming.id, &path)?;
        if Self::replay_digest(&saved)? != expected { return Err(Error::Store("history replay identity conflict".into())); }
        Ok(true)
    }

    fn read_record_path(&self, peer: &Address, id: &str, path: &Path) -> Result<MessageRecord> {
        let bytes=fs::read(path).map_err(|e|Error::Store(format!("history: {e}")))?;
        if bytes.len()<=12 {return Err(Error::Store("history record truncated".into()));}
        let plaintext=self.cipher().decrypt(Nonce::from_slice(&bytes[..12]),Payload{msg:&bytes[12..],aad:&Self::aad(peer,id)}).map_err(|_|Error::Crypto("history: не удалось расшифровать запись".into()))?;
        let record:MessageRecord=serde_json::from_slice(&plaintext).map_err(|e|Error::Envelope(format!("history json: {e}")))?;
        if record.id!=id {return Err(Error::Store("history record id mismatch".into()));}Ok(record)
    }

    fn read_records(&self, peer: &Address) -> Result<Vec<MessageRecord>> {
        #[cfg(test)] self.scans.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
        let dir = self.peer_dir(peer);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut records = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|e| Error::Store(format!("history: {e}")))? {
            let path = entry
                .map_err(|e| Error::Store(format!("history: {e}")))?
                .path();
            if path.extension().and_then(|e| e.to_str()) != Some("msg") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            records.push(self.read_record_path(peer,id,&path)?);
        }
        Ok(records)
    }
    pub fn conversations(&self) -> Result<Vec<Address>> {
        let _guard = self.guard()?;
        let mut peers = Vec::new();
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Ok(peers);
        };
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(peer) = Address::parse(name) {
                    self.cleanup_peer_locked(&peer, unix_now());
                    peers.push(peer);
                }
            }
        }
        Ok(peers)
    }

    fn payment_generation_locked(&self)->Result<Option<u64>> {
        let path=self.root.join(".payment-generation-v1");
        let bytes=match fs::read(path) {Ok(x)=>x,Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(None),Err(e)=>return Err(Error::Store(format!("payment generation: {e}")))};
        if bytes.len()<28 || bytes.len()>512{return Err(Error::Crypto("payment generation damaged".into()));}
        let plain=self.cipher().decrypt(Nonce::from_slice(&bytes[..12]),Payload{msg:&bytes[12..],aad:b"glaux-payment-generation-v1"}).map_err(|_|Error::Crypto("payment generation authentication".into()))?;
        let value: (u8,u64)=serde_json::from_slice(&plain).map_err(|_|Error::Crypto("payment generation invalid".into()))?;
        if value.0!=1{return Err(Error::Crypto("payment generation invalid".into()));}Ok(Some(value.1))
    }
    fn write_payment_generation_locked(&self,generation:u64)->Result<()> {
        let plain=serde_json::to_vec(&(1u8,generation)).map_err(|e|Error::Store(format!("payment generation: {e}")))?;
        let mut nonce=[0u8;12];getrandom::getrandom(&mut nonce).map_err(|e|Error::Crypto(format!("payment generation RNG: {e}")))?;
        let cipher=self.cipher().encrypt(Nonce::from_slice(&nonce),Payload{msg:&plain,aad:b"glaux-payment-generation-v1"}).map_err(|_|Error::Crypto("payment generation encryption".into()))?;
        let mut bytes=nonce.to_vec();bytes.extend(cipher);write_atomic(&self.root.join(".payment-generation-v1"),&bytes)
    }
    fn bump_payment_generation_locked(&self)->Result<()> {
        match self.payment_generation_locked()? {
            Some(g)=>self.write_payment_generation_locked(g.checked_add(1).ok_or_else(||Error::Store("payment generation overflow".into()))?),
            None if self.root.join(".payment-checkpoint-v2").exists()=>Err(Error::Crypto("payment generation missing".into())),
            None=>Ok(()), // before migration, initialization snapshots all records
        }
    }
    pub fn payment_generation(&self)->Result<u64> {
        let _guard=self.guard()?;self.payment_generation_locked()?.ok_or_else(||Error::Crypto("payment generation missing".into()))
    }

    /// Constant-cost watch used between full authenticated scans.
    pub fn payment_watch(&self)->Result<(u64,u64,[u8;32],u64,[u8;32])> {
        let _guard=self.guard()?;
        let generation=self.payment_generation_locked()?.ok_or_else(||Error::Crypto("payment generation missing".into()))?;
        let (anchor_len,anchor_head)=self.read_payment_anchor_locked()?;
        let mut file=fs::File::open(self.root.join(".payment-events-v2")).map_err(|e|Error::Store(format!("payment journal: {e}")))?;
        let len=file.metadata().map_err(|e|Error::Store(format!("payment journal: {e}")))?.len();
        if len<32 || len>64*1024*1024{return Err(Error::Crypto("payment journal invalid".into()));}
        file.seek(SeekFrom::End(-32)).map_err(|e|Error::Store(format!("payment journal: {e}")))?;let mut tail=[0u8;32];file.read_exact(&mut tail).map_err(|e|Error::Store(format!("payment journal: {e}")))?;
        Ok((generation,anchor_len,anchor_head,len,tail))
    }

    fn read_payment_anchor_locked(&self)->Result<(u64,[u8;32])> {
        let bytes=fs::read(self.root.join(".payment-anchor-v2")).map_err(|e|Error::Store(format!("payment anchor unavailable: {e}")))?;
        if bytes.len()<28 || bytes.len()>4096{return Err(Error::Crypto("payment anchor damaged".into()));}
        let plain=self.cipher().decrypt(Nonce::from_slice(&bytes[..12]),Payload{msg:&bytes[12..],aad:b"glaux-payment-anchor-v2"}).map_err(|_|Error::Crypto("payment anchor authentication".into()))?;
        let (version,len,head):(u8,u64,Vec<u8>)=serde_json::from_slice(&plain).map_err(|_|Error::Crypto("invalid payment anchor".into()))?;
        if version!=2 || head.len()!=32{return Err(Error::Crypto("invalid payment anchor".into()));}
        let mut array=[0;32];array.copy_from_slice(&head);Ok((len,array))
    }
    fn write_payment_anchor_locked(&self,len:u64,head:&[u8;32])->Result<()> {
        let plain=serde_json::to_vec(&(2u8,len,head.to_vec())).map_err(|e|Error::Store(format!("payment anchor: {e}")))?;
        let mut nonce=[0u8;12];getrandom::getrandom(&mut nonce).map_err(|e|Error::Crypto(format!("payment anchor RNG: {e}")))?;
        let cipher=self.cipher().encrypt(Nonce::from_slice(&nonce),Payload{msg:&plain,aad:b"glaux-payment-anchor-v2"}).map_err(|_|Error::Crypto("payment anchor encryption".into()))?;
        let mut bytes=nonce.to_vec();bytes.extend(cipher);write_atomic(&self.root.join(".payment-anchor-v2"),&bytes)
    }

    fn payment_checkpoint_locked(&self) -> Result<Option<PaymentCheckpoint>> {
        let path=self.root.join(".payment-checkpoint-v2");
        match fs::metadata(&path) {Ok(_) => {}, Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(None), Err(e)=>return Err(Error::Store(format!("payment checkpoint metadata: {e}")))}
        let bytes=read_capped(&path,64*1024*1024)?;
        if bytes.len()<28 || bytes.len()>64*1024*1024 { return Err(Error::Crypto("payment checkpoint damaged".into())); }
        let plain=self.cipher().decrypt(Nonce::from_slice(&bytes[..12]),Payload{msg:&bytes[12..],aad:b"glaux-payment-checkpoint-v2"}).map_err(|_|Error::Crypto("payment checkpoint authentication".into()))?;
        let mut state:PaymentCheckpoint=serde_json::from_slice(&plain).map_err(|_|Error::Crypto("invalid payment checkpoint".into()))?;
        if state.version!=2 || !state.processed.is_empty() || state.review.iter().any(|(p,id,d)|Address::parse(p).is_err() || uuid::Uuid::parse_str(id).is_err() || d.len()!=32) {return Err(Error::Crypto("invalid payment checkpoint".into()));}
        let journal=read_capped(&self.root.join(".payment-events-v2"),64*1024*1024)?;
        if journal.len()<32 || journal[..32]!=[0u8;32] || journal.len()>64*1024*1024 {return Err(Error::Crypto("payment journal invalid".into()));}
        let (anchor_len,anchor_head)=self.read_payment_anchor_locked()?;
        if anchor_len<32 || anchor_len>journal.len() as u64{return Err(Error::Crypto("payment journal rolled back or truncated".into()));}
        let mut anchor_seen=anchor_len==32 && anchor_head==[0u8;32];
        let mut pos=32usize;let mut head=[0u8;32];
        while pos<journal.len() {
            if journal.len()-pos<4{return Err(Error::Crypto("payment journal truncated".into()));}
            let size=u32::from_le_bytes(journal[pos..pos+4].try_into().unwrap()) as usize;pos+=4;
            if size<28 || size>4096 || journal.len()-pos<size+32{return Err(Error::Crypto("payment journal truncated".into()));}
            let frame=&journal[pos..pos+size];pos+=size;let saved=&journal[pos..pos+32];pos+=32;
            let mut hash=Sha256::new();hash.update(head);hash.update(frame);let next:[u8;32]=hash.finalize().into();
            if saved!=next{return Err(Error::Crypto("payment journal chain mismatch".into()));}
            let mut aad=b"glaux-payment-event-v2".to_vec();aad.extend_from_slice(&head);
            let plain=self.cipher().decrypt(Nonce::from_slice(&frame[..12]),Payload{msg:&frame[12..],aad:&aad}).map_err(|_|Error::Crypto("payment event authentication".into()))?;
            let event:(String,String,Vec<u8>)=serde_json::from_slice(&plain).map_err(|_|Error::Crypto("invalid payment event".into()))?;
            if Address::parse(&event.0).is_err() || uuid::Uuid::parse_str(&event.1).is_err() || event.2.len()!=32{return Err(Error::Crypto("invalid payment event".into()));}
            state.processed.push(event);head=next;
            if pos as u64==anchor_len {if head!=anchor_head{return Err(Error::Crypto("payment journal anchor mismatch".into()));}anchor_seen=true;}
        }
        if !anchor_seen{return Err(Error::Crypto("payment journal anchor not on record boundary".into()));}
        if anchor_len<journal.len() as u64 {self.write_payment_anchor_locked(journal.len() as u64,&head)?;}
        Ok(Some(state))
    }
    fn save_payment_checkpoint_locked(&self,state:&PaymentCheckpoint)->Result<()> {
        let plain=Zeroizing::new(serde_json::to_vec(state).map_err(|e|Error::Store(format!("payment checkpoint: {e}")))?);
        if plain.len()>64*1024*1024 {return Err(Error::Store("payment checkpoint full".into()));}
        let mut nonce=[0u8;12];getrandom::getrandom(&mut nonce).map_err(|e|Error::Crypto(format!("payment checkpoint RNG: {e}")))?;
        let encrypted=self.cipher().encrypt(Nonce::from_slice(&nonce),Payload{msg:&plain,aad:b"glaux-payment-checkpoint-v2"}).map_err(|_|Error::Crypto("payment checkpoint encryption".into()))?;
        let mut bytes=nonce.to_vec();bytes.extend(encrypted);write_atomic(&self.root.join(".payment-checkpoint-v2"),&bytes)
    }
    fn all_payment_records_locked(&self)->Result<Vec<(String,MessageRecord)>> {
        let mut rows=Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|e|Error::Store(format!("history: {e}")))? {
            let entry=entry.map_err(|e|Error::Store(format!("history: {e}")))?;
            if !entry.file_type().map_err(|e|Error::Store(format!("history: {e}")))?.is_dir() {continue;}
            let name=entry.file_name().into_string().map_err(|_|Error::Store("invalid history directory".into()))?;
            let Ok(peer)=Address::parse(&name) else {continue};
            for record in self.read_records(&peer)? {
                if record.direction==Direction::Incoming && matches!(&record.kind,MessageKind::Slatepack{..}) {rows.push((name.clone(),record));}
            }
        }
        rows.sort_by(|a,b|(&a.0,&a.1.id).cmp(&(&b.0,&b.1.id))); Ok(rows)
    }
    /// Create the cutover atomically under the same cross-process lock as history writes.
    /// All pre-existing incoming payment messages require explicit review.
    pub fn initialize_payment_checkpoint(&self)->Result<()> {
        let _guard=self.guard()?;
        if self.payment_checkpoint_locked()?.is_some() {return Ok(());}
        if self.payment_generation_locked()?.is_some() {return Err(Error::Crypto("orphaned payment generation; manual recovery required".into()));}
        match fs::metadata(self.root.join(".payment-anchor-v2")) {Ok(_)=>return Err(Error::Crypto("orphaned payment anchor; manual recovery required".into())),Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},Err(e)=>return Err(Error::Store(format!("payment anchor metadata: {e}")))}
        let mut state=PaymentCheckpoint{version:2,..Default::default()};
        for (peer,record) in self.all_payment_records_locked()? {state.review.push((peer,record.id.clone(),Self::replay_digest(&record)?));}
        let mut journal=fs::OpenOptions::new().write(true).create_new(true).open(self.root.join(".payment-events-v2")).map_err(|e|Error::Store(format!("payment journal initialization: {e}")))?;
        journal.write_all(&[0u8;32]).and_then(|_|journal.sync_all()).map_err(|e|Error::Store(format!("payment journal initialization: {e}")))?;
        self.write_payment_anchor_locked(32,&[0u8;32])?;
        self.write_payment_generation_locked(0)?;
        self.save_payment_checkpoint_locked(&state)
    }
    /// Ordered page of durable incoming payment records; never reads the UI cache.
    /// The boolean is true when an old message needs manual recovery.
    pub fn payment_page(&self,after:Option<(&str,&str)>,limit:usize)->Result<Vec<(String,MessageRecord,bool)>> {
        let _guard=self.guard()?;
        let state=self.payment_checkpoint_locked()?.ok_or_else(||Error::Store("payment checkpoint missing".into()))?;
        let rows=self.all_payment_records_locked()?;
        let mut index=std::collections::HashMap::new();
        for (review,items) in [(true,&state.review),(false,&state.processed)] {
            for (peer,id,digest) in items {
                if index.insert((peer.clone(),id.clone()),(review,digest)).is_some() {return Err(Error::Crypto("duplicate payment checkpoint entry".into()));}
            }
        }
        let mut known=std::collections::HashSet::new();
        for (peer,record) in &rows {
            if let Some((_,digest))=index.get(&(peer.clone(),record.id.clone())) {
                if **digest!=Self::replay_digest(record)? {return Err(Error::Crypto("payment checkpoint content mismatch".into()));}
                known.insert((peer.clone(),record.id.clone()));
            }
        }
        if known.len()!=index.len() {return Err(Error::Crypto("indexed payment history missing".into()));}
        let mut out=Vec::new();
        for (peer,record) in rows {
            if after.is_some_and(|(p,id)|(peer.as_str(),record.id.as_str()) <= (p,id)) {continue;}
            let state=index.get(&(peer.clone(),record.id.clone()));
            if state.is_some_and(|(review,_)| !review) {continue;}
            out.push((peer,record,state.is_some()));
            if out.len()>=limit.clamp(1,1000) {break;}
        }
        Ok(out)
    }
    /// Bounded manual-review page; only the selected records are decrypted.
    pub fn legacy_review_page(&self,offset:usize,limit:usize)->Result<(Vec<(String,MessageRecord)>,usize,bool)> {
        let _guard=self.guard()?;
        let bytes=read_capped(&self.root.join(".payment-checkpoint-v2"),64*1024*1024)?;
        if bytes.len()<28 || bytes.len()>64*1024*1024{return Err(Error::Crypto("payment checkpoint damaged".into()));}
        let plain=self.cipher().decrypt(Nonce::from_slice(&bytes[..12]),Payload{msg:&bytes[12..],aad:b"glaux-payment-checkpoint-v2"}).map_err(|_|Error::Crypto("payment checkpoint authentication".into()))?;
        let state:PaymentCheckpoint=serde_json::from_slice(&plain).map_err(|_|Error::Crypto("invalid payment checkpoint".into()))?;
        if state.version!=2 || !state.processed.is_empty(){return Err(Error::Crypto("invalid payment checkpoint".into()));}
        let start=offset.min(state.review.len());let end=start.saturating_add(limit.clamp(1,100)).min(state.review.len());let mut rows=Vec::new();
        for (peer,id,digest) in &state.review[start..end] {
            let address=Address::parse(peer)?;if uuid::Uuid::parse_str(id).is_err()||digest.len()!=32{return Err(Error::Crypto("invalid review entry".into()));}
            let bytes=fs::read(self.peer_dir(&address).join(format!("{id}.msg"))).map_err(|e|Error::Store(format!("review record unavailable: {e}")))?;
            if bytes.len()<=12{return Err(Error::Crypto("review record truncated".into()));}
            let plain=self.cipher().decrypt(Nonce::from_slice(&bytes[..12]),Payload{msg:&bytes[12..],aad:&Self::aad(&address,id)}).map_err(|_|Error::Crypto("review record authentication".into()))?;
            let record:MessageRecord=serde_json::from_slice(&plain).map_err(|_|Error::Crypto("review record invalid".into()))?;
            if record.id!=*id || record.direction!=Direction::Incoming || !matches!(&record.kind,MessageKind::Slatepack{..}) || Self::replay_digest(&record)?!=*digest{return Err(Error::Crypto("review record mismatch".into()));}
            rows.push((peer.clone(),record));
        }
        Ok((rows,end,end<state.review.len()))
    }

    /// A bounded scan session snapshots filenames once. New arrivals are picked
    /// up by the next session; pages decrypt at most `limit` records.
    pub fn begin_payment_scan(&self)->Result<PaymentScan> {
        #[cfg(debug_assertions)] self.payment_full_scans.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
        let _guard=self.guard()?;
        let state=self.payment_checkpoint_locked()?.ok_or_else(||Error::Store("payment checkpoint missing".into()))?;
        self.payment_generation_locked()?.ok_or_else(||Error::Crypto("payment generation missing".into()))?;
        let mut index=std::collections::HashMap::new();
        for (review,items) in [(true,&state.review),(false,&state.processed)] {
            for (peer,id,digest) in items {if index.insert((peer.clone(),id.clone()),(review,digest.clone())).is_some(){return Err(Error::Crypto("duplicate payment checkpoint entry".into()));}}
        }
        let mut items=Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|e|Error::Store(format!("history: {e}")))? {
            let entry=entry.map_err(|e|Error::Store(format!("history: {e}")))?;
            if !entry.file_type().map_err(|e|Error::Store(format!("history: {e}")))?.is_dir(){continue;}
            let name=entry.file_name().into_string().map_err(|_|Error::Store("invalid history directory".into()))?;
            if Address::parse(&name).is_err(){continue;}
            for child in fs::read_dir(entry.path()).map_err(|e|Error::Store(format!("history: {e}")))? {
                let path=child.map_err(|e|Error::Store(format!("history: {e}")))?.path();
                if path.extension().and_then(|e|e.to_str())!=Some("msg"){continue;}
                let id=path.file_stem().and_then(|s|s.to_str()).ok_or_else(||Error::Store("invalid history file".into()))?.to_string();
                if uuid::Uuid::parse_str(&id).is_err(){return Err(Error::Store("invalid history id".into()));}
                items.push((name.clone(),id));if items.len()>100_000{return Err(Error::Store("history scan exceeds safe limit".into()));}
            }
        }
        items.sort();let present:std::collections::HashSet<_>=items.iter().cloned().collect();
        if index.keys().any(|k|!present.contains(k)){return Err(Error::Crypto("indexed payment history missing".into()));}
        let mut journal=fs::File::open(self.root.join(".payment-events-v2")).map_err(|e|Error::Store(format!("payment journal: {e}")))?;
        let log_len=journal.metadata().map_err(|e|Error::Store(format!("payment journal: {e}")))?.len();
        if log_len<32{return Err(Error::Crypto("payment journal invalid".into()));}
        journal.seek(SeekFrom::End(-32)).map_err(|e|Error::Store(format!("payment journal: {e}")))?;
        let mut log_head=[0u8;32];journal.read_exact(&mut log_head).map_err(|e|Error::Store(format!("payment journal: {e}")))?;
        let root=fs::canonicalize(&self.root).map_err(|e|Error::Store(format!("history root: {e}")))?;
        Ok(PaymentScan{root,items,cursor:0,index,log_len,log_head})
    }
    pub fn next_payment_scan(&self,scan:&mut PaymentScan,limit:usize)->Result<(Vec<(String,MessageRecord,bool)>,bool)> {
        let _guard=self.guard()?;
        if fs::canonicalize(&self.root).map_err(|e|Error::Store(format!("history root: {e}")))? != scan.root {return Err(Error::Store("payment scan profile mismatch".into()));}
        let end=scan.cursor.saturating_add(limit.clamp(1,1000)).min(scan.items.len());let mut out=Vec::new();
        while scan.cursor<end {
            let (peer,id)=&scan.items[scan.cursor];let address=Address::parse(peer)?;
            let path=self.peer_dir(&address).join(format!("{id}.msg"));
            let bytes=fs::read(&path).map_err(|e|Error::Store(format!("history scan: {e}")))?;
            if bytes.len()<=12{return Err(Error::Crypto("truncated history record".into()));}
            let plain=self.cipher().decrypt(Nonce::from_slice(&bytes[..12]),Payload{msg:&bytes[12..],aad:&Self::aad(&address,id)}).map_err(|_|Error::Crypto("history record authentication".into()))?;
            let record:MessageRecord=serde_json::from_slice(&plain).map_err(|_|Error::Crypto("invalid history record".into()))?;
            if record.id!=*id{return Err(Error::Crypto("history id mismatch".into()));}
            let status=scan.index.get(&(peer.clone(),id.clone()));
            if let Some((_,digest))=status {if *digest!=Self::replay_digest(&record)? {return Err(Error::Crypto("payment checkpoint content mismatch".into()));}}
            if record.direction==Direction::Incoming && matches!(&record.kind,MessageKind::Slatepack{..}) && !status.is_some_and(|(review,_)|!*review) {
                if status.is_none() && !record.signature_verified {return Err(Error::Crypto("unverified new payment requires recovery".into()));}
                out.push((peer.clone(),record,status.is_some()));
            }
            scan.cursor+=1;
        }
        Ok((out,scan.cursor==scan.items.len()))
    }

    /// Validate an incremental event against durable authenticated history and
    /// the checkpoint snapshot; None means already processed or requires review.
    pub fn payment_event_candidate(&self,scan:&PaymentScan,peer:&str,id:&str)->Result<Option<MessageRecord>> {
        let _guard=self.guard()?;
        if fs::canonicalize(&self.root).map_err(|e|Error::Store(format!("history root: {e}")))? != scan.root {return Err(Error::Store("payment scan profile mismatch".into()));}
        let address=Address::parse(peer)?;if uuid::Uuid::parse_str(id).is_err(){return Err(Error::Store("invalid payment event id".into()));}
        let path=self.peer_dir(&address).join(format!("{id}.msg"));let record=self.read_record_path(&address,id,&path)?;
        if record.direction!=Direction::Incoming || !record.signature_verified || !matches!(&record.kind,MessageKind::Slatepack{..}) {return Err(Error::Crypto("payment event is not a verified incoming slatepack".into()));}
        if let Some((_,digest))=scan.index.get(&(peer.to_string(),id.to_string())) {
            if *digest!=Self::replay_digest(&record)?{return Err(Error::Crypto("payment event identity mismatch".into()));}
            return Ok(None);
        }
        Ok(Some(record))
    }

    /// Trusted internal integration only: invoke after the wallet handler has
    /// durably stored the inbox/pending request or terminal transaction result.
    /// This method is deliberately not exposed through the messenger HTTP API.
    #[doc(hidden)]
    pub fn mark_payment_processed_after_durable_handler(&self,scan:&mut PaymentScan,peer:&str,id:&str)->Result<()> {
        let _guard=self.guard()?;
        if fs::canonicalize(&self.root).map_err(|e|Error::Store(format!("history root: {e}")))? != scan.root {return Err(Error::Store("payment scan profile mismatch".into()));}
        let address=Address::parse(peer)?;if uuid::Uuid::parse_str(id).is_err(){return Err(Error::Store("invalid payment id".into()));}
        let bytes=fs::read(self.peer_dir(&address).join(format!("{id}.msg"))).map_err(|e|Error::Store(format!("payment record: {e}")))?;
        if bytes.len()<=12{return Err(Error::Crypto("payment record truncated".into()));}
        let plain=self.cipher().decrypt(Nonce::from_slice(&bytes[..12]),Payload{msg:&bytes[12..],aad:&Self::aad(&address,id)}).map_err(|_|Error::Crypto("payment record authentication".into()))?;
        let record:MessageRecord=serde_json::from_slice(&plain).map_err(|_|Error::Crypto("payment record invalid".into()))?;
        if record.id!=id || record.direction!=Direction::Incoming || !matches!(&record.kind,MessageKind::Slatepack{..}) {return Err(Error::Crypto("payment record identity".into()));}
        let key=(peer.to_string(),id.to_string());let digest=Self::replay_digest(&record)?;
        if let Some((review,old))=scan.index.get(&key) {if *review{return Err(Error::Store("payment requires manual review".into()));}if *old!=digest{return Err(Error::Crypto("payment checkpoint content mismatch".into()));}return Ok(());}
        if scan.index.len()>=100_000 {return Err(Error::Store("payment scan cache full; no outcome marked".into()));}
        let path=self.root.join(".payment-events-v2");let mut file=fs::OpenOptions::new().read(true).append(true).open(&path).map_err(|e|Error::Store(format!("payment journal: {e}")))?;
        let len=file.metadata().map_err(|e|Error::Store(format!("payment journal: {e}")))?.len();if len<32 || len>64*1024*1024 || len!=scan.log_len{return Err(Error::Crypto("payment journal changed; restart scan".into()));}
        file.seek(SeekFrom::End(-32)).map_err(|e|Error::Store(format!("payment journal: {e}")))?;let mut head=[0u8;32];file.read_exact(&mut head).map_err(|e|Error::Store(format!("payment journal: {e}")))?;
        if head!=scan.log_head {return Err(Error::Crypto("payment journal changed; restart scan".into()));}
        let event=serde_json::to_vec(&(peer,id,&digest)).map_err(|e|Error::Store(format!("payment event: {e}")))?;
        let mut nonce=[0u8;12];getrandom::getrandom(&mut nonce).map_err(|e|Error::Crypto(format!("payment RNG: {e}")))?;
        let mut aad=b"glaux-payment-event-v2".to_vec();aad.extend_from_slice(&head);
        let cipher=self.cipher().encrypt(Nonce::from_slice(&nonce),Payload{msg:&event,aad:&aad}).map_err(|_|Error::Crypto("payment event encryption".into()))?;
        let mut frame=nonce.to_vec();frame.extend(cipher);let mut hash=Sha256::new();hash.update(head);hash.update(&frame);let new_head:[u8;32]=hash.finalize().into();
        let mut entry=(frame.len() as u32).to_le_bytes().to_vec();entry.extend(frame);entry.extend(new_head);
        if len.saturating_add(entry.len() as u64)>64*1024*1024{return Err(Error::Store("payment journal full".into()));}
        file.write_all(&entry).and_then(|_|file.sync_all()).map_err(|e|Error::Store(format!("payment journal write: {e}")))?;
        #[cfg(test)]
        if let Ok(path)=std::env::var("GS_PAYMENT_PAUSE_AFTER_APPEND") {
            let mut marker=fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(|e|Error::Store(format!("test marker: {e}")))?;
            marker.write_all(b"journal-synced").and_then(|_|marker.sync_all()).map_err(|e|Error::Store(format!("test marker: {e}")))?;
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
        self.write_payment_anchor_locked(len+entry.len() as u64,&new_head)?;
        scan.log_len+=entry.len() as u64;scan.log_head=new_head;scan.index.insert(key,(false,digest));Ok(())
    }

    pub fn delete(&self, peer: &Address, id: &str) -> Result<bool> {
        let _guard = self.guard()?;
        if uuid::Uuid::parse_str(id).is_err() {
            return Ok(false);
        }
        let path = self.peer_dir(peer).join(format!("{id}.msg"));
        if path.exists() {
            let record = self.read_record_path(peer, id, &path)?;
            self.save_marker_locked(peer, &record)?;
            self.remove_record_locked(peer, &record, &path)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn remove_record_locked(&self, peer: &Address, record: &MessageRecord, path: &Path) -> Result<()> {
        let mut quota=self.load_quota(peer)?;
        let slate=matches!(record.kind,MessageKind::Slatepack { .. });
        if (if slate {quota.slate} else {quota.text})==0 {return Err(Error::Store("quota count mismatch".into()));}
        quota.dirty=true;self.write_quota(peer,&quota)?;
        fs::remove_file(path).map_err(|e|Error::Store(format!("history delete: {e}")))?;
        if slate {quota.slate-=1;} else {quota.text-=1;}
        quota.dirty=false;self.write_quota(peer,&quota)
    }

    fn cleanup_peer_locked(&self, peer: &Address, now: u64) -> usize {
        let Ok(records) = self.read_records(peer) else {
            return 0;
        };
        let mut removed = 0;
        for record in records {
            if record.local_expiry_opt_in && matches!(record.kind, MessageKind::Text { .. }) && record
                .expires_at
                .is_some_and(|expires_at| expires_at <= now)
            {
                let path = self.peer_dir(peer).join(format!("{}.msg", record.id));
                if self.save_marker_locked(peer, &record).is_ok() && self.remove_record_locked(peer, &record, &path).is_ok() {
                    removed += 1;
                }
            }
        }
        removed
    }

    /// Delete locally expired encrypted history records. Corrupt records are
    /// left untouched so a damaged file is not silently treated as absent.
    pub fn cleanup_expired(&self, now: u64) -> Result<usize> {
        let _guard = self.guard()?;
        let mut removed = 0;
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Ok(0);
        };
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if let Ok(peer) = Address::parse(&name) {
                removed += self.cleanup_peer_locked(&peer, now);
            }
        }
        Ok(removed)
    }


}
fn read_capped(path:&Path,max:u64)->Result<Vec<u8>> {
    let file=fs::File::open(path).map_err(|e|Error::Store(format!("history read: {e}")))?;
    if file.metadata().map_err(|e|Error::Store(format!("history metadata: {e}")))?.len()>max{return Err(Error::Store("history file exceeds safe limit".into()));}
    let mut out=Vec::new();file.take(max+1).read_to_end(&mut out).map_err(|e|Error::Store(format!("history read: {e}")))?;
    if out.len() as u64>max{return Err(Error::Store("history file exceeds safe limit".into()));}Ok(out)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_file_name(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("history"),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let write = || -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| Error::Store(format!("history write: {e}")))?;
        file.write_all(bytes)
            .map_err(|e| Error::Store(format!("history write: {e}")))?;
        file.sync_all()
            .map_err(|e| Error::Store(format!("history fsync: {e}")))?;
        drop(file);
        fs::rename(&tmp, path).map_err(|e| Error::Store(format!("history rename: {e}")))?;
        #[cfg(unix)]
        fs::File::open(path.parent().ok_or_else(|| Error::Store("history parent missing".into()))?)
            .and_then(|dir| dir.sync_all()).map_err(|e| Error::Store(format!("history directory sync: {e}")))?;
        Ok(())
    };
    match write() {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::MessageKind;
    use uuid::Uuid;

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("glaux-hist-{tag}-{}", Uuid::new_v4()))
    }

    fn peer() -> Address {
        let identity = crate::Identity::from_seed([9u8; 32], "tgrin").unwrap();
        identity.address().clone()
    }

    fn record(text: &str, at: u64) -> MessageRecord {
        MessageRecord {
            id: Uuid::new_v4().to_string(),
            direction: Direction::Incoming,
            signature_verified: true,
            kind: MessageKind::Text { text: text.into() },
            created_at: at,
            expires_at: None,
            local_expiry_opt_in: false,
        }
    }

    #[test]
    fn high_frequency_watch_does_not_rescan_and_new_payment_invalidates_it() {
        use std::sync::atomic::Ordering;
        let dir=temp_dir("payment-watch");let peer=peer();let h=History::open(&dir,[7;32]).unwrap();h.initialize_payment_checkpoint().unwrap();
        let first=h.payment_watch().unwrap();let scans=h.scans.load(Ordering::Relaxed);let start=std::time::Instant::now();
        for _ in 0..1000 {assert_eq!(h.payment_watch().unwrap(),first);}
        eprintln!("PAYMENT_WATCH_1000_MS={}",start.elapsed().as_millis());assert_eq!(h.scans.load(Ordering::Relaxed),scans);
        let text=record("text",1);h.record(&peer,&text).unwrap();assert_eq!(h.payment_watch().unwrap(),first);
        let mut payment=record("payment",2);payment.kind=MessageKind::Slatepack{armor:"test".into(),encrypted:true};h.record(&peer,&payment).unwrap();
        let changed=h.payment_watch().unwrap();assert!(changed.0>first.0);
        fs::remove_file(dir.join(".payment-generation-v1")).unwrap();assert!(h.payment_watch().is_err());
        let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn seen_anchor_crash_worker() {
        let Ok(root)=std::env::var("GS_SEEN_CRASH_ROOT") else{return;};
        let h=History::open(&root,[7;32]).unwrap();let peer=peer();let item=record("crash",1);
        let mut item=item;item.id="11111111-1111-4111-8111-111111111111".into();
        let stage=std::env::var("GS_SEEN_CRASH_STAGE").unwrap_or_else(|_|"append".into());
        let key=if stage=="anchor" {"GS_SEEN_PAUSE_AFTER_ANCHOR"} else {"GS_SEEN_PAUSE_AFTER_APPEND"};
        std::env::set_var(key,Path::new(&root).join("journal-synced"));h.delete(&peer,&item.id).unwrap();
    }
    #[test]
    fn seen_process_kill_after_journal_before_anchor_keeps_message_recoverable() {
        let dir=temp_dir("seen-anchor-kill");let peer=peer();let h=History::open(&dir,[7;32]).unwrap();let mut item=record("crash",1);item.id="11111111-1111-4111-8111-111111111111".into();h.record(&peer,&item).unwrap();drop(h);
        let mut child=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","history::tests::seen_anchor_crash_worker"]).env("GS_SEEN_CRASH_ROOT",&dir).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
        let until=std::time::Instant::now()+std::time::Duration::from_secs(5);while !dir.join("journal-synced").exists()&&std::time::Instant::now()<until{std::thread::sleep(std::time::Duration::from_millis(10));}
        if !dir.join("journal-synced").exists(){let _=child.kill();let _=child.wait();panic!("child did not reach seen journal fsync");}
        child.kill().unwrap();child.wait().unwrap();
        let h=History::open(&dir,[7;32]).unwrap();assert!(h.contains_record(&peer,&item).unwrap());assert!(h.delete(&peer,&item.id).unwrap());assert!(h.contains_record(&peer,&item).unwrap());let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn seen_process_kill_after_anchor_before_marker_keeps_original() {
        let dir=temp_dir("seen-marker-kill");let peer=peer();let h=History::open(&dir,[7;32]).unwrap();let mut item=record("crash",1);item.id="11111111-1111-4111-8111-111111111111".into();h.record(&peer,&item).unwrap();drop(h);
        let mut child=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","history::tests::seen_anchor_crash_worker"]).env("GS_SEEN_CRASH_ROOT",&dir).env("GS_SEEN_CRASH_STAGE","anchor").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
        let until=std::time::Instant::now()+std::time::Duration::from_secs(5);while !dir.join("journal-synced").exists()&&std::time::Instant::now()<until{std::thread::sleep(std::time::Duration::from_millis(10));}
        if !dir.join("journal-synced").exists(){let _=child.kill();let _=child.wait();panic!("child did not reach seen anchor");}child.kill().unwrap();child.wait().unwrap();
        let h=History::open(&dir,[7;32]).unwrap();assert!(h.contains_record(&peer,&item).unwrap());assert!(h.delete(&peer,&item.id).unwrap());assert!(h.contains_record(&peer,&item).unwrap());let _=fs::remove_dir_all(dir);
    }
    #[test]
    fn seen_journal_tamper_or_missing_anchor_fails_closed_after_cache() {
        let dir=temp_dir("seen-journal-tamper");let peer=peer();let h=History::open(&dir,[7;32]).unwrap();let a=record("a",1);h.record(&peer,&a).unwrap();h.delete(&peer,&a.id).unwrap();assert!(h.contains_record(&peer,&a).unwrap());
        let path=h.peer_dir(&peer).join(".seen-events-v2");let mut data=fs::read(&path).unwrap();data[40]^=1;std::thread::sleep(std::time::Duration::from_millis(20));fs::write(&path,data).unwrap();assert!(h.contains_record(&peer,&a).is_err());
        let _=fs::remove_dir_all(dir);
        let dir=temp_dir("seen-anchor-missing");let h=History::open(&dir,[7;32]).unwrap();let a=record("a",1);h.record(&peer,&a).unwrap();h.delete(&peer,&a.id).unwrap();fs::remove_file(h.peer_dir(&peer).join(".seen-anchor-v2")).unwrap();assert!(h.contains_record(&peer,&a).is_err());let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn seen_cache_invalidates_across_instances_and_detects_missing_marker() {
        let dir=temp_dir("seen-cache-other-instance");let peer=peer();let a=History::open(&dir,[7;32]).unwrap();let b=History::open(&dir,[7;32]).unwrap();
        let x=record("a",1);a.record(&peer,&x).unwrap();a.delete(&peer,&x.id).unwrap();assert!(a.contains_record(&peer,&x).unwrap());
        let y=record("b",2);b.record(&peer,&y).unwrap();b.delete(&peer,&y.id).unwrap();assert!(a.contains_record(&peer,&y).unwrap());
        fs::remove_file(a.marker_path(&peer,&y.id)).unwrap();assert!(a.contains_record(&peer,&y).is_err());
        let _=fs::remove_dir_all(dir);
    }
    #[test]
    #[cfg(debug_assertions)]
    fn seen_incremental_registry_handles_thousand_deletions_without_reload() {
        use std::sync::atomic::Ordering;
        let dir=temp_dir("seen-1000");let peer=peer();let h=History::open(&dir,[7;32]).unwrap();
        let start=std::time::Instant::now();
        for n in 0..1000 {let r=record("synthetic",n);h.record(&peer,&r).unwrap();h.delete(&peer,&r.id).unwrap();}
        eprintln!("SEEN_1000_MS={} RELOADS={}",start.elapsed().as_millis(),h.seen_full_reloads.load(Ordering::Relaxed));
        assert!(h.seen_full_reloads.load(Ordering::Relaxed)<=2,"full reload per message is forbidden");
        drop(h);let h=History::open(&dir,[7;32]).unwrap();let r=record("fresh",2000);h.record(&peer,&r).unwrap();let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn authenticated_seen_index_detects_missing_marker_and_handles_interrupted_delete() {
        let dir=temp_dir("seen-index-missing");let peer=peer();let h=History::open(&dir,[7;32]).unwrap();
        let item=record("deleted",1);h.record(&peer,&item).unwrap();assert!(h.delete(&peer,&item.id).unwrap());
        let marker=h.marker_path(&peer,&item.id);fs::remove_file(&marker).unwrap();
        assert!(h.contains_record(&peer,&item).is_err());assert!(h.record(&peer,&item).is_err());drop(h);
        let h=History::open(&dir,[7;32]).unwrap();assert!(h.contains_record(&peer,&item).is_err());let _=fs::remove_dir_all(dir);
        let dir=temp_dir("seen-index-interrupted");let h=History::open(&dir,[7;32]).unwrap();let item=record("still-here",1);h.record(&peer,&item).unwrap();
        {let _guard=h.guard().unwrap();h.save_marker_locked(&peer,&item).unwrap();fs::remove_file(h.marker_path(&peer,&item.id)).unwrap();}
        assert!(h.contains_record(&peer,&item).unwrap(),"original authenticated record remains retry-safe");
        assert!(h.delete(&peer,&item.id).unwrap());assert!(h.contains_record(&peer,&item).unwrap());
        let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_or_tampered_seen_index_fails_closed() {
        let dir=temp_dir("seen-index-tamper");let peer=peer();let h=History::open(&dir,[7;32]).unwrap();let item=record("x",1);h.record(&peer,&item).unwrap();h.delete(&peer,&item.id).unwrap();
        let idx=h.peer_dir(&peer).join(".seen-index-v1");let mut raw=fs::read(&idx).unwrap();let n=raw.len()-1;raw[n]^=1;fs::write(&idx,raw).unwrap();assert!(h.contains_record(&peer,&item).is_err());
        fs::remove_file(idx).unwrap();assert!(h.contains_record(&peer,&item).is_err());let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn payment_scan_recovers_over_ten_thousand_records() {
        let dir=temp_dir("payment-10001");let peer=peer();let h=History::open(&dir,[7;32]).unwrap();fs::create_dir_all(h.peer_dir(&peer)).unwrap();
        for n in 0..10_001u64 {
            let mut r=record("x",n);r.id=Uuid::from_u128(n as u128+1).to_string();r.kind=MessageKind::Slatepack{armor:format!("payload-{n}"),encrypted:true};
            let plain=serde_json::to_vec(&r).unwrap();let nonce=[0;12];let cipher=h.cipher().encrypt(Nonce::from_slice(&nonce),Payload{msg:&plain,aad:&History::aad(&peer,&r.id)}).unwrap();
            let mut data=nonce.to_vec();data.extend(cipher);fs::write(h.peer_dir(&peer).join(format!("{}.msg",r.id)),data).unwrap();
        }
        h.initialize_payment_checkpoint().unwrap();drop(h);let h=History::open(&dir,[7;32]).unwrap();
        let start=std::time::Instant::now();let mut scan=h.begin_payment_scan().unwrap();let mut count=0;
        loop {let (page,done)=h.next_payment_scan(&mut scan,100).unwrap();assert!(page.len()<=100);assert!(page.iter().all(|r|r.2));count+=page.len();if done{break;}}
        let elapsed=start.elapsed();eprintln!("PAYMENT_SCAN_10001_MS={}",elapsed.as_millis());
        assert!(elapsed<std::time::Duration::from_secs(30),"scan exceeded 30 s");assert_eq!(count,10_001);let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn journal_anchor_crash_worker() {
        let Ok(root)=std::env::var("GS_JOURNAL_ANCHOR_TEST") else{return;};
        let h=History::open(&root,[7;32]).unwrap();let mut scan=h.begin_payment_scan().unwrap();let (page,_)=h.next_payment_scan(&mut scan,10).unwrap();assert_eq!(page.len(),1);
        // In production this durable result is supplied by the handler before mark.
        let mut result=fs::OpenOptions::new().write(true).create_new(true).open(Path::new(&root).join("durable-result")).unwrap();result.write_all(b"result").unwrap();result.sync_all().unwrap();drop(result);
        std::env::set_var("GS_PAYMENT_PAUSE_AFTER_APPEND",Path::new(&root).join("journal-synced"));
        h.mark_payment_processed_after_durable_handler(&mut scan,&page[0].0,&page[0].1.id).unwrap();
    }
    #[test]
    fn process_kill_after_journal_fsync_before_anchor_recovers() {
        let dir=temp_dir("payment-anchor-kill");let peer=peer();let h=History::open(&dir,[7;32]).unwrap();h.initialize_payment_checkpoint().unwrap();
        let mut r=record("x",1);r.kind=MessageKind::Slatepack{armor:"test".into(),encrypted:true};h.record(&peer,&r).unwrap();drop(h);
        let mut child=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","history::tests::journal_anchor_crash_worker"]).env("GS_JOURNAL_ANCHOR_TEST",&dir).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
        let until=std::time::Instant::now()+std::time::Duration::from_secs(5);while !dir.join("journal-synced").exists()&&std::time::Instant::now()<until {std::thread::sleep(std::time::Duration::from_millis(10));}
        if !dir.join("journal-synced").exists(){let _=child.kill();let _=child.wait();panic!("child did not reach journal fsync");}
        child.kill().unwrap();child.wait().unwrap();assert_eq!(fs::read(dir.join("durable-result")).unwrap(),b"result");
        let h=History::open(&dir,[7;32]).unwrap();let mut scan=h.begin_payment_scan().unwrap();let (page,done)=h.next_payment_scan(&mut scan,10).unwrap();assert!(done&&page.is_empty());let _=fs::remove_dir_all(dir);
    }
    #[test]
    fn missing_or_tampered_anchor_fails_closed() {
        let dir=temp_dir("payment-anchor-missing");let h=History::open(&dir,[7;32]).unwrap();h.initialize_payment_checkpoint().unwrap();
        let path=dir.join(".payment-anchor-v2");let original=fs::read(&path).unwrap();let mut bad=original.clone();let n=bad.len()-1;bad[n]^=1;fs::write(&path,bad).unwrap();assert!(h.begin_payment_scan().is_err());
        fs::remove_file(&path).unwrap();assert!(h.begin_payment_scan().is_err());let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn payment_crash_worker() {
        let Ok(root)=std::env::var("GS_PAYMENT_CRASH_TEST") else {return;};
        let h=History::open(&root,[7;32]).unwrap();let page=h.payment_page(None,10).unwrap();assert_eq!(page.len(),1);assert!(!page[0].2);
        let mut file=fs::OpenOptions::new().create_new(true).write(true).open(Path::new(&root).join("durable-pending" )).unwrap();file.write_all(b"pending").unwrap();file.sync_all().unwrap();
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
    #[test]
    fn payment_scan_retries_after_process_dies_before_mark() {
        let dir=temp_dir("payment-kill");let peer=peer();let h=History::open(&dir,[7;32]).unwrap();h.initialize_payment_checkpoint().unwrap();
        let mut r=record("x",1);r.kind=MessageKind::Slatepack{armor:"test".into(),encrypted:true};h.record(&peer,&r).unwrap();drop(h);
        let mut child=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","history::tests::payment_crash_worker"]).env("GS_PAYMENT_CRASH_TEST",&dir).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
        let until=std::time::Instant::now()+std::time::Duration::from_secs(5);while !dir.join("durable-pending").exists()&&std::time::Instant::now()<until{std::thread::sleep(std::time::Duration::from_millis(10));}
        assert!(dir.join("durable-pending").exists());child.kill().unwrap();child.wait().unwrap();
        let h=History::open(&dir,[7;32]).unwrap();let page=h.payment_page(None,10).unwrap();assert_eq!(page.len(),1);assert!(!page[0].2);
        let mut scan=h.begin_payment_scan().unwrap();h.mark_payment_processed_after_durable_handler(&mut scan,&peer.to_string(),&r.id).unwrap();drop(h);let h=History::open(&dir,[7;32]).unwrap();assert!(h.payment_page(None,10).unwrap().is_empty());let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn incremental_payment_marks_are_append_only_and_recoverable() {
        let dir=temp_dir("payment-1000-marks");let peer=peer();let h=History::open(&dir,[7;32]).unwrap();h.initialize_payment_checkpoint().unwrap();fs::create_dir_all(h.peer_dir(&peer)).unwrap();
        for n in 0..1000u64 {
            let mut r=record("x",n);r.id=Uuid::from_u128(n as u128+1).to_string();r.kind=MessageKind::Slatepack{armor:format!("payload-{n}"),encrypted:true};
            let plain=serde_json::to_vec(&r).unwrap();let nonce=[0;12];let cipher=h.cipher().encrypt(Nonce::from_slice(&nonce),Payload{msg:&plain,aad:&History::aad(&peer,&r.id)}).unwrap();let mut data=nonce.to_vec();data.extend(cipher);fs::write(h.peer_dir(&peer).join(format!("{}.msg",r.id)),data).unwrap();
        }
        let start=std::time::Instant::now();let mut scan=h.begin_payment_scan().unwrap();let mut count=0;
        loop {let (page,done)=h.next_payment_scan(&mut scan,100).unwrap();for (p,r,review) in page {assert!(!review);h.mark_payment_processed_after_durable_handler(&mut scan,&p,&r.id).unwrap();count+=1;}if done{break;}}
        let elapsed=start.elapsed();eprintln!("PAYMENT_MARK_1000_MS={}",elapsed.as_millis());assert_eq!(count,1000);assert!(elapsed<std::time::Duration::from_secs(30));
        let len=fs::metadata(dir.join(".payment-events-v2")).unwrap().len();assert!(len<1000*512);
        drop(h);let h=History::open(&dir,[7;32]).unwrap();let mut scan=h.begin_payment_scan().unwrap();let mut left=0;
        loop {let (page,done)=h.next_payment_scan(&mut scan,100).unwrap();left+=page.len();if done{break;}}assert_eq!(left,0);let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn payment_lock_process_worker() {
        let Ok(root)=std::env::var("GS_PAYMENT_LOCK_TEST") else {return;};
        let h=History::open(&root,[7;32]).unwrap();let _lock=h.guard().unwrap();
        fs::write(Path::new(&root).join("lock-ready"),b"ok").unwrap();std::thread::sleep(std::time::Duration::from_secs(30));
    }
    #[test]
    fn competing_process_lock_is_bounded_and_released_on_crash() {
        let dir=temp_dir("payment-process-lock");fs::create_dir_all(&dir).unwrap();
        let mut child=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","history::tests::payment_lock_process_worker"]).env("GS_PAYMENT_LOCK_TEST",&dir).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
        let until=std::time::Instant::now()+std::time::Duration::from_secs(5);while !dir.join("lock-ready").exists()&&std::time::Instant::now()<until {std::thread::sleep(std::time::Duration::from_millis(10));}
        assert!(dir.join("lock-ready").exists());let h=History::open(&dir,[7;32]).unwrap();let start=std::time::Instant::now();
        assert!(h.initialize_payment_checkpoint().is_err());assert!(start.elapsed()<std::time::Duration::from_secs(7));
        child.kill().unwrap();child.wait().unwrap();assert!(h.initialize_payment_checkpoint().is_ok());let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn payment_migration_is_conservative_and_new_payment_survives_restart() {
        let dir=temp_dir("payment-migration");let peer=peer();let h=History::open(&dir,[7;32]).unwrap();
        let mut old=record("old",1);old.kind=MessageKind::Slatepack{armor:"old".into(),encrypted:true};h.record(&peer,&old).unwrap();
        h.initialize_payment_checkpoint().unwrap();
        let mut new=record("new",2);new.kind=MessageKind::Slatepack{armor:"new".into(),encrypted:true};h.record(&peer,&new).unwrap();
        let page=h.payment_page(None,10).unwrap();assert_eq!(page.len(),2);
        assert!(page.iter().find(|x|x.1.id==old.id).unwrap().2);
        assert!(!page.iter().find(|x|x.1.id==new.id).unwrap().2);
        let mut scan=h.begin_payment_scan().unwrap();assert!(h.mark_payment_processed_after_durable_handler(&mut scan,&peer.to_string(),&old.id).is_err());
        drop(h);let h=History::open(&dir,[7;32]).unwrap();h.initialize_payment_checkpoint().unwrap();
        assert_eq!(h.payment_page(None,10).unwrap().len(),2);
        let mut scan=h.begin_payment_scan().unwrap();h.mark_payment_processed_after_durable_handler(&mut scan,&peer.to_string(),&new.id).unwrap();drop(h);
        let h=History::open(&dir,[7;32]).unwrap();let page=h.payment_page(None,10).unwrap();assert_eq!(page.len(),1);assert_eq!(page[0].1.id,old.id);
        fs::remove_file(dir.join(peer.to_string()).join(format!("{}.msg",new.id))).unwrap();
        assert!(h.payment_page(None,10).is_err(),"missing indexed record must not be silently ignored");
        let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn anchor_recovers_committed_suffix_and_detects_whole_record_truncation() {
        let dir=temp_dir("payment-anchor");let peer=peer();let h=History::open(&dir,[7;32]).unwrap();h.initialize_payment_checkpoint().unwrap();
        let mut a=record("a",1);a.kind=MessageKind::Slatepack{armor:"a".into(),encrypted:true};h.record(&peer,&a).unwrap();
        let mut b=record("b",2);b.kind=MessageKind::Slatepack{armor:"b".into(),encrypted:true};h.record(&peer,&b).unwrap();
        let mut scan=h.begin_payment_scan().unwrap();h.mark_payment_processed_after_durable_handler(&mut scan,&peer.to_string(),&a.id).unwrap();
        let journal=dir.join(".payment-events-v2");let anchor=dir.join(".payment-anchor-v2");let first_journal=fs::read(&journal).unwrap();let first_anchor=fs::read(&anchor).unwrap();
        h.mark_payment_processed_after_durable_handler(&mut scan,&peer.to_string(),&b.id).unwrap();
        // Crash after journal fsync before anchor commit: old anchor + complete suffix.
        fs::write(&anchor,first_anchor).unwrap();drop(h);let h=History::open(&dir,[7;32]).unwrap();
        let mut scan=h.begin_payment_scan().unwrap();let (page,done)=h.next_payment_scan(&mut scan,100).unwrap();assert!(done && page.is_empty());
        // Committed whole-record truncation must not cause a silent retry.
        fs::write(&journal,first_journal).unwrap();assert!(h.begin_payment_scan().is_err());
        let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn incremental_payment_journal_detects_competing_writer_and_torn_data() {
        let dir=temp_dir("payment-incremental");let peer=peer();let h=History::open(&dir,[7;32]).unwrap();h.initialize_payment_checkpoint().unwrap();
        let mut a=record("a",1);a.kind=MessageKind::Slatepack{armor:"a".into(),encrypted:true};h.record(&peer,&a).unwrap();
        let mut b=record("b",2);b.kind=MessageKind::Slatepack{armor:"b".into(),encrypted:true};h.record(&peer,&b).unwrap();
        let mut one=h.begin_payment_scan().unwrap();let mut stale=h.begin_payment_scan().unwrap();
        h.mark_payment_processed_after_durable_handler(&mut one,&peer.to_string(),&a.id).unwrap();
        assert!(h.mark_payment_processed_after_durable_handler(&mut stale,&peer.to_string(),&b.id).is_err());
        let mut fresh=h.begin_payment_scan().unwrap();h.mark_payment_processed_after_durable_handler(&mut fresh,&peer.to_string(),&b.id).unwrap();drop(h);
        let h=History::open(&dir,[7;32]).unwrap();let mut scan=h.begin_payment_scan().unwrap();let (page,done)=h.next_payment_scan(&mut scan,100).unwrap();assert!(done&&page.is_empty());
        let path=dir.join(".payment-events-v2");let mut bytes=fs::read(&path).unwrap();bytes.pop();fs::write(&path,bytes).unwrap();assert!(h.begin_payment_scan().is_err());
        let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn payment_checkpoint_rejects_tamper_and_unknown_empty_journal() {
        let dir=temp_dir("payment-checkpoint-tamper");let h=History::open(&dir,[7;32]).unwrap();
        assert!(h.payment_page(None,10).is_err());h.initialize_payment_checkpoint().unwrap();
        let path=dir.join(".payment-checkpoint-v2");let mut data=fs::read(&path).unwrap();let n=data.len()-1;data[n]^=1;fs::write(path,data).unwrap();
        assert!(h.initialize_payment_checkpoint().is_err());assert!(h.payment_page(None,10).is_err());
        let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn expired_records_are_removed_but_legacy_records_stay() {
        let dir = temp_dir("ttl");
        let history = History::open(&dir, [7u8; 32]).unwrap();
        let peer = peer();
        let mut expired = record("old", 1);
        expired.expires_at = Some(2);
        expired.local_expiry_opt_in = true;
        history.record(&peer, &expired).unwrap();
        let legacy = record("legacy", 3);
        history.record(&peer, &legacy).unwrap();

        let listed = history.list(&peer, 10).unwrap();
        assert_eq!(listed.len(), 1, "only the legacy record remains");
        assert_eq!(listed[0].id, legacy.id);
        assert!(!dir
            .join(peer.to_string())
            .join(format!("{}.msg", expired.id))
            .exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn contains_is_the_persistent_dedup_marker() {
        let dir = temp_dir("contains");
        let history = History::open(&dir, [7u8; 32]).unwrap();
        let record = record("once", 1);
        history.record(&peer(), &record).unwrap();
        assert!(history.contains(&peer(), &record.id).unwrap());
        assert!(!history
            .contains(&peer(), &Uuid::new_v4().to_string())
            .unwrap());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn deletion_currently_removes_the_durable_replay_marker() {
        let dir = temp_dir("delete-replay-evidence");
        let history = History::open(&dir, [7u8; 32]).unwrap();
        let item = record("synthetic", 1);
        history.record(&peer(), &item).unwrap();
        assert!(history.delete(&peer(), &item.id).unwrap());
        drop(history);
        let history = History::open(&dir, [7u8; 32]).unwrap();
        assert!(!history.contains(&peer(), &item.id).unwrap());
        assert!(history.contains_record(&peer(), &item).unwrap());
        let mut changed = item.clone();
        changed.kind = MessageKind::Text { text: "other".into() };
        assert!(history.contains_record(&peer(), &changed).is_err());
        let marker = history.marker_path(&peer(), &item.id);
        fs::write(marker, b"corrupt").unwrap();
        assert!(history.contains_record(&peer(), &item).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn process_exit_between_marker_and_delete_preserves_dedup() {
        const ENV: &str = "GS_REPLAY_CHILD_DIR";
        let item = MessageRecord { id: "d11d47df-6a00-4aef-88e2-5621391646b4".into(), ..record("synthetic", 1) };
        if let Some(dir) = std::env::var_os(ENV) {
            let history = History::open(dir, [7;32]).unwrap();
            let _guard = history.guard().unwrap();
            history.save_marker_locked(&peer(), &item).unwrap();
            std::process::exit(23);
        }
        let dir = temp_dir("process-exit");
        let history = History::open(&dir, [7;32]).unwrap();
        history.record(&peer(), &item).unwrap(); drop(history);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact").arg("history::tests::process_exit_between_marker_and_delete_preserves_dedup")
            .env(ENV, &dir).status().unwrap();
        assert_eq!(status.code(), Some(23));
        let history = History::open(&dir, [7;32]).unwrap();
        assert!(history.contains_record(&peer(), &item).unwrap());
        assert_eq!(history.list(&peer(), 10).unwrap().len(), 1);
        drop(history); let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn process_exit_after_save_before_ack_preserves_dedup() {
        const ENV: &str = "GS_REPLAY_SAVE_CHILD_DIR";
        let item = MessageRecord { id: "3bb4bc13-9356-4b36-a119-34fab7b20131".into(), ..record("synthetic", 1) };
        if let Some(dir) = std::env::var_os(ENV) {
            let history = History::open(dir, [7;32]).unwrap();
            history.record(&peer(), &item).unwrap();
            std::process::exit(23);
        }
        let dir = temp_dir("save-before-ack");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact").arg("history::tests::process_exit_after_save_before_ack_preserves_dedup")
            .env(ENV, &dir).status().unwrap();
        assert_eq!(status.code(), Some(23));
        let history = History::open(&dir, [7;32]).unwrap();
        assert!(history.contains_record(&peer(), &item).unwrap());
        drop(history); let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn concurrent_processes_cannot_replace_same_identity_with_other_payload() {
        const DIR: &str = "GS_REPLAY_RACE_DIR";
        const TEXT: &str = "GS_REPLAY_RACE_TEXT";
        if let Some(dir) = std::env::var_os(DIR) {
            let item = MessageRecord { id: "99d65467-15e9-4a45-a032-a7ef040967fd".into(), ..record(&std::env::var(TEXT).unwrap(), 1) };
            let history = History::open(dir, [7;32]).unwrap();
            std::process::exit(if history.record(&peer(), &item).is_ok() { 0 } else { 23 });
        }
        let dir = temp_dir("process-conflict");
        let _history = History::open(&dir, [7;32]).unwrap();
        let spawn = |text: &str| std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact").arg("history::tests::concurrent_processes_cannot_replace_same_identity_with_other_payload")
            .env(DIR, &dir).env(TEXT, text).spawn().unwrap();
        let mut a = spawn("first"); let mut b = spawn("second");
        let mut codes = [a.wait().unwrap().code().unwrap(), b.wait().unwrap().code().unwrap()];
        codes.sort(); assert_eq!(codes, [0,23]);
        let records = _history.list(&peer(), 10).unwrap();
        assert_eq!(records.len(), 1);
        drop(_history); let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn another_process_holding_history_lock_times_out() {
        const DIR:&str="GS_HISTORY_LOCK_CHILD";
        if let Some(dir)=std::env::var_os(DIR) {
            let history=History::open(&dir,[7;32]).unwrap();let _guard=history.guard().unwrap();
            fs::write(PathBuf::from(dir).join("ready"),b"ready").unwrap();
            std::thread::sleep(std::time::Duration::from_secs(8));return;
        }
        let dir=temp_dir("lock-timeout");let history=History::open(&dir,[7;32]).unwrap();
        let mut child=std::process::Command::new(std::env::current_exe().unwrap()).arg("--exact").arg("history::tests::another_process_holding_history_lock_times_out").env(DIR,&dir).spawn().unwrap();
        let start=std::time::Instant::now();while !dir.join("ready").exists() && start.elapsed()<std::time::Duration::from_secs(5) { std::thread::sleep(std::time::Duration::from_millis(10)); }
        assert!(dir.join("ready").exists());let start=std::time::Instant::now();
        let err=history.contains(&peer(),&uuid::Uuid::new_v4().to_string()).unwrap_err().to_string();
        assert!(err.contains("timed out"));assert!(start.elapsed()<std::time::Duration::from_secs(5));
        child.kill().unwrap();child.wait().unwrap();drop(history);let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn roundtrip_ordered_and_encrypted_at_rest() {
        let dir = temp_dir("round");
        let history = History::open(&dir, [7u8; 32]).unwrap();
        let peer = peer();
        history.record(&peer, &record("second", 2)).unwrap();
        history.record(&peer, &record("first", 1)).unwrap();

        let raw = fs::read_dir(dir.join(peer.to_string()))
            .unwrap()
            .flatten()
            .map(|entry| fs::read(entry.path()).unwrap())
            .collect::<Vec<_>>();
        for bytes in &raw {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains("first"), "plaintext leaked");
            assert!(!text.contains("second"), "plaintext leaked");
        }

        let records = history.list(&peer, 10).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].created_at, 1);
        assert_eq!(records[1].created_at, 2);
        assert_eq!(history.conversations().unwrap(), vec![peer.clone()]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_key_and_tamper_fail() {
        let dir = temp_dir("keys");
        let peer = peer();
        let item = record("x", 1);
        {
            let history = History::open(&dir, [7u8; 32]).unwrap();
            history.record(&peer, &item).unwrap();
        }
        let other = History::open(&dir, [8u8; 32]).unwrap();
        assert!(other.list(&peer, 10).is_err());

        let path = dir.join(peer.to_string()).join(format!("{}.msg", item.id));
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();
        let history = History::open(&dir, [7u8; 32]).unwrap();
        assert!(history.list(&peer, 10).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_and_uuid_validation() {
        let dir = temp_dir("delete");
        let history = History::open(&dir, [7u8; 32]).unwrap();
        let peer = peer();
        let item = record("x", 1);
        history.record(&peer, &item).unwrap();
        assert!(history.delete(&peer, &item.id).unwrap());
        assert!(!history.delete(&peer, "../../etc/passwd").unwrap());
        assert!(history.list(&peer, 10).unwrap().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_returns_the_newest_page() {
        let dir = temp_dir("newest");
        let history = History::open(&dir, [7u8; 32]).unwrap();
        let peer = peer();
        for at in 1..=5 {
            history
                .record(&peer, &record(&format!("m{at}"), at))
                .unwrap();
        }
        let records = history.list(&peer, 2).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].created_at, 4);
        assert_eq!(records[1].created_at, 5);
        let _ = fs::remove_dir_all(&dir);
    }


    #[test]
    fn quota_is_fail_closed_and_preserves_older_messages() {
        let dir=temp_dir("quota");let history=History::open(&dir,[7;32]).unwrap().with_limit(2);let peer=peer();
        let first=record("first",1);let second=record("second",2);let third=record("third",3);
        history.record(&peer,&first).unwrap();history.record(&peer,&second).unwrap();
        assert!(history.record(&peer,&third).is_err());drop(history);
        let reopened=History::open(&dir,[7;32]).unwrap();
        assert!(reopened.contains(&peer,&first.id).unwrap());assert!(reopened.contains(&peer,&second.id).unwrap());
        assert!(!reopened.contains(&peer,&third.id).unwrap());let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn full_text_history_does_not_consume_payment_reserve() {
        let dir=temp_dir("payment-reserve");let history=History::open(&dir,[7;32]).unwrap().with_limit(2);let p=peer();
        history.record(&p,&record("one",1)).unwrap();history.record(&p,&record("two",2)).unwrap();
        assert!(history.record(&p,&record("three",3)).unwrap_err().to_string().contains("text history full"));
        let mut payment=record("unused",4);payment.kind=MessageKind::Slatepack { armor:"synthetic".into(), encrypted:true };
        history.record(&p,&payment).unwrap();assert!(history.contains_record(&p,&payment).unwrap());
        drop(history);let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn dirty_quota_recovers_once_and_corruption_fails_closed() {
        let dir=temp_dir("quota-recovery");let p=peer();let history=History::open(&dir,[7;32]).unwrap().with_limit(1);
        history.record(&p,&record("one",1)).unwrap();
        let mut index=history.load_quota(&p).unwrap();index.dirty=true;index.text=0;
        history.write_quota(&p,&index).unwrap();drop(history);
        let history=History::open(&dir,[7;32]).unwrap().with_limit(1);
        assert!(history.record(&p,&record("two",2)).is_err());
        let recovered=history.load_quota(&p).unwrap();assert!(!recovered.dirty);assert_eq!(recovered.text,1);
        fs::write(dir.join(p.to_string()).join("quota-index.enc"),b"broken").unwrap();
        assert!(history.record(&p,&record("three",3)).is_err());
        drop(history);let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn quota_index_does_not_rescan_per_insertion() {
        let dir=temp_dir("quota-linear");let p=peer();let history=History::open(&dir,[7;32]).unwrap();
        for i in 0..2000 {history.record(&p,&record("synthetic",i)).unwrap();}
        assert!(history.scans.load(std::sync::atomic::Ordering::Relaxed)<=1);
        drop(history);let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn process_exit_after_quota_prepare_and_record_rebuilds_counts() {
        const ENV:&str="GS_QUOTA_CRASH_CHILD";
        let item=MessageRecord{id:"1e4b7a73-148b-437a-82a3-709c1604be8b".into(),..record("second",2)};
        if let Some(dir)=std::env::var_os(ENV) {
            let h=History::open(dir,[7;32]).unwrap();let _guard=h.guard().unwrap();let p=peer();
            let mut q=h.load_quota(&p).unwrap();q.dirty=true;h.write_quota(&p,&q).unwrap();
            let plain=serde_json::to_vec(&item).unwrap();let nonce=[11u8;12];
            let cipher=h.cipher().encrypt(Nonce::from_slice(&nonce),Payload{msg:&plain,aad:&History::aad(&p,&item.id)}).unwrap();
            let mut bytes=nonce.to_vec();bytes.extend_from_slice(&cipher);write_atomic(&h.peer_dir(&p).join(format!("{}.msg",item.id)),&bytes).unwrap();
            std::process::exit(23);
        }
        let dir=temp_dir("quota-crash");let p=peer();let h=History::open(&dir,[7;32]).unwrap();h.record(&p,&record("first",1)).unwrap();drop(h);
        let status=std::process::Command::new(std::env::current_exe().unwrap()).arg("--exact").arg("history::tests::process_exit_after_quota_prepare_and_record_rebuilds_counts").env(ENV,&dir).status().unwrap();
        assert_eq!(status.code(),Some(23));let h=History::open(&dir,[7;32]).unwrap();let q=h.load_quota(&p).unwrap();
        assert!(!q.dirty);assert_eq!(q.text,2);assert!(h.contains_record(&p,&item).unwrap());drop(h);let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn quarantine_is_durable_and_corruption_fails_closed() {
        let dir=temp_dir("quarantine");let token="a".repeat(64);
        let history=History::open(&dir,[7;32]).unwrap();history.quarantine_event(&token).unwrap();drop(history);
        let history=History::open(&dir,[7;32]).unwrap();history.quarantine_event(&token).unwrap();
        let name=data_encoding::HEXLOWER.encode(&Sha256::digest(token.as_bytes()));
        fs::write(dir.join("quarantine").join(format!("{name}.bad")),b"corrupt").unwrap();
        assert!(history.quarantine_event(&token).is_err());drop(history);let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn full_quarantine_refuses_reject_ack() {
        let dir=temp_dir("quarantine-cap");let history=History::open(&dir,[7;32]).unwrap();
        let q=dir.join("quarantine");fs::create_dir_all(&q).unwrap();
        for i in 0..1000 { fs::write(q.join(format!("{i}.bad")),b"x").unwrap(); }
        assert!(history.quarantine_event(&"a".repeat(64)).unwrap_err().to_string().contains("quarantine full"));
        drop(history);let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn legacy_expiry_is_not_treated_as_local_deletion_consent() {
        let dir=temp_dir("legacy-format");let history=History::open(&dir,[7;32]).unwrap();let peer=peer();let mut r=record("legacy",1);r.expires_at=Some(2);
        let mut legacy=serde_json::to_value(&r).unwrap();legacy.as_object_mut().unwrap().remove("local_expiry_opt_in");
        let bytes=serde_json::to_vec(&legacy).unwrap();let nonce=[4u8;12];let cipher=history.cipher().encrypt(Nonce::from_slice(&nonce),Payload{msg:&bytes,aad:&History::aad(&peer,&r.id)}).unwrap();
        let path=dir.join(peer.to_string());fs::create_dir_all(&path).unwrap();let mut encrypted=nonce.to_vec();encrypted.extend_from_slice(&cipher);fs::write(path.join(format!("{}.msg",r.id)),encrypted).unwrap();
        drop(history);let reopened=History::open(&dir,[7;32]).unwrap();assert_eq!(reopened.list(&peer,10).unwrap().len(),1);
        assert!(reopened.contains(&peer,&r.id).unwrap());let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn mixed_legacy_record_and_new_tombstone_survive_restart() {
        let dir = temp_dir("mixed-migration"); let p = peer();
        let history = History::open(&dir,[7;32]).unwrap();
        let old = record("old", 1); let newer = record("new", 2);
        let mut value = serde_json::to_value(&old).unwrap(); value.as_object_mut().unwrap().remove("local_expiry_opt_in");
        let data = serde_json::to_vec(&value).unwrap(); let nonce = [8u8;12];
        let cipher = history.cipher().encrypt(Nonce::from_slice(&nonce),Payload { msg: &data, aad: &History::aad(&p,&old.id) }).unwrap();
        let path=dir.join(p.to_string()); fs::create_dir_all(&path).unwrap(); let mut bytes=nonce.to_vec();bytes.extend_from_slice(&cipher);
        fs::write(path.join(format!("{}.msg",old.id)),bytes).unwrap();
        history.record(&p,&newer).unwrap(); assert!(history.delete(&p,&newer.id).unwrap()); drop(history);
        let history=History::open(&dir,[7;32]).unwrap();
        assert!(history.contains_record(&p,&old).unwrap());assert!(history.contains_record(&p,&newer).unwrap());
        assert_eq!(history.list(&p,10).unwrap().len(),1);
        assert!(history.delete(&p,&old.id).unwrap());drop(history);
        let history=History::open(&dir,[7;32]).unwrap();assert!(history.contains_record(&p,&old).unwrap());
        drop(history);let _=fs::remove_dir_all(dir);
    }

}

