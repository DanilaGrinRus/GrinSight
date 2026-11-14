// SPDX-License-Identifier: MIT OR Apache-2.0
//! Experimental page checkpoint state; not yet connected to the transport.
use std::collections::{BTreeSet,BTreeMap};
use serde::{Deserialize, Serialize};
use crate::error::{Error, Result};
use std::path::{Path,PathBuf};
use std::io::{Read,Write};
use chacha20poly1305::{ChaCha20Poly1305,Key,Nonce};
use chacha20poly1305::aead::{Aead,NewAead,Payload};
use zeroize::Zeroizing;
use sha2::{Digest,Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane { Live, Backfill }

const MAX_STATE_BYTES:usize=8*1024*1024;
const MAX_DEFERRED:usize=256;
const MAX_EVENT_BYTES:usize=120_000;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredEvent { pub id:String, pub json:String, pub received_at:u64 }
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    pub live_until: Option<u64>,
    pub live_floor: u64,
    pub backfill_until: Option<u64>,
    pub backfill_done: bool,
    #[serde(default)] pub deferred:Vec<DeferredEvent>,
    #[serde(default)] pub next_backfill: bool,
}

impl Cursor {
    pub fn preserve(&mut self,event:&super::event::Event,now:u64)->Result<()> {
        event.verify()?;
        let json=serde_json::to_string(event).map_err(|_|Error::Store("deferred event encoding".into()))?;
        if json.len()>MAX_EVENT_BYTES {return Err(Error::Quota("deferred event too large".into()));}
        if let Some(old)=self.deferred.iter().find(|v|v.id==event.id) {
            if old.json!=json {return Err(Error::Store("deferred event identity conflict".into()));}
            return Ok(());
        }
        if self.deferred.len()>=MAX_DEFERRED {return Err(Error::Quota("deferred queue full".into()));}
        self.deferred.push(DeferredEvent{id:event.id.clone(),json,received_at:now});
        if serde_json::to_vec(&self).map_err(|_|Error::Store("cursor encode".into()))?.len()>MAX_STATE_BYTES-28 {
            self.deferred.pop();return Err(Error::Quota("deferred queue size limit".into()));
        }
        Ok(())
    }
}

/// Prototype store: construction must be explicitly initialized on first use;
/// the caller must serialize all access with the profile's process lock.
#[derive(Clone)]
pub struct CursorStore { path:PathBuf, key:Zeroizing<[u8;32]>, aad:Vec<u8>, lock_path:Option<PathBuf> }

#[derive(Default, Serialize, Deserialize)]
struct RouteRegistry { version:u8, routes:BTreeSet<String>, #[serde(default)] names:BTreeMap<String,String> }

/// All operations require the common profile process lock held by the caller.
pub struct Registry { root:PathBuf, key:Zeroizing<[u8;32]>, profile:String, lock_path:Option<PathBuf> }
impl Registry {
    pub fn new(root:PathBuf,key:[u8;32],profile:&str)->Result<Self> {
        if profile.is_empty() || profile.len()>512 {return Err(Error::Store("invalid cursor profile".into()));}
        Ok(Self{root,key:Zeroizing::new(key),profile:profile.into(),lock_path:None})
    }
    pub fn with_profile_lock(mut self,path:PathBuf)->Self {self.lock_path=Some(path);self}
    fn registry_path(&self)->PathBuf {self.root.join("route-registry.enc")}
    fn marker_path(&self)->PathBuf {self.root.join("route-registry.initialized")}
    fn aad(&self)->Vec<u8> {let mut a=b"glaux-cursor-route-registry-v1\0".to_vec();a.extend_from_slice(self.profile.as_bytes());a}
    fn crypt_write(&self,path:&Path,plain:&[u8],aad:&[u8])->Result<()> {
        if plain.len()>1024*1024-28 {return Err(Error::Quota("cursor registry size limit".into()));}
        std::fs::create_dir_all(&self.root).map_err(|e|Error::Store(format!("cursor registry directory: {e}")))?;
        let mut nonce=[0u8;12];getrandom::getrandom(&mut nonce).map_err(|e|Error::Crypto(format!("cursor registry RNG: {e}")))?;
        let cipher=ChaCha20Poly1305::new(Key::from_slice(&self.key[..]));
        let encrypted=cipher.encrypt(Nonce::from_slice(&nonce),Payload{msg:plain,aad}).map_err(|_|Error::Crypto("cursor registry encrypt".into()))?;
        let tmp=path.with_extension(format!("{}.tmp",uuid::Uuid::new_v4()));
        let result=(|| -> Result<()> {let mut f=std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(|e|Error::Store(format!("cursor registry create: {e}")))?;
            f.write_all(&nonce).and_then(|_|f.write_all(&encrypted)).and_then(|_|f.sync_all()).map_err(|e|Error::Store(format!("cursor registry write: {e}")))?;drop(f);
            std::fs::rename(&tmp,path).map_err(|e|Error::Store(format!("cursor registry rename: {e}")))?;sync_parent(&self.root)?;Ok(())})();
        if result.is_err(){let _=std::fs::remove_file(tmp);}result
    }
    fn crypt_read(&self,path:&Path,aad:&[u8])->Result<Vec<u8>> {
        let file=std::fs::File::open(path).map_err(|e|Error::Store(format!("cursor registry read: {e}")))?;
        let mut bytes=Vec::new();file.take(1024*1024+1).read_to_end(&mut bytes).map_err(|e|Error::Store(format!("cursor registry read: {e}")))?;
        if bytes.len()<28 || bytes.len()>1024*1024{return Err(Error::Crypto("cursor registry length".into()));}
        ChaCha20Poly1305::new(Key::from_slice(&self.key[..])).decrypt(Nonce::from_slice(&bytes[..12]),Payload{msg:&bytes[12..],aad}).map_err(|_|Error::Crypto("cursor registry authentication".into()))
    }
    /// Caller must explicitly choose a new/legacy baseline; never inferred on load.
    pub fn initialize_baseline(&self)->Result<()> {
        if self.registry_path().exists() || self.marker_path().exists() {return Err(Error::Store("cursor baseline already exists or incomplete".into()));}
        let bytes=serde_json::to_vec(&RouteRegistry{version:1,routes:BTreeSet::new(),names:BTreeMap::new()}).map_err(|e|Error::Store(e.to_string()))?;
        self.crypt_write(&self.registry_path(),&bytes,&self.aad())?;
        let mut marker_aad=self.aad();marker_aad.extend_from_slice(b"\0initialized");
        self.crypt_write(&self.marker_path(),b"initialized",&marker_aad)
    }
    /// Resume only a provably empty, interrupted first baseline. Never reset an
    /// existing route or checkpoint. Caller supplies an independently persisted
    /// pending-initialization sentinel before invoking this method.
    pub fn resume_empty_baseline(&self)->Result<()> {
        let _lock=self.lock_path.as_ref().map(|path|acquire_lock(path)).transpose()?;
        match (self.registry_path().exists(),self.marker_path().exists()) {
            (false,false)=>self.initialize_baseline(),
            (true,false)=>{
                let registry:RouteRegistry=serde_json::from_slice(&self.crypt_read(&self.registry_path(),&self.aad())?).map_err(|_|Error::Crypto("cursor registry invalid".into()))?;
                if registry.version!=1 || !registry.routes.is_empty() || !registry.names.is_empty() {return Err(Error::Store("incomplete nonempty registry requires recovery".into()));}
                let mut marker_aad=self.aad();marker_aad.extend_from_slice(b"\0initialized");
                self.crypt_write(&self.marker_path(),b"initialized",&marker_aad)
            },
            (true,true)=>{self.load()?;Ok(())},
            (false,true)=>Err(Error::Store("incomplete cursor baseline requires recovery".into())),
        }
    }
    fn load(&self)->Result<RouteRegistry> {
        let mut marker_aad=self.aad();marker_aad.extend_from_slice(b"\0initialized");
        if self.crypt_read(&self.marker_path(),&marker_aad)?!=b"initialized" {return Err(Error::Crypto("cursor registry marker invalid".into()));}
        let registry:RouteRegistry=serde_json::from_slice(&self.crypt_read(&self.registry_path(),&self.aad())?).map_err(|_|Error::Crypto("cursor registry invalid".into()))?;
        if registry.version!=1 || registry.routes.iter().any(|s|s.len()!=64 || !s.bytes().all(|b|b.is_ascii_hexdigit() && !b.is_ascii_uppercase())) {return Err(Error::Crypto("cursor registry invalid".into()));}
        if registry.names.len()!=registry.routes.len() || registry.names.iter().any(|(id,route)| !registry.routes.contains(id) || !Self::route_id(route).is_ok_and(|value|value==*id)) {return Err(Error::Store("cursor registry requires explicit route migration".into()));}
        Ok(registry)
    }
    fn route_id(route:&str)->Result<String> {
        if route.is_empty() || route.len()>2048{return Err(Error::Store("invalid cursor route".into()));}
        Ok(data_encoding::HEXLOWER.encode(&Sha256::digest(route.as_bytes())))
    }
    pub fn register_route(&self,route:&str,initial:&Cursor)->Result<()> {
        let mut registry=self.load()?;let id=Self::route_id(route)?;
        if registry.routes.len()>=1000 {return Err(Error::Quota("cursor route registry full".into()));}
        if !registry.routes.insert(id.clone()) {return Err(Error::Store("route already registered".into()));}
        registry.names.insert(id.clone(),route.to_string());
        let bytes=serde_json::to_vec(&registry).map_err(|e|Error::Store(e.to_string()))?;
        self.crypt_write(&self.registry_path(),&bytes,&self.aad())?;
        #[cfg(test)] if std::env::var_os("GS_CURSOR_EXIT_AFTER_REGISTRY").is_some() {std::process::exit(23);}
        // Registry first: a crash before checkpoint leaves a detectable error.
        CursorStore::new(self.root.join(format!("route-{id}.enc")),*self.key,&self.profile,route)?.initialize(initial)
    }
    pub fn route(&self,route:&str)->Result<CursorStore> {
        let registry=self.load()?;let id=Self::route_id(route)?;
        if !registry.routes.contains(&id){return Err(Error::Store("cursor route is not registered".into()));}
        let mut store=CursorStore::new(self.root.join(format!("route-{id}.enc")),*self.key,&self.profile,route)?;
        store.lock_path=self.lock_path.clone();
        store.load()?;Ok(store)
    }
    /// Only opaque route tokens are exposed outside encrypted profile state.
    pub fn all_routes(&self)->Result<Vec<(String,CursorStore)>> {
        let _lock=self.lock_path.as_ref().map(|path|acquire_lock(path)).transpose()?;
        let registry=self.load()?;let mut out=Vec::with_capacity(registry.names.len());
        for (id,route) in registry.names {
            let mut store=CursorStore::new(self.root.join(format!("route-{id}.enc")),*self.key,&self.profile,&route)?;
            store.lock_path=self.lock_path.clone();store.load()?;out.push((id,store));
        }Ok(out)
    }
    /// Caller holds the profile lock; migration is an explicit one-time choice.
    pub fn ensure_route(&self,route:&str,allow_initial_migration:bool)->Result<CursorStore> {
        let _lock=self.lock_path.as_ref().map(|path|acquire_lock(path)).transpose()?;
        let registry_exists=self.registry_path().exists();let marker_exists=self.marker_path().exists();
        if !registry_exists && !marker_exists && allow_initial_migration {self.initialize_baseline()?;}
        let registry=self.load()?;let id=Self::route_id(route)?;
        if !registry.routes.contains(&id) {self.register_route(route,&Cursor::default())?;}
        self.route(route)
    }
}
impl CursorStore {
    pub fn new(path:PathBuf,key:[u8;32],profile:&str,route:&str)->Result<Self> {
        if profile.is_empty() || route.is_empty() || profile.len()>512 || route.len()>2048 {return Err(Error::Store("invalid cursor scope".into()));}
        let mut aad=b"glaux-nostr-cursor-v2\0".to_vec();
        for field in [profile,route] {aad.extend_from_slice(&(field.len() as u64).to_le_bytes());aad.extend_from_slice(field.as_bytes());}
        Ok(Self{path,key:Zeroizing::new(key),aad,lock_path:None})
    }
    pub fn with_lock(mut self,path:PathBuf)->Self {self.lock_path=Some(path);self}
    pub fn load(&self)->Result<Cursor> {
        let file=std::fs::File::open(&self.path).map_err(|e|Error::Store(format!("cursor missing or unreadable: {e}")))?;
        let mut bytes=Vec::new();file.take((MAX_STATE_BYTES+1) as u64).read_to_end(&mut bytes).map_err(|e|Error::Store(format!("cursor read: {e}")))?;
        if bytes.len()<28 || bytes.len()>MAX_STATE_BYTES {return Err(Error::Crypto("cursor truncated".into()));}
        let cipher=ChaCha20Poly1305::new(Key::from_slice(&self.key[..]));
        let plain=cipher.decrypt(Nonce::from_slice(&bytes[..12]),Payload{msg:&bytes[12..],aad:&self.aad}).map_err(|_|Error::Crypto("cursor authentication".into()))?;
        let state:Cursor=serde_json::from_slice(&plain).map_err(|_|Error::Crypto("cursor invalid".into()))?;
        if state.deferred.len()>MAX_DEFERRED || state.deferred.iter().any(|item| item.id.len()!=64 || item.json.len()>MAX_EVENT_BYTES) {return Err(Error::Crypto("cursor deferred invalid".into()));}
        Ok(state)
    }
    pub fn initialize(&self,cursor:&Cursor)->Result<()> {
        if self.path.exists() {return Err(Error::Store("cursor already initialized".into()));}
        self.persist(cursor)
    }
    /// Serialize read-modify-write with the same process lock as page commits.
    pub fn update<T>(&self,apply:impl FnOnce(&mut Cursor)->Result<T>)->Result<T> {
        let _lock=self.lock_path.as_ref().map(|path|acquire_lock(path)).transpose()?;
        let mut state=self.load()?;let old=state.clone();let value=apply(&mut state)?;if state!=old {self.persist(&state)?;}Ok(value)
    }
    pub fn save(&self,cursor:&Cursor)->Result<()> {
        let _lock=self.lock_path.as_ref().map(|path|acquire_lock(path)).transpose()?;
        self.load()?;
        self.persist(cursor)
    }
    pub fn save_if(&self,expected:&Cursor,next:&Cursor)->Result<()> {
        let _lock=self.lock_path.as_ref().map(|path|acquire_lock(path)).transpose()?;
        if self.load()?!=*expected {return Err(Error::Store("cursor changed concurrently; restart polling".into()));}
        self.persist(next)
    }
    fn persist(&self,cursor:&Cursor)->Result<()> {
        let plain=serde_json::to_vec(cursor).map_err(|e|Error::Store(format!("cursor encode: {e}")))?;
        if plain.len()>MAX_STATE_BYTES-28 || cursor.deferred.len()>MAX_DEFERRED {return Err(Error::Quota("cursor state size limit".into()));}
        let mut nonce=[0u8;12];getrandom::getrandom(&mut nonce).map_err(|e|Error::Crypto(format!("cursor RNG: {e}")))?;
        let cipher=ChaCha20Poly1305::new(Key::from_slice(&self.key[..]));
        let encrypted=cipher.encrypt(Nonce::from_slice(&nonce),Payload{msg:&plain,aad:&self.aad}).map_err(|_|Error::Crypto("cursor encryption".into()))?;
        let parent=self.path.parent().ok_or_else(||Error::Store("cursor parent missing".into()))?;
        std::fs::create_dir_all(parent).map_err(|e|Error::Store(format!("cursor directory: {e}")))?;
        let tmp=self.path.with_extension(format!("{}.tmp",uuid::Uuid::new_v4()));
        let result=(|| -> Result<()> {let mut file=std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(|e|Error::Store(format!("cursor open: {e}")))?;
            file.write_all(&nonce).and_then(|_|file.write_all(&encrypted)).and_then(|_|file.sync_all()).map_err(|e|Error::Store(format!("cursor write: {e}")))?;drop(file);
            std::fs::rename(&tmp,&self.path).map_err(|e|Error::Store(format!("cursor rename: {e}")))?;
            sync_parent(parent)?;Ok(())})();
        if result.is_err() {let _=std::fs::remove_file(tmp);}result
    }
}
fn acquire_lock(path:&Path)->Result<std::fs::File> {
    let file=std::fs::OpenOptions::new().read(true).write(true).create(true).open(path).map_err(|e|Error::Store(format!("cursor lock open: {e}")))?;
    let started=std::time::Instant::now();loop {match file.try_lock() {
        Ok(())=>return Ok(file),
        Err(std::fs::TryLockError::WouldBlock) if started.elapsed()<std::time::Duration::from_secs(3)=>std::thread::sleep(std::time::Duration::from_millis(20)),
        Err(std::fs::TryLockError::WouldBlock)=>return Err(Error::Store("cursor lock timed out".into())),
        Err(e)=>return Err(Error::Store(format!("cursor lock: {e}"))),
    }}
}
fn sync_parent(_parent:&Path)->Result<()> {
    #[cfg(unix)] std::fs::File::open(_parent).and_then(|f|f.sync_all()).map_err(|e|Error::Store(format!("cursor directory sync: {e}")))?;
    Ok(())
}

/// Transient pending IDs are deliberately not committed: after a crash the
/// persisted cursor remains at the old page and history deduplicates repeats.
#[derive(Clone)]
pub struct PendingPage {
    lane: Lane,
    ids: BTreeSet<String>,
    next: Option<u64>,
    complete: bool,
    saturated: bool,
}

impl PendingPage {
    pub fn new(lane:Lane, events:&[(String,u64)], requested:usize, completeness_verified:bool, boundary_verified:bool) -> Result<Self> {
        if requested==0 || events.len()>requested {return Err(Error::Store("invalid page size".into()));}
        let mut ids=BTreeSet::new();
        for (id,_) in events {
            if id.len()!=64 || !id.bytes().all(|b|b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) || !ids.insert(id.clone()) {
                return Err(Error::Store("invalid or duplicate event id".into()));
            }
        }
        let oldest=events.iter().map(|(_,ts)|*ts).min();
        let full=events.len()==requested;
        let saturated=full && oldest.is_some_and(|ts|events.iter().all(|(_,t)|*t==ts));
        let next=oldest.and_then(|n|n.checked_sub(1));
        // A full page at timestamp zero cannot safely advance.
        // A full page can cut through the oldest second even when several
        // different timestamps are present. Never subtract one until a
        // separate boundary query has established completeness.
        let saturated=saturated || (full && (next.is_none() || !boundary_verified)) || (!full && !completeness_verified);
        Ok(Self{lane,ids,next,complete:!full,saturated})
    }
    pub fn ack(&mut self,id:&str)->Result<()> {
        if !self.ids.remove(id) {return Err(Error::Store("unknown or duplicate page ACK".into()));}Ok(())
    }
    pub fn ready(&self)->bool {self.ids.is_empty()}
    pub fn incomplete(&self)->bool {self.saturated}
    /// Caller must persist returned cursor atomically only after this succeeds.
    pub fn commit(self, old:&Cursor) -> Result<Cursor> {
        if !self.ready() {return Err(Error::Store("page has unacknowledged events".into()));}
        if self.saturated {return Err(Error::Store("timestamp saturated; page incomplete".into()));}
        let mut next=old.clone();
        match self.lane {
            Lane::Live => next.live_until=if self.complete {None} else {self.next},
            Lane::Backfill => {next.backfill_until=if self.complete {None} else {self.next};if self.complete {next.backfill_done=true;}}
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(n:u8)->String {format!("{n:064x}")}
    #[test]
    fn oversized_registry_write_does_not_replace_valid_registry() {
        let d=std::env::temp_dir().join(format!("gs-registry-quota-{}",uuid::Uuid::new_v4()));std::fs::create_dir_all(&d).unwrap();
        let registry=Registry::new(d.clone(),[7;32],"profile").unwrap();registry.initialize_baseline().unwrap();
        let before=std::fs::read(registry.registry_path()).unwrap();
        assert!(registry.crypt_write(&registry.registry_path(),&vec![0;1024*1024],&registry.aad()).is_err());
        assert_eq!(std::fs::read(registry.registry_path()).unwrap(),before);assert!(registry.load().is_ok());let _=std::fs::remove_dir_all(d);
    }
    #[test]
    fn interrupted_empty_registry_marker_is_recovered_without_resetting_routes() {
        let d=std::env::temp_dir().join(format!("gs-registry-resume-{}",uuid::Uuid::new_v4()));std::fs::create_dir_all(&d).unwrap();
        let registry=Registry::new(d.clone(),[7;32],"profile").unwrap();
        let bytes=serde_json::to_vec(&RouteRegistry{version:1,routes:BTreeSet::new(),names:BTreeMap::new()}).unwrap();
        registry.crypt_write(&registry.registry_path(),&bytes,&registry.aad()).unwrap();
        registry.resume_empty_baseline().unwrap();assert!(registry.marker_path().exists());
        registry.register_route("route",&Cursor::default()).unwrap();std::fs::remove_file(registry.marker_path()).unwrap();
        assert!(registry.resume_empty_baseline().is_err());assert!(registry.registry_path().exists());
        let _=std::fs::remove_dir_all(d);
    }
    #[test]
    fn queue_and_cursor_commit_together_and_survive_restart() {
        let d=std::env::temp_dir().join(format!("gs-atomic-cursor-{}",uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        let path=d.join("cursor.enc");let key=[7u8;32];
        let store=CursorStore::new(path.clone(),key,"test","route").unwrap();
        let old=Cursor::default();store.initialize(&old).unwrap();
        let a=crate::nostr::NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let b=crate::nostr::NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000002").unwrap();
        let event=a.wrap_event(&b.public(),"synthetic".into(),123).unwrap();
        let mut next=old.clone();next.live_floor=123;next.preserve(&event,123).unwrap();
        // A process crash before the atomic replace leaves both absent.
        assert_eq!(CursorStore::new(path.clone(),key,"test","route").unwrap().load().unwrap(),old);
        store.save_if(&old,&next).unwrap();
        assert_eq!(CursorStore::new(path.clone(),key,"test","route").unwrap().load().unwrap(),next);
        // A conflicting stale writer cannot discard the committed event.
        assert!(store.save_if(&old,&old).is_err());assert_eq!(store.load().unwrap(),next);
        std::fs::remove_dir_all(d).unwrap();
    }
    #[test]
    fn oversized_state_rejected_without_overwriting_old_checkpoint() {
        let d=std::env::temp_dir().join(format!("gs-atomic-quota-{}",uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();let store=CursorStore::new(d.join("cursor.enc"),[9;32],"test","route").unwrap();
        let old=Cursor::default();store.initialize(&old).unwrap();let mut next=old.clone();
        next.deferred=(0..=MAX_DEFERRED).map(|i|DeferredEvent{id:format!("{i:064x}"),json:"{}".into(),received_at:0}).collect();
        assert!(store.save_if(&old,&next).is_err());assert_eq!(store.load().unwrap(),old);std::fs::remove_dir_all(d).unwrap();
    }
    #[test]
    fn commit_waits_for_every_exact_event_and_survives_replay() {
        let cursor=Cursor::default();let mut page=PendingPage::new(Lane::Backfill,&[(id(1),100),(id(2),99)],2,true,true).unwrap();
        page.ack(&id(1)).unwrap();assert!(page.ack(&id(9)).is_err());assert!(!page.ready());
        // Crash here leaves the committed cursor untouched.
        let replay=cursor.clone();assert_eq!(replay,Cursor::default());
        page.ack(&id(2)).unwrap();let next=page.commit(&cursor).unwrap();assert_eq!(next.backfill_until,Some(98));
    }
    #[test]
    fn saturated_second_never_commits_even_after_all_acks() {
        let mut page=PendingPage::new(Lane::Live,&[(id(1),100),(id(2),100)],2,true,true).unwrap();
        page.ack(&id(1)).unwrap();page.ack(&id(2)).unwrap();assert!(page.incomplete());assert!(page.commit(&Cursor::default()).is_err());
    }
    #[test]
    fn completion_is_lane_specific() {
        let page=PendingPage::new(Lane::Backfill,&[],100,true,true).unwrap();let next=page.commit(&Cursor::default()).unwrap();
        assert!(next.backfill_done);assert_eq!(next.live_until,None);
    }
    #[test]
    fn hidden_relay_cap_cannot_be_called_complete() {
        let mut page=PendingPage::new(Lane::Live,&[(id(1),100)],100,false,false).unwrap();page.ack(&id(1)).unwrap();
        assert!(page.incomplete());assert!(page.commit(&Cursor::default()).is_err());
    }
    #[test]
    fn full_mixed_timestamp_page_requires_boundary_verification() {
        let mut page=PendingPage::new(Lane::Backfill,&[(id(1),100),(id(2),99)],2,true,false).unwrap();
        page.ack(&id(1)).unwrap();page.ack(&id(2)).unwrap();assert!(page.commit(&Cursor::default()).is_err());
    }
    #[test]
    fn checkpoint_is_bound_to_profile_and_route_and_detects_damage() {
        let dir=std::env::temp_dir().join(format!("gs-cursor-{}",uuid::Uuid::new_v4()));let path=dir.join("cursor.enc");
        let store=CursorStore::new(path.clone(),[7;32],"profile-a","wss://relay-a").unwrap();
        assert!(store.load().is_err());let cursor=Cursor{live_floor:42,..Cursor::default()};store.initialize(&cursor).unwrap();assert_eq!(store.load().unwrap(),cursor);
        assert!(CursorStore::new(path.clone(),[7;32],"profile-b","wss://relay-a").unwrap().load().is_err());
        assert!(CursorStore::new(path.clone(),[7;32],"profile-a","wss://relay-b").unwrap().load().is_err());
        std::fs::write(&path,b"broken").unwrap();assert!(store.load().is_err());assert!(store.save(&cursor).is_err());let _=std::fs::remove_dir_all(dir);
    }
    #[test]
    fn explicit_baseline_and_routes_fail_closed_on_interrupted_initialization() {
        let root=std::env::temp_dir().join(format!("gs-route-registry-{}",uuid::Uuid::new_v4()));
        let registry=Registry::new(root.clone(),[8;32],"profile").unwrap();
        assert!(registry.route("wss://a").is_err());registry.initialize_baseline().unwrap();
        registry.register_route("wss://a",&Cursor{live_floor:10,..Cursor::default()}).unwrap();
        registry.register_route("wss://b",&Cursor{live_floor:20,..Cursor::default()}).unwrap();
        assert_eq!(registry.route("wss://a").unwrap().load().unwrap().live_floor,10);
        assert_eq!(registry.route("wss://b").unwrap().load().unwrap().live_floor,20);
        assert!(registry.register_route("wss://a",&Cursor::default()).is_err());
        let id=Registry::route_id("wss://b").unwrap();std::fs::remove_file(root.join(format!("route-{id}.enc"))).unwrap();
        assert!(registry.route("wss://b").is_err());assert!(registry.register_route("wss://b",&Cursor::default()).is_err());
        assert!(registry.route("wss://a").is_ok());
        let other=Registry::new(root.clone(),[8;32],"other-profile").unwrap();assert!(other.route("wss://a").is_err());
        let _=std::fs::remove_dir_all(root);
    }
    #[test]
    fn process_exit_after_registry_does_not_reset_checkpoint() {
        const CHILD:&str="GS_CURSOR_REGISTRY_CHILD";
        if let Some(root)=std::env::var_os(CHILD) {
            let registry=Registry::new(PathBuf::from(root),[8;32],"profile").unwrap();
            let _=registry.register_route("wss://a",&Cursor::default());panic!("child did not exit");
        }
        let root=std::env::temp_dir().join(format!("gs-route-crash-{}",uuid::Uuid::new_v4()));
        let registry=Registry::new(root.clone(),[8;32],"profile").unwrap();registry.initialize_baseline().unwrap();
        let status=std::process::Command::new(std::env::current_exe().unwrap()).arg("--exact")
            .arg("nostr::cursor::tests::process_exit_after_registry_does_not_reset_checkpoint")
            .env(CHILD,&root).env("GS_CURSOR_EXIT_AFTER_REGISTRY","1").status().unwrap();
        assert_eq!(status.code(),Some(23));assert!(registry.route("wss://a").is_err());
        assert!(registry.register_route("wss://a",&Cursor::default()).is_err());let _=std::fs::remove_dir_all(root);
    }
}

