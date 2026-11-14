// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable encrypted payment envelopes; exact retries preserve the message id.
use std::{fs::{self, OpenOptions}, io::{Read, Write}, path::{Path, PathBuf}, sync::Mutex};
use chacha20poly1305::{aead::{Aead, NewAead, Payload}, ChaCha20Poly1305, Key, Nonce};
use glaux_messenger::{Address, Envelope, Identity, MessageKind};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const AAD: &[u8] = b"grinsight-payment-outbox/v1";
const MAX_FILE: u64 = 256 * 1024;
const MAX_ENTRIES: usize = 10_000;
#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(),String> { fs::File::open(path).and_then(|f|f.sync_all()).map_err(|_| "payment outbox directory sync failed".into()) }
#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(),String> { Ok(()) }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved { version: u8, peer: String, armor: String, route: String, envelope: Envelope }

pub struct PaymentOutbox { root: PathBuf, key: Zeroizing<[u8;32]>, index: Zeroizing<[u8;32]>, lock: Mutex<()> }
impl PaymentOutbox {
    pub fn open(root: PathBuf, seed: &[u8;32], network: &str) -> Result<Self, String> {
        fs::create_dir_all(&root).map_err(|_| "payment outbox unavailable")?;
        let hk=Hkdf::<Sha256>::new(Some(b"grinsight-payment-outbox-v1"),seed);
        let mut key=Zeroizing::new([0u8;32]); let mut index=Zeroizing::new([0u8;32]);
        let label=crate::identity::network_hrp(network);
        hk.expand(&[b"encryption/".as_slice(),label.as_bytes()].concat(),key.as_mut()).map_err(|_| "outbox key failed")?;
        hk.expand(&[b"index/".as_slice(),label.as_bytes()].concat(),index.as_mut()).map_err(|_| "outbox key failed")?;
        let mut verifier=Zeroizing::new([0u8;32]);
        hk.expand(&[b"verifier/".as_slice(),label.as_bytes()].concat(),verifier.as_mut()).map_err(|_| "outbox key failed")?;
        let marker=root.join(".profile");
        if !marker.exists() && (root.join(".ledger").exists() || fs::read_dir(&root).map_err(|_| "payment outbox unavailable")?.filter_map(Result::ok).any(|e|e.path().extension().and_then(|x|x.to_str())==Some("msg"))) {
            return Err("payment outbox profile marker missing while records exist".into());
        }
        match OpenOptions::new().write(true).create_new(true).open(&marker) {
            Ok(mut f) => f.write_all(&verifier[..]).and_then(|_|f.sync_all()).map_err(|_| "payment outbox profile write failed")?,
            Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists => {
                let bytes=fs::read(&marker).map_err(|_| "payment outbox profile unreadable")?;
                if bytes.len()!=32 || bytes.iter().zip(verifier.iter()).fold(0u8,|a,(x,y)|a|(x^y))!=0 { return Err("payment outbox profile mismatch or corrupt".into()); }
            }
            Err(_) => return Err("payment outbox profile unavailable".into()),
        }
        let ledger=root.join(".ledger");
        if !ledger.exists() && fs::read_dir(&root).map_err(|_| "payment outbox unavailable")?.filter_map(Result::ok).any(|e|e.path().extension().and_then(|x|x.to_str())==Some("msg")) {
            return Err("payment outbox ledger missing while messages exist".into());
        }
        match OpenOptions::new().write(true).create_new(true).open(&ledger) {
            Ok(f) => { f.sync_all().map_err(|_| "payment outbox ledger unavailable")?; }
            Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists => {},
            Err(_) => return Err("payment outbox ledger unavailable".into()),
        }
        sync_directory(&root)?;
        Ok(Self{root,key,index,lock:Mutex::new(())})
    }
    fn ledger(&self) -> Result<std::collections::HashSet<String>,String> {
        let data=fs::read_to_string(self.root.join(".ledger")).map_err(|_| "payment outbox ledger unreadable")?;
        if !data.is_empty() && !data.ends_with('\n') { return Err("payment outbox ledger truncated".into()); }
        let mut ids=std::collections::HashSet::new();
        for id in data.lines() {
            if id.len()!=64 || !id.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) || !ids.insert(id.to_owned()) { return Err("payment outbox ledger corrupt".into()); }
        }
        Ok(ids)
    }
    fn record_id(&self, id:&str) -> Result<(),String> {
        let mut f=OpenOptions::new().append(true).open(self.root.join(".ledger")).map_err(|_| "payment outbox ledger unavailable")?;
        f.write_all(format!("{id}\n").as_bytes()).and_then(|_|f.sync_all()).map_err(|_| "payment outbox ledger write failed".into())
    }
    fn filename(&self, _peer: &Address, armor: &str) -> Result<String,String> {
        let digest=Sha256::digest(armor.as_bytes()); let hk=Hkdf::<Sha256>::new(Some(b"payment-id-v1"),&self.index[..]);
        let mut out=[0u8;32]; let mut info=b"slatepack/".to_vec(); info.extend_from_slice(&digest);
        hk.expand(&info,&mut out).map_err(|_| "outbox id failed")?;
        Ok(data_encoding::HEXLOWER.encode(&out))
    }
    fn read(&self, path: &Path, file_id: &str) -> Result<Saved,String> {
        let mut f=fs::File::open(path).map_err(|_| "payment outbox read failed")?;
        let mut raw=Vec::new(); (&mut f).take(MAX_FILE+1).read_to_end(&mut raw).map_err(|_| "payment outbox read failed")?;
        if raw.len()<28 || raw.len() as u64>MAX_FILE { return Err("payment outbox corrupt".into()); }
        let mut aad=AAD.to_vec(); aad.extend_from_slice(file_id.as_bytes());
        let plain=Zeroizing::new(ChaCha20Poly1305::new(Key::from_slice(&self.key[..])).decrypt(Nonce::from_slice(&raw[..12]),Payload{msg:&raw[12..],aad:&aad}).map_err(|_| "payment outbox authentication failed")?);
        serde_json::from_slice(&plain).map_err(|_| "payment outbox corrupt".into())
    }
    pub fn envelope(&self, identity: &Identity, peer: &Address, armor: &str, route: &str, ttl: u64) -> Result<Envelope,String> {
        let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| "clock error")?.as_secs();
        self.envelope_at(identity,peer,armor,route,ttl,now)
    }
    fn envelope_at(&self, identity: &Identity, peer: &Address, armor: &str, route: &str, ttl: u64, now: u64) -> Result<Envelope,String> {
        let _guard=self.lock.lock().map_err(|_| "payment outbox lock failed")?;
        let id=self.filename(peer,armor)?; let path=self.root.join(format!("{id}.msg"));
        let recorded=self.ledger()?.contains(&id);
        match fs::metadata(&path) {
            Ok(m) if !m.is_file() || m.len()>MAX_FILE => return Err("payment outbox corrupt".into()),
            Ok(_) => {
                let entry=self.read(&path,&id)?;
                if entry.version!=1 || entry.peer!=peer.to_string() || entry.armor!=armor || entry.envelope.recipient!=peer.to_string() { return Err("payment outbox mismatch".into()); }
                if entry.route!=route { return Err("payment was prepared for a different messaging route; verify its state before changing channels".into()); }
                let expired = if route.starts_with("nostr-direct:") || route.starts_with("nostr-i2p:") {
                    now >= entry.envelope.created_at.saturating_add(entry.envelope.ttl)
                } else { entry.envelope.is_expired(now) };
                if expired { return Err("payment message expired; verify payment state before retrying".into()); }
                if !recorded { self.record_id(&id)?; }
                return Ok(entry.envelope);
            }
            Err(e) if e.kind()==std::io::ErrorKind::NotFound && recorded => return Err("saved payment message is missing; verify payment state before retrying".into()),
            Err(e) if e.kind()==std::io::ErrorKind::NotFound => {},
            Err(_) => return Err("payment outbox inaccessible".into()),
        }
        let count=fs::read_dir(&self.root).map_err(|_| "payment outbox unavailable")?.filter_map(Result::ok).filter(|e|e.path().extension().and_then(|x|x.to_str())==Some("msg")).take(MAX_ENTRIES+1).count();
        if count>=MAX_ENTRIES {return Err("payment outbox full".into())}
        let envelope=Envelope::seal(identity,peer,MessageKind::Slatepack{armor:armor.to_owned(),encrypted:true},ttl,now).map_err(|e|format!("payment envelope: {e}"))?;
        let entry=Saved{version:1,peer:peer.to_string(),armor:armor.to_string(),route:route.to_string(),envelope:envelope.clone()};
        let plain=Zeroizing::new(serde_json::to_vec(&entry).map_err(|_| "payment outbox serialization failed")?);
        let mut nonce=[0u8;12]; getrandom::getrandom(&mut nonce).map_err(|_| "payment outbox random failed")?;
        let mut aad=AAD.to_vec();aad.extend_from_slice(id.as_bytes());
        let encrypted=ChaCha20Poly1305::new(Key::from_slice(&self.key[..])).encrypt(Nonce::from_slice(&nonce),Payload{msg:&plain,aad:&aad}).map_err(|_| "payment outbox encryption failed")?;
        if (encrypted.len()+12) as u64>MAX_FILE{return Err("payment outbox item too large".into())}
        let tmp=self.root.join(format!(".{id}.{}.tmp",data_encoding::HEXLOWER.encode(&nonce)));
        let mut options=OpenOptions::new();options.write(true).create_new(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        let mut f=options.open(&tmp).map_err(|_| "payment outbox temporary file exists or cannot be created")?;
        f.write_all(&nonce).and_then(|_|f.write_all(&encrypted)).and_then(|_|f.sync_all()).map_err(|_| "payment outbox write failed")?;
        drop(f);
        if fs::hard_link(&tmp,&path).is_err() {
            let _ = fs::remove_file(&tmp);
            return Err("payment outbox commit failed or another writer won; retry safely".into());
        }
        let _ = fs::remove_file(&tmp);
        sync_directory(&self.root)?;
        self.record_id(&id)?;
        Ok(envelope)
    }
}
#[cfg(test)] mod tests {
 use super::*;
 fn dir(tag:&str)->PathBuf{std::env::temp_dir().join(format!("gs-outbox-{tag}-{}",std::process::id()))}
 #[test] fn nostr_retry_stops_at_exact_expiry_without_new_envelope(){
  let d=dir("boundary");let _=fs::remove_dir_all(&d);let a=Identity::from_seed([1;32],"tgrin").unwrap();let b=Identity::from_seed([2;32],"tgrin").unwrap();
  let out=PaymentOutbox::open(d.clone(),&[3;32],"floonet").unwrap();let route="nostr-direct:wss://relay.example";
  let e=out.envelope_at(&a,b.address(),"synthetic-s1",route,900,1000).unwrap();
  let retry=out.envelope_at(&a,b.address(),"synthetic-s1",route,900,1899).unwrap();assert_eq!(serde_json::to_vec(&e).unwrap(),serde_json::to_vec(&retry).unwrap());
  assert!(out.envelope_at(&a,b.address(),"synthetic-s1",route,900,1900).unwrap_err().contains("expired"));
  assert!(out.envelope_at(&a,b.address(),"synthetic-s1",route,900,1901).unwrap_err().contains("expired"));
  let unchanged=out.read(&d.join(format!("{}.msg",out.filename(b.address(),"synthetic-s1").unwrap())),&out.filename(b.address(),"synthetic-s1").unwrap()).unwrap();
  assert_eq!(unchanged.envelope.id,e.id);drop(out);let _=fs::remove_dir_all(d);
 }
 #[test] fn retries_survive_restart_without_changing_id_and_reject_route_change(){
  let d=dir("retry");let _=fs::remove_dir_all(&d);let seed=[3;32];let a=Identity::from_seed([1;32],"tgrin").unwrap();let b=Identity::from_seed([2;32],"tgrin").unwrap();
  let out=PaymentOutbox::open(d.clone(),&seed,"floonet").unwrap();let e=out.envelope(&a,b.address(),"ciphertext","direct:wss://server",60).unwrap();drop(out);
  let out=PaymentOutbox::open(d.clone(),&seed,"floonet").unwrap();let f=out.envelope(&a,b.address(),"ciphertext","direct:wss://server",60).unwrap();assert_eq!(e.id,f.id);assert_eq!(serde_json::to_vec(&e).unwrap(),serde_json::to_vec(&f).unwrap());
  assert!(PaymentOutbox::open(d.clone(),&[4;32],"floonet").is_err());
  assert!(out.envelope(&a,b.address(),"ciphertext","i2p:other",60).is_err());
  let other=Identity::from_seed([9;32],"tgrin").unwrap();assert!(out.envelope(&a,other.address(),"ciphertext","direct:wss://server",60).is_err());drop(out);let _=fs::remove_dir_all(d);
 }
 #[test] fn existing_13h_packet_is_not_resealed_with_new_15_minute_ttl(){
  let d=dir("legacy-ttl");let _=fs::remove_dir_all(&d);let a=Identity::from_seed([1;32],"tgrin").unwrap();let b=Identity::from_seed([2;32],"tgrin").unwrap();
  let old=PaymentOutbox::open(d.clone(),&[3;32],"floonet").unwrap();let original=old.envelope(&a,b.address(),"legacy-armor","route",13*3600).unwrap();drop(old);
  let reopened=PaymentOutbox::open(d.clone(),&[3;32],"floonet").unwrap();let retried=reopened.envelope(&a,b.address(),"legacy-armor","route",900).unwrap();
  assert_eq!(retried.ttl,13*3600);assert_eq!(serde_json::to_vec(&retried).unwrap(),serde_json::to_vec(&original).unwrap());drop(reopened);let _=fs::remove_dir_all(d);
 }
 #[test] fn missing_saved_message_and_truncated_ledger_fail_closed(){
  let d=dir("missing");let _=fs::remove_dir_all(&d);let a=Identity::from_seed([1;32],"tgrin").unwrap();let b=Identity::from_seed([2;32],"tgrin").unwrap();let out=PaymentOutbox::open(d.clone(),&[3;32],"floonet").unwrap();out.envelope(&a,b.address(),"ciphertext","i2p",60).unwrap();
  let path=d.join(format!("{}.msg",out.filename(b.address(),"ciphertext").unwrap()));fs::remove_file(&path).unwrap();assert!(out.envelope(&a,b.address(),"ciphertext","i2p",60).is_err());assert!(!path.exists());
  fs::write(d.join(".ledger"),b"partial").unwrap();assert!(out.envelope(&a,b.address(),"ciphertext","i2p",60).is_err());drop(out);
  fs::remove_file(d.join(".profile")).unwrap();assert!(PaymentOutbox::open(d.clone(),&[3;32],"floonet").is_err());let _=fs::remove_dir_all(d);
 }
 #[test] fn tamper_or_wrong_key_never_regenerates_message(){
  let d=dir("corrupt");let _=fs::remove_dir_all(&d);let a=Identity::from_seed([1;32],"tgrin").unwrap();let b=Identity::from_seed([2;32],"tgrin").unwrap();let out=PaymentOutbox::open(d.clone(),&[3;32],"floonet").unwrap();out.envelope(&a,b.address(),"ciphertext","i2p",60).unwrap();
  let path=d.join(format!("{}.msg",out.filename(b.address(),"ciphertext").unwrap()));let mut raw=fs::read(&path).unwrap();let end=raw.len()-1;raw[end]^=1;fs::write(&path,&raw).unwrap();assert!(out.envelope(&a,b.address(),"ciphertext","i2p",60).is_err());assert_eq!(fs::read(&path).unwrap(),raw);drop(out);let _=fs::remove_dir_all(d);
 }
}
