//! Encrypted, bounded preservation of malformed raw gateway payloads.
//! The caller must save successfully before sending any signed raw reject.
//! An OS file lock serializes separate processes. Windows directory fsync and
//! power-loss durability are not established by `rename` alone.
use std::{fs, io::{Read,Write}, path::{Path,PathBuf}, sync::Mutex};
use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize,Serialize};
use zeroize::Zeroizing;
use crate::{address::Address, ack::{definitely_malformed_raw,raw_payload_digest}, error::{Error,Result}};

const DOMAIN:&[u8]=b"grinsight-raw-quarantine-v1";
const MAX_PAYLOAD:usize=64*1024;
const MAX_RECORDS:usize=1000;
const MAX_TOTAL_BYTES:u64=68*1024*1024;

#[derive(Serialize,Deserialize)]
struct Record { to:String,id:String,digest:String,payload:String,#[serde(default)] envelope:bool }

/// Capability emitted only after the item is persisted and verified.
#[derive(Clone,Debug)]
pub struct QuarantinedRaw { pub(crate) owner:String, pub(crate) id:String, pub(crate) digest:String, envelope:bool }
impl QuarantinedRaw { pub fn digest(&self)->&str { &self.digest } pub fn id(&self)->&str {&self.id} pub fn is_envelope(&self)->bool {self.envelope} }

pub struct RawStatus {pub id:String,pub digest:String,pub kind:&'static str,pub corrupt:bool,pub name_token:Option<String>}
pub struct RawQuarantine { root:PathBuf, owner:Address, key:Zeroizing<[u8;32]>, lock:Mutex<()> }
impl RawQuarantine {
    pub fn open(root:impl Into<PathBuf>,owner:Address,key:[u8;32])->Result<Self>{
        let root=root.into();fs::create_dir_all(&root).map_err(|e|Error::Store(format!("raw quarantine: {e}")))?;
        Ok(Self{root,owner,key:Zeroizing::new(key),lock:Mutex::new(())})
    }
    fn guard(&self)->Result<(std::sync::MutexGuard<'_,()>,fs::File)> {
        let started=std::time::Instant::now();
        let guard=loop {match self.lock.try_lock() {
            Ok(g)=>break g,
            Err(std::sync::TryLockError::WouldBlock) if started.elapsed()<std::time::Duration::from_secs(3)=>std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(_)=>return Err(Error::Store("raw quarantine lock unavailable".into())),
        }};
        let file=fs::OpenOptions::new().read(true).write(true).create(true).open(self.root.join("raw-quarantine.lock")).map_err(|e|Error::Store(format!("raw quarantine lock open: {e}")))?;
        loop {match file.try_lock() {
            Ok(())=>break,
            Err(std::fs::TryLockError::WouldBlock) if started.elapsed()<std::time::Duration::from_secs(3)=>std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(_)=>return Err(Error::Store("raw quarantine lock unavailable".into())),
        }}
        Ok((guard,file))
    }
    fn cipher(&self)->ChaCha20Poly1305 { ChaCha20Poly1305::new(Key::from_slice(&self.key[..])) }
    fn verify_record(&self,path:&Path)->Result<Record>{
        let file=fs::File::open(path).map_err(|e|Error::Store(format!("raw quarantine read: {e}")))?;
        let mut data=Vec::new();file.take((MAX_PAYLOAD*2+1) as u64).read_to_end(&mut data).map_err(|e|Error::Store(format!("raw quarantine read: {e}")))?;
        if data.len()<=12 || data.len()>MAX_PAYLOAD*2 {return Err(Error::Crypto("raw quarantine damaged".into()))}
        let plain=Zeroizing::new(self.cipher().decrypt(Nonce::from_slice(&data[..12]),Payload{msg:&data[12..],aad:DOMAIN}).map_err(|_|Error::Crypto("raw quarantine authentication failed".into()))?);
        let rec:Record=serde_json::from_slice(&plain).map_err(|_|Error::Crypto("raw quarantine invalid".into()))?;
        if rec.to!=self.owner.to_string() || rec.payload.len()>MAX_PAYLOAD || rec.digest!=raw_payload_digest(&rec.payload) || (!rec.envelope && !definitely_malformed_raw(&rec.payload)) || (rec.envelope && !valid_envelope(&rec.id,&rec.payload)) || !valid_id(&rec.id) {return Err(Error::Crypto("raw quarantine invalid".into()))}
        Ok(rec)
    }
    /// Hold both process and filesystem locks, and revalidate the saved record
    /// immediately before the caller attempts its irreversible network reject.
    pub fn with_saved<F>(&self,saved:&QuarantinedRaw,action:F)->Result<()>
    where F:FnOnce()->Result<()> {
        let _guard=self.guard()?;
        if saved.owner!=self.owner.to_string() || !valid_id(&saved.id) {return Err(Error::Crypto("raw quarantine owner mismatch".into()))}
        let path=self.root.join(format!("{}-{}.raw",saved.id,saved.digest));
        let rec=self.verify_record(&path)?;
        if rec.id!=saved.id || rec.digest!=saved.digest {return Err(Error::Crypto("raw quarantine capability mismatch".into()))}
        action()
    }

    /// Enumerate authenticated recovery capabilities without revealing plaintext.
    pub fn list_saved(&self)->Result<Vec<QuarantinedRaw>> {
        let _guard=self.guard()?;let mut out=Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|e|Error::Store(format!("raw quarantine list: {e}")))? {
            let entry=entry.map_err(|e|Error::Store(format!("raw quarantine list: {e}")))?;
            if entry.path().extension().and_then(|v|v.to_str())!=Some("raw") {continue;}
            let ty=entry.file_type().map_err(|e|Error::Store(format!("raw quarantine type: {e}")))?;
            if !ty.is_file(){return Err(Error::Store("raw quarantine unexpected entry".into()));}
            let rec=self.verify_record(&entry.path())?;
            let expected=format!("{}-{}.raw",rec.id,rec.digest);
            if entry.file_name()!=std::ffi::OsStr::new(&expected){return Err(Error::Crypto("raw quarantine name mismatch".into()));}
            out.push(QuarantinedRaw{owner:self.owner.to_string(),id:rec.id,digest:rec.digest,envelope:rec.envelope});
            if out.len()>MAX_RECORDS{return Err(Error::Quota("raw quarantine limit exceeded".into()));}
        }
        Ok(out)
    }
    pub fn list_status(&self)->Result<Vec<RawStatus>> {
        let _guard=self.guard()?;let mut out=Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|e|Error::Store(format!("raw quarantine list: {e}")))? {
            let entry=entry.map_err(|e|Error::Store(format!("raw quarantine list: {e}")))?;let name=entry.file_name();let name=name.to_str().ok_or_else(||Error::Store("raw quarantine invalid name".into()))?;
            let Some(stem)=name.strip_suffix(".raw") else {continue};
            if !entry.file_type().map_err(|e|Error::Store(format!("raw quarantine type: {e}")))?.is_file(){return Err(Error::Store("raw quarantine unsafe entry".into()));}
            match parse_parts(stem) {
                Ok((id,digest))=>{
                    let (kind,corrupt)=match self.verify_record(&entry.path()) {Ok(rec) if rec.id==id && rec.digest==digest=>(if rec.envelope {"envelope"} else {"malformed"},false),_=>("unknown",true)};
                    out.push(RawStatus{id:id.into(),digest:digest.into(),kind,corrupt,name_token:None});
                },
                Err(_)=>out.push(RawStatus{id:String::new(),digest:String::new(),kind:"invalid_name",corrupt:true,name_token:Some(name_token(name))}),
            }
            if out.len()>MAX_RECORDS{return Err(Error::Quota("raw quarantine limit exceeded".into()));}
        }
        out.sort_by(|a,b|(&a.id,&a.digest).cmp(&(&b.id,&b.digest)));Ok(out)
    }
    fn invalid_path_by_token(&self,token:&str)->Result<PathBuf> {
        if token.len()!=64 || !token.bytes().all(|b|b.is_ascii_hexdigit()&&!b.is_ascii_uppercase()){return Err(Error::Store("invalid quarantine token".into()));}
        let mut found=None;
        for entry in fs::read_dir(&self.root).map_err(|e|Error::Store(format!("raw quarantine list: {e}")))? {
            let entry=entry.map_err(|e|Error::Store(format!("raw quarantine list: {e}")))?;let name=entry.file_name();let Some(name)=name.to_str() else {continue};
            let Some(stem)=name.strip_suffix(".raw") else {continue};if parse_parts(stem).is_ok() || name_token(name)!=token {continue;}
            if !entry.file_type().map_err(|e|Error::Store(format!("raw quarantine type: {e}")))?.is_file(){return Err(Error::Store("raw quarantine unsafe entry".into()));}
            if found.replace(entry.path()).is_some(){return Err(Error::Store("ambiguous quarantine token".into()));}
        }
        found.ok_or_else(||Error::Store("quarantine entry not found".into()))
    }
    pub fn export_invalid_envelope(&self,token:&str)->Result<String> {
        let _guard=self.guard()?;let path=self.invalid_path_by_token(token)?;let rec=self.verify_record(&path)?;
        if !rec.envelope{return Err(Error::Store("not an encrypted envelope".into()));}Ok(rec.payload)
    }
    pub fn delete_invalid_name(&self,token:&str)->Result<()> {
        let _guard=self.guard()?;let path=self.invalid_path_by_token(token)?;
        fs::remove_file(path).map_err(|e|Error::Store(format!("raw quarantine delete: {e}")))?;
        #[cfg(unix)] fs::File::open(&self.root).and_then(|d|d.sync_all()).map_err(|e|Error::Store(format!("raw quarantine directory sync: {e}")))?;Ok(())
    }
    pub fn recover_envelope_by_parts(&self,id:&str,digest:&str)->Result<String> {
        let _guard=self.guard()?;let path=self.checked_path(id,digest)?;let rec=self.verify_record(&path)?;
        if !rec.envelope || rec.id!=id || rec.digest!=digest {return Err(Error::Crypto("quarantine record mismatch".into()));}Ok(rec.payload)
    }
    /// Requires explicit user confirmation; corruption needs separate confirmation.
    pub fn delete_by_parts(&self,id:&str,digest:&str,allow_corrupt:bool)->Result<()> {
        let _guard=self.guard()?;let path=self.checked_path(id,digest)?;
        match self.verify_record(&path) {Ok(rec) if rec.id==id && rec.digest==digest=>{},_ if allow_corrupt=>{},_=>return Err(Error::Crypto("corrupt quarantine requires separate confirmation".into()))};
        fs::remove_file(path).map_err(|e|Error::Store(format!("raw quarantine delete: {e}")))?;
        #[cfg(unix)] fs::File::open(&self.root).and_then(|d|d.sync_all()).map_err(|e|Error::Store(format!("raw quarantine directory sync: {e}")))?;Ok(())
    }
    fn checked_path(&self,id:&str,digest:&str)->Result<PathBuf> {
        parse_parts(&format!("{id}-{digest}"))?;let path=self.root.join(format!("{id}-{digest}.raw"));
        if !fs::symlink_metadata(&path).map_err(|e|Error::Store(format!("raw quarantine metadata: {e}")))?.file_type().is_file(){return Err(Error::Store("raw quarantine unsafe entry".into()));}Ok(path)
    }
    /// Retrieve a previously saved, authenticated copy for explicit recovery.
    pub fn recover_saved(&self,saved:&QuarantinedRaw)->Result<String> {
        let _guard=self.guard()?;
        if saved.owner!=self.owner.to_string() || !valid_id(&saved.id) {return Err(Error::Crypto("raw quarantine owner mismatch".into()))}
        let rec=self.verify_record(&self.root.join(format!("{}-{}.raw",saved.id,saved.digest)))?;
        if rec.id!=saved.id || rec.digest!=saved.digest {return Err(Error::Crypto("raw quarantine capability mismatch".into()))}Ok(rec.payload)
    }
    /// Caller must obtain explicit user consent before permanently discarding.
    pub fn delete_saved(&self,saved:&QuarantinedRaw)->Result<()> {
        let _guard=self.guard()?;
        if saved.owner!=self.owner.to_string() || !valid_id(&saved.id) {return Err(Error::Crypto("raw quarantine owner mismatch".into()))}
        let path=self.root.join(format!("{}-{}.raw",saved.id,saved.digest));let rec=self.verify_record(&path)?;
        if rec.envelope!=saved.envelope || rec.id!=saved.id || rec.digest!=saved.digest {return Err(Error::Crypto("raw quarantine capability mismatch".into()));}
        fs::remove_file(path).map_err(|e|Error::Store(format!("raw quarantine delete: {e}")))?;
        #[cfg(unix)] fs::File::open(&self.root).and_then(|d|d.sync_all()).map_err(|e|Error::Store(format!("raw quarantine directory sync: {e}")))?;
        Ok(())
    }
    /// Remove only named abandoned temporary files while holding the shared lock.
    /// A crash before rename never granted an ACK capability.
    pub fn cleanup_abandoned_temps(&self)->Result<usize> {
        let _guard=self.guard()?;let mut paths=Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|e|Error::Store(format!("raw quarantine list: {e}")))? {
            let entry=entry.map_err(|e|Error::Store(format!("raw quarantine entry: {e}")))?;
            let name=entry.file_name();let Some(name)=name.to_str() else {return Err(Error::Store("raw quarantine invalid name".into()));};
            if let Some(id)=name.strip_suffix(".tmp") {
                if !valid_id(id) || !entry.file_type().map_err(|e|Error::Store(format!("raw quarantine type: {e}")))?.is_file(){return Err(Error::Store("raw quarantine unsafe temp; manual recovery required".into()));}
                paths.push(entry.path());
            }
        }
        for path in &paths {fs::remove_file(path).map_err(|e|Error::Store(format!("raw quarantine temp cleanup: {e}")))?;}
        #[cfg(unix)] fs::File::open(&self.root).and_then(|d|d.sync_all()).map_err(|e|Error::Store(format!("raw quarantine directory sync: {e}")))?;
        Ok(paths.len())
    }
    /// Preserve raw bytes before constructing a RawRejectProof. Errors mean no ACK.
    pub fn save(&self,id:&str,payload:&str)->Result<QuarantinedRaw>{self.save_inner(id,payload,false)}
    /// Preserve the full ciphertext for an invalid signed envelope before ACK.
    pub fn save_envelope(&self,id:&str,payload:&str)->Result<QuarantinedRaw>{self.save_inner(id,payload,true)}
    fn save_inner(&self,id:&str,payload:&str,envelope:bool)->Result<QuarantinedRaw>{
        let _guard=self.guard()?;
        if !valid_id(id) || payload.is_empty() || payload.len()>MAX_PAYLOAD || (!envelope && !definitely_malformed_raw(payload)) || (envelope && !valid_envelope(id,payload)) {return Err(Error::Store("raw item is not safely rejectable".into()))}
        let digest=raw_payload_digest(payload);
        let name=format!("{id}-{digest}.raw");
        let mut records=0usize;let mut total=0u64;
        for entry in fs::read_dir(&self.root).map_err(|e|Error::Store(format!("raw quarantine list: {e}")))? {
            let entry=entry.map_err(|e|Error::Store(format!("raw quarantine entry: {e}")))?;
            if entry.file_name()=="raw-quarantine.lock" {continue}
            let ty=entry.file_type().map_err(|e|Error::Store(format!("raw quarantine type: {e}")))?;
            if !ty.is_file(){return Err(Error::Store("raw quarantine unexpected entry".into()))}
            records=records.saturating_add(1);total=total.saturating_add(entry.metadata().map_err(|e|Error::Store(format!("raw quarantine metadata: {e}")))?.len());
            if entry.path().extension().and_then(|e|e.to_str())==Some("raw") { self.verify_record(&entry.path())?; }
        }
        let path=self.root.join(name);
        if path.exists(){ let rec=self.verify_record(&path)?;if rec.id==id && rec.payload==payload && rec.envelope==envelope{return Ok(QuarantinedRaw {owner:self.owner.to_string(),id:id.into(),digest,envelope})}return Err(Error::Crypto("raw quarantine conflict".into())) }
        if records>=MAX_RECORDS || total.saturating_add(payload.len() as u64*2+4096)>MAX_TOTAL_BYTES{return Err(Error::Quota("raw quarantine full; message not acknowledged".into()))}
        let rec=Record{to:self.owner.to_string(),id:id.into(),digest:digest.clone(),payload:payload.into(),envelope};
        let plain=Zeroizing::new(serde_json::to_vec(&rec).map_err(|_|Error::Crypto("raw quarantine encoding failed".into()))?);
        if plain.len() > MAX_PAYLOAD*2 || total.saturating_add(plain.len() as u64 + 28)>MAX_TOTAL_BYTES { return Err(Error::Quota("raw quarantine full; message not acknowledged".into())); }
        let mut nonce=[0u8;12];getrandom::getrandom(&mut nonce).map_err(|e|Error::Crypto(format!("raw quarantine RNG: {e}")))?;
        let encrypted=self.cipher().encrypt(Nonce::from_slice(&nonce),Payload{msg:&plain,aad:DOMAIN}).map_err(|_|Error::Crypto("raw quarantine encryption failed".into()))?;
        let tmp=self.root.join(format!("{}.tmp",uuid::Uuid::new_v4()));
        let mut f=fs::OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(|e|Error::Store(format!("raw quarantine create: {e}")))?;
        f.write_all(&nonce).and_then(|_|f.write_all(&encrypted)).and_then(|_|f.sync_all()).map_err(|e|Error::Store(format!("raw quarantine write: {e}")))?;
        drop(f);
        #[cfg(test)]
        if std::env::var_os("GS_RAW_TEST_CRASH_BEFORE_RENAME").is_some() {std::process::exit(73);}
        fs::rename(&tmp,&path).map_err(|e|Error::Store(format!("raw quarantine commit: {e}")))?;
        #[cfg(unix)] {fs::File::open(&self.root).and_then(|d|d.sync_all()).map_err(|e|Error::Store(format!("raw quarantine directory sync: {e}")))?;}
        Ok(QuarantinedRaw {owner:self.owner.to_string(),id:id.into(),digest,envelope})
    }
}
fn name_token(name:&str)->String {use sha2::{Digest,Sha256};data_encoding::HEXLOWER.encode(&Sha256::digest(name.as_bytes()))}
fn parse_parts(stem:&str)->Result<(&str,&str)> {
    let (id,digest)=stem.rsplit_once('-').ok_or_else(||Error::Store("invalid quarantine name".into()))?;
    if !valid_id(id) || digest.len()!=64 || !digest.bytes().all(|b|b.is_ascii_hexdigit()&&!b.is_ascii_uppercase()){return Err(Error::Store("invalid quarantine name".into()));}Ok((id,digest))
}
fn valid_envelope(id:&str,payload:&str)->bool {serde_json::from_str::<crate::envelope::Envelope>(payload).is_ok_and(|e|e.id==id)}
fn valid_id(id:&str)->bool { uuid::Uuid::parse_str(id).map(|u|u.to_string()==id).unwrap_or(false) }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;
    fn root()->PathBuf {std::env::temp_dir().join(format!("gs-raw-test-{}",uuid::Uuid::new_v4()))}
    #[test]
    fn raw_payload_is_encrypted_and_preserved_across_restart() {
        let dir=root();let owner=Identity::from_seed([7;32],"tgrin").unwrap().address().clone();
        let id="11111111-2222-4333-8444-555555555555";let payload="{damaged-secret-payload";
        let q=RawQuarantine::open(&dir,owner.clone(),[8;32]).unwrap();let digest=q.save(id,payload).unwrap().digest().to_string();drop(q);
        let bytes=fs::read(dir.join(format!("{id}-{digest}.raw"))).unwrap();assert!(!bytes.windows(payload.len()).any(|w|w==payload.as_bytes()));
        let q=RawQuarantine::open(&dir,owner.clone(),[8;32]).unwrap();assert_eq!(q.save(id,payload).unwrap().digest(),digest);
        let wrong=RawQuarantine::open(&dir,owner,[9;32]).unwrap();assert!(wrong.save(id,payload).is_err());
        let _=fs::remove_dir_all(dir);
    }
    #[test]
    fn invalid_filename_is_identified_without_using_it_as_a_path_parameter() {
        let dir=root();let recipient=Identity::from_seed([7;32],"tgrin").unwrap();let sender=Identity::from_seed([8;32],"tgrin").unwrap();let q=RawQuarantine::open(&dir,recipient.address().clone(),[8;32]).unwrap();
        let e=crate::envelope::Envelope::seal_now(&sender,recipient.address(),crate::envelope::MessageKind::Text{text:"synthetic".into()},600).unwrap();let raw=serde_json::to_string(&e).unwrap();
        let saved=q.save_envelope(&e.id,&raw).unwrap();fs::rename(dir.join(format!("{}-{}.raw",saved.id(),saved.digest())),dir.join("not-a-uuid.raw")).unwrap();
        let rows=q.list_status().unwrap();assert_eq!(rows.len(),1);assert_eq!(rows[0].kind,"invalid_name");let token=rows[0].name_token.as_ref().unwrap();
        assert_eq!(q.export_invalid_envelope(token).unwrap(),raw);assert!(q.delete_invalid_name(&"00".repeat(32)).is_err());
        q.delete_invalid_name(token).unwrap();assert!(q.list_status().unwrap().is_empty());drop(q);let _=fs::remove_dir_all(dir);
    }
    #[test]
    fn corrupt_record_does_not_hide_healthy_and_requires_separate_discard_consent() {
        let dir=root();let recipient=Identity::from_seed([7;32],"tgrin").unwrap();let sender=Identity::from_seed([8;32],"tgrin").unwrap();let q=RawQuarantine::open(&dir,recipient.address().clone(),[8;32]).unwrap();
        let a=crate::envelope::Envelope::seal_now(&sender,recipient.address(),crate::envelope::MessageKind::Text{text:"one".into()},600).unwrap();
        let b=crate::envelope::Envelope::seal_now(&sender,recipient.address(),crate::envelope::MessageKind::Text{text:"two".into()},600).unwrap();
        let ar=serde_json::to_string(&a).unwrap();let br=serde_json::to_string(&b).unwrap();let ac=q.save_envelope(&a.id,&ar).unwrap();let bc=q.save_envelope(&b.id,&br).unwrap();
        fs::write(dir.join(format!("{}-{}.raw",ac.id(),ac.digest())),b"damaged").unwrap();let status=q.list_status().unwrap();assert_eq!(status.len(),2);assert!(status.iter().any(|v|v.id==a.id && v.corrupt));
        assert_eq!(q.recover_envelope_by_parts(&b.id,bc.digest()).unwrap(),br);assert!(q.delete_by_parts(&a.id,ac.digest(),false).is_err());
        q.delete_by_parts(&a.id,ac.digest(),true).unwrap();assert_eq!(q.list_status().unwrap().len(),1);assert_eq!(q.recover_envelope_by_parts(&b.id,bc.digest()).unwrap(),br);
        drop(q);let _=fs::remove_dir_all(dir);
    }
    #[test]
    fn only_recognized_abandoned_temps_are_removed_under_lock() {
        let dir=root();let recipient=Identity::from_seed([7;32],"tgrin").unwrap();let q=RawQuarantine::open(&dir,recipient.address().clone(),[8;32]).unwrap();
        let temp=dir.join(format!("{}.tmp",uuid::Uuid::new_v4()));std::fs::write(&temp,b"test").unwrap();let other=dir.join("unknown.tmp");std::fs::write(&other,b"preserve").unwrap();
        assert!(q.cleanup_abandoned_temps().is_err());assert!(temp.exists());std::fs::remove_file(other).unwrap();assert_eq!(q.cleanup_abandoned_temps().unwrap(),1);assert!(!temp.exists());
        drop(q);let _=fs::remove_dir_all(dir);
    }
    #[test]
    fn signed_envelope_ciphertext_can_be_recovered_after_restart() {
        let dir=root();let recipient=Identity::from_seed([7;32],"tgrin").unwrap();let sender=Identity::from_seed([8;32],"tgrin").unwrap();
        let mut e=crate::envelope::Envelope::seal_now(&sender,recipient.address(),crate::envelope::MessageKind::Text{text:"synthetic".into()},600).unwrap();e.ciphertext.push(1);
        let payload=serde_json::to_string(&e).unwrap();let q=RawQuarantine::open(&dir,recipient.address().clone(),[8;32]).unwrap();q.save_envelope(&e.id,&payload).unwrap();drop(q);
        let q=RawQuarantine::open(&dir,recipient.address().clone(),[8;32]).unwrap();let items=q.list_saved().unwrap();assert_eq!(items.len(),1);assert_eq!(q.recover_saved(&items[0]).unwrap(),payload);
        let _=fs::remove_dir_all(dir);
    }
    #[test]
    fn crash_before_commit_cannot_create_a_reject_capability() {
        const CHILD:&str="GS_RAW_TEST_CRASH_DIR";
        if let Some(path)=std::env::var_os(CHILD) {
            let owner=Identity::from_seed([7;32],"tgrin").unwrap().address().clone();
            let q=RawQuarantine::open(path,owner,[8;32]).unwrap();
            let _=q.save("11111111-2222-4333-8444-555555555555","{bad");
            panic!("fault injection did not terminate");
        }
        let dir=root();let owner=Identity::from_seed([7;32],"tgrin").unwrap().address().clone();
        let mut cmd=std::process::Command::new(std::env::current_exe().unwrap());
        cmd.arg("--exact").arg("raw_quarantine::tests::crash_before_commit_cannot_create_a_reject_capability").env(CHILD,&dir).env("GS_RAW_TEST_CRASH_BEFORE_RENAME","1");
        #[cfg(windows)] { use std::os::windows::process::CommandExt;cmd.creation_flags(0x08000000); }
        assert_eq!(cmd.status().unwrap().code(),Some(73));
        assert!(!fs::read_dir(&dir).unwrap().any(|e|e.unwrap().path().extension().and_then(|x|x.to_str())==Some("raw")));
        let q=RawQuarantine::open(&dir,owner,[8;32]).unwrap();
        assert!(q.save("11111111-2222-4333-8444-555555555555","{bad").is_ok());
        let _=fs::remove_dir_all(dir);
    }
    #[test]
    fn crash_after_commit_before_reject_recovers_saved_payload() {
        const CHILD:&str="GS_RAW_TEST_COMMIT_DIR";
        if let Some(path)=std::env::var_os(CHILD) {
            let owner=Identity::from_seed([7;32],"tgrin").unwrap().address().clone();
            let q=RawQuarantine::open(path,owner,[8;32]).unwrap();
            q.save("11111111-2222-4333-8444-555555555555","{bad").unwrap();
            std::process::exit(74);
        }
        let dir=root();let owner=Identity::from_seed([7;32],"tgrin").unwrap().address().clone();
        let mut cmd=std::process::Command::new(std::env::current_exe().unwrap());
        cmd.arg("--exact").arg("raw_quarantine::tests::crash_after_commit_before_reject_recovers_saved_payload").env(CHILD,&dir);
        #[cfg(windows)] {use std::os::windows::process::CommandExt;cmd.creation_flags(0x08000000);}
        assert_eq!(cmd.status().unwrap().code(),Some(74));
        let q=RawQuarantine::open(&dir,owner,[8;32]).unwrap();
        let saved=q.save("11111111-2222-4333-8444-555555555555","{bad").unwrap();
        assert_eq!(saved.digest(),raw_payload_digest("{bad"));
        assert_eq!(fs::read_dir(&dir).unwrap().filter(|e|e.as_ref().unwrap().path().extension().and_then(|x|x.to_str())==Some("raw")).count(),1);
        let _=fs::remove_dir_all(dir);
    }
    #[test]
    fn another_process_holding_lock_blocks_quarantine() {
        const CHILD:&str="GS_RAW_LOCK_CHILD_DIR";
        if let Some(path)=std::env::var_os(CHILD) {
            let dir=PathBuf::from(path);let owner=Identity::from_seed([7;32],"tgrin").unwrap().address().clone();
            let q=RawQuarantine::open(&dir,owner,[8;32]).unwrap();let _guard=q.guard().unwrap();
            fs::write(dir.join("ready.tmp"),b"ready").unwrap();std::thread::sleep(std::time::Duration::from_secs(8));return;
        }
        let dir=root();let owner=Identity::from_seed([7;32],"tgrin").unwrap().address().clone();let q=RawQuarantine::open(&dir,owner,[8;32]).unwrap();
        let mut cmd=std::process::Command::new(std::env::current_exe().unwrap());cmd.arg("--exact").arg("raw_quarantine::tests::another_process_holding_lock_blocks_quarantine").env(CHILD,&dir);
        #[cfg(windows)] {use std::os::windows::process::CommandExt;cmd.creation_flags(0x08000000);}
        let mut child=cmd.spawn().unwrap();let start=std::time::Instant::now();
        while !dir.join("ready.tmp").exists() && start.elapsed()<std::time::Duration::from_secs(5) {std::thread::sleep(std::time::Duration::from_millis(10));}
        assert!(dir.join("ready.tmp").exists());
        assert!(q.save("11111111-2222-4333-8444-555555555555","{bad").is_err());
        let _=child.kill();let _=child.wait();
        let _=fs::remove_dir_all(dir);
    }
    #[test]
    fn flood_reaches_bounded_quota_without_silent_eviction() {
        let dir=root(); let owner=Identity::from_seed([7;32],"tgrin").unwrap().address().clone();
        let q=RawQuarantine::open(&dir,owner,[8;32]).unwrap();
        for n in 0..MAX_RECORDS { fs::write(dir.join(format!("{n}.tmp")),b"x").unwrap(); }
        assert!(matches!(q.save("11111111-2222-4333-8444-555555555555","{bad"),Err(Error::Quota(_))));
        assert_eq!(fs::read_dir(&dir).unwrap().count(),MAX_RECORDS+1);
        let _=fs::remove_dir_all(dir);
    }
    #[test]
    fn corruption_and_quota_fail_closed_and_unknown_versions_are_preserved() {
        let dir=root();let owner=Identity::from_seed([7;32],"tgrin").unwrap().address().clone();let q=RawQuarantine::open(&dir,owner,[8;32]).unwrap();
        let id="11111111-2222-4333-8444-555555555555";let digest=q.save(id,"{bad").unwrap().digest().to_string();
        assert!(q.save(id,r#"{"version":99,"data":"future"}"#).is_err());
        fs::write(dir.join(format!("{id}-{digest}.raw")),b"short").unwrap();assert!(q.save(id,"{bad").is_err());
        let _=fs::remove_dir_all(dir);
    }
}
