//! Encrypted create-only contact records for a trusted stable directory.
//! A local label and key do not establish a person's identity or a payment
//! address. This module does not protect against rollback or deletion.
use std::{fs, io::Read, path::{Path, PathBuf}};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use nostr_sdk::PublicKey;
use sha2::Sha256;
use zeroize::Zeroizing;
use super::{queue_record::Network, queue_store::{self, StoreError}};

const MAGIC: &[u8;8] = b"FLYCON01";
const MAX_RECORD: usize = 8 + 24 + 1 + 64 + 64 + 16;
const MAX_CONTACTS: usize = 512;
const MAX_ENTRIES: usize = 8192;

/// Caller must authenticate wallet identity and obtain explicit user consent
/// for a key. A fingerprint or local label alone is not identity proof.
#[derive(Clone, Copy)]
pub struct BookIdentity { pub network:Network, pub wallet_id:[u8;32] }
pub struct BookKey(Zeroizing<[u8;32]>);
pub struct Contact { label:Zeroizing<String>, pub public_key:PublicKey }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateError { Storage(StoreError), DuplicateKey }
impl From<StoreError> for CreateError { fn from(error:StoreError)->Self { Self::Storage(error) } }
impl Contact {
    pub fn new(label: &str, public_key: PublicKey) -> Result<Self, StoreError> {
        if label.trim().is_empty() || label.len()>64 || label.chars().any(char::is_control) { return Err(StoreError::InvalidRecord); }
        Ok(Self { label:Zeroizing::new(label.to_owned()), public_key })
    }
    pub fn label(&self) -> &str { &self.label }
}
impl BookKey {
    pub fn derive_from_wallet_entropy(entropy:&[u8], identity:&BookIdentity) -> Result<Self, StoreError> {
        if !matches!(entropy.len(),16|20|24|28|32) || identity.wallet_id == [0;32] { return Err(StoreError::InvalidRecord); }
        let mut salt=[0u8;33]; salt[0]=network_byte(identity.network); salt[1..].copy_from_slice(&identity.wallet_id);
        let hk=Hkdf::<Sha256>::new(Some(&salt),entropy);
        let mut key=Zeroizing::new([0u8;32]);
        hk.expand(b"GrinSight Fly contact book v1", &mut *key).map_err(|_|StoreError::InvalidRecord)?;
        Ok(Self(key))
    }
}
fn network_byte(n:Network)->u8 { match n { Network::Mainnet=>1, Network::Floonet=>2 } }
fn aad(identity:&BookIdentity, slot:&[u8;16])->Result<Vec<u8>,StoreError> {
    if identity.wallet_id == [0;32] || *slot == [0;16] { return Err(StoreError::InvalidRecord); }
    let mut out=Vec::with_capacity(57); out.extend_from_slice(MAGIC); out.push(network_byte(identity.network));
    out.extend_from_slice(&identity.wallet_id); out.extend_from_slice(slot); Ok(out)
}
fn path(dir:&Path, slot:&[u8;16])->Result<PathBuf,StoreError> {
    if *slot == [0;16] { return Err(StoreError::InvalidRecord); }
    let hex:String=slot.iter().map(|b|format!("{b:02x}")).collect(); Ok(dir.join(format!("contact-{hex}.flyc")))
}
fn seal(key:&BookKey, identity:&BookIdentity, slot:&[u8;16], contact:&Contact)->Result<Vec<u8>,StoreError> {
    let context=aad(identity,slot)?;
    let key_hex=contact.public_key.to_string();
    if key_hex.len()!=64 { return Err(StoreError::InvalidRecord); }
    let mut plain=Zeroizing::new(Vec::with_capacity(1+64+contact.label.len()));
    plain.push(contact.label.len() as u8); plain.extend_from_slice(contact.label.as_bytes()); plain.extend_from_slice(key_hex.as_bytes());
    let mut nonce=[0u8;24]; getrandom::getrandom(&mut nonce).map_err(|_|StoreError::BeforePublication)?;
    let cipher=XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(|_|StoreError::InvalidRecord)?;
    let encrypted=cipher.encrypt(XNonce::from_slice(&nonce),Payload{msg:&plain,aad:&context}).map_err(|_|StoreError::InvalidRecord)?;
    let mut out=Vec::with_capacity(8+24+encrypted.len()); out.extend_from_slice(MAGIC); out.extend_from_slice(&nonce); out.extend_from_slice(&encrypted); Ok(out)
}
fn open(key:&BookKey, identity:&BookIdentity, slot:&[u8;16], record:&[u8])->Result<Contact,StoreError> {
    if record.len()<8+24+1+64+16 || record.len()>MAX_RECORD || &record[..8]!=MAGIC { return Err(StoreError::InvalidRecord); }
    let context=aad(identity,slot)?; let cipher=XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(|_|StoreError::InvalidRecord)?;
    let plain=Zeroizing::new(cipher.decrypt(XNonce::from_slice(&record[8..32]),Payload{msg:&record[32..],aad:&context}).map_err(|_|StoreError::InvalidRecord)?);
    let len=usize::from(*plain.first().ok_or(StoreError::InvalidRecord)?);
    if len==0 || len>64 || plain.len()!=1+len+64 { return Err(StoreError::InvalidRecord); }
    let label=std::str::from_utf8(&plain[1..1+len]).map_err(|_|StoreError::InvalidRecord)?;
    let hex=std::str::from_utf8(&plain[1+len..]).map_err(|_|StoreError::InvalidRecord)?;
    let public_key=PublicKey::parse(hex).map_err(|_|StoreError::InvalidRecord)?;
    if public_key.to_string()!=hex { return Err(StoreError::InvalidRecord); }
    Contact::new(label,public_key)
}

/// List untrusted filename slots; each must be opened and authenticated.
pub fn discover(dir:&Path)->Result<Vec<[u8;16]>,StoreError> {
    queue_store::check_dir(dir)?; let mut slots=Vec::new(); let mut count=0usize;
    for entry in fs::read_dir(dir).map_err(|_|StoreError::InvalidRecord)? {
        count+=1; if count>MAX_ENTRIES { return Err(StoreError::Capacity); }
        let entry=entry.map_err(|_|StoreError::InvalidRecord)?; let name=entry.file_name();
        let name=name.to_str().ok_or(StoreError::InvalidRecord)?;
        if !name.to_ascii_lowercase().starts_with("contact-") && !name.to_ascii_lowercase().ends_with(".flyc") { continue; }
        let hex=name.strip_prefix("contact-").and_then(|n|n.strip_suffix(".flyc"))
            .filter(|v|v.len()==32 && v.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))).ok_or(StoreError::InvalidRecord)?;
        let md=fs::symlink_metadata(entry.path()).map_err(|_|StoreError::InvalidRecord)?;
        if !queue_store::safe_metadata(&md)||!md.is_file()||md.len()>MAX_RECORD as u64 { return Err(StoreError::InvalidRecord); }
        let mut slot=[0u8;16]; for (i,pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            let digit=|b:u8|if b<=b'9'{b-b'0'}else{b-b'a'+10}; slot[i]=digit(pair[0])*16+digit(pair[1]);
        }
        if slot==[0;16]||slots.len()>=MAX_CONTACTS { return Err(StoreError::Capacity); }
        slots.push(slot);
    }
    slots.sort_unstable(); Ok(slots)
}

/// Create once under a process-shared directory lock. An indeterminate result
/// must be inspected at the same slot and never retried with a fresh slot.
pub fn create(dir:&Path,key:&BookKey,identity:&BookIdentity,slot:&[u8;16],contact:&Contact)->Result<(),CreateError> {
    queue_store::check_dir(dir)?; let destination=path(dir,slot)?; let record=seal(key,identity,slot,contact)?;
    let _lock=queue_store::inbox_lock(dir)?;
    let slots=discover(dir)?;
    // The original slot may have been committed despite a failed return.
    if slots.contains(slot) { return Err(StoreError::Indeterminate.into()); }
    // Read all existing records under the same cross-process lock. A corrupt
    // entry fails closed instead of allowing a possible duplicate to slip in.
    for existing in &slots {
        if read(dir,key,identity,existing)?.public_key == contact.public_key { return Err(CreateError::DuplicateKey); }
    }
    if slots.len()>=MAX_CONTACTS { return Err(StoreError::Capacity.into()); }
    queue_store::publish_bytes(dir,&destination,&record,".flyc-",||{},||{}).map_err(Into::into)
}

pub fn read(dir:&Path,key:&BookKey,identity:&BookIdentity,slot:&[u8;16])->Result<Contact,StoreError> {
    queue_store::check_dir(dir)?; let destination=path(dir,slot)?;
    let md=fs::symlink_metadata(&destination).map_err(|_|StoreError::InvalidRecord)?;
    if !queue_store::safe_metadata(&md)||!md.is_file()||md.len()>MAX_RECORD as u64 { return Err(StoreError::InvalidRecord); }
    let file=queue_store::read_options().open(destination).map_err(|_|StoreError::InvalidRecord)?;
    let md=file.metadata().map_err(|_|StoreError::InvalidRecord)?;
    if !queue_store::safe_metadata(&md)||!md.is_file()||md.len()>MAX_RECORD as u64 { return Err(StoreError::InvalidRecord); }
    let mut record=Vec::new(); file.take((MAX_RECORD+1) as u64).read_to_end(&mut record).map_err(|_|StoreError::InvalidRecord)?;
    open(key,identity,slot,&record)
}

/// Authenticate a complete inventory while excluding cooperating writers.
/// The directory, ancestors and lock file must remain trusted and stable;
/// non-cooperating processes and rollback are outside this guarantee.
pub fn read_all(dir:&Path,key:&BookKey,identity:&BookIdentity)->Result<Vec<([u8;16],Contact)>,StoreError> {
    queue_store::check_dir(dir)?;
    let _lock=queue_store::inbox_lock(dir)?;
    let slots=discover(dir)?;
    slots.into_iter().map(|slot|read(dir,key,identity,&slot).map(|contact|(slot,contact))).collect()
}

#[cfg(all(test,windows))]
mod tests {
    use super::*;
    use nostr_sdk::Keys;
    #[test]
    fn encrypted_contact_is_bound_to_wallet_network_and_slot() {
        let root=PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        assert_eq!(fs::canonicalize(&root).unwrap(),fs::canonicalize(r"C:\DHW\GrinSight\FlyClient").unwrap());
        let tmp=root.join(".tmp"); assert_eq!(fs::canonicalize(std::env::temp_dir()).unwrap(),fs::canonicalize(&tmp).unwrap());
        let mut random=[0u8;16]; getrandom::getrandom(&mut random).unwrap();
        let suffix:String=random.iter().map(|b|format!("{b:02x}")).collect();
        let dir=tmp.join(format!("fly-contact-synthetic-{suffix}")); fs::create_dir(&dir).unwrap();
        let identity=BookIdentity { network:Network::Floonet,wallet_id:[7;32] }; let slot=[3;16];
        let key=BookKey::derive_from_wallet_entropy(&[9;16],&identity).unwrap();
        let pubkey=Keys::generate().public_key();
        let contact=Contact::new("SYNTHETIC_CONTACT",pubkey).unwrap();
        assert!(Contact::new("bad\nname",pubkey).is_err());
        assert_eq!(create(&dir,&key,&identity,&slot,&contact),Ok(()));
        assert_eq!(create(&dir,&key,&identity,&slot,&contact),Err(CreateError::Storage(StoreError::Indeterminate)));
        assert_eq!(create(&dir,&key,&identity,&[5;16],&contact),Err(CreateError::DuplicateKey));
        assert_eq!(discover(&dir).unwrap(),vec![slot]);
        let all=read_all(&dir,&key,&identity).unwrap();
        assert_eq!(all.len(),1); assert_eq!(all[0].0,slot); assert_eq!(all[0].1.label(),"SYNTHETIC_CONTACT");
        let held=queue_store::inbox_lock(&dir).unwrap();
        assert!(matches!(read_all(&dir,&key,&identity),Err(StoreError::Busy)));
        drop(held);
        assert_eq!(read_all(&dir,&key,&identity).unwrap().len(),1);
        let restored=read(&dir,&key,&identity,&slot).unwrap();
        assert_eq!(restored.label(),"SYNTHETIC_CONTACT"); assert_eq!(restored.public_key,pubkey);
        let bytes=fs::read(path(&dir,&slot).unwrap()).unwrap();
        assert!(!bytes.windows(b"SYNTHETIC_CONTACT".len()).any(|v|v==b"SYNTHETIC_CONTACT"));
        assert!(!bytes.windows(32).any(|v|v==pubkey.as_bytes()));
        let public_hex=pubkey.to_string();
        assert!(!bytes.windows(public_hex.len()).any(|v|v==public_hex.as_bytes()));
        let wrong=BookKey::derive_from_wallet_entropy(&[8;16],&identity).unwrap();
        assert!(read(&dir,&wrong,&identity,&slot).is_err());
        let mut other=identity; other.network=Network::Mainnet;
        assert!(read(&dir,&key,&other,&slot).is_err());
        other=identity; other.wallet_id[0]^=1;
        assert!(read(&dir,&key,&other,&slot).is_err());
        let other_slot=[4;16]; fs::write(path(&dir,&other_slot).unwrap(),&bytes).unwrap();
        assert!(read(&dir,&key,&identity,&other_slot).is_err());
        let mut damaged=bytes; let end=damaged.len()-1; damaged[end]^=1;
        fs::write(path(&dir,&slot).unwrap(),damaged).unwrap();
        assert!(read(&dir,&key,&identity,&slot).is_err());
        let another=Contact::new("Another",Keys::generate().public_key()).unwrap();
        assert_eq!(create(&dir,&key,&identity,&[6;16],&another),Err(CreateError::Storage(StoreError::InvalidRecord)));
    }

    #[test]
    fn simultaneous_duplicate_creation_has_at_most_one_winner() {
        use std::sync::{Arc,Barrier};
        let root=PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        assert_eq!(fs::canonicalize(&root).unwrap(),fs::canonicalize(r"C:\DHW\GrinSight\FlyClient").unwrap());
        let tmp=root.join(".tmp"); assert_eq!(fs::canonicalize(std::env::temp_dir()).unwrap(),fs::canonicalize(&tmp).unwrap());
        let mut random=[0u8;16]; getrandom::getrandom(&mut random).unwrap();
        let suffix:String=random.iter().map(|b|format!("{b:02x}")).collect();
        let dir=tmp.join(format!("fly-contact-race-synthetic-{suffix}")); fs::create_dir(&dir).unwrap();
        let identity=BookIdentity { network:Network::Floonet,wallet_id:[7;32] };
        let pubkey=Keys::generate().public_key(); let barrier=Arc::new(Barrier::new(3));
        let mut threads=Vec::new();
        for byte in [1u8,2] {
            let dir=dir.clone(); let barrier=barrier.clone();
            threads.push(std::thread::spawn(move || {
                let key=BookKey::derive_from_wallet_entropy(&[9;16],&identity).unwrap();
                let contact=Contact::new("Synthetic",pubkey).unwrap();
                barrier.wait(); create(&dir,&key,&identity,&[byte;16],&contact)
            }));
        }
        barrier.wait();
        let results:Vec<_>=threads.into_iter().map(|t|t.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r|r.is_ok()).count(),1);
        assert!(results.iter().any(|r|matches!(r,Err(CreateError::DuplicateKey)|Err(CreateError::Storage(StoreError::Busy)))));
        assert_eq!(discover(&dir).unwrap().len(),1);
    }
}
