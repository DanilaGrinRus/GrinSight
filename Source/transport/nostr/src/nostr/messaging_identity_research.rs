//! Create-only NIP-49 messaging identity, separate from the wallet seed.
//! Experimental native storage; no automatic recovery or key rotation.
//! Callers must authenticate the unlocked profile, password and directory.
use std::{fs, io::Read, path::Path};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use nostr_sdk::{Keys, PublicKey, SecretKey, nips::{nip19::{FromBech32,ToBech32},nip49::{EncryptedSecretKey, KeySecurity}}};
use rand_core::SeedableRng;
use sha2::Sha256;
use zeroize::Zeroizing;
use super::{contact_book_research::BookIdentity, queue_record::Network, queue_store::{self, StoreError}};

const MAGIC:&[u8;8]=b"FLYNID01";
const LOG_N:u8=16;
const RECORD_LEN:usize=8+24+EncryptedSecretKey::LEN+16;
const NAME:&str="nostr.identity";

fn validate(password:&str, entropy:&[u8], identity:&BookIdentity)->Result<(),StoreError> {
    if password.is_empty() || password.len()>1024 || !matches!(entropy.len(),16|20|24|28|32)
        || identity.wallet_id==[0;32] { return Err(StoreError::InvalidRecord); }
    Ok(())
}
fn context(identity:&BookIdentity)->Vec<u8> {
    let mut out=Vec::with_capacity(41); out.extend_from_slice(MAGIC);
    out.push(match identity.network { Network::Mainnet=>1, Network::Floonet=>2 });
    out.extend_from_slice(&identity.wallet_id); out
}
fn derive(entropy:&[u8],identity:&BookIdentity)->Result<Zeroizing<[u8;32]>,StoreError> {
    let ctx=context(identity); let hk=Hkdf::<Sha256>::new(Some(&ctx),entropy);
    let mut key=Zeroizing::new([0u8;32]);
    hk.expand(b"GrinSight Fly Nostr identity envelope v1",&mut *key).map_err(|_|StoreError::InvalidRecord)?;
    Ok(key)
}

/// Generate an independent key once, encrypt with NIP-49 and bind the record
/// to the wallet. An indeterminate publication must be inspected at the same
/// path; never silently generate a replacement. Returns only the public key.
pub fn create_once(dir:&Path,entropy:&[u8],password:&str,identity:&BookIdentity)->Result<PublicKey,StoreError> {
    create_with_random(dir,entropy,password,identity,|bytes|getrandom::getrandom(bytes).map_err(|_|()))
}

fn create_with_random(dir:&Path,entropy:&[u8],password:&str,identity:&BookIdentity,
    mut random:impl FnMut(&mut [u8])->Result<(),()>)->Result<PublicKey,StoreError> {
    validate(password,entropy,identity)?; queue_store::check_dir(dir)?;
    let _lock=queue_store::inbox_lock(dir)?;
    let path=dir.join(NAME);
    match fs::symlink_metadata(&path) {
        Ok(_)=>return Err(StoreError::Indeterminate),
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>(),
        Err(_)=>return Err(StoreError::BeforePublication),
    }
    // Rejection sampling avoids an invalid secp256k1 scalar; failure of the
    // operating-system random source is an error before publication.
    let mut candidate=Zeroizing::new([0u8;32]);
    let mut secret=None;
    for _ in 0..16 {
        random(&mut *candidate).map_err(|_|StoreError::BeforePublication)?;
        if let Ok(value)=SecretKey::from_slice(&*candidate) { secret=Some(value); break; }
    }
    let keys=Keys::new(secret.ok_or(StoreError::BeforePublication)?);
    publish_keys(dir,entropy,password,identity,&keys,&mut random)
}

// Caller owns the directory lock and has confirmed the destination is absent.
fn publish_keys(dir:&Path,entropy:&[u8],password:&str,identity:&BookIdentity,keys:&Keys,
    random:&mut impl FnMut(&mut [u8])->Result<(),()>)->Result<PublicKey,StoreError> {
    // The NIP-49 library accepts a CryptoRng but uses infallible fill_bytes.
    // Seed a local CSPRNG only after a checked OS random call.
    let mut rng_seed=Zeroizing::new([0u8;32]);
    random(&mut *rng_seed).map_err(|_|StoreError::BeforePublication)?;
    let mut rng=rand_chacha::ChaCha20Rng::from_seed(*rng_seed);
    let encrypted=EncryptedSecretKey::new_with_rng(&mut rng,keys.secret_key(),password,LOG_N,KeySecurity::Unknown)
        .map_err(|_|StoreError::BeforePublication)?;
    let mut nonce=[0u8;24]; random(&mut nonce).map_err(|_|StoreError::BeforePublication)?;
    let storage_key=derive(entropy,identity)?;
    let cipher=XChaCha20Poly1305::new_from_slice(storage_key.as_ref()).map_err(|_|StoreError::InvalidRecord)?;
    let ctx=context(identity);
    let ciphertext=cipher.encrypt(XNonce::from_slice(&nonce),Payload{msg:&encrypted.as_vec(),aad:&ctx}).map_err(|_|StoreError::BeforePublication)?;
    let mut record=Vec::with_capacity(RECORD_LEN);record.extend_from_slice(MAGIC);record.extend_from_slice(&nonce);record.extend_from_slice(&ciphertext);
    if record.len()!=RECORD_LEN { return Err(StoreError::BeforePublication); }
    queue_store::publish_bytes(dir,&dir.join(NAME),&record,".flyn-",||{},||{})?;
    Ok(keys.public_key())
}

/// Reopen only after authenticating the wallet profile. Returned keys remain
/// in trusted native code, never as a Dart/JS string. Wrong password, wallet,
/// network, KDF setting or record all fail closed; no replacement is created.
fn read_encrypted(dir:&Path,entropy:&[u8],password:&str,identity:&BookIdentity)->Result<EncryptedSecretKey,StoreError> {
    validate(password,entropy,identity)?;queue_store::check_dir(dir)?;
    let path=dir.join(NAME);let md=fs::symlink_metadata(&path).map_err(|_|StoreError::InvalidRecord)?;
    if !queue_store::safe_metadata(&md)||!md.is_file()||md.len()!=RECORD_LEN as u64 { return Err(StoreError::InvalidRecord); }
    let file=queue_store::read_options().open(path).map_err(|_|StoreError::InvalidRecord)?;
    let md=file.metadata().map_err(|_|StoreError::InvalidRecord)?;
    if !queue_store::safe_metadata(&md)||!md.is_file()||md.len()!=RECORD_LEN as u64 { return Err(StoreError::InvalidRecord); }
    let mut record=Vec::with_capacity(RECORD_LEN);file.take((RECORD_LEN+1) as u64).read_to_end(&mut record).map_err(|_|StoreError::InvalidRecord)?;
    if record.len()!=RECORD_LEN || &record[..8]!=MAGIC { return Err(StoreError::InvalidRecord); }
    let key=derive(entropy,identity)?;let cipher=XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_|StoreError::InvalidRecord)?;
    let ctx=context(identity);
    let encrypted=Zeroizing::new(cipher.decrypt(XNonce::from_slice(&record[8..32]),Payload{msg:&record[32..],aad:&ctx}).map_err(|_|StoreError::InvalidRecord)?);
    let nip49=EncryptedSecretKey::from_slice(&encrypted).map_err(|_|StoreError::InvalidRecord)?;
    if nip49.log_n()!=LOG_N { return Err(StoreError::InvalidRecord); }
    Ok(nip49)
}

pub fn open(dir:&Path,entropy:&[u8],password:&str,identity:&BookIdentity)->Result<Keys,StoreError> {
    let nip49=read_encrypted(dir,entropy,password,identity)?;
    let secret=nip49.decrypt_with_max_log_n(password,LOG_N).map_err(|_|StoreError::InvalidRecord)?;
    Ok(Keys::new(secret))
}

/// Export the NIP-49 ciphertext only after verifying its password. The caller
/// must protect the returned backup and clear all UI/clipboard copies.
pub fn export_backup(dir:&Path,entropy:&[u8],password:&str,identity:&BookIdentity)->Result<Zeroizing<String>,StoreError> {
    let nip49=read_encrypted(dir,entropy,password,identity)?;
    let verified=nip49.decrypt_with_max_log_n(password,LOG_N).map_err(|_|StoreError::InvalidRecord)?;
    drop(verified);
    Ok(Zeroizing::new(nip49.to_bech32().map_err(|_|StoreError::InvalidRecord)?))
}

/// Import an encrypted backup into an absent slot, re-encrypting the same key
/// under the current profile password. No plaintext key leaves this module.
pub fn import_backup_once(dir:&Path,entropy:&[u8],password:&str,identity:&BookIdentity,
    backup:&str,backup_password:&str)->Result<PublicKey,StoreError> {
    validate(password,entropy,identity)?;
    if backup.len()>256 || backup_password.is_empty() || backup_password.len()>1024 { return Err(StoreError::InvalidRecord); }
    queue_store::check_dir(dir)?;
    let _lock=queue_store::inbox_lock(dir)?;
    match fs::symlink_metadata(dir.join(NAME)) {
        Ok(_)=>return Err(StoreError::Indeterminate),
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>(),
        Err(_)=>return Err(StoreError::BeforePublication),
    }
    let nip49=EncryptedSecretKey::from_bech32(backup).map_err(|_|StoreError::InvalidRecord)?;
    if nip49.log_n()>LOG_N { return Err(StoreError::InvalidRecord); }
    let secret=nip49.decrypt_with_max_log_n(backup_password,LOG_N).map_err(|_|StoreError::InvalidRecord)?;
    let keys=Keys::new(secret);
    publish_keys(dir,entropy,password,identity,&keys,&mut |bytes|getrandom::getrandom(bytes).map_err(|_|()))
}

#[cfg(all(test,windows))]
mod tests {
    use super::*;
    #[test]
    fn independent_nip49_identity_reopens_and_never_silently_replaces() {
        let root=std::path::PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        assert_eq!(fs::canonicalize(&root).unwrap(),fs::canonicalize(r"C:\DHW\GrinSight\FlyClient").unwrap());
        let tmp=root.join(".tmp"); assert_eq!(fs::canonicalize(std::env::temp_dir()).unwrap(),fs::canonicalize(&tmp).unwrap());
        let mut random=[0u8;16]; getrandom::getrandom(&mut random).unwrap();
        let suffix:String=random.iter().map(|b|format!("{b:02x}")).collect();
        let dir=tmp.join(format!("fly-nostr-identity-synthetic-{suffix}")); fs::create_dir(&dir).unwrap();
        let identity=BookIdentity { network:Network::Floonet,wallet_id:[7;32] };
        let entropy=Zeroizing::new([9u8;16]);
        for fail_at in [1,2,3] {
            let mut calls=0;
            let result=create_with_random(&dir,&*entropy,"synthetic-password",&identity,|bytes| {
                calls+=1; if calls==fail_at { return Err(()); } bytes.fill(1); Ok(())
            });
            assert_eq!(result,Err(StoreError::BeforePublication));
            assert!(!dir.join(NAME).exists());
        }
        let invalid=create_with_random(&dir,&*entropy,"synthetic-password",&identity,|bytes| { bytes.fill(0); Ok(()) });
        assert_eq!(invalid,Err(StoreError::BeforePublication));
        assert!(!dir.join(NAME).exists());
        let public=create_once(&dir,&*entropy,"synthetic-password",&identity).unwrap();
        assert_eq!(open(&dir,&*entropy,"synthetic-password",&identity).unwrap().public_key(),public);
        assert!(open(&dir,&*entropy,"wrong",&identity).is_err());
        assert!(open(&dir,&[8;16],"synthetic-password",&identity).is_err());
        assert!(export_backup(&dir,&*entropy,"wrong",&identity).is_err());
        let backup=export_backup(&dir,&*entropy,"synthetic-password",&identity).unwrap();
        assert!(backup.starts_with("ncryptsec1"));
        let restored_dir=tmp.join(format!("fly-nostr-restore-synthetic-{suffix}")); fs::create_dir(&restored_dir).unwrap();
        let restored_identity=BookIdentity { network:Network::Floonet,wallet_id:[8;32] };
        assert!(import_backup_once(&restored_dir,&[6;16],"new-password",&restored_identity,&backup,"wrong").is_err());
        assert!(!restored_dir.join(NAME).exists());
        let mut oversized=EncryptedSecretKey::from_bech32(&backup).unwrap().as_vec(); oversized[1]=LOG_N+1;
        let expensive=EncryptedSecretKey::from_slice(&oversized).unwrap().to_bech32().unwrap();
        assert!(import_backup_once(&restored_dir,&[6;16],"new-password",&restored_identity,&expensive,"synthetic-password").is_err());
        assert!(!restored_dir.join(NAME).exists());
        assert_eq!(import_backup_once(&restored_dir,&[6;16],"new-password",&restored_identity,&backup,"synthetic-password"),Ok(public));
        assert_eq!(open(&restored_dir,&[6;16],"new-password",&restored_identity).unwrap().public_key(),public);
        assert_eq!(import_backup_once(&restored_dir,&[6;16],"new-password",&restored_identity,&backup,"synthetic-password"),Err(StoreError::Indeterminate));
        let mut other=identity; other.network=Network::Mainnet;
        assert!(open(&dir,&*entropy,"synthetic-password",&other).is_err());
        assert_eq!(create_once(&dir,&*entropy,"synthetic-password",&identity),Err(StoreError::Indeterminate));
        let path=dir.join(NAME); let bytes=fs::read(&path).unwrap();
        assert!(!bytes.windows(entropy.len()).any(|v|v==entropy.as_slice()));
        let mut damaged=bytes; let last=damaged.len()-1; damaged[last]^=1;fs::write(path,damaged).unwrap();
        assert!(open(&dir,&*entropy,"synthetic-password",&identity).is_err());
        assert_eq!(create_once(&dir,&*entropy,"synthetic-password",&identity),Err(StoreError::Indeterminate));
    }
}
