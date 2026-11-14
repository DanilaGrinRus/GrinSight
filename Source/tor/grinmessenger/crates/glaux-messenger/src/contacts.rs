// SPDX-License-Identifier: MIT OR Apache-2.0
//! Encrypted address book.
//!
//! A nickname plus a slatepack address is local metadata: the address is public,
//! but the association between them is not. The whole list is one
//! ChaCha20-Poly1305 blob under the same history key; no address or nickname is
//! written in clear.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::address::Address;
use crate::envelope::unix_now;
use crate::error::{Error, Result};

const AAD: &[u8] = b"glaux-messenger-contacts-v1";
const MAX_CONTACTS: usize = 500;
const MAX_NAME_CHARS: usize = 64;
const FILE: &str = "contacts.enc";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Contact {
    pub address: String,
    pub name: String,
    pub created_at: u64,
    pub updated_at: u64,
    /// Optional Nostr transport key (x-only hex) used by the Nostr transport.
    /// Kept in the encrypted contact file, not in the address itself.
    #[serde(default)]
    pub nostr: Option<String>,
    /// Verified signed binding; absence on older contacts is expected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nostr_binding: Option<crate::nostr::binding::NostrBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i2p_binding: Option<crate::i2p_binding::Binding>,
    /// User-approved signed catalogue profile; identity is never implied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_profile: Option<crate::nostr::catalog::Profile>,
    /// Full key-set fingerprint explicitly confirmed by the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_verified_fingerprint: Option<String>,
}

pub struct ContactBook {
    root: PathBuf,
    key: Zeroizing<[u8; 32]>,
    lock: Mutex<()>,
}

/// Cross-instance lock for the load-modify-store contact file. The in-process
/// Mutex only serializes one `ContactBook`; runtime creates a fresh object for
/// each operation, so two saves could otherwise overwrite each other.
struct ContactFileLock {
    path: PathBuf,
    token: String,
}

/// A lock held longer than this is treated as stale. A contact save only does
/// a local load-modify-store under the lock, so a live holder never needs
/// anywhere near this long; the threshold protects against deleting a lock
/// that is merely slow.
const LOCK_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

fn is_stale(path: &Path) -> bool {
    let Ok(modified) = fs::metadata(path).and_then(|m| m.modified()) else {
        return false;
    };
    std::time::SystemTime::now()
        .duration_since(modified)
        .map(|age| age >= LOCK_STALE_AFTER)
        .unwrap_or(false)
}

impl ContactFileLock {
    fn acquire(root: &Path) -> Result<Self> {
        let path = root.join("contacts.lock");
        let token = format!(
            "{} {}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        for _ in 0..200 {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    let _ = std::io::Write::write_all(&mut file, token.as_bytes());
                    let _ = file.sync_all();
                    return Ok(Self { path, token });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if is_stale(&path) {
                        eprintln!(
                            "contacts: stale lock {} is older than {} s, recovering",
                            path.display(),
                            LOCK_STALE_AFTER.as_secs()
                        );
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => return Err(Error::Store(format!("contacts lock: {e}"))),
            }
        }
        Err(Error::Store(format!(
            "contacts: блокировка {} не освободилась за 2 с; если процесс не работает, удалите файл вручную",
            path.display()
        )))
    }
}

impl Drop for ContactFileLock {
    fn drop(&mut self) {
        // Only remove a lock that still belongs to this holder: a stale lock may
        // have been reclaimed and replaced by another process meanwhile.
        let owned = fs::read(&self.path)
            .map(|bytes| bytes == self.token.as_bytes())
            .unwrap_or(false);
        if owned {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl ContactBook {
    pub fn open(root: impl Into<PathBuf>, key: [u8; 32]) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| Error::Store(format!("contacts: {e}")))?;
        Ok(Self {
            root,
            key: Zeroizing::new(key),
            lock: Mutex::new(()),
        })
    }

    fn path(&self) -> PathBuf {
        self.root.join(FILE)
    }

    fn guard(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        self.lock
            .lock()
            .map_err(|_| Error::Store("contacts poisoned".into()))
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.key[..]))
    }

    fn load(&self) -> Result<Vec<Contact>> {
        let path = self.path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let bytes = fs::read(&path).map_err(|e| Error::Store(format!("contacts: {e}")))?;
        if bytes.len() <= 12 {
            return Ok(Vec::new());
        }
        let nonce: [u8; 12] = bytes[..12]
            .try_into()
            .map_err(|_| Error::Envelope("contacts nonce".into()))?;
        let plaintext = self
            .cipher()
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &bytes[12..],
                    aad: AAD,
                },
            )
            .map_err(|_| Error::Crypto("contacts: не удалось расшифровать".into()))?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| Error::Envelope(format!("contacts json: {e}")))
    }

    fn store(&self, contacts: &[Contact]) -> Result<()> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(contacts)
                .map_err(|e| Error::Envelope(format!("contacts json: {e}")))?,
        );
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| Error::Crypto(format!("contacts RNG: {e}")))?;
        let ciphertext = self
            .cipher()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: AAD,
                },
            )
            .map_err(|_| Error::Crypto("contacts encrypt".into()))?;
        let mut bytes = Vec::with_capacity(12 + ciphertext.len());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);
        write_atomic(&self.path(), &bytes)
    }

    pub fn list(&self) -> Result<Vec<Contact>> {
        let _guard = self.guard()?;
        let mut contacts = self.load()?;
        for c in &mut contacts {
            let valid = c.catalog_profile.as_ref().is_some_and(|p| {
                p.claims.binding.owner == c.address && !p.claims.revoked && c.nostr_binding.as_ref().is_some_and(|b| b.transport_key == p.claims.binding.transport_key) &&
                crate::nostr::catalog::validate_profile(p, &p.claims.binding.transport_key, unix_now()).is_ok() &&
                c.identity_verified_fingerprint.as_deref() == Some(crate::nostr::catalog::identity_fingerprint(p).as_str())
            });
            if !valid { c.identity_verified_fingerprint = None; }
        }
        sort(&mut contacts);
        Ok(contacts)
    }

    pub fn save(&self, address: &str, name: &str) -> Result<Contact> {
        let address: Address = address.trim().parse()?;
        let address = address.to_string();
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Store("контакт: пустое имя".into()));
        }
        if name.chars().count() > MAX_NAME_CHARS {
            return Err(Error::Store(format!(
                "контакт: имя длиннее {MAX_NAME_CHARS} символов"
            )));
        }
        if name.chars().any(char::is_control) {
            return Err(Error::Store("контакт: управляющие символы в имени".into()));
        }

        let _file_lock = ContactFileLock::acquire(&self.root)?;
        let _guard = self.guard()?;
        let mut contacts = self.load()?;
        let now = unix_now();
        let contact = if let Some(existing) = contacts.iter_mut().find(|c| c.address == address) {
            existing.name = name.to_string();
            existing.updated_at = now;
            existing.clone()
        } else {
            if contacts.len() >= MAX_CONTACTS {
                return Err(Error::Store(format!(
                    "контакт: не больше {MAX_CONTACTS} записей"
                )));
            }
            let contact = Contact {
                address,
                name: name.to_string(),
                created_at: now,
                updated_at: now,
                nostr: None,
                nostr_binding: None,
                i2p_binding: None,
                catalog_profile: None,
                identity_verified_fingerprint: None,
            };
            contacts.push(contact.clone());
            contact
        };
        sort(&mut contacts);
        self.store(&contacts)?;
        Ok(contact)
    }

    /// Save a contact and set (or clear) its Nostr transport key.
    ///
    /// `None` keeps the stored value, `Some("")` clears it and `Some(hex)` must
    /// be a 64-character x-only public key.
    pub fn save_with_nostr(
        &self,
        address: &str,
        name: &str,
        nostr: Option<&str>,
    ) -> Result<Contact> {
        let nostr = match nostr {
            None => None,
            Some(value) => Some(validate_nostr(value)?),
        };
        let contact = self.save(address, name)?;
        let address = contact.address.clone();
        let _file_lock = ContactFileLock::acquire(&self.root)?;
        let _guard = self.guard()?;
        let mut contacts = self.load()?;
        let now = unix_now();
        let updated = if let Some(existing) = contacts.iter_mut().find(|c| c.address == address) {
            if let Some(value) = nostr {
                existing.nostr = value;
            }
            existing.updated_at = now;
            existing.clone()
        } else {
            contact
        };
        sort(&mut contacts);
        self.store(&contacts)?;
        Ok(updated)
    }

    /// Atomically validate and store a signed Nostr contact binding. The
    /// previously accepted sequence remains in the encrypted contact file.
    pub fn save_nostr_binding(&self, binding: &crate::nostr::binding::NostrBinding, name: &str, now: u64) -> Result<Contact> {
        let owner = Address::parse(&binding.owner)?;
        let address = owner.to_string();
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME_CHARS || name.chars().any(char::is_control) {
            return Err(Error::Store("invalid contact name".into()));
        }
        let _file_lock = ContactFileLock::acquire(&self.root)?;
        let _guard = self.guard()?;
        let mut contacts = self.load()?;
        let existing = contacts.iter().position(|c| c.address == address);
        if existing.is_none() && contacts.len() >= MAX_CONTACTS { return Err(Error::Quota("contact limit".into())); }
        let previous = existing.and_then(|i| contacts[i].nostr_binding.as_ref());
        binding.verify_update(&owner, now, previous).map_err(|_| Error::Store("invalid, expired, conflicting or stale Nostr binding".into()))?;
        if let Some(profile) = existing.and_then(|i| contacts[i].catalog_profile.as_ref()) {
            if profile.claims.binding.transport_key != binding.transport_key {
                return Err(Error::Store("contact key changed; verify the profile again".into()));
            }
        }
        let contact = if let Some(i) = existing {
            let c = &mut contacts[i]; c.name = name.to_string(); c.updated_at = now;
            c.nostr = Some(binding.transport_key.clone()); c.nostr_binding = Some(binding.clone()); c.clone()
        } else {
            let c = Contact { address, name: name.to_string(), created_at: now, updated_at: now,
                nostr: Some(binding.transport_key.clone()), nostr_binding: Some(binding.clone()), i2p_binding: None, catalog_profile: None, identity_verified_fingerprint: None };
            contacts.push(c.clone()); c
        };
        sort(&mut contacts); self.store(&contacts)?; Ok(contact)
    }

    /// Persist the exact approved signed profile. Existing wallet/key changes
    /// or stale/conflicting sequences cannot silently replace a pinned contact.
    pub fn save_catalog_profile(&self, profile: &crate::nostr::catalog::Profile, name: &str, now: u64, identity_checked: bool) -> Result<Contact> {
        use crate::nostr::catalog::{identity_fingerprint, validate_profile};
        let claims=&profile.claims;
        validate_profile(profile, &claims.binding.transport_key, now)?;
        if claims.revoked { return Err(Error::Store("profile is revoked".into())); }
        let owner=Address::parse(&claims.binding.owner)?;
        let name=name.trim();
        if name.is_empty() || name.chars().count()>MAX_NAME_CHARS || name.chars().any(char::is_control) { return Err(Error::Store("invalid contact name".into())); }
        let _file_lock=ContactFileLock::acquire(&self.root)?;
        let _guard=self.guard()?;
        let mut contacts=self.load()?;
        let existing=contacts.iter().position(|c| c.address==claims.binding.owner);
        if existing.is_none() && contacts.len()>=MAX_CONTACTS { return Err(Error::Quota("contact limit".into())); }
        let previous=existing.and_then(|i| contacts[i].nostr_binding.as_ref());
        claims.binding.verify_update(&owner,now,previous).map_err(|_| Error::Store("stale or conflicting binding".into()))?;
        if let Some(old)=existing.and_then(|i| contacts[i].catalog_profile.as_ref()) {
            if old.claims.wallet_address!=claims.wallet_address || old.claims.binding.transport_key!=claims.binding.transport_key || claims.sequence<old.claims.sequence || (claims.sequence==old.claims.sequence && old!=profile) {
                return Err(Error::Store("profile changed or was rolled back; verify contact again".into()));
            }
        }
        let out=if let Some(i)=existing {
            let c=&mut contacts[i]; c.name=name.into(); c.updated_at=now; c.nostr=Some(claims.binding.transport_key.clone()); c.nostr_binding=Some(claims.binding.clone()); c.catalog_profile=Some(profile.clone());
            let fingerprint=identity_fingerprint(profile);
            if identity_checked {c.identity_verified_fingerprint=Some(fingerprint.clone());}
            else if c.identity_verified_fingerprint.as_deref()!=Some(fingerprint.as_str()) {c.identity_verified_fingerprint=None;}
            c.clone()
        } else {
            let c=Contact {address:claims.binding.owner.clone(),name:name.into(),created_at:now,updated_at:now,nostr:Some(claims.binding.transport_key.clone()),nostr_binding:Some(claims.binding.clone()),i2p_binding:None,catalog_profile:Some(profile.clone()),identity_verified_fingerprint:if identity_checked {Some(identity_fingerprint(profile))} else {None}};
            contacts.push(c.clone()); c
        };
        sort(&mut contacts); self.store(&contacts)?; Ok(out)
    }

    /// Store the I2P destination only after checking the Glaux signature and
    /// comparing the sequence against the encrypted previous value.
    pub fn save_i2p_binding(&self, binding: &crate::i2p_binding::Binding, name: &str, now: u64) -> Result<Contact> {
        let owner = Address::parse(&binding.owner)?;
        let address = owner.to_string(); let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME_CHARS || name.chars().any(char::is_control) {
            return Err(Error::Store("invalid contact name".into()));
        }
        let _file_lock = ContactFileLock::acquire(&self.root)?; let _guard = self.guard()?;
        let mut contacts = self.load()?;
        let existing = contacts.iter().position(|c| c.address == address);
        if existing.is_none() && contacts.len() >= MAX_CONTACTS { return Err(Error::Quota("contact limit".into())); }
        let previous = existing.and_then(|i| contacts[i].i2p_binding.as_ref());
        binding.verify_update(&owner, now, previous).map_err(|_| Error::Store("invalid, expired, conflicting or stale I2P binding".into()))?;
        let contact = if let Some(i) = existing {
            let c = &mut contacts[i]; c.name = name.to_string(); c.updated_at = now; c.i2p_binding = Some(binding.clone()); c.clone()
        } else {
            let c = Contact { address, name: name.to_string(), created_at: now, updated_at: now,
                nostr: None, nostr_binding: None, i2p_binding: Some(binding.clone()), catalog_profile: None, identity_verified_fingerprint: None };
            contacts.push(c.clone()); c
        };
        sort(&mut contacts); self.store(&contacts)?; Ok(contact)
    }

    pub fn delete(&self, address: &str) -> Result<bool> {
        let address: Address = address.trim().parse()?;
        let address = address.to_string();
        let _file_lock = ContactFileLock::acquire(&self.root)?;
        let _guard = self.guard()?;
        let mut contacts = self.load()?;
        let before = contacts.len();
        contacts.retain(|c| c.address != address);
        if contacts.len() == before {
            return Ok(false);
        }
        self.store(&contacts)?;
        Ok(true)
    }
}

fn sort(contacts: &mut [Contact]) {
    contacts.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| a.address.cmp(&b.address))
    });
}

fn validate_nostr(value: &str) -> Result<Option<String>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let key = crate::nostr::parse_public_hex(trimmed)?;
    Ok(Some(crate::nostr::hex_encode(&key.to_byte_array())))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = path.with_extension(format!("enc.tmp-{}-{nanos}", std::process::id()));
    fs::write(&tmp, bytes).map_err(|e| Error::Store(format!("contacts: {e}")))?;
    fs::rename(&tmp, path).map_err(|e| Error::Store(format!("contacts: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [0x42; 32]
    }

    fn book() -> (ContactBook, PathBuf) {
        let dir = std::env::temp_dir().join(format!("glaux-contacts-{}", uuid::Uuid::new_v4()));
        (ContactBook::open(&dir, key()).unwrap(), dir)
    }

    fn addr(seed: u8) -> String {
        let address = Address::from_key("tgrin", [seed; 32]).unwrap();
        address.to_string()
    }

    #[test]
    fn signed_i2p_binding_is_encrypted_and_rejects_conflicts_after_restart() {
        let dir=std::env::temp_dir().join(format!("gs-i2p-binding-{}",uuid::Uuid::new_v4()));
        let seed=[5u8;32]; let identity=crate::Identity::from_seed([9;32],"tgrin").unwrap();
        let first=crate::i2p_binding::Binding::create(&identity,"abc-def",2,1000,1500).unwrap();
        { let book=ContactBook::open(&dir,seed).unwrap(); book.save_i2p_binding(&first,"test",1100).unwrap(); }
        let book=ContactBook::open(&dir,seed).unwrap();
        let bad=crate::i2p_binding::Binding::create(&identity,"other-def",2,1000,1500).unwrap();
        assert!(book.save_i2p_binding(&bad,"test",1100).is_err());
        let next=crate::i2p_binding::Binding::create(&identity,"other-def",3,1000,1500).unwrap();
        book.save_i2p_binding(&next,"test",1100).unwrap();
        assert!(book.save_i2p_binding(&first,"test",1100).is_err());
        assert_eq!(book.list().unwrap()[0].i2p_binding.as_ref().unwrap().sequence,3);
        let raw=std::fs::read(dir.join("contacts.enc")).unwrap(); assert!(!String::from_utf8_lossy(&raw).contains("other-def"));
        let _=std::fs::remove_file(dir.join("contacts.enc")); let _=std::fs::remove_dir(dir);
    }

    #[test]
    fn signed_nostr_binding_survives_restart_and_rejects_rollback_or_conflict() {
        let dir=std::env::temp_dir().join(format!("gs-nostr-binding-{}",uuid::Uuid::new_v4()));
        let seed=[5u8;32];
        let identity=crate::Identity::from_seed([9;32],"tgrin").unwrap();
        let a=crate::NostrKeys::from_hex(&format!("{:064x}",1)).unwrap();
        let b=crate::NostrKeys::from_hex(&format!("{:064x}",2)).unwrap();
        let first=crate::nostr::binding::NostrBinding::create(&identity,&a.public_hex(),2,1000,1500).unwrap();
        { let book=ContactBook::open(&dir,seed).unwrap(); book.save_nostr_binding(&first,"test",1100).unwrap(); }
        let book=ContactBook::open(&dir,seed).unwrap();
        let older=crate::nostr::binding::NostrBinding::create(&identity,&b.public_hex(),1,1000,1500).unwrap();
        let conflict=crate::nostr::binding::NostrBinding::create(&identity,&b.public_hex(),2,1000,1500).unwrap();
        assert!(book.save_nostr_binding(&older,"test",1100).is_err());
        assert!(book.save_nostr_binding(&conflict,"test",1100).is_err());
        let next=crate::nostr::binding::NostrBinding::create(&identity,&b.public_hex(),3,1000,1500).unwrap();
        book.save_nostr_binding(&next,"test",1100).unwrap();
        assert_eq!(book.list().unwrap()[0].nostr_binding.as_ref().unwrap().sequence,3);
        let _=std::fs::remove_file(dir.join("contacts.enc")); let _=std::fs::remove_dir(dir);
    }

    #[test]
    fn saves_updates_lists_and_deletes() {
        let (book, dir) = book();
        let a = addr(7);
        let b = addr(9);
        book.save(&a, "Боб").unwrap();
        book.save(&b, "Алиса").unwrap();
        let list = book.list().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "Алиса");

        let updated = book.save(&a, "Боб 2").unwrap();
        assert_eq!(updated.name, "Боб 2");
        assert_eq!(book.list().unwrap().len(), 2);
        assert!(book.delete(&b).unwrap());
        assert!(!book.delete(&b).unwrap());
        assert_eq!(book.list().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parallel_books_do_not_lose_contacts() {
        let (book, dir) = book();
        drop(book);
        let (a, b) = (addr(1), addr(2));
        let d1 = dir.clone();
        let d2 = dir.clone();
        let h1 = std::thread::spawn(move || {
            ContactBook::open(d1, [7u8; 32])
                .unwrap()
                .save(&a, "Первый")
                .unwrap();
        });
        let h2 = std::thread::spawn(move || {
            ContactBook::open(d2, [7u8; 32])
                .unwrap()
                .save(&b, "Второй")
                .unwrap();
        });
        h1.join().unwrap();
        h2.join().unwrap();
        let contacts = ContactBook::open(dir.clone(), [7u8; 32])
            .unwrap()
            .list()
            .unwrap();
        assert_eq!(contacts.len(), 2, "parallel save lost a contact");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn file_contains_no_addresses_or_names() {
        let (book, dir) = book();
        book.save(&addr(7), "Очень личное имя").unwrap();
        let bytes = std::fs::read(dir.join(FILE)).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("Очень личное имя"));
        assert!(!text.contains("tgrin1"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn wrong_key_and_tamper_fail() {
        let (book, dir) = book();
        book.save(&addr(7), "Боб").unwrap();
        let other = ContactBook::open(dir.clone(), [0x43; 32]).unwrap();
        assert!(other.list().is_err());

        let path = dir.join(FILE);
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 0xff;
        std::fs::write(&path, bytes).unwrap();
        assert!(book.list().is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn invalid_names_and_addresses_are_rejected() {
        let (book, dir) = book();
        assert!(book.save("not-an-address", "Боб").is_err());
        assert!(book.save(&addr(7), "  ").is_err());
        assert!(book
            .save(&addr(7), &"x".repeat(MAX_NAME_CHARS + 1))
            .is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn fresh_lock_is_not_treated_as_stale() {
        let (_book, dir) = book();
        let path = dir.join("contacts.lock");
        std::fs::write(&path, b"live holder").unwrap();
        assert!(!is_stale(&path));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn stale_lock_is_recovered() {
        let (book, dir) = book();
        let path = dir.join("contacts.lock");
        std::fs::write(&path, b"dead process").unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(120);
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
        drop(file);
        assert!(is_stale(&path));

        book.save(&addr(5), "После падения").unwrap();
        assert!(!path.exists(), "stale lock was not removed");
        assert_eq!(book.list().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn old_holder_does_not_delete_a_replaced_lock() {
        let dir = std::env::temp_dir().join(format!("glaux-contacts-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("contacts.lock");
        std::fs::write(&path, b"another owner").unwrap();
        let lock = ContactFileLock {
            path: path.clone(),
            token: "mine".into(),
        };
        drop(lock);
        assert!(path.exists(), "foreign lock was removed");
        let _ = std::fs::remove_dir_all(dir);
    }
}
