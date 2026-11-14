// SPDX-License-Identifier: MIT OR Apache-2.0
//! Experimental authenticated storage for a profile's I2P destination.
//! Not yet connected to wallet startup or recovery UI.
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use glaux_messenger::i2p_sam::Destination;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

const AAD: &[u8] = b"grinsight-i2p-destination-v1";
const MAX_FILE: u64 = 16 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredDestination { version: u8, public: String, private: String }
impl Drop for StoredDestination { fn drop(&mut self) { self.private.zeroize(); } }

fn key(seed: &[u8;32], network: &str) -> Result<Zeroizing<[u8;32]>, String> {
    let hk=Hkdf::<Sha256>::new(Some(b"grinsight-i2p-storage/v1"),seed);
    let mut out=Zeroizing::new([0u8;32]);
    let label=crate::identity::network_hrp(network);
    hk.expand(label.as_bytes(),out.as_mut()).map_err(|_| "I2P key derivation failed")?;
    Ok(out)
}

/// Create a new encrypted destination file; an existing file is never replaced.
pub fn save_new(path: &Path, seed: &[u8;32], network: &str, destination: &Destination) -> Result<(), String> {
    let k=key(seed,network)?;
    let stored=StoredDestination { version:1, public:destination.public().to_owned(), private:destination.private_for_storage().to_string() };
    let data=Zeroizing::new(serde_json::to_vec(&stored).map_err(|_| "invalid I2P destination")?);
    let mut nonce=[0u8;12]; getrandom::getrandom(&mut nonce).map_err(|_| "I2P storage random generation failed")?;
    let cipher=ChaCha20Poly1305::new(Key::from_slice(&k[..]));
    let ciphertext=cipher.encrypt(Nonce::from_slice(&nonce), Payload {msg:&data, aad:AAD}).map_err(|_| "I2P storage encryption failed")?;
    let mut options=OpenOptions::new(); options.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let mut f=options.open(path).map_err(|_| "I2P destination file already exists or cannot be created")?;
    f.write_all(&nonce).and_then(|_|f.write_all(&ciphertext)).and_then(|_|f.sync_all()).map_err(|_| "I2P destination write failed")?;
    Ok(())
}

/// A damaged or wrong-key file is an error; it must never cause key regeneration.
pub fn load(path: &Path, seed: &[u8;32], network: &str) -> Result<Destination, String> {
    let mut file=fs::File::open(path).map_err(|_| "I2P destination unavailable")?;
    if file.metadata().map_err(|_| "I2P destination unavailable")?.len()>MAX_FILE { return Err("I2P destination too large".into()); }
    let mut raw=Vec::new(); (&mut file).take(MAX_FILE+1).read_to_end(&mut raw).map_err(|_| "I2P destination read failed")?;
    if raw.len()<28 || raw.len() as u64>MAX_FILE { return Err("invalid I2P destination file".into()); }
    let k=key(seed,network)?;
    let cipher=ChaCha20Poly1305::new(Key::from_slice(&k[..]));
    let plain=Zeroizing::new(cipher.decrypt(Nonce::from_slice(&raw[..12]),Payload {msg:&raw[12..],aad:AAD}).map_err(|_| "I2P destination authentication failed")?);
    let value:StoredDestination=serde_json::from_slice(&plain).map_err(|_| "invalid I2P destination contents")?;
    if value.version!=1 {return Err("unsupported I2P destination version".into())}
    Destination::from_saved(&value.public,&value.private).map_err(|_| "invalid saved I2P destination".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_storage_reopens_and_rejects_wrong_key_tampering_and_overwrite() {
        let dir=std::env::temp_dir().join(format!("gs-i2p-storage-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(&dir).unwrap(); let path=dir.join("destination.enc");
        let dest=Destination::from_saved("test-public-destination","test-private-destination").unwrap();
        save_new(&path,&[1;32],"testnet",&dest).unwrap();
        let before=fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&before).contains("test-private-destination"));
        assert_eq!(load(&path,&[1;32],"testnet").unwrap().public(),"test-public-destination");
        assert!(load(&path,&[2;32],"testnet").is_err());
        assert!(load(&path,&[1;32],"mainnet").is_err());
        assert!(save_new(&path,&[1;32],"testnet",&dest).is_err());
        assert_eq!(before,fs::read(&path).unwrap());
        let mut changed=before; changed[12]^=1; fs::write(&path,changed).unwrap();
        assert!(load(&path,&[1;32],"testnet").is_err());
        let _=fs::remove_file(path); let _=fs::remove_dir(dir);
    }
}
