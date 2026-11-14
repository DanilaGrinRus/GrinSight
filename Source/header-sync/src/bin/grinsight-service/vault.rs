//! Seed vault: the recovery phrase (12, 18 or 24 words) encrypted with the user's password.
//!
//! scrypt (N = 2^15, r = 8, p = 1: ~32 MiB, a fraction of a second) derives a
//! 256-bit key; ChaCha20-Poly1305 encrypts the phrase with a random nonce. The
//! file holds only salt, nonce, ciphertext and parameters. A wrong password
//! and a changed file are the same error (authentication tag mismatch).
//!
//! The phrase is held in `Zeroizing` buffers and handed to the core only on
//! the standard input of a child process (`--seeds -`).

use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use grin_keychain::mnemonic;
use serde_json::{json, Value};
use std::path::Path;
use zeroize::Zeroizing;

const AAD: &[u8] = b"grinsight-vault-v1";
const LOG_N: u8 = 15;
const R: u32 = 8;
const P: u32 = 1;
pub const MIN_PASSWORD: usize = 8;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    grinsight_state::session::hex_bytes(s)
}

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| format!("system random: {e}"))?;
    Ok(b)
}

fn kdf(password: &str, salt: &[u8], log_n: u8, r: u32, p: u32) -> Result<Zeroizing<[u8; 32]>, String> {
    let params = scrypt::Params::new(log_n, r, p).map_err(|e| format!("scrypt params: {e}"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(password.as_bytes(), salt, &params, &mut key[..]).map_err(|e| format!("scrypt: {e}"))?;
    Ok(key)
}

/// Phrase lengths a wallet can be CREATED with (BIP39: 16, 24 or 32 bytes).
pub const CREATE_WORDS: [usize; 3] = [12, 18, 24];

/// A new phrase from system randomness (BIP39): 12 words = 16 bytes,
/// 18 = 24 bytes, 24 = 32 bytes.
pub fn new_phrase(words: usize) -> Result<Zeroizing<String>, String> {
    if !CREATE_WORDS.contains(&words) {
        return Err(format!("a new phrase has 12, 18 or 24 words, not {words}"));
    }
    let bytes = words / 3 * 4;
    let mut entropy = Zeroizing::new(vec![0u8; bytes]);
    getrandom::getrandom(&mut entropy[..]).map_err(|e| format!("system random: {e}"))?;
    mnemonic::from_entropy(&entropy[..]).map(Zeroizing::new).map_err(|e| format!("mnemonic: {e:?}"))
}

/// Lowercase, single spaces, 12/15/18/21/24 BIP39 words with a valid checksum
/// (restore takes any BIP39 length; wallets are created with 12, 18 or 24).
pub fn normalize_phrase(text: &str) -> Result<Zeroizing<String>, String> {
    let words: Vec<String> = text.split_whitespace().map(|w| w.to_ascii_lowercase()).collect();
    if !grinsight_state::wallet::is_phrase_len(words.len()) {
        return Err(format!("the phrase needs 12, 18 or 24 words (15 and 21 also restore), got {}", words.len()));
    }
    for (i, w) in words.iter().enumerate() {
        if mnemonic::search(w).is_err() {
            return Err(format!("word {} is not a BIP39 word", i + 1));
        }
    }
    let p = Zeroizing::new(words.join(" "));
    mnemonic::to_entropy(&p).map_err(|_| "the phrase checksum is wrong (a word is mistyped)".to_string())?;
    Ok(p)
}

/// Writes a new vault file; refuses to overwrite an existing one.
pub fn create(path: &Path, phrase: &str, password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD {
        return Err(format!("the password needs at least {MIN_PASSWORD} characters"));
    }
    let phrase = normalize_phrase(phrase)?;
    if path.exists() {
        return Err("a wallet with this name already exists".into());
    }
    let doc = seal(&phrase, password)?;
    store(path, &doc)
}

/// Encrypts the phrase under the password (fresh salt and nonce).
fn seal(phrase: &str, password: &str) -> Result<Value, String> {
    let salt = random::<16>()?;
    let nonce = random::<12>()?;
    let key = kdf(password, &salt, LOG_N, R, P)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: phrase.as_bytes(), aad: AAD })
        .map_err(|_| "encryption failed")?;
    Ok(json!({
        "version": 1, "kdf": "scrypt", "log_n": LOG_N, "r": R, "p": P,
        "cipher": "chacha20poly1305", "salt": hex(&salt), "nonce": hex(&nonce), "ciphertext": hex(&ct),
    }))
}

fn store(path: &Path, v: &Value) -> Result<(), String> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, v.to_string()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Re-encrypts the same phrase under a new password (the old one is checked first).
pub fn change_password(path: &Path, old: &str, new: &str) -> Result<(), String> {
    if new.chars().count() < MIN_PASSWORD {
        return Err(format!("the password needs at least {MIN_PASSWORD} characters"));
    }
    let phrase = open(path, old)?;
    let doc = seal(&phrase, new)?;
    store(path, &doc)
}

pub fn verify_and_hash(path: &Path, password: &str, expected_phrase: &str) -> Result<String, String> {
    let bytes = read_bounded(path)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "wallet file is damaged")?;
    let phrase = open_text(text, password)?;
    if phrase.as_str() != expected_phrase { return Err("wallet changed; use wallet password".into()); }
    Ok(grinsight_state::session::sha256_hex(&bytes))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|_| "no such wallet".to_string())?;
    let mut bytes = Vec::new();
    file.take(1_048_577).read_to_end(&mut bytes).map_err(|_| "wallet unavailable")?;
    if bytes.len() > 1_048_576 { return Err("wallet file too large".into()); }
    Ok(bytes)
}

pub fn fingerprint(path: &Path) -> Result<String, String> {
    Ok(grinsight_state::session::sha256_hex(&read_bounded(path)?))
}

/// The phrase, or an error for a wrong password / damaged file.
pub fn open(path: &Path, password: &str) -> Result<Zeroizing<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|_| "no such wallet".to_string())?;
    open_text(&text, password)
}

/// Bound biometric unlock: hash and decrypt the exact same bounded bytes.
pub fn open_bound(path: &Path, password: &str, expected: &str) -> Result<Zeroizing<String>, String> {
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("invalid wallet binding".into());
    }
    let bytes = read_bounded(path)?;
    if grinsight_state::session::sha256_hex(&bytes) != expected {
        return Err("wallet changed; use wallet password".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "wallet file is damaged")?;
    open_text(text, password)
}

fn open_text(text: &str, password: &str) -> Result<Zeroizing<String>, String> {
    let v: Value = serde_json::from_str(&text).map_err(|_| "the wallet file is damaged")?;
    let s = |k: &str| v.get(k).and_then(Value::as_str).and_then(unhex).ok_or("the wallet file is damaged");
    let n = |k: &str| v.get(k).and_then(Value::as_u64).ok_or("the wallet file is damaged");
    if v.get("version").and_then(Value::as_u64) != Some(1) || v.get("kdf").and_then(Value::as_str) != Some("scrypt") {
        return Err("unsupported wallet file".into());
    }
    let (log_n, r, p) = (n("log_n")?, n("r")?, n("p")?);
    // Bounded parameters: a crafted file must not make us allocate gigabytes.
    if !(10..=20).contains(&log_n) || !(1..=16).contains(&r) || !(1..=4).contains(&p) {
        return Err("unsupported wallet file parameters".into());
    }
    let (salt, nonce, ct) = (s("salt")?, s("nonce")?, s("ciphertext")?);
    if nonce.len() != 12 {
        return Err("the wallet file is damaged".into());
    }
    let key = kdf(password, &salt, log_n as u8, r as u32, p as u32)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let pt = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad: AAD })
            .map_err(|_| "wrong password (or the wallet file was changed)".to_string())?,
    );
    let phrase = std::str::from_utf8(&pt).map_err(|_| "the wallet file is damaged")?;
    normalize_phrase(phrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("gs-vault-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn bound_credential_rejects_replaced_seed_with_same_password() {
        let d = dir("bound-other-seed");
        let file = d.join("vault.json");
        let first = new_phrase(12).unwrap();
        let second = new_phrase(12).unwrap();
        create(&file, &first, "synthetic password").unwrap();
        let digest = verify_and_hash(&file, "synthetic password", &first).unwrap();
        assert!(open_bound(&file, "synthetic password", &digest).is_ok());
        std::fs::remove_file(&file).unwrap();
        create(&file, &second, "synthetic password").unwrap();
        assert!(verify_and_hash(&file, "synthetic password", &first).is_err());
        assert!(open_bound(&file, "synthetic password", &digest).is_err());
        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&d);
    }

    #[test]
    fn password_change_keeps_the_phrase() {
        let d = dir("pw");
        let f = d.join("vault.json");
        let phrase = new_phrase(12).unwrap();
        create(&f, &phrase, "first password").unwrap();
        assert!(change_password(&f, "not the password", "second password").is_err());
        assert!(change_password(&f, "first password", "short").is_err());
        change_password(&f, "first password", "second password").unwrap();
        assert!(open(&f, "first password").is_err());
        assert_eq!(*open(&f, "second password").unwrap(), *phrase);
    }

    #[test]
    fn round_trip_wrong_password_and_tamper() {
        let d = dir("rt");
        let f = d.join("vault.json");
        let phrase = new_phrase(24).unwrap();
        assert_eq!(phrase.split(' ').count(), 24);
        create(&f, &phrase.to_uppercase(), "correct horse").unwrap();
        assert_eq!(*open(&f, "correct horse").unwrap(), *phrase);
        assert!(open(&f, "wrong horse!").unwrap_err().contains("wrong password"));
        assert!(create(&f, &phrase, "correct horse").is_err(), "no overwrite");
        // The file never contains the phrase or a word of it.
        let raw = std::fs::read_to_string(&f).unwrap();
        // Not a leak, so not checked: the file's own key names («salt» is a
        // BIP39 word) and words made only of a-f («face», «fade»), which
        // random hex can contain by chance.
        let mut body = raw.clone();
        for k in ["ciphertext", "cipher", "chacha20poly1305", "scrypt", "kdf", "log_n", "nonce", "salt", "version"] {
            body = body.replace(&format!("\"{k}\""), "\"\"");
        }
        let hexy = |w: &str| w.chars().all(|c| ('a'..='f').contains(&c));
        assert!(!raw.contains(phrase.as_str()), "{raw}");
        assert!(phrase.split(' ').all(|w| w.len() < 4 || hexy(w) || !body.contains(w)), "{raw}");
        // One flipped ciphertext bit: refused like a wrong password.
        let mut v: Value = serde_json::from_str(&raw).unwrap();
        let mut ct = unhex(v["ciphertext"].as_str().unwrap()).unwrap();
        ct[3] ^= 1;
        v["ciphertext"] = json!(hex(&ct));
        std::fs::write(&f, v.to_string()).unwrap();
        assert!(open(&f, "correct horse").is_err());
        // Absurd scrypt parameters are refused before any work.
        v["log_n"] = json!(30);
        std::fs::write(&f, v.to_string()).unwrap();
        assert!(open(&f, "correct horse").unwrap_err().contains("parameters"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn phrases_of_every_length() {
        for n in [12usize, 18, 24] {
            let p = new_phrase(n).unwrap();
            assert_eq!(p.split(' ').count(), n);
            assert_eq!(*normalize_phrase(&p.to_uppercase()).unwrap(), *p, "{n} words round-trip");
        }
        assert!(new_phrase(15).is_err() && new_phrase(13).is_err() && new_phrase(0).is_err());
        // 15 and 21 words restore (valid BIP39), 13 does not
        let p15 = mnemonic::from_entropy(&[1u8; 20]).unwrap();
        let p21 = mnemonic::from_entropy(&[2u8; 28]).unwrap();
        assert!(normalize_phrase(&p15).is_ok() && normalize_phrase(&p21).is_ok());
        assert!(normalize_phrase(&format!("{p15} abandon")).is_err());
        // two fresh phrases differ
        assert_ne!(*new_phrase(12).unwrap(), *new_phrase(12).unwrap());
    }

    #[test]
    fn phrase_rules() {
        let d = dir("rules");
        let ok = format!("{}art", "abandon ".repeat(23));
        assert!(normalize_phrase(&ok).is_ok());
        assert!(normalize_phrase(&format!("{}abandon", "abandon ".repeat(23))).unwrap_err().contains("checksum"));
        assert!(normalize_phrase(&format!("{}art", "abandon ".repeat(22))).unwrap_err().contains("12, 18 or 24 words"));
        assert!(normalize_phrase(&format!("{}zzzz", "abandon ".repeat(23))).unwrap_err().contains("word 24"));
        assert!(create(&d.join("v.json"), &ok, "short").unwrap_err().contains("at least"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
