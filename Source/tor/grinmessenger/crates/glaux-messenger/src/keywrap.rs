// SPDX-License-Identifier: MIT OR Apache-2.0
//! Password-wrapped history key.
//!
//! `History` needs a stable 32-byte key, but the wallet password must not be
//! used as that key directly. On first use the app generates a random history
//! key, wraps it with the user's password and stores the wrapped blob; unlock
//! unwraps it. Changing the password only rewraps this blob (old history stays
//! readable).
//!
//! The current format is version 2: Argon2id (`m = 64 MiB, t = 3, p = 4` →
//! ChaCha20-Poly1305, AAD binds the KDF parameters, salt and nonce). Version 1
//! (PBKDF2-HMAC-SHA256, 100k iterations) is still **read** so existing history
//! keys do not need the user's attention; the app upgrades a v1 blob to v2
//! automatically after a successful unlock and on password change.
//!
//! This KDF is for local chat history, not for any wallet seed. The original
//! Glaux wallet kept its seed envelope separately; this standalone crate does
//! not contain wallet code. See `docs/PROTOCOL.md` («Ключ истории и пароль»).

use argon2::{Algorithm, Argon2, Params as Argon2Params, Version as Argon2Version};
use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ring::pbkdf2;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Format written by [`wrap`]. Version 1 is read-only (legacy).
pub const CURRENT_VERSION: u8 = 2;
const LEGACY_VERSION: u8 = 1;
/// Upstream iteration count of the old history-key format. It is not a tunable
/// security parameter: it identifies the legacy blob only.
const LEGACY_ITERATIONS: u32 = 100_000;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
/// A wrapped key is well under a kilobyte; this bound stops a huge file from
/// being read/parsed at all.
pub const MAX_WRAPPED_BYTES: usize = 4096;

/// Domain separation: v1 and v2 blobs must not be interchangeable.
const AAD_V1: &[u8] = b"glaux-messenger-history-key-v1";
const AAD_V2: &[u8] = b"glaux-messenger-history-key-v2\x00";

// Argon2id cost for the history-key wrapper (`docs/PROTOCOL.md`, «Ключ истории
// и пароль»). Fixed to keep test vectors reproducible; a change means a new
// `version`.
const ARGON2_VERSION: u32 = 19;
const ARGON2_M_KIB: u32 = 65_536;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 4;
const MIN_M_KIB: u32 = 19_456;
const MAX_M_KIB: u32 = 262_144;
const MAX_T: u32 = 10;
const MAX_P: u32 = 8;

/// Version 1 blob (PBKDF2-HMAC-SHA256). Kept public because it was the shape of
/// the wrapped-key API before version 2; only [`unwrap`] can consume it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct WrappedKey {
    pub version: u8,
    pub salt: [u8; SALT_LEN],
    #[serde(with = "b64_nonce")]
    pub nonce: [u8; 12],
    #[serde(with = "b64_vec")]
    pub ciphertext: Vec<u8>,
}

#[derive(Deserialize)]
struct VersionProbe {
    version: u8,
}

/// Version 2 blob: self-describing KDF parameters and cipher domain.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct WrappedKeyV2 {
    version: u8,
    kdf: KdfJson,
    cipher: CipherJson,
    #[serde(with = "b64_vec")]
    ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct KdfJson {
    algorithm: String,
    version: u32,
    m_kib: u32,
    t: u32,
    p: u32,
    salt: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct CipherJson {
    algorithm: String,
    nonce: String,
}

/// Generate a fresh random key and wrap it under `password`.
pub fn create(password: &str) -> Result<(Zeroizing<[u8; KEY_LEN]>, Vec<u8>)> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::getrandom(&mut key[..]).map_err(|e| Error::Crypto(format!("RNG: {e}")))?;
    let wrapped = wrap(password, &key)?;
    Ok((key, wrapped))
}

/// Wrap `key` under `password` with a fresh salt and nonce (version 2).
pub fn wrap(password: &str, key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    check_password(password)?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| Error::Crypto(format!("RNG: {e}")))?;
    getrandom::getrandom(&mut nonce).map_err(|e| Error::Crypto(format!("RNG: {e}")))?;

    let kdf = KdfJson {
        algorithm: "argon2id".to_string(),
        version: ARGON2_VERSION,
        m_kib: ARGON2_M_KIB,
        t: ARGON2_T,
        p: ARGON2_P,
        salt: base64::encode(salt),
    };
    let cipher_json = CipherJson {
        algorithm: "chacha20poly1305".to_string(),
        nonce: base64::encode(nonce),
    };
    let aad = aad_v2(&kdf, &nonce)?;
    let kek = derive_v2(password, &salt, ARGON2_M_KIB, ARGON2_T, ARGON2_P)?;
    let aead = ChaCha20Poly1305::new(Key::from_slice(&kek[..]));
    let ciphertext = aead
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: key,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto("ключ истории: не удалось зашифровать".into()))?;
    let wrapped = WrappedKeyV2 {
        version: CURRENT_VERSION,
        kdf,
        cipher: cipher_json,
        ciphertext,
    };
    serde_json::to_vec(&wrapped).map_err(|e| Error::Envelope(format!("ключ истории json: {e}")))
}

/// Unwrap a version 1 (PBKDF2) or version 2 (Argon2id) blob.
pub fn unwrap(password: &str, wrapped: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    match version_of(wrapped)? {
        LEGACY_VERSION => unwrap_v1(password, wrapped),
        CURRENT_VERSION => unwrap_v2(password, wrapped),
        other => Err(Error::Version(other)),
    }
}

/// True when the blob is still the PBKDF2 version and should be rewrapped.
pub fn needs_upgrade(wrapped: &[u8]) -> Result<bool> {
    match version_of(wrapped)? {
        LEGACY_VERSION => Ok(true),
        CURRENT_VERSION => Ok(false),
        other => Err(Error::Version(other)),
    }
}

/// Re-wrap the key under a new password (and, for a v1 blob, upgrade to v2).
/// The new blob is opened once before it is returned: a caller that writes it
/// to disk must not replace a readable blob with an unreadable one.
pub fn rewrap(old_password: &str, new_password: &str, wrapped: &[u8]) -> Result<Vec<u8>> {
    let key = unwrap(old_password, wrapped)?;
    let updated = wrap(new_password, &key)?;
    let check = unwrap(new_password, &updated)?;
    if check[..] != key[..] {
        return Err(Error::Crypto(
            "ключ истории: проверка после переупаковки не совпала".into(),
        ));
    }
    Ok(updated)
}

fn version_of(wrapped: &[u8]) -> Result<u8> {
    if wrapped.len() > MAX_WRAPPED_BYTES {
        return Err(Error::Envelope(
            "ключ истории: файл подозрительно большой".into(),
        ));
    }
    let probe: VersionProbe = serde_json::from_slice(wrapped)
        .map_err(|e| Error::Envelope(format!("ключ истории json: {e}")))?;
    Ok(probe.version)
}

fn unwrap_v1(password: &str, wrapped: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    check_password(password)?;
    let value: WrappedKey = serde_json::from_slice(wrapped)
        .map_err(|e| Error::Envelope(format!("ключ истории json: {e}")))?;
    if value.version != LEGACY_VERSION {
        return Err(Error::Version(value.version));
    }
    if value.ciphertext.len() != KEY_LEN + TAG_LEN {
        return Err(Error::Crypto("ключ истории: неверная длина".into()));
    }
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(LEGACY_ITERATIONS).expect("iterations > 0"),
        &value.salt,
        password.as_bytes(),
        &mut kek[..],
    );
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek[..]));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&value.nonce),
                Payload {
                    msg: &value.ciphertext,
                    aad: AAD_V1,
                },
            )
            .map_err(|_| {
                Error::Crypto("ключ истории: неверный пароль или повреждённый файл".into())
            })?,
    );
    to_key(plaintext.as_slice())
}

fn unwrap_v2(password: &str, wrapped: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    check_password(password)?;
    let value: WrappedKeyV2 = serde_json::from_slice(wrapped)
        .map_err(|e| Error::Envelope(format!("ключ истории json: {e}")))?;
    if value.version != CURRENT_VERSION {
        return Err(Error::Version(value.version));
    }
    validate_kdf(&value.kdf)?;
    if value.cipher.algorithm != "chacha20poly1305" {
        return Err(Error::Envelope("ключ истории: неизвестный шифр".into()));
    }
    let salt = base64::decode(&value.kdf.salt)
        .map_err(|_| Error::Envelope("ключ истории: соль — не base64".into()))?;
    let nonce_bytes = base64::decode(&value.cipher.nonce)
        .map_err(|_| Error::Envelope("ключ истории: nonce — не base64".into()))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(Error::Envelope("ключ истории: nonce неверной длины".into()));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nonce_bytes);
    // `ciphertext` already comes out of serde's base64 adapter as bytes.
    if value.ciphertext.len() != KEY_LEN + TAG_LEN {
        return Err(Error::Crypto("ключ истории: неверная длина".into()));
    }

    let aad = aad_v2(&value.kdf, &nonce)?;
    let kek = derive_v2(password, &salt, value.kdf.m_kib, value.kdf.t, value.kdf.p)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek[..]));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &value.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                Error::Crypto("ключ истории: неверный пароль или повреждённый файл".into())
            })?,
    );
    to_key(plaintext.as_slice())
}

fn to_key(plaintext: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if plaintext.len() != KEY_LEN {
        return Err(Error::Crypto("ключ истории: неверная длина".into()));
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(plaintext);
    Ok(key)
}

fn check_password(password: &str) -> Result<()> {
    if password.is_empty() {
        return Err(Error::Crypto(
            "ключ истории: пустой пароль недопустим".into(),
        ));
    }
    Ok(())
}

/// Validate the KDF header *before* Argon2 allocates memory. A damaged or
/// malicious file must not make the app allocate gigabytes or spin for hours.
fn validate_kdf(kdf: &KdfJson) -> Result<()> {
    if kdf.algorithm != "argon2id" || kdf.version != ARGON2_VERSION {
        return Err(Error::Envelope("ключ истории: неизвестный KDF".into()));
    }
    if !(MIN_M_KIB..=MAX_M_KIB).contains(&kdf.m_kib) {
        return Err(Error::Envelope(
            "ключ истории: память Argon2id вне допустимого диапазона".into(),
        ));
    }
    if kdf.t == 0 || kdf.t > MAX_T {
        return Err(Error::Envelope(
            "ключ истории: число проходов Argon2id вне допустимого диапазона".into(),
        ));
    }
    if kdf.p == 0 || kdf.p > MAX_P {
        return Err(Error::Envelope(
            "ключ истории: параллелизм Argon2id вне допустимого диапазона".into(),
        ));
    }
    let salt = base64::decode(&kdf.salt)
        .map_err(|_| Error::Envelope("ключ истории: соль — не base64".into()))?;
    if salt.len() != SALT_LEN {
        return Err(Error::Envelope("ключ истории: соль неверной длины".into()));
    }
    Ok(())
}

fn aad_v2(kdf: &KdfJson, nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>> {
    let salt = base64::decode(&kdf.salt)
        .map_err(|_| Error::Envelope("ключ истории: соль — не base64".into()))?;
    let mut aad = Vec::with_capacity(AAD_V2.len() + 4 * 5 + salt.len() + nonce.len());
    aad.extend_from_slice(AAD_V2);
    aad.extend_from_slice(&kdf.m_kib.to_le_bytes());
    aad.extend_from_slice(&kdf.t.to_le_bytes());
    aad.extend_from_slice(&kdf.p.to_le_bytes());
    aad.extend_from_slice(&kdf.version.to_le_bytes());
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(nonce);
    Ok(aad)
}

fn derive_v2(
    password: &str,
    salt: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Argon2Params::new(m_kib, t, p, Some(KEY_LEN))
        .map_err(|_| Error::Crypto("ключ истории: недопустимые параметры Argon2id".into()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Argon2Version::V0x13, params);
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt, &mut kek[..])
        .map_err(|_| Error::Crypto("ключ истории: Argon2id не смог вывести ключ".into()))?;
    Ok(kek)
}

mod b64_nonce {
    use base64::{decode, encode};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 12], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 12], D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        let bytes = decode(text).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("ожидались 12 байт"))
    }
}

mod b64_vec {
    use base64::{decode, encode};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        decode(text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A blob written by the version 1 code (PBKDF2-100k) for password
    /// `history-fixture-password` and key `[0x42; 32]`. Kept as a fixed fixture:
    /// a refactor of the writer must not silently break old history files.
    const V1_FIXTURE: &str = concat!(
        r#"{"version":1,"salt":[95,202,19,243,168,238,54,82,99,108,0,128,45,239,18,251],"#,
        r#""nonce":"Dufa88sLZU53v/Di","#,
        r#""ciphertext":"FaIcRhs+PggBe7vOgnv2fRcXtJ0xlwWeqjnzIpQrhNLpxsaQRi/hmWU0082uaKAW"}"#
    );

    fn fixture_v2(kdf: KdfJson) -> String {
        let value = WrappedKeyV2 {
            version: CURRENT_VERSION,
            kdf,
            cipher: CipherJson {
                algorithm: "chacha20poly1305".into(),
                nonce: base64::encode([7u8; NONCE_LEN]),
            },
            ciphertext: vec![0u8; KEY_LEN + TAG_LEN],
        };
        serde_json::to_string(&value).unwrap()
    }

    #[test]
    fn v2_roundtrip_and_rewrap() {
        let (key, wrapped) = create("old-password").unwrap();
        assert!(!needs_upgrade(&wrapped).unwrap());
        let opened = unwrap("old-password", &wrapped).unwrap();
        assert_eq!(&key[..], &opened[..]);

        let rewrapped = rewrap("old-password", "new-password", &wrapped).unwrap();
        assert!(unwrap("new-password", &rewrapped).is_ok());
        assert!(unwrap("old-password", &rewrapped).is_err());

        let text = String::from_utf8_lossy(&wrapped);
        assert!(
            !text.contains(&base64::encode(&key[..])),
            "key leaked into the blob"
        );
    }

    #[test]
    fn v1_fixture_opens_and_upgrades() {
        let key = unwrap("history-fixture-password", V1_FIXTURE.as_bytes()).unwrap();
        assert_eq!(&key[..], &[0x42u8; 32]);
        assert!(needs_upgrade(V1_FIXTURE.as_bytes()).unwrap());

        let upgraded = rewrap(
            "history-fixture-password",
            "history-fixture-password",
            V1_FIXTURE.as_bytes(),
        )
        .unwrap();
        assert!(!needs_upgrade(&upgraded).unwrap());
        let opened = unwrap("history-fixture-password", &upgraded).unwrap();
        assert_eq!(&opened[..], &key[..]);
        assert!(unwrap("wrong-password", &upgraded).is_err());
    }

    #[test]
    fn wrong_password_and_tamper_fail() {
        let (_key, wrapped) = create("password").unwrap();
        assert!(unwrap("wrong", &wrapped).is_err());

        let mut value: WrappedKeyV2 = serde_json::from_slice(&wrapped).unwrap();
        let last = value.ciphertext.len() - 1;
        value.ciphertext[last] ^= 1;
        let tampered = serde_json::to_vec(&value).unwrap();
        assert!(unwrap("password", &tampered).is_err());
    }

    #[test]
    fn version_is_checked() {
        let (_key, wrapped) = create("password").unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&wrapped).unwrap();
        value["version"] = 9.into();
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(matches!(unwrap("password", &bytes), Err(Error::Version(9))));
        assert!(matches!(needs_upgrade(&bytes), Err(Error::Version(9))));
    }

    #[test]
    fn absurd_kdf_parameters_are_rejected_before_allocation() {
        let cases = [
            (4_000_000u32, 3u32, 4u32),
            (1, 3, 4),
            (ARGON2_M_KIB, 0, 4),
            (ARGON2_M_KIB, 3, 0),
            (ARGON2_M_KIB, 11, 4),
        ];
        for (m_kib, t, p) in cases {
            let kdf = KdfJson {
                algorithm: "argon2id".into(),
                version: ARGON2_VERSION,
                m_kib,
                t,
                p,
                salt: base64::encode([1u8; SALT_LEN]),
            };
            let err = unwrap("password", fixture_v2(kdf).as_bytes()).unwrap_err();
            assert!(
                matches!(err, Error::Envelope(_)),
                "m={m_kib} t={t} p={p}: {err}"
            );
        }
    }

    #[test]
    fn empty_password_is_refused() {
        assert!(create("").is_err());
        let (_key, wrapped) = create("password").unwrap();
        assert!(unwrap("", &wrapped).is_err());
    }

    #[test]
    fn short_nonce_is_an_error_not_a_panic() {
        let (_key, wrapped) = create("password").unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&wrapped).unwrap();
        value["cipher"]["nonce"] = "AA==".into();
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(matches!(
            unwrap("password", &bytes),
            Err(Error::Envelope(_))
        ));
    }

    #[test]
    fn each_wrap_has_fresh_salt_and_nonce() {
        let (_key, first) = create("password").unwrap();
        let (_key2, second) = create("password").unwrap();
        let a: WrappedKeyV2 = serde_json::from_slice(&first).unwrap();
        let b: WrappedKeyV2 = serde_json::from_slice(&second).unwrap();
        assert_ne!(a.kdf.salt, b.kdf.salt);
        assert_ne!(a.cipher.nonce, b.cipher.nonce);
    }
}
