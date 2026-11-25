//! The profile file: what the wallet cannot be opened without, sealed under
//! the user's password.
//!
//! `profile.json` holds the seed, the root key of the journal, the wallet
//! instance and the key that wraps the tail guard's key where the operating
//! system offers nothing better. All of it is one sealed blob
//! (XChaCha20-Poly1305); the key comes from the password through scrypt.
//! The parameters, the salt and the network are in the clear and are bound
//! to the blob, so none of them can be swapped without the password.
//!
//! The file is written whole to a temporary name, flushed, and renamed.
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

/// Name of the profile file inside the profile directory.
pub const FILE: &str = "profile.json";
const TMP: &str = "profile.json.tmp";
const FORMAT: &str = "grinsight-fly-profile";
const VERSION: u32 = 1;
/// Nothing we write comes near this; anything larger is not ours.
const MAX_FILE_LEN: u64 = 8 * 1024;
const PLAIN_VERSION: u8 = 1;
/// Highest cost accepted from a file: 2^20 blocks is 1 GB of memory.
pub const MAX_LOG_N: u8 = 20;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
/// Longest password, in bytes.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// The chain a profile belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// The main network.
    Main,
    /// The public test network.
    Test,
    /// The chain of automated tests; only a test program accepts it.
    Automated,
}

impl Network {
    /// The name used in requests and in the profile file.
    pub fn name(self) -> &'static str {
        match self {
            Network::Main => "main",
            Network::Test => "test",
            Network::Automated => "automated",
        }
    }
    /// The network of that name.
    pub fn from_name(name: &str) -> Option<Network> {
        match name {
            "main" => Some(Network::Main),
            "test" => Some(Network::Test),
            "automated" => Some(Network::Automated),
            _ => None,
        }
    }
    /// The tag the journal is bound to.
    pub fn tag(self) -> u8 {
        match self {
            Network::Main => 1,
            Network::Test => 2,
            Network::Automated => 3,
        }
    }
}

/// What the sealed blob holds.
pub struct Secrets {
    /// The chain.
    pub network: Network,
    /// Seed of the wallet: the entropy the recovery phrase stands for.
    pub seed: Zeroizing<Vec<u8>>,
    /// Root key of the journal.
    pub root: Zeroizing<[u8; 32]>,
    /// Wraps the tail guard's key where the operating system has no keeper
    /// of its own.
    pub guard_wrap: Zeroizing<[u8; 32]>,
    /// Random identifier of this wallet instance.
    pub instance: [u8; 16],
    /// Account of the wallet.
    pub account: u32,
}

/// Why the profile could not be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileError {
    /// There is no profile file.
    Missing,
    /// There already is one; it is never overwritten by a new profile.
    Exists,
    /// The password does not open the blob (or the blob was altered: the
    /// two cannot be told apart).
    WrongPassword,
    /// The file is not a profile this program can read.
    Damaged(&'static str),
    /// The password is empty or too long, or the seed has no valid length.
    BadInput(&'static str),
    /// The file system refused.
    Io(io::ErrorKind),
    /// The random generator of the operating system failed.
    Rng,
}

impl From<io::Error> for ProfileError {
    fn from(e: io::Error) -> Self {
        ProfileError::Io(e.kind())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OnDisk {
    format: String,
    version: u32,
    network: String,
    kdf: String,
    log_n: u8,
    r: u32,
    p: u32,
    salt: String,
    nonce: String,
    sealed: String,
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    <[u8; N]>::try_from(unhex_vec(text, N)?).ok()
}

fn unhex_vec(text: &str, max: usize) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() & 1 == 1 || bytes.len() / 2 > max {
        return None;
    }
    let digit = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => c.checked_sub(b'0'),
            b'a'..=b'f' => c.checked_sub(b'a').and_then(|d| d.checked_add(10)),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let (hi, lo) = (digit(*pair.first()?)?, digit(*pair.get(1)?)?);
        out.push(hi.checked_mul(16)?.checked_add(lo)?);
    }
    Some(out)
}

/// What is in the clear and bound to the blob.
fn bound(network: Network, log_n: u8, salt: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(FORMAT.as_bytes());
    out.push(0);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.push(network.tag());
    out.push(log_n);
    out.extend_from_slice(&SCRYPT_R.to_le_bytes());
    out.extend_from_slice(&SCRYPT_P.to_le_bytes());
    out.extend_from_slice(salt);
    out
}

fn derive(password: &[u8], salt: &[u8; 32], log_n: u8) -> Result<Zeroizing<[u8; 32]>, ProfileError> {
    if password.is_empty() || password.len() > MAX_PASSWORD_LEN {
        return Err(ProfileError::BadInput("password length"));
    }
    let params = scrypt::Params::new(log_n, SCRYPT_R, SCRYPT_P)
        .map_err(|_| ProfileError::Damaged("key derivation parameters"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(password, salt, &params, key.as_mut())
        .map_err(|_| ProfileError::Damaged("key derivation parameters"))?;
    Ok(key)
}

fn encode(s: &Secrets) -> Result<Zeroizing<Vec<u8>>, ProfileError> {
    if ![16, 20, 24, 28, 32].contains(&s.seed.len()) {
        return Err(ProfileError::BadInput("seed length"));
    }
    let seed_len = u8::try_from(s.seed.len()).map_err(|_| ProfileError::BadInput("seed length"))?;
    let mut out = Zeroizing::new(Vec::with_capacity(128));
    out.push(PLAIN_VERSION);
    out.push(s.network.tag());
    out.extend_from_slice(&s.account.to_le_bytes());
    out.extend_from_slice(&s.instance);
    out.extend_from_slice(s.root.as_ref());
    out.extend_from_slice(s.guard_wrap.as_ref());
    out.push(seed_len);
    out.extend_from_slice(&s.seed);
    Ok(out)
}

fn decode(plain: &[u8], network: Network) -> Option<Secrets> {
    let (head, rest) = plain.split_first_chunk::<2>()?;
    if *head != [PLAIN_VERSION, network.tag()] {
        return None;
    }
    let (account, rest) = rest.split_first_chunk::<4>()?;
    let (instance, rest) = rest.split_first_chunk::<16>()?;
    let (root, rest) = rest.split_first_chunk::<32>()?;
    let (guard_wrap, rest) = rest.split_first_chunk::<32>()?;
    let (seed_len, seed) = rest.split_first()?;
    if usize::from(*seed_len) != seed.len() || ![16, 20, 24, 28, 32].contains(&seed.len()) {
        return None;
    }
    Some(Secrets {
        network,
        seed: Zeroizing::new(seed.to_vec()),
        root: Zeroizing::new(*root),
        guard_wrap: Zeroizing::new(*guard_wrap),
        instance: *instance,
        account: u32::from_le_bytes(*account),
    })
}

/// Seal `secrets` under `password` and return the text of the profile file.
pub fn seal(secrets: &Secrets, password: &[u8], log_n: u8) -> Result<String, ProfileError> {
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut salt).map_err(|_| ProfileError::Rng)?;
    getrandom::getrandom(&mut nonce).map_err(|_| ProfileError::Rng)?;
    let key = derive(password, &salt, log_n)?;
    let plain = encode(secrets)?;
    let aad = bound(secrets.network, log_n, &salt);
    let sealed = XChaCha20Poly1305::new(key.as_ref().into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plain.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| ProfileError::Damaged("sealing"))?;
    let disk = OnDisk {
        format: FORMAT.to_string(),
        version: VERSION,
        network: secrets.network.name().to_string(),
        kdf: "scrypt".to_string(),
        log_n,
        r: SCRYPT_R,
        p: SCRYPT_P,
        salt: hex(&salt),
        nonce: hex(&nonce),
        sealed: hex(&sealed),
    };
    serde_json::to_string_pretty(&disk).map_err(|_| ProfileError::Damaged("encoding"))
}

fn read(dir: &Path) -> Result<OnDisk, ProfileError> {
    let file = match File::open(dir.join(FILE)) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ProfileError::Missing),
        Err(e) => return Err(e.into()),
    };
    let mut text = String::new();
    file.take(MAX_FILE_LEN.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(|e| match e.kind() {
            io::ErrorKind::InvalidData => ProfileError::Damaged("not text"),
            kind => ProfileError::Io(kind),
        })?;
    if u64::try_from(text.len()).map_or(true, |n| n > MAX_FILE_LEN) {
        return Err(ProfileError::Damaged("too large"));
    }
    let disk: OnDisk = serde_json::from_str(&text).map_err(|_| ProfileError::Damaged("not a profile"))?;
    if disk.format != FORMAT || disk.version != VERSION || disk.kdf != "scrypt" {
        return Err(ProfileError::Damaged("unknown format"));
    }
    Ok(disk)
}

/// Whether the directory has a profile file at all.
pub fn exists(dir: &Path) -> bool {
    dir.join(FILE).exists()
}

/// The network a profile says it belongs to, without the password. It is
/// confirmed only by [`open`].
pub fn network(dir: &Path) -> Result<Network, ProfileError> {
    Network::from_name(&read(dir)?.network).ok_or(ProfileError::Damaged("network"))
}

/// Open the profile with `password`. A file that asks for less work than
/// `min_log_n` or for more than [`MAX_LOG_N`] is refused before any work.
pub fn open(dir: &Path, password: &[u8], min_log_n: u8) -> Result<Secrets, ProfileError> {
    let disk = read(dir)?;
    let network = Network::from_name(&disk.network).ok_or(ProfileError::Damaged("network"))?;
    if disk.log_n < min_log_n || disk.log_n > MAX_LOG_N || disk.r != SCRYPT_R || disk.p != SCRYPT_P {
        return Err(ProfileError::Damaged("key derivation parameters"));
    }
    let salt = unhex::<32>(&disk.salt).ok_or(ProfileError::Damaged("salt"))?;
    let nonce = unhex::<24>(&disk.nonce).ok_or(ProfileError::Damaged("nonce"))?;
    let sealed = unhex_vec(&disk.sealed, 512).ok_or(ProfileError::Damaged("blob"))?;
    let key = derive(password, &salt, disk.log_n)?;
    let aad = bound(network, disk.log_n, &salt);
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new(key.as_ref().into())
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: sealed.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| ProfileError::WrongPassword)?,
    );
    decode(&plain, network).ok_or(ProfileError::Damaged("content"))
}

fn write(dir: &Path, text: &str) -> Result<(), ProfileError> {
    let tmp = dir.join(TMP);
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // current user only
        options.mode(0o600);
    }
    let mut f = options.open(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, dir.join(FILE))?;
    // make the rename itself durable where a directory can be opened
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

// Journal locks belong to individual instances. Publication is shared by
// all instances in the profile directory, including competing first runs.
// Keep the lock file: unlinking it would allow a second independent lock.
fn publication_lock(dir: &Path) -> Result<File, ProfileError> {
    let file = OpenOptions::new().read(true).write(true).create(true)
        .truncate(false).open(dir.join("profile.publish.lock"))?;
    // The browser's file system has no file locks and one program, on one
    // thread: there is nobody to compete with at publication.
    #[cfg(not(target_os = "emscripten"))]
    file.try_lock().map_err(|err| match err {
        fs::TryLockError::WouldBlock => ProfileError::Io(io::ErrorKind::WouldBlock),
        fs::TryLockError::Error(error) => error.into(),
    })?;
    Ok(file)
}

/// Write the file of a new profile. An existing profile is never replaced.
pub fn write_new(dir: &Path, text: &str) -> Result<(), ProfileError> {
    let _publication = publication_lock(dir)?;
    if exists(dir) {
        return Err(ProfileError::Exists);
    }
    write(dir, text)
}

/// Replace the file of an existing profile (a new password).
pub fn replace(dir: &Path, text: &str) -> Result<(), ProfileError> {
    let _publication = publication_lock(dir)?;
    if !exists(dir) {
        return Err(ProfileError::Missing);
    }
    write(dir, text)
}

/// Remove the file of the profile: the wallet is gone from this computer
/// once this returns. A file that is not there is not an error - the
/// removal may be the second try of one that was cut short.
pub fn remove(dir: &Path) -> Result<(), ProfileError> {
    let _publication = publication_lock(dir)?;
    for name in [TMP, FILE] {
        match fs::remove_file(dir.join(name)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(ProfileError::Io(e.kind())),
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    fn secrets(network: Network, seed_len: usize) -> Secrets {
        Secrets {
            network,
            seed: Zeroizing::new((0..seed_len).map(|i| i as u8).collect()),
            root: Zeroizing::new([0x11; 32]),
            guard_wrap: Zeroizing::new([0x22; 32]),
            instance: [0x33; 16],
            account: 7,
        }
    }
    fn temp(tag: &str) -> std::path::PathBuf {
        let mut r = [0u8; 8];
        getrandom::getrandom(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!("fly-profile-{tag}-{}", u64::from_le_bytes(r)));
        fs::create_dir_all(&p).unwrap();
        p
    }
    fn same(a: &Secrets, b: &Secrets) -> bool {
        a.network == b.network
            && a.seed == b.seed
            && a.root == b.root
            && a.guard_wrap == b.guard_wrap
            && a.instance == b.instance
            && a.account == b.account
    }

    #[test]
    fn one_profile_wins_concurrent_creation() -> std::io::Result<()> {
        use std::sync::Barrier;
        for _ in 0..16 {
            let dir = temp("single-winner");
            let gate = Barrier::new(8);
            let results = std::thread::scope(|scope| {
                let mut jobs = Vec::new();
                for n in 0..8 {
                    let gate = &gate;
                    let dir = &dir;
                    jobs.push(scope.spawn(move || {
                        let contents = format!("fixture-{n}");
                        gate.wait();
                        (write_new(dir, &contents), contents)
                    }));
                }
                jobs.into_iter().map(|job| job.join().map_err(|_| io::Error::other("fixture thread")))
                    .collect::<io::Result<Vec<_>>>()
            })?;
            let actual = fs::read_to_string(dir.join(FILE))?;
            fs::remove_dir_all(dir)?;
            let winners: Vec<_> = results.iter().filter(|(result, _)| result.is_ok()).collect();
            assert_eq!(winners.len(), 1);
            assert!(winners.first().is_some_and(|(_, written)| written == &actual));
            assert!(results.iter().all(|(result, _)| matches!(result,
                Ok(()) | Err(ProfileError::Exists | ProfileError::Io(io::ErrorKind::WouldBlock)))));
        }
        Ok(())
    }

    #[test]
    fn a_profile_opens_with_its_password_only() {
        let dir = temp("open");
        assert_eq!(open(&dir, b"pw", 10).err(), Some(ProfileError::Missing));
        for len in [16, 20, 24, 28, 32] {
            let s = secrets(Network::Test, len);
            let text = seal(&s, b"correct horse", 10).unwrap();
            let _ = fs::remove_file(dir.join(FILE));
            write_new(&dir, &text).unwrap();
            assert!(same(&open(&dir, b"correct horse", 10).unwrap(), &s));
            assert_eq!(open(&dir, b"correct horsf", 10).err(), Some(ProfileError::WrongPassword));
        }
        assert_eq!(network(&dir).unwrap(), Network::Test);
        // a new profile never replaces one that is there
        let text = seal(&secrets(Network::Main, 32), b"other", 10).unwrap();
        assert_eq!(write_new(&dir, &text).err(), Some(ProfileError::Exists));
        assert!(open(&dir, b"correct horse", 10).is_ok());
        // a new password replaces the old one
        replace(&dir, &seal(&secrets(Network::Test, 32), b"next", 10).unwrap()).unwrap();
        assert_eq!(open(&dir, b"correct horse", 10).err(), Some(ProfileError::WrongPassword));
        assert!(open(&dir, b"next", 10).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn nothing_in_the_file_can_be_changed_without_the_password() {
        let dir = temp("bound");
        let s = secrets(Network::Test, 32);
        let text = seal(&s, b"pw", 11).unwrap();
        // the secrets are not in the file in any readable form
        for secret in [hex(&s.seed), hex(s.root.as_ref()), hex(s.guard_wrap.as_ref())] {
            assert!(!text.contains(&secret));
        }
        let put = |t: &str| fs::write(dir.join(FILE), t).unwrap();
        put(&text);
        assert!(open(&dir, b"pw", 10).is_ok());
        // the network in the clear is bound to the blob
        put(&text.replace("\"test\"", "\"main\""));
        assert_eq!(open(&dir, b"pw", 10).err(), Some(ProfileError::WrongPassword));
        // so is the cost of the key derivation
        put(&text.replace("\"log_n\": 11", "\"log_n\": 10"));
        assert_eq!(open(&dir, b"pw", 10).err(), Some(ProfileError::WrongPassword));
        // a file that asks for too little or too much work is refused unopened
        assert_eq!(open(&dir, b"pw", 11).err(), Some(ProfileError::Damaged("key derivation parameters")));
        put(&text.replace("\"log_n\": 11", "\"log_n\": 21"));
        assert_eq!(open(&dir, b"pw", 10).err(), Some(ProfileError::Damaged("key derivation parameters")));
        put(&text.replace("\"r\": 8", "\"r\": 1"));
        assert_eq!(open(&dir, b"pw", 10).err(), Some(ProfileError::Damaged("key derivation parameters")));
        // every byte of salt, nonce and blob matters
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        for field in ["salt", "nonce", "sealed"] {
            let old = v[field].as_str().unwrap();
            let flip = if old.starts_with('0') { "1" } else { "0" };
            let new = format!("{flip}{}", &old[1..]);
            put(&text.replace(old, &new));
            assert_eq!(open(&dir, b"pw", 10).err(), Some(ProfileError::WrongPassword), "{field}");
        }
        // not a profile at all, an unknown field, an oversized file
        put("{}");
        assert_eq!(open(&dir, b"pw", 10).err(), Some(ProfileError::Damaged("not a profile")));
        put(&text.replacen('{', "{\"extra\": 1,", 1));
        assert_eq!(open(&dir, b"pw", 10).err(), Some(ProfileError::Damaged("not a profile")));
        put(&format!("{text}{}", " ".repeat(9000)));
        assert_eq!(open(&dir, b"pw", 10).err(), Some(ProfileError::Damaged("too large")));
        // passwords
        assert_eq!(seal(&s, b"", 10).err(), Some(ProfileError::BadInput("password length")));
        assert_eq!(seal(&s, &[b'a'; 1025], 10).err(), Some(ProfileError::BadInput("password length")));
        assert_eq!(seal(&secrets(Network::Test, 17), b"pw", 10).err(), Some(ProfileError::BadInput("seed length")));
        fs::remove_dir_all(&dir).unwrap();
    }
}
