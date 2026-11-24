//! The OS-keyed guard with a stand-in for the platform, and with DPAPI on
//! Windows.
use fly_paycore_guard_os::{OpenError, Origin, OsGuard, Protector};
use fly_paycore_store::{FsDir, Guard, GuardCheck, GuardValue, Identity, RootKey, Store};
use std::cell::RefCell;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

struct Temp(PathBuf);
impl Temp {
    fn new(tag: &str) -> Temp {
        let mut r = [0u8; 8];
        getrandom::getrandom(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!("fly-guard-os-{tag}-{}", u64::from_le_bytes(r)));
        fs::create_dir_all(p.join("os")).unwrap();
        Temp(p)
    }
    fn os(&self) -> PathBuf {
        self.0.join("os")
    }
    fn wallet(&self) -> PathBuf {
        self.0.join("wallet")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Stands in for the platform: wraps with a per-"machine" secret and a
/// checksum, and remembers the secrets it was shown.
struct Machine {
    secret: u8,
    seen: RefCell<Vec<Vec<u8>>>,
    broken: bool,
}
impl Machine {
    fn new(secret: u8) -> Machine {
        Machine {
            secret,
            seen: RefCell::new(vec![]),
            broken: false,
        }
    }
    fn sum(&self, body: &[u8]) -> u8 {
        body.iter()
            .fold(self.secret, |a, b| a.wrapping_mul(31).wrapping_add(*b))
    }
}
impl Protector for Machine {
    fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
        self.seen.borrow_mut().push(plain.to_vec());
        let mut out: Vec<u8> = plain.iter().map(|b| b ^ self.secret ^ 0x5A).collect();
        if self.broken {
            out.reverse();
        }
        let sum = self.sum(&out);
        out.push(sum);
        out.push(self.secret.wrapping_mul(7));
        Ok(out)
    }
    fn unprotect(&self, blob: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let denied = || io::Error::new(io::ErrorKind::PermissionDenied, "not ours");
        let (owner, rest) = blob.split_last().ok_or_else(denied)?;
        let (sum, body) = rest.split_last().ok_or_else(denied)?;
        if *owner != self.secret.wrapping_mul(7) || *sum != self.sum(body) {
            return Err(denied());
        }
        Ok(Zeroizing::new(
            body.iter().map(|b| b ^ self.secret ^ 0x5A).collect(),
        ))
    }
}

fn value(n: u64) -> GuardValue {
    GuardValue {
        next_seq: n,
        tail: [n as u8; 32],
    }
}
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}
fn files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<(String, Vec<u8>)> = fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    v.sort();
    v
}

#[test]
fn key_is_created_once_and_never_stored_in_the_clear() {
    let t = Temp::new("create");
    let m = Machine::new(11);
    let (g, origin) = OsGuard::open(&t.os(), &m).unwrap();
    assert_eq!(origin, Origin::Created);
    assert_eq!(g.load().unwrap(), None);
    g.store(&value(5)).unwrap();
    assert_eq!(g.load().unwrap(), Some(value(5)));
    drop(g);

    let key = m.seen.borrow().first().cloned().unwrap();
    assert_eq!(key.len(), 32);
    assert!(key.iter().any(|b| *b != 0), "the key is not random");
    let on_disk = files(&t.os());
    assert_eq!(on_disk.len(), 2, "{:?}", on_disk.iter().map(|f| &f.0).collect::<Vec<_>>());
    for (name, bytes) in &on_disk {
        assert!(!contains(bytes, &key), "{name} holds the key in the clear");
        assert!(!contains(bytes, &key[..8]), "{name} holds part of the key");
    }

    // the same machine opens the same key and reads the same value
    let (g, origin) = OsGuard::open(&t.os(), &m).unwrap();
    assert_eq!(origin, Origin::Existing);
    assert_eq!(g.load().unwrap(), Some(value(5)));
    assert_eq!(m.seen.borrow().len(), 1, "a second key was made");
    g.store(&value(6)).unwrap();
    let (g, _) = OsGuard::open(&t.os(), &m).unwrap();
    assert_eq!(g.load().unwrap(), Some(value(6)));

    // two guards never share a key
    let t2 = Temp::new("create2");
    let m2 = Machine::new(11);
    OsGuard::open(&t2.os(), &m2).unwrap();
    assert_ne!(m2.seen.borrow().first().cloned().unwrap(), key);
}

#[test]
fn a_profile_from_another_machine_is_reported_and_left_untouched() {
    let t = Temp::new("foreign");
    let home = Machine::new(11);
    let (g, _) = OsGuard::open(&t.os(), &home).unwrap();
    g.store(&value(9)).unwrap();
    drop(g);
    let before = files(&t.os());

    let elsewhere = Machine::new(12);
    assert!(matches!(
        OsGuard::open(&t.os(), &elsewhere),
        Err(OpenError::Foreign)
    ));
    assert_eq!(files(&t.os()), before, "a refused open changed the files");
    assert!(elsewhere.seen.borrow().is_empty(), "a key was made silently");
    // at home everything still works
    let (g, origin) = OsGuard::open(&t.os(), &home).unwrap();
    assert_eq!((origin, g.load().unwrap()), (Origin::Existing, Some(value(9))));
    drop(g);

    // the host decides to start over on the new machine
    let (g, origin) = OsGuard::reset(&t.os(), &elsewhere).unwrap();
    assert_eq!(origin, Origin::Reset);
    assert_eq!(g.load().unwrap(), None, "the old value must not be trusted");
    g.store(&value(1)).unwrap();
    drop(g);
    let (g, origin) = OsGuard::open(&t.os(), &elsewhere).unwrap();
    assert_eq!((origin, g.load().unwrap()), (Origin::Existing, Some(value(1))));
    assert!(matches!(
        OsGuard::open(&t.os(), &home),
        Err(OpenError::Foreign)
    ));
}

#[test]
fn damaged_key_files_are_refused_without_panic() {
    let t = Temp::new("damaged");
    let m = Machine::new(11);
    let (g, _) = OsGuard::open(&t.os(), &m).unwrap();
    g.store(&value(3)).unwrap();
    drop(g);
    let path = t.os().join("guard.key");
    let good = fs::read(&path).unwrap();
    let made = m.seen.borrow().len();

    let check = |bytes: &[u8], what: &str| {
        fs::write(&path, bytes).unwrap();
        match OsGuard::open(&t.os(), &m) {
            Err(OpenError::Damaged) | Err(OpenError::Foreign) => {}
            Ok(_) => panic!("{what}: accepted"),
            Err(OpenError::Io(e)) => panic!("{what}: {e}"),
        }
    };
    for i in 0..good.len() {
        let mut bad = good.clone();
        bad[i] ^= 1;
        check(&bad, &format!("byte {i}"));
    }
    for n in 0..good.len() {
        check(&good[..n], &format!("length {n}"));
    }
    let mut long = good.clone();
    long.push(0);
    check(&long, "one byte longer");
    check(&vec![0xAB; 1 << 20], "a megabyte of noise");
    let mut huge = b"FLYGKW01".to_vec();
    huge.extend_from_slice(&u32::MAX.to_le_bytes());
    check(&huge, "length field of four gigabytes");
    let mut zero = b"FLYGKW01".to_vec();
    zero.extend_from_slice(&0u32.to_le_bytes());
    check(&zero, "empty blob");
    assert_eq!(m.seen.borrow().len(), made, "a damaged file led to a new key");

    fs::write(&path, &good).unwrap();
    let (g, origin) = OsGuard::open(&t.os(), &m).unwrap();
    assert_eq!((origin, g.load().unwrap()), (Origin::Existing, Some(value(3))));
    // a changed value file is an error, not "no value"
    let dat = files(&t.os())
        .into_iter()
        .find(|f| f.0.ends_with(".dat"))
        .unwrap();
    let mut bad = dat.1.clone();
    bad[20] ^= 1;
    fs::write(t.os().join(&dat.0), &bad).unwrap();
    assert_eq!(g.load().unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[test]
fn a_key_that_would_not_open_again_is_never_relied_on() {
    let t = Temp::new("roundtrip");
    let mut m = Machine::new(11);
    m.broken = true;
    assert!(matches!(OsGuard::open(&t.os(), &m), Err(OpenError::Io(_))));
    assert!(files(&t.os()).is_empty(), "a useless key was written");
}

fn id() -> Identity {
    Identity {
        network: 2,
        genesis: [1; 32],
        instance: [2; 16],
    }
}

/// End to end with the journal: the wallet directory and the guard directory
/// arrive on another machine; after the host resets the key the store sees a
/// journal without a guard and demands recovery.
#[test]
fn a_moved_wallet_requires_recovery() {
    let t = Temp::new("moved");
    let root = RootKey::new([3; 32]);
    let home = Machine::new(11);
    let (g, _) = OsGuard::open(&t.os(), &home).unwrap();
    let mut s = Store::create(FsDir::new(&t.wallet()).unwrap(), g, &root, id()).unwrap();
    s.commit_sealed(2, b"one").unwrap();
    drop(s);
    let (g, _) = OsGuard::open(&t.os(), &home).unwrap();
    let o = Store::open(FsDir::new(&t.wallet()).unwrap(), g, &root, id()).unwrap();
    assert_eq!(o.guard, GuardCheck::Match);
    drop(o);

    let elsewhere = Machine::new(12);
    assert!(matches!(
        OsGuard::open(&t.os(), &elsewhere),
        Err(OpenError::Foreign)
    ));
    let (g, _) = OsGuard::reset(&t.os(), &elsewhere).unwrap();
    let o = Store::open(FsDir::new(&t.wallet()).unwrap(), g, &root, id()).unwrap();
    assert_eq!(o.guard, GuardCheck::Missing);
    assert!(o.guard.recovery_required());
}

#[cfg(windows)]
mod windows {
    use super::*;
    use fly_paycore_guard_os::Dpapi;

    #[test]
    fn dpapi_wraps_for_this_user_and_refuses_altered_blobs() {
        let secret = [0x6Bu8; 32];
        let blob = Dpapi.protect(&secret).unwrap();
        assert!(blob.len() > secret.len());
        assert!(!contains(&blob, &secret), "the blob holds the secret in the clear");
        assert_eq!(Dpapi.unprotect(&blob).unwrap().as_slice(), &secret);
        // wrapping twice gives different blobs that both open
        let again = Dpapi.protect(&secret).unwrap();
        assert_ne!(again, blob);
        assert_eq!(Dpapi.unprotect(&again).unwrap().as_slice(), &secret);
        // altered, truncated and foreign data are refused, never a panic
        let mut refused = 0;
        for i in (0..blob.len()).step_by(7) {
            let mut bad = blob.clone();
            bad[i] ^= 0x40;
            match Dpapi.unprotect(&bad) {
                Err(_) => refused += 1,
                Ok(plain) => assert_eq!(plain.as_slice(), &secret, "byte {i} changed the secret"),
            }
        }
        assert!(refused > 0, "no altered blob was refused");
        assert!(Dpapi.unprotect(&blob[..blob.len() / 2]).is_err());
        assert!(Dpapi.unprotect(&[]).is_err());
        assert!(Dpapi.unprotect(&[0u8; 64]).is_err());
    }

    #[test]
    fn os_guard_on_dpapi() {
        let t = Temp::new("dpapi");
        let (g, origin) = OsGuard::open(&t.os(), &Dpapi).unwrap();
        assert_eq!(origin, Origin::Created);
        assert_eq!(g.load().unwrap(), None);
        g.store(&value(7)).unwrap();
        drop(g);
        let (g, origin) = OsGuard::open(&t.os(), &Dpapi).unwrap();
        assert_eq!((origin, g.load().unwrap()), (Origin::Existing, Some(value(7))));
        drop(g);

        // a key wrapped by something else is foreign to DPAPI
        let key_file = t.os().join("guard.key");
        let good = fs::read(&key_file).unwrap();
        let mut bad = good.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        bad[last / 2] ^= 0xFF;
        fs::write(&key_file, &bad).unwrap();
        assert!(matches!(
            OsGuard::open(&t.os(), &Dpapi),
            Err(OpenError::Foreign) | Err(OpenError::Damaged)
        ));
        let (g, origin) = OsGuard::reset(&t.os(), &Dpapi).unwrap();
        assert_eq!((origin, g.load().unwrap()), (Origin::Reset, None));

        // with the journal
        let root = RootKey::new([3; 32]);
        let mut s = Store::create(FsDir::new(&t.wallet()).unwrap(), g, &root, id()).unwrap();
        s.commit_sealed(2, b"one").unwrap();
        drop(s);
        let (g, _) = OsGuard::open(&t.os(), &Dpapi).unwrap();
        let o = Store::open(FsDir::new(&t.wallet()).unwrap(), g, &root, id()).unwrap();
        assert_eq!(o.guard, GuardCheck::Match);
    }
}
