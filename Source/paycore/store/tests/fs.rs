//! The same store on real files.
use fly_paycore_store::{
    CommitError, FileGuard, FsDir, Guard, GuardCheck, GuardValue, Identity, OpenError, RootKey,
    Store,
};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

struct Temp(PathBuf);
impl Temp {
    fn new(tag: &str) -> Temp {
        let mut r = [0u8; 8];
        getrandom(&mut r);
        let p = std::env::temp_dir().join(format!("fly-paycore-{tag}-{}", u64::from_le_bytes(r)));
        fs::create_dir_all(p.join("os")).unwrap();
        Temp(p)
    }
    fn wallet(&self) -> PathBuf {
        self.0.join("wallet")
    }
    fn guard(&self) -> FileGuard {
        FileGuard::new(&self.0.join("os").join("guard"), [7u8; 32]).unwrap()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn getrandom(buf: &mut [u8]) {
    getrandom::getrandom(buf).unwrap();
}

fn id() -> Identity {
    Identity {
        network: 2,
        genesis: [1; 32],
        instance: [2; 16],
    }
}
fn key() -> RootKey {
    RootKey::new([3; 32])
}
fn dir(p: &Path) -> FsDir {
    FsDir::new(p).unwrap()
}

#[test]
fn real_files_roundtrip_checkpoint_and_torn_tail() {
    let t = Temp::new("roundtrip");
    let mut s = Store::create(dir(&t.wallet()), t.guard(), &key(), id()).unwrap();
    s.commit(1, b"alpha").unwrap();
    s.commit_sealed(2, b"bravo").unwrap();
    s.checkpoint(b"state one").unwrap();
    s.commit_sealed(2, b"charlie").unwrap();
    drop(s);

    let o = Store::open(dir(&t.wallet()), t.guard(), &key(), id()).unwrap();
    assert_eq!(o.guard, GuardCheck::Match);
    assert_eq!(
        o.snapshot.as_deref().map(|s| s.as_slice()),
        Some(&b"state one"[..])
    );
    assert_eq!(o.frames.len(), 1);
    assert_eq!(o.frames[0].body.as_slice(), b"charlie");
    drop(o);

    // an append that never completed: cut frame, then garbage
    let journal = t.wallet().join("journal-0000000000000001.fly");
    let good = fs::read(&journal).unwrap();
    for junk in [
        &[0x55u8, 0, 0, 0, 9, 9][..],
        &[0u8; 200][..],
        &[0xEEu8; 97][..],
    ] {
        let mut f = fs::OpenOptions::new().append(true).open(&journal).unwrap();
        f.write_all(junk).unwrap();
        drop(f);
        let mut o = Store::open(dir(&t.wallet()), t.guard(), &key(), id()).unwrap();
        assert_eq!(o.frames.len(), 1);
        assert_eq!(o.guard, GuardCheck::Match);
        drop(o.store.commit(1, b"probe"));
        drop(o);
        // the junk is gone from the file, the new frame follows the valid ones
        let now = fs::read(&journal).unwrap();
        assert!(now.starts_with(&good));
        fs::write(&journal, &good).unwrap();
        t.guard()
            .store(
                &Store::open(
                    dir(&t.wallet()),
                    FileGuard::new(&t.0.join("os").join("scratch"), [7u8; 32]).unwrap(),
                    &key(),
                    id(),
                )
                .unwrap()
                .store
                .tail(),
            )
            .unwrap();
    }

    // rollback of the directory to an earlier copy
    let o = Store::open(dir(&t.wallet()), t.guard(), &key(), id()).unwrap();
    drop(o);
    let backup = t.0.join("backup");
    fs::create_dir(&backup).unwrap();
    for e in fs::read_dir(t.wallet()).unwrap() {
        let e = e.unwrap();
        fs::copy(e.path(), backup.join(e.file_name())).unwrap();
    }
    let mut s = Store::open(dir(&t.wallet()), t.guard(), &key(), id())
        .unwrap()
        .store;
    s.commit_sealed(2, b"delta").unwrap();
    drop(s);
    for e in fs::read_dir(&backup).unwrap() {
        let e = e.unwrap();
        fs::copy(e.path(), t.wallet().join(e.file_name())).unwrap();
    }
    let mut o = Store::open(dir(&t.wallet()), t.guard(), &key(), id()).unwrap();
    assert_eq!(o.guard, GuardCheck::RolledBack);
    assert_eq!(
        o.store.commit_sealed(2, b"x").unwrap_err(),
        CommitError::RecoveryRequired
    );
}

#[test]
fn real_files_single_writer_and_permissions() {
    let t = Temp::new("lock");
    let s = Store::create(dir(&t.wallet()), t.guard(), &key(), id()).unwrap();
    assert!(matches!(
        Store::open(dir(&t.wallet()), t.guard(), &key(), id()),
        Err(OpenError::Locked)
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(t.wallet()), 0o700);
        assert_eq!(mode(t.wallet().join("journal-0000000000000000.fly")), 0o600);
    }
    drop(s);
    Store::open(dir(&t.wallet()), t.guard(), &key(), id()).unwrap();
}

#[test]
fn file_names_cannot_escape_the_directory() {
    use fly_paycore_store::Dir;
    let t = Temp::new("names");
    let d = dir(&t.wallet());
    for bad in [
        "../x",
        "a/b",
        "..",
        ".hidden",
        "",
        "A",
        "x\\y",
        "journal-0000000000000000.fly\0",
    ] {
        assert!(d.create_new(bad).is_err(), "{bad:?}");
        assert!(d.open(bad).is_err(), "{bad:?}");
        assert!(d.remove(bad).is_err(), "{bad:?}");
    }
}

/// The file guard: authenticated, replaced atomically, and a damaged file is
/// an error rather than "no guard".
#[test]
fn file_guard_authenticates_and_detects_rollback_of_the_wallet_directory() {
    let t = Temp::new("fileguard");
    let path = t.0.join("os").join("guard");
    let g = t.guard();
    assert_eq!(g.load().unwrap(), None);
    let v = GuardValue {
        next_seq: 42,
        tail: [9u8; 32],
    };
    g.store(&v).unwrap();
    assert_eq!(g.load().unwrap(), Some(v));
    let good = fs::read(&path).unwrap();
    assert_eq!(good.len(), 80);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // every single-byte change, every truncation and an extension are refused
    for i in 0..good.len() {
        let mut bad = good.clone();
        bad[i] ^= 1;
        fs::write(&path, &bad).unwrap();
        assert_eq!(
            g.load().unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "byte {i}"
        );
    }
    for n in 0..good.len() {
        fs::write(&path, &good[..n]).unwrap();
        assert_eq!(
            g.load().unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "len {n}"
        );
    }
    let mut long = good.clone();
    long.push(0);
    fs::write(&path, &long).unwrap();
    assert!(g.load().is_err());
    // another key does not accept the file; a stale temp file is harmless
    fs::write(&path, &good).unwrap();
    assert!(FileGuard::new(&path, [8u8; 32]).unwrap().load().is_err());
    fs::write(t.0.join("os").join("guard.tmp"), b"half").unwrap();
    assert_eq!(g.load().unwrap(), Some(v));
    let w = GuardValue {
        next_seq: 43,
        tail: [1u8; 32],
    };
    g.store(&w).unwrap();
    assert_eq!(g.load().unwrap(), Some(w));

    // the wallet directory is put back to an older copy; the guard is not
    let mut s = Store::create(dir(&t.wallet()), t.guard(), &key(), id()).unwrap();
    s.commit_sealed(2, b"one").unwrap();
    drop(s);
    let backup = t.0.join("backup");
    fs::create_dir_all(&backup).unwrap();
    for e in fs::read_dir(t.wallet()).unwrap() {
        let e = e.unwrap();
        fs::copy(e.path(), backup.join(e.file_name())).unwrap();
    }
    let mut o = Store::open(dir(&t.wallet()), t.guard(), &key(), id()).unwrap();
    assert_eq!(o.guard, GuardCheck::Match);
    o.store.commit_sealed(2, b"two").unwrap();
    drop(o);
    for e in fs::read_dir(&backup).unwrap() {
        let e = e.unwrap();
        fs::copy(e.path(), t.wallet().join(e.file_name())).unwrap();
    }
    let o = Store::open(dir(&t.wallet()), t.guard(), &key(), id()).unwrap();
    assert_eq!(o.guard, GuardCheck::RolledBack);
    // a damaged guard file stops the wallet from opening
    drop(o);
    fs::write(&path, b"garbage").unwrap();
    assert!(Store::open(dir(&t.wallet()), t.guard(), &key(), id()).is_err());
}
