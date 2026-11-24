//! In-memory directory and guard with fault injection. **Test support only.**
//!
//! Models what a crash can do to files: data appended but not synced may be
//! lost, kept, cut at any byte, or replaced by zeros or garbage; files created
//! or removed without a directory sync may or may not survive. The guard
//! lives in the same simulated machine and is durable as soon as it is stored.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    missing_docs
)]

use crate::io::{Dir, Guard, GuardValue, Medium};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone, Default)]
struct SimFileData {
    /// Content as of the last sync.
    durable: Vec<u8>,
    /// Content as the running process sees it.
    current: Vec<u8>,
}

/// What happens to un-synced file data when the machine goes down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataLoss {
    /// Everything not synced is gone.
    LoseAll,
    /// Everything written survived.
    KeepAll,
    /// The first `n` un-synced appended bytes survived.
    Torn(usize),
    /// The file grew to its new size but holds zeros there.
    Zeros,
    /// The file grew to its new size but holds garbage there.
    Garbage,
}

/// Crash outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reboot {
    pub data: DataLoss,
    /// Whether file creations and removals not followed by a directory sync
    /// survived.
    pub keep_dir_changes: bool,
}

/// When an injected fault strikes, counted in mutating operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// The machine dies before operation `n` takes effect.
    CrashBefore(u64),
    /// The machine dies right after operation `n` took effect.
    CrashAfter(u64),
    /// Operation `n` fails with an error and has no effect; the machine lives.
    Fail(u64),
}

#[derive(Default)]
struct State {
    files: BTreeMap<String, SimFileData>,
    durable_names: BTreeSet<String>,
    /// Files removed since the last directory sync.
    removed: BTreeMap<String, SimFileData>,
    locked: bool,
    guard: Option<GuardValue>,
    ops: u64,
    fault: Option<Fault>,
    crashed: bool,
}

/// The simulated machine. Clone to share between handles.
#[derive(Clone, Default)]
pub struct Sim(Arc<Mutex<State>>);

/// Copy of the simulated disk (not of the guard), for rollback tests.
#[derive(Clone)]
pub struct DiskImage {
    files: BTreeMap<String, SimFileData>,
    durable_names: BTreeSet<String>,
}

fn dead() -> io::Error {
    io::Error::other("simulated crash")
}

impl Sim {
    pub fn new() -> Sim {
        Sim::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Run one mutating operation under the fault plan.
    fn op<T>(&self, f: impl FnOnce(&mut State) -> io::Result<T>) -> io::Result<T> {
        let mut s = self.state();
        if s.crashed {
            return Err(dead());
        }
        let n = s.ops;
        s.ops += 1;
        match s.fault {
            Some(Fault::CrashBefore(k)) if k == n => {
                s.crashed = true;
                Err(dead())
            }
            Some(Fault::Fail(k)) if k == n => Err(io::Error::other("simulated failure")),
            Some(Fault::CrashAfter(k)) if k == n => {
                let r = f(&mut s);
                s.crashed = true;
                r.and(Err(dead()))
            }
            _ => f(&mut s),
        }
    }

    fn read<T>(&self, f: impl FnOnce(&State) -> io::Result<T>) -> io::Result<T> {
        let s = self.state();
        if s.crashed {
            return Err(dead());
        }
        f(&s)
    }

    pub fn dir(&self) -> SimDir {
        SimDir(self.clone())
    }

    pub fn guard(&self) -> SimGuard {
        SimGuard(self.clone())
    }

    pub fn set_fault(&self, fault: Option<Fault>) {
        self.state().fault = fault;
    }

    /// Number of mutating operations performed so far.
    pub fn ops(&self) -> u64 {
        self.state().ops
    }

    pub fn crashed(&self) -> bool {
        self.state().crashed
    }

    /// Bring the machine back up after a crash (or simply drop all un-synced
    /// state, as a power cut would).
    pub fn reboot(&self, how: Reboot) {
        let mut s = self.state();
        let names: Vec<String> = s.files.keys().cloned().collect();
        for name in names {
            let durable_name = s.durable_names.contains(&name);
            if !durable_name && !how.keep_dir_changes {
                s.files.remove(&name);
                continue;
            }
            let f = s.files.get_mut(&name).unwrap();
            let appended = f.current.len() > f.durable.len() && f.current.starts_with(&f.durable);
            let after = match how.data {
                DataLoss::KeepAll => f.current.clone(),
                DataLoss::LoseAll => f.durable.clone(),
                _ if !appended => f.durable.clone(),
                DataLoss::Torn(n) => {
                    let end = (f.durable.len() + n).min(f.current.len());
                    f.current[..end].to_vec()
                }
                DataLoss::Zeros => {
                    let mut v = f.durable.clone();
                    v.resize(f.current.len(), 0);
                    v
                }
                DataLoss::Garbage => {
                    let mut v = f.current.clone();
                    for b in &mut v[f.durable.len()..] {
                        *b ^= 0xA5;
                    }
                    v
                }
            };
            f.durable = after.clone();
            f.current = after;
        }
        // removals without a directory sync come back with their durable content
        let removed = std::mem::take(&mut s.removed);
        if !how.keep_dir_changes {
            for (name, mut f) in removed {
                if s.durable_names.contains(&name) && !s.files.contains_key(&name) {
                    f.current = f.durable.clone();
                    s.files.insert(name, f);
                }
            }
        }
        s.durable_names = s.files.keys().cloned().collect();
        s.crashed = false;
        s.locked = false;
        s.fault = None;
    }

    pub fn disk_image(&self) -> DiskImage {
        let s = self.state();
        DiskImage {
            files: s.files.clone(),
            durable_names: s.durable_names.clone(),
        }
    }

    /// Replace the disk with an earlier image. The guard is not touched.
    pub fn restore_disk(&self, image: &DiskImage) {
        let mut s = self.state();
        s.files = image.files.clone();
        s.durable_names = image.durable_names.clone();
        s.removed.clear();
    }

    pub fn file(&self, name: &str) -> Option<Vec<u8>> {
        self.state().files.get(name).map(|f| f.current.clone())
    }

    /// Overwrite a file's content, durably.
    pub fn set_file(&self, name: &str, bytes: &[u8]) {
        let mut s = self.state();
        s.files.insert(
            name.to_owned(),
            SimFileData {
                durable: bytes.to_vec(),
                current: bytes.to_vec(),
            },
        );
        s.durable_names.insert(name.to_owned());
    }

    pub fn file_names(&self) -> Vec<String> {
        self.state().files.keys().cloned().collect()
    }

    pub fn guard_value(&self) -> Option<GuardValue> {
        self.state().guard
    }

    pub fn set_guard_value(&self, v: Option<GuardValue>) {
        self.state().guard = v;
    }
}

pub struct SimDir(Sim);
pub struct SimFile {
    sim: Sim,
    name: String,
}
pub struct SimLock(Sim);
pub struct SimGuard(Sim);

impl Drop for SimLock {
    fn drop(&mut self) {
        self.0.state().locked = false;
    }
}

fn missing() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "no such file")
}

impl Dir for SimDir {
    type File = SimFile;
    type Lock = SimLock;

    fn lock(&self) -> io::Result<SimLock> {
        let mut s = self.0.state();
        if s.crashed {
            return Err(dead());
        }
        if s.locked {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "locked"));
        }
        s.locked = true;
        Ok(SimLock(self.0.clone()))
    }

    fn list(&self) -> io::Result<Vec<String>> {
        self.0.read(|s| Ok(s.files.keys().cloned().collect()))
    }

    fn open(&self, name: &str) -> io::Result<SimFile> {
        self.0.read(|s| {
            if s.files.contains_key(name) {
                Ok(())
            } else {
                Err(missing())
            }
        })?;
        Ok(SimFile {
            sim: self.0.clone(),
            name: name.to_owned(),
        })
    }

    fn create_new(&self, name: &str) -> io::Result<SimFile> {
        self.0.op(|s| {
            if s.files.contains_key(name) {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "exists"));
            }
            s.files.insert(name.to_owned(), SimFileData::default());
            Ok(())
        })?;
        Ok(SimFile {
            sim: self.0.clone(),
            name: name.to_owned(),
        })
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        self.0.op(|s| {
            let f = s.files.remove(name).ok_or_else(missing)?;
            s.removed.entry(name.to_owned()).or_insert(f);
            Ok(())
        })
    }

    fn sync(&self) -> io::Result<()> {
        self.0.op(|s| {
            s.durable_names = s.files.keys().cloned().collect();
            s.removed.clear();
            Ok(())
        })
    }
}

impl Medium for SimFile {
    fn len(&mut self) -> io::Result<u64> {
        let name = self.name.clone();
        self.sim.read(|s| {
            s.files
                .get(&name)
                .map(|f| f.current.len() as u64)
                .ok_or_else(missing)
        })
    }

    fn read_all(&mut self) -> io::Result<Vec<u8>> {
        let name = self.name.clone();
        self.sim.read(|s| {
            s.files
                .get(&name)
                .map(|f| f.current.clone())
                .ok_or_else(missing)
        })
    }

    fn append(&mut self, data: &[u8]) -> io::Result<()> {
        let name = self.name.clone();
        self.sim.op(|s| {
            s.files
                .get_mut(&name)
                .ok_or_else(missing)?
                .current
                .extend_from_slice(data);
            Ok(())
        })
    }

    fn sync(&mut self) -> io::Result<()> {
        let name = self.name.clone();
        self.sim.op(|s| {
            let f = s.files.get_mut(&name).ok_or_else(missing)?;
            f.durable = f.current.clone();
            Ok(())
        })
    }

    fn truncate(&mut self, len: u64) -> io::Result<()> {
        let name = self.name.clone();
        self.sim.op(|s| {
            s.files
                .get_mut(&name)
                .ok_or_else(missing)?
                .current
                .truncate(len as usize);
            Ok(())
        })
    }
}

impl Guard for SimGuard {
    fn load(&self) -> io::Result<Option<GuardValue>> {
        self.0.read(|s| Ok(s.guard))
    }

    fn store(&self, value: &GuardValue) -> io::Result<()> {
        let v = *value;
        self.0.op(|s| {
            s.guard = Some(v);
            Ok(())
        })
    }
}
