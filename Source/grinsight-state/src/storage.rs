//! Storage boundary for the GrinSight core.
//!
//! The verifier currently uses files on desktop. The web build must never
//! assume a writable filesystem: IndexedDB/OPFS is supplied by the host and
//! exposed to Rust through this trait. `MemoryStorage` is the deterministic
//! implementation used by tests and the Wasm spike.

use std::collections::BTreeMap;

/// Key/value byte storage. Keys are opaque, slash-separated names chosen by the
/// core (e.g. `checkpoints/floonet/checkpoint.rwm`). Implementations must reject
/// traversal and must return data unchanged.
pub trait Storage {
    /// Read a value; `None` means the key does not exist.
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String>;
    /// Atomically create or replace a value.
    fn put(&mut self, key: &str, data: &[u8]) -> Result<(), String>;
    /// Remove a value; missing values are not an error.
    fn remove(&mut self, key: &str) -> Result<(), String>;
    /// List keys beginning with `prefix`, sorted.
    fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, String>;
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && !key.starts_with('/')
        && !key.contains('\\')
        && key.split('/').all(|part| !part.is_empty() && part != "." && part != "..")
}

/// In-memory storage. Used by tests and by the Wasm core until the JS host
/// supplies IndexedDB/OPFS.
#[derive(Default, Clone, Debug)]
pub struct MemoryStorage {
    map: BTreeMap<String, Vec<u8>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl Storage for MemoryStorage {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        if !valid_key(key) {
            return Err(format!("invalid storage key {key:?}"));
        }
        Ok(self.map.get(key).cloned())
    }
    fn put(&mut self, key: &str, data: &[u8]) -> Result<(), String> {
        if !valid_key(key) {
            return Err(format!("invalid storage key {key:?}"));
        }
        self.map.insert(key.to_string(), data.to_vec());
        Ok(())
    }
    fn remove(&mut self, key: &str) -> Result<(), String> {
        if !valid_key(key) {
            return Err(format!("invalid storage key {key:?}"));
        }
        self.map.remove(key);
        Ok(())
    }
    fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, String> {
        if prefix.contains('\\') || prefix.starts_with('/') {
            return Err(format!("invalid storage prefix {prefix:?}"));
        }
        Ok(self.map.keys().filter(|k| k.starts_with(prefix)).cloned().collect())
    }
}

/// Desktop filesystem implementation for the existing native flows.
/// Not compiled into the browser/Wasm core.
#[cfg(not(feature = "web"))]
pub struct FileStorage {
    root: std::path::PathBuf,
}

#[cfg(not(feature = "web"))]
impl FileStorage {
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        Self { root: root.into() }
    }
    fn path(&self, key: &str) -> Result<std::path::PathBuf, String> {
        if !valid_key(key) {
            return Err(format!("invalid storage key {key:?}"));
        }
        Ok(self.root.join(key))
    }
}

#[cfg(not(feature = "web"))]
impl Storage for FileStorage {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        let p = self.path(key)?;
        match std::fs::read(&p) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("read {}: {e}", p.display())),
        }
    }
    fn put(&mut self, key: &str, data: &[u8]) -> Result<(), String> {
        let p = self.path(key)?;
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        }
        let tmp = p.with_extension("tmp-write");
        std::fs::write(&tmp, data).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &p).map_err(|e| format!("rename {}: {e}", p.display()))?;
        Ok(())
    }
    fn remove(&mut self, key: &str) -> Result<(), String> {
        let p = self.path(key)?;
        match std::fs::remove_file(&p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("remove {}: {e}", p.display())),
        }
    }
    fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        let base = self.root.join(prefix);
        let dir = if base.is_dir() { base } else { self.root.clone() };
        fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) -> Result<(), String> {
            for e in std::fs::read_dir(dir).map_err(|e| format!("list {}: {e}", dir.display()))? {
                let e = e.map_err(|e| format!("list entry: {e}"))?;
                let p = e.path();
                if p.is_dir() {
                    walk(root, &p, out)?;
                } else if let Ok(rel) = p.strip_prefix(root) {
                    out.push(rel.to_string_lossy().replace('\\', "/"));
                }
            }
            Ok(())
        }
        walk(&self.root, &dir, &mut out)?;
        out.sort();
        out.retain(|k| k.starts_with(prefix));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_roundtrip_and_prefix() {
        let mut s = MemoryStorage::new();
        assert_eq!(s.get("a/b").unwrap(), None);
        s.put("a/b", b"x").unwrap();
        s.put("a/c", b"y").unwrap();
        s.put("z", b"z").unwrap();
        assert_eq!(s.get("a/b").unwrap(), Some(b"x".to_vec()));
        assert_eq!(s.list_prefix("a/").unwrap(), vec!["a/b", "a/c"]);
        s.remove("a/b").unwrap();
        assert_eq!(s.get("a/b").unwrap(), None);
    }

    #[test]
    fn checkpoint_roundtrip_in_memory() {
        grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Testnet);
        let checkpoint = include_str!("../../checkpoints/floonet/checkpoint.rwm");
        let mut s = MemoryStorage::new();
        s.put("checkpoints/floonet/checkpoint.rwm", checkpoint.as_bytes()).unwrap();
        let v = crate::headers::load_checkpoint_storage(
            &s, "checkpoints/floonet/checkpoint.rwm", None).unwrap();
        assert_eq!(v.tip.height, 3_318_854);
        crate::headers::write_checkpoint_storage(
            &mut s, "checkpoints/copy.rwm", &v).unwrap();
        let copy = s.get("checkpoints/copy.rwm").unwrap().unwrap();
        assert_eq!(String::from_utf8(copy).unwrap(), checkpoint);
    }

    #[test]
    fn keys_cannot_escape() {
        let mut s = MemoryStorage::new();
        for k in ["", "/x", "../x", "a//b", "a/../b", "a\\b"] {
            assert!(s.put(k, b"x").is_err(), "key {k:?} must be rejected");
        }
    }
}
