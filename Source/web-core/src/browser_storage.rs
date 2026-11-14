//! Browser `localStorage` bridge for small values (checkpoint, test state).
//!
//! This is deliberately not the final 670 MB state storage: IndexedDB/OPFS is
//! still required. It proves the `Storage` boundary can be backed by the host
//! without touching `std::fs`, and is enough for the checkpoint/selftest.

#[cfg(target_os = "emscripten")]
mod imp {
    use grinsight_state::storage::Storage;

    extern "C" {
        fn gs_ls_put(key: *const u8, klen: usize, value: *const u8, vlen: usize) -> i32;
        fn gs_ls_get(key: *const u8, klen: usize, out: *mut u8, cap: usize) -> i32;
        fn gs_ls_remove(key: *const u8, klen: usize) -> i32;
    }

    /// `localStorage` adapter. Keys are plain strings; values are bytes.
    pub struct BrowserStorage;

    impl Storage for BrowserStorage {
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
            let mut out = vec![0u8; 64 * 1024];
            let n = unsafe { gs_ls_get(key.as_ptr(), key.len(), out.as_mut_ptr(), out.len()) };
            if n < 0 {
                if n == -1 { Ok(None) } else { Err(format!("localStorage get error {n}")) }
            } else {
                out.truncate(n as usize);
                Ok(Some(out))
            }
        }
        fn put(&mut self, key: &str, data: &[u8]) -> Result<(), String> {
            let n = unsafe { gs_ls_put(key.as_ptr(), key.len(), data.as_ptr(), data.len()) };
            if n == 0 { Ok(()) } else { Err(format!("localStorage put error {n}")) }
        }
        fn remove(&mut self, key: &str) -> Result<(), String> {
            let n = unsafe { gs_ls_remove(key.as_ptr(), key.len()) };
            if n == 0 { Ok(()) } else { Err(format!("localStorage remove error {n}")) }
        }
        fn list_prefix(&self, _prefix: &str) -> Result<Vec<String>, String> {
            Err("localStorage list_prefix not implemented".into())
        }
    }
}

#[cfg(target_os = "emscripten")]
pub use imp::BrowserStorage;

