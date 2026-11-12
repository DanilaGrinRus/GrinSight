# lmdb-master-sys 0.2.6 (patched)

Unmodified crates.io release 0.2.6 (archive SHA-256
aaeb9bd22e73bd1babffff614994b341e9b2008de7bb73bf1f7e9154f1978f8b, the checksum
in Cargo.lock before the patch), with ONE change in `build.rs`:

`advapi32` is linked when the TARGET is Windows (`CARGO_CFG_TARGET_OS`), not
when the build machine is Windows. Upstream used `#[cfg(target_os = "windows")]`
inside the build script, which tests the host: building for Android on a
Windows PC then failed with `ld.lld: unable to find library -ladvapi32`.

Nothing else differs; builds for Windows and Linux link exactly as before.
