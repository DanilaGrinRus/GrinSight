Source: crates.io scrypt 0.9.0, checksum
`ba0aaf3911fff0d942c10a49779de7754699810fc7dbe3df515613b2ecc8195a`,
RustCrypto/password-hashes commit `70063ea675ee0d640a5fc8ce5cdd1f28f21f6fbe`,
path `scrypt`. The source and its existing test vectors retain the upstream
MIT OR Apache-2.0 licences included in this directory.

Research change: wrap only the B, V and T heap buffers in `zeroize::Zeroizing`.
This preserves the KDF algorithm. The local patch is scoped to the vault
research crate; it has not been verified merely by copying the source.
Unwinding/normal drop wipes these buffers; abort, power loss, stack temporaries,
allocator copies, and intermediate state in dependencies are not covered.
The vault research crate compiled offline and its RFC 7914 empty-input vector
passed on Windows in a release test. That vector alone is not a complete audit
or authorization for real seeds.
