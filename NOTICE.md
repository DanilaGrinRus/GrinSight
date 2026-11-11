# Third-party components

GrinSight's own code is MIT (see `LICENSE`). It is built on, and ships, the
following components under their own licenses; their notices are kept in the
source package (`vendor/`, `tor/grinmessenger/`, and each crate's metadata).

| Component | Used for | License |
|---|---|---|
| Grin 5.5.2 (`grin_core`, `grin_chain`, `grin_p2p`, `grin_keychain`, `grin_util`, …) | consensus rules, P2P, keys | Apache-2.0 |
| grin-wallet `libwallet` | slatepack, slates | Apache-2.0 |
| secp256k1-zkp (`grin_secp256k1zkp`) | commitments, rangeproofs, signatures | CC0-1.0 / MIT |
| GrinMessenger (`flint-*` crates) | messenger envelopes, relay | MIT OR Apache-2.0 |
| Arti (Tor in Rust) | Tor, onion services | MIT OR Apache-2.0 |
| CRoaring, LMDB (`lmdb-master-sys`, patched build script), SQLite | bitmaps, storage | Apache-2.0 / OpenLDAP Public License / public domain |
| Flutter and Dart packages | user interface | BSD-3-Clause and the packages' licenses |
| Rust crates (full list with versions: `DEPENDENCIES.txt` in the release) | | their own licenses |
