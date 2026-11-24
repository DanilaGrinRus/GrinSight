# Third-party components

GrinSight's own code is MIT (see `LICENSE`). It is built on, and ships, the
following components under their own licenses; their notices are kept in the
source package and in each crate's metadata. Because the packages include
Slint under GPLv3, **the packages as a whole are distributed under the GNU
General Public License, version 3**; the license text is inside every package.

| Component | Used for | License |
|---|---|---|
| Slint | the window | GPL-3.0-only (one of Slint's three licenses) |
| Grin (`grin_core`, `grin_chain`, `grin_p2p`, `grin_keychain`, `grin_util`, …) | consensus rules, P2P, keys | Apache-2.0 |
| grin-wallet `libwallet` | Slatepack, slates | Apache-2.0 |
| secp256k1-zkp (`grin_secp256k1zkp`) | commitments, rangeproofs, signatures | CC0-1.0 / MIT |
| Arti (Tor in Rust) | Tor for transactions and delivery | MIT OR Apache-2.0 |
| rust-nostr (`nostr-sdk`, `nostr-relay-pool`, patched copies) | delivery over Nostr | MIT |
| CRoaring, LMDB (`lmdb-master-sys`, patched build script), SQLite | bitmaps and storage inside third-party crates | Apache-2.0 / OpenLDAP Public License / public domain |
| Inter, DejaVu Sans Mono | fonts of the window | SIL OFL 1.1 / Bitstream Vera license |
| Other Rust crates (versions: the `Cargo.lock` files in the source) | | their own licenses |
