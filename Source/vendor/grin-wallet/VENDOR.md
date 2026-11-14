# Vendored grin-wallet crates (libwallet, util, config)

Source: https://github.com/mimblewimble/grin-wallet, commit f097811 (2026-10-11), version 5.5.1. License: Apache-2.0 (LICENSE).

Changes: (1) the Grin crate paths in the three `Cargo.toml` files point to `../../grin-5.5.2/...` (the node crates vendored next to this folder) instead of the `grin` git submodule. `libwallet/tests` removed. (2) `libwallet/src/lib.rs` also exports `PaymentInfo` (to request a payment proof when sending).

Used by `header-sync/src/receive.rs` for slatepack decoding/encryption, the v4 slate and the receiver's signature steps (the same code grin-wallet runs in `api_impl::foreign::receive_tx`).
