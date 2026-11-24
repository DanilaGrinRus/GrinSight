# Pinned grin-wallet source

Rust source for `libwallet`, `config`, and `util` comes from upstream commit
`f097811ee953fc81be4e70435d6ef845b6b2e8c9` (v5.5.1). The 42 files under
their `src/` directories were compared byte-for-byte with that source. Only
manifest paths to the locally pinned Grin crates and the small workspace root
were changed. License is in `LICENSE`.

These unmodified upstream functions do not enforce Fly's wallet policy.
Signing, storage and broadcast require external controls before exposure.

## Local change: stateless receive (2026-11-21)

`libwallet/src` is no longer byte-identical to the pinned commit. Eight files
carry the libwallet part of the patch proposed upstream for
mimblewimble/grin-wallet#844 ("Add opt-in stateless receive"), applied
unmodified:

- `internal/keys.rs`: `stateless_receive_key_id`, `is_stateless_receive_key_id`,
  `output_parent_key_id`
- `internal/selection.rs`, `internal/tx.rs`: recipient output and signature
  built without the wallet database
- `api_impl/foreign.rs`: `receive_tx_stateless`
- `api_impl/types.rs`: `StatelessReceiveConfig`
- `internal/scan.rs`: outputs in the stateless range are filed under their
  account and do not move its child index
- `error.rs`: `ReceiveAmountTooLow`
- `lib.rs`: re-exports

`config` and `util` are unchanged; the upstream config switch
(`stateless_receive` in `grin-wallet.toml`) is not vendored because Fly does
not read that file. Existing functions, including `receive_tx`, behave as
before. If upstream merges the change in a different form, replace these
files with the merged version rather than keeping both.
