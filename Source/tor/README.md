# unity-tor — automatic slatepack exchange (RESEARCH / NOT VERIFIED)

One daemon per wallet (`run_user.ps1 -TorStart -Wallet N`). It does no wallet
math itself: receive / finalize / broadcast are the Unity wallet executable
(`reverse-wtema-header-sync`), called as a subprocess.

Transports:

* **grin-wallet Tor foreign API** — onion derived from the wallet's slatepack
  address (same onion grin-wallet / Grin++ use), `POST /v2/foreign`
  `check_version`, `receive_tx`, `finalize_tx`. Sender not authenticated: only
  the address claimed in the payment-proof request is known.
* **GrinMessenger envelopes** — separate messenger key (HKDF from the phrase
  entropy, GrinMessenger's `derive_messaging_seed` salt), signed envelopes,
  direct over Tor/Arti, or through a store-and-forward relay (`-Relay URL`) when
  Tor does not come up.

Address book: `evidence\user-mainnet\address-book.json`
(`auto_accept` = off | contacts | all; contact = slatepack address `id`,
optional `messenger` address, `auto` flag). Under `contacts` only a signed
messenger envelope from a contact with `auto` is received automatically; a
payment over the Tor foreign API only *claims* its sender address, so it is
never automatic under `contacts` (inbox, receive by hand). `all` accepts anyone.
Invoices are never paid automatically; refused payments are saved in
`tor-wallet-N\inbox`.

`grinmessenger/` holds copies of the GrinMessenger crates (MIT OR Apache-2.0,
https://github.com/DanilaGrinRus/GrinMessenger, 47e66ab): flint-messenger,
flint-tor-arti, flint-gateway (relay), flint-messenger-wallet. Changes:
`flint-messenger-wallet`: binaries removed; `ActiveTransport` now forwards
`fetch_signed` (without it a relay that requires a fetch proof — flint-relay's
default — answered 401 "fetch proof required"; worth fixing upstream).
Tests/examples removed. `Cargo.lock` = GrinMessenger's (same 552 crates).

Build: `cargo --config tor\vendor.toml build --offline --locked --release --manifest-path tor\Cargo.toml -p unity-tor`
(`vendor.toml` points the vendored source at `C:/DHW/vendor`; Unity's own
`.cargo\config.toml` already switches crates.io to the vendored source and offline).
