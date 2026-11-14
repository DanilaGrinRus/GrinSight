# grinsight-tor — automatic slatepack exchange

One daemon per wallet (`run_user.ps1 -TorStart -Wallet N`, or started by
`grinsight-service`). It does no wallet math itself: receive / finalize /
broadcast are the GrinSight wallet executable (`reverse-wtema-header-sync`),
called as a subprocess.

Transports:

* **grin-wallet / Grin++ Tor foreign API** — onion derived from the wallet's
  slatepack address (the same onion grin-wallet and Grin++ use), `POST
  /v2/foreign`: `check_version`, `receive_tx`, `finalize_tx`. On this transport
  the sender is **not authenticated**: the address in the payment proof
  (`proof.saddr`) is only *claimed*.
* **GrinMessenger envelopes** — separate messenger key (HKDF from the phrase
  entropy, GrinMessenger's `derive_messaging_seed` salt), signed envelopes,
  direct over Tor/Arti, or through a store-and-forward relay (`-Relay URL`) when
  Tor does not come up. Here the sender is authenticated by the envelope
  signature.

## Address book (v2) and the acceptance policy

`<profile>\address-book.json`: `version` (2), `auto_accept`, `contacts`
(`id` = slatepack address, optional `messenger` address, `name`, `auto`).

A book without `version` is v1: on load, `auto_accept == "contacts"` (the old
default) becomes `"ask"` and the file is rewritten with `version: 2`; the modes
`off`/`all` the user set are left alone. A new book defaults to `ask`.

| auto_accept | contact with `auto=yes` | stranger |
|---|---|---|
| `off` | inbox | inbox |
| `ask` (default) | accept at once | **ask the user** |
| `contacts` | accept at once | inbox, no question |
| `all` | accept at once | accept at once |

A contact is found over the Tor foreign API by the **claimed** address
(`proof.saddr`) and over the messenger by the signature. Since v2 a claimed
address of a contact is trusted for automatic acceptance of a *payment* in
`ask`/`contacts`: the worst case is that someone names a contact and **sends us
money**, and the history shows it under that contact. The money is ours either
way. Invoices are different: an I1 is never paid automatically, in any mode
(audit rule, not a policy choice).

A payment without `proof.saddr` has no known sender: in `ask` the user is asked,
but "add to the address book" is not offered (there is nothing to add).

## Manual acceptance (`ask`)

`receive_tx` from a stranger in mode `ask`:

1. the request is written to `tor-wallet-N\pending\<slate_id>.json`
   (`slate_id, amount, fee, from, channel: "tor-foreign", received_at,
   expires_at, sender_verified: false`) with the S1 next to it
   (`<slate_id>.s1.json`);
2. the HTTP request is **held up to 40 s** (`GRINSIGHT_TOR_HOLD_SECS` only for
   tests) while the app watches `tor.status.pending_count` and the user answers;
   the decision is a file `tor-wallet-N\decisions\<slate_id>.json`
   (`{"slate_id","accept","add_contact","name"}`, written atomically);
3. "accept": the usual receive; the S2 goes back in the same HTTP answer; with
   `add_contact` the sender (`id`, `name`, `auto: yes`) is added to the book;
4. "decline": the answer is the JSON-RPC error `declined by the receiver`;
5. no decision in 40 s: the answer is `waiting for the receiver's confirmation;
   send a slatepack instead`, the S1 stays in the inbox with a `.meta.json`
   sidecar and can be received by hand later. grin-wallet does not cancel the
   transaction then: it gives the sender a slatepack fallback (`command.rs`,
   the `Err` branch after `try_slatepack_sync_workflow`).

Spam limits: at most **3** requests wait at once and at most **10** new
strangers per hour; over the limit the S1 goes to the inbox at once and the
connection is not held. Held requests are counted separately from
`MAX_CONNECTIONS`, so a waiting request never uses up all connection slots.

A messenger envelope from a stranger in mode `ask` takes the same `pending/`
path but nothing is held (there is no connection): when the user accepts, the
S2 goes back as a signed envelope (`<slate_id>.s2.txt` is kept until the
envelope is really sent). The sender address is authenticated by the signature,
so the contact is saved with its `messenger` address too. An unanswered
messenger request expires into the inbox after 24 h.

## Invoices over Tor

An I1 is never paid automatically: it is listed in the inbox. Paying it by hand
(`wallet.pay_invoice` → `tor.deliver`) builds the I2 and, when the issuer has a
slatepack address, delivers it over the issuer's Tor foreign API with
`finalize_tx` (the I2 as plain V4 JSON; the issuer finalizes and broadcasts and
answers with the I3). If the issuer is only reachable through the messenger the
I2 goes there; otherwise it is shown for manual handover.

## Files and status

* `outbox/` — requests from `queue` (payments and invoice answers);
* `sends/`, `replies/` — accepted outgoing requests, `.status` per slate;
* `inbox/` — S1/I1 not accepted automatically, with `<name>.meta.json`
  (`kind: payment|invoice, amount, fee, from, channel, received_at, slate_id`);
* `pending/`, `decisions/` — manual acceptance above (`strangers.log` is the
  hourly rate limit);
* `status.json` — `address`, `onion`, `foreign_api {address, onion}`,
  `pending_count`, `tor`, `messenger`, `glauxnet`, `policy`. The app reads it
  through `grinsight-service`'s `tor.status`.

## Compatibility and verification

The protocol is grin-wallet's own foreign API. The unit tests in
`grinsight-tor` replay the **exact doctest request/answer JSON of grin-wallet
5.5.1** (`api/src/foreign_rpc.rs`, commit f097811, fixtures in
`tests/fixtures/grin_wallet_5_5_1_foreign.json`) through `handle_foreign`:
`check_version`, `receive_tx` (the answer is compared with grin-wallet's
expected S2) and `finalize_tx` (the answer is the finalized I3). The
`header-sync/tests/tor_foreign_format.rs` test parses those answers with
`grin_wallet_libwallet::VersionedSlate` (the vendored crate) and round-trips our
own `slate_from_json`/`slate_to_json` through it. The policy table, the v1→v2
migration, the 40 s hold, the limits and the messenger retry have their own
tests.

Live floonet checks: `evidence\tor-compat-2026-11-12\REPORT_RU.md` — all **6 of 6**
scenarios passed with grin-wallet 5.5.1 and Grin++ 2.0.0 (incoming: manual
"yes", the second payment auto-accepted, timeout → slatepack fallback → manual
receive → finalize; outgoing with a payment proof; an invoice paid over Tor;
both directions Grin++ ↔ GrinSight over Tor). Incoming grin-wallet deliveries
need its **external** `tor.exe` (integrated Arti could not post the S1 to an
onion in that environment; the GrinSight onion itself answered `check_version`
200 through a normal Tor client). Grin++ 2.0.0 echoes the whole slate in its
compact S2 with its own element order; `finalize` therefore adds only the
elements that are really missing (adding our change twice produced `Fee Dispute
Error: 23500000, 34000000` before the fix).

Build: `cargo --config tor\vendor.toml build --offline --locked --release --manifest-path tor\Cargo.toml -p grinsight-tor`
(`vendor.toml` points the vendored source at `C:/DHW/vendor`; GrinSight's own
`.cargo\config.toml` already switches crates.io to the vendored source and offline).
