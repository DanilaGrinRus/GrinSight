# GrinSight 0.4.2 — release notes

"Revelio for your coins" 🐻 — a light Grin wallet that verifies the chain itself.

## Files

| File | For |
|---|---|
| `GrinSight-0.4.2-windows-x64-setup.exe` | **installer** for Windows 10/11 x64, the signed mainnet checkpoint inside; no administrator rights needed |
| `GrinSight-0.4.2-android-arm64.apk` | Android 7+ (preview build), the same signed checkpoint inside |
| `GrinSight-0.4.2-linux-amd64.deb` | **Debian/Ubuntu** amd64 package (.deb), the same signed checkpoint inside; the app, launcher and Tor are included |
| `GrinSight-0.4.2-CHECKPOINT.txt` | which signed mainnet checkpoint is inside every package of this version (height, hash, SHA-256) |
| `GrinSight-0.4.2-source.zip` | source code: core, Tor/GlauxNet, C API, Flutter app, build scripts (no user data or secrets) |
| `SHA256SUMS.txt` | checksums of every file above |

The documents (how it works, mathematics, diagrams, dependencies) are in the repository, folder `Documents`.

**Check the download before running it** (PowerShell):

```powershell
Get-FileHash .\GrinSight-0.4.2-windows-x64-setup.exe -Algorithm SHA256
```

The hash must equal the line for that file in `SHA256SUMS.txt`.

## What's new in this version

- **Rangeproof root on every block (review follow-up).** The wallet keeps the rangeproof MMR
  peaks (from the archive segments, checked against range_proof_root) and checks them against
  each header's range_proof_root after every block; without them it fails. A 0.4.1 state is
  rebuilt once.
- **The source builds from the repository:** the release `.gitignore` hid
  `vendor/grin-5.5.2/p2p/src/build/build.rs`; fixed, and publishing now fails if any release
  file is hidden.
- **Chain checks on par with a full node (after an external review).** When it builds the
  state from the archive, the wallet now verifies every unspent output's rangeproof, every
  kernel signature, kernel_root and the emission sum (no inflated supply); a missing kernel
  segment is a failure, not a skip. Every block is checked for coinbase maturity (1440
  blocks), as in Grin. A state saved by an older version is rebuilt once (slower first sync).
- **New main screen.** Balance and verification status in one card (a single
  "PROVEN / NOT VERIFIED" line with Refresh); incoming amounts turn green only once
  confirmed. "My details": the wallet address and the Nostr search phrase copy on a tap.
  A log of warnings and errors where every entry has a "?" — what it means and what to do.
  "Incoming slatepacks" and "Messages" side by side; the columns line up.
- **More honest Tor:** "process running" and "connected to the network" are different
  states; until Tor connects, "Bridge settings" is right there. Tor is turned on and off
  separately from the messenger and closes together with the app (no leftover process).
- **Payment delivery as explicit buttons** Tor / Manual / GlauxMail. "Manual" lists every
  slatepack of the last payment (S1, S2, I1, I2) with Copy and Show.
- **The messenger can be turned off entirely;** message channels are a window with
  buttons Tor, Direct I2P, Nostr via I2P, Direct Nostr and the plain properties of each
  (is your IP visible, is a server needed, delivery while the contact is offline).
- **Header:** every action is an icon in one line, nothing hidden; "Try the future" is a
  switch. Settings keep only the name, password and seed phrase.
- **Style:** the bear in a hexagon, GrinSight, "Revelio for your coins"; a "B/W"
  monochrome theme in the spirit of grin.mw (pick it right on the sign-in screen); the logo
  and the button under the pointer stay black and gold.
- **Fixes:** signing in to wallets in the old format ("malformed"); "another wallet
  operation is running" when sending after Refresh; Refresh without an own checkpoint;
  a clear error when an address is pasted instead of a slatepack.

## What's inside

- **Verified light wallet:** headers from several public peers (PoW, difficulty,
  links, heaviest chain backed by peers from different networks), the unspent-output
  state rebuilt from PIBD segments and checked against `output_root`, every block to
  the tip checked against `output_root` / `kernel_root`. No node, no trusted server.
- **Signed checkpoint:** mainnet starts from a checkpoint signed with the key compiled
  into the wallet (height 4,098,960); a rollback to an older release is refused.
  A rolling checkpoint keeps later updates short (seconds).
- **Keys stay on the device:** the phrase (12, 18 or 24 words) is encrypted with your password
  (scrypt + ChaCha20-Poly1305) and passed to the core only in memory.
- **Payments:** send, receive, invoices (slatepack), automatic broadcast after
  finalizing, confirmation by kernel in a block of the verified chain (with reorg
  check), payment proof (receiver's signature).
- **Tor payments are compatible with grin-wallet and Grin++:** the first payment
  from a new sender is confirmed by hand.
- **Balance split:** available / reserved / incoming / immature.
- **GlauxNet (Windows):** your own encrypted mailbox runs while the wallet is open:
  a local store-and-forward gateway published as your Tor onion, so payments and
  invoices reach you with no third-party server. On by default, can be turned off in
  Settings; an optional backup GlauxNet server is used only when Tor cannot start.
  Automatic slatepack delivery to contacts, auto-accept policy.

## Verified on the live networks

- **Mainnet:** five transactions sent from the wallet were confirmed in mainnet blocks
  4,100,766 to 4,100,860.
- **Floonet:** install, updates and a proven balance; a payment of 1 tGRIN between two
  wallets through the app (S1 → S2 → finalize → broadcast), confirmed at depth 14 with
  a payment proof.
- Acceptance tests: core, verification, payment failure points, reorg, fuzzing,
  dependency advisories, an end-to-end test of the wallet service.

## Install

- **Windows:** run the installer, then GrinSight from the Start menu. Wallet data:
  `%APPDATA%\GrinSight` (kept when the program is uninstalled). The first
  "Update" builds the verified state (mainnet: about 670 MB to download, 10–20 minutes);
  later updates take seconds.
- **Android (preview build):** install the APK (allow installs from this source). Use Wi-Fi
  for the first update.
- **Linux (Debian/Ubuntu):** `sudo apt install ./GrinSight-0.4.2-linux-amd64.deb`,
  then GrinSight from the applications menu. Wallet data: `~/.grinsight`. The first
  "Update" is the same 10–20 minutes; later updates take seconds.

## Known limitations

- The monochrome theme is not remembered yet: after a restart the app is in colour again.
- "Turn messenger off" hides contacts and conversations in the interface; the messaging service keeps running.
- The full core acceptance suite was not re-run for this version; core unit tests (including new ones for coinbase maturity, emission and fail-closed kernels) PASS; app widget tests 148/148 PASS.
- A shipped checkpoint older than ~300 days: the wallet asks you to build your own ("Check myself").
- "Try the future" (header-proof) is experimental and does not affect verification yet.
- The web version (PWA) is not part of this release.
- Android: Tor delivery is not in every build yet; exchange slatepacks as text.
- The chain you see is the one your peers gave you and the wallet verified: several
  peers from different networks reduce, but do not exclude, isolation by dishonest peers
  (see `MATHEMATICS_EN.md`).
- No independent security audit yet.

## License

Code — MIT, documentation and diagrams — CC BY 4.0. Attribution to the author
(DanilaBear) is required. Third-party components: `NOTICE.md`.
