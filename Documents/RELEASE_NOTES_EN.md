# GrinSight 0.2.0 — release notes

"Revelio for your coins" 🐻 — a light Grin wallet that verifies the chain itself.

## Files

| File | For |
|---|---|
| `GrinSight-0.2.0-windows-x64-setup.exe` | **installer** for Windows 10/11 x64, the signed mainnet checkpoint inside; no administrator rights needed |
| `GrinSight-0.2.0-android-arm64.apk` | Android 7+ (preview build), the same signed checkpoint inside |
| `GrinSight-0.2.0-CHECKPOINT.txt` | which signed mainnet checkpoint is inside every package of this version (height, hash, SHA-256) |
| `GrinSight-0.2.0-source.zip` | source code: core, Tor/GlauxNet, C API, Flutter app, build scripts (no user data or secrets) |
| `SHA256SUMS.txt` | checksums of every file above |

The documents (how it works, mathematics, diagrams, dependencies) are in the repository, folder `Documents`.

**Check the download before running it** (PowerShell):

```powershell
Get-FileHash .\GrinSight-0.2.0-windows-x64-setup.exe -Algorithm SHA256
```

The hash must equal the line for that file in `SHA256SUMS.txt`.

## What's new in this version

- **Check the checkpoint yourself — before signing in.** "Check myself" downloads every
  header from the first block from independent nodes, checks each one, builds a fresh
  checkpoint and checks that the shipped one is on the same chain. Wallets switch to it
  by themselves, so a wallet works even with an outdated shipped checkpoint.
- **An aging checkpoint no longer breaks the wallet.** A new wallet used to stop opening
  about two weeks after the checkpoint was cut; now it is about a year. Release policy:
  a checkpoint at most 90 days old.
- **A balance is shown as proven only when it is:** the balance file is checked by a MAC
  keyed with your seed and must describe the same tip (height and block hash) as the
  proof; a lost reservations journal is reported too.
- **History after a reorg:** blocks of recent payments are re-checked on every update;
  without that a payment shows "not re-checked", never "confirmed".
- **Seed phrase of 12, 18 or 24 words** (compatible with grin-wallet and Grin++), check of
  two random words; show seed and change password; rename a wallet.
- **Interface:** one "Verification" window with status, checkpoint and own peer; compact
  Send and Receive, QR from an image file, incoming payments on the main screen, address
  book search and own contact names, Enter to sign in.
- **"Try the future"** is marked honestly as an experiment: header-proof verification is
  not wired in yet, the balance is checked the usual way.

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

## Known limitations

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
