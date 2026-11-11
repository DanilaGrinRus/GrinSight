# GrinSight 0.1.0 — release notes

"Revelio for your coins" 🐻 — a light Grin wallet that verifies the chain itself.

## Files

| File | For |
|---|---|
| `GrinSight-0.1.0-windows-x64.zip` | **the app**, Windows 10/11 x64, ready to run with the signed mainnet checkpoint inside: unzip anywhere, run `grinsight.exe` |
| Android APK | coming soon |
| `GrinSight-0.1.0-documents.zip` | documents: how it works, mathematics, release notes, diagrams, list of dependencies with licenses |
| `GrinSight-0.1.0-source.zip` | source code: core, Tor/GlauxNet, C API, Flutter app, build scripts (no user data or secrets) |
| `SHA256SUMS.txt` | checksums of every file above |

**Check the download before running it** (PowerShell):

```powershell
Get-FileHash .\GrinSight-0.1.0-windows-x64.zip -Algorithm SHA256
```

The hash must equal the line for that file in `SHA256SUMS.txt`.

## What's inside

- **Verified light wallet:** headers from several public peers (PoW, difficulty,
  links, heaviest chain backed by peers from different networks), the unspent-output
  state rebuilt from PIBD segments and checked against `output_root`, every block to
  the tip checked against `output_root` / `kernel_root`. No node, no trusted server.
- **Signed checkpoint:** mainnet starts from a checkpoint signed with the key compiled
  into the wallet (height 4,095,360); a rollback to an older release is refused.
  A rolling checkpoint keeps later updates short (seconds).
- **Keys stay on the device:** the 24-word phrase is encrypted with your password
  (scrypt + ChaCha20-Poly1305) and passed to the core only in memory.
- **Payments:** send, receive, invoices (slatepack), automatic broadcast after
  finalizing, confirmation by kernel in a block of the verified chain (with reorg
  check), payment proof (receiver's signature).
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

- **Windows:** unzip, run `grinsight.exe`. Data: `%APPDATA%\GrinSight`. The first
  "Update" builds the verified state (mainnet: about 670 MB to download, 10–20 minutes);
  later updates take seconds.
- **Android (coming soon):** install the APK (allow installs from this source). Use Wi-Fi for the
  first update.

## Known limitations

- New wallets need a checkpoint less than ~34 days old; releases are refreshed monthly.
- Android: Tor delivery is not in every build yet; exchange slatepacks as text.
- The chain you see is the one your peers gave you and the wallet verified: several
  peers from different networks reduce, but do not exclude, isolation by dishonest peers
  (see `MATHEMATICS_EN.md`).
- No independent security audit yet.

## License

Code — MIT, documentation and diagrams — CC BY 4.0. Attribution to the author
(DanilaBear) is required. Third-party components: `NOTICE.md`.
