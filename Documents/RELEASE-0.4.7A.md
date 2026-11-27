# GrinSight 0.4.7A

GrinSight can verify Grin headers from genesis on your device and save a checkpoint for future starts. To move a checkpoint, export it in Settings and select the resulting file on the second wallet. The checkpoint contains public chain data. Keep your recovery words separately.

**Windows portable upgrade from 0.4.6.** Close the wallet, replace the EXE in its original folder and reopen it with the same password. Keep the existing `data` folder. Your operation history and reserved outputs stay with the profile. A draft left unsigned before the upgrade retains its reserve and its previous signing session expires. Check that operation before starting a new exchange.

**First launch.** Pick English, Русский, Deutsch, Français, 简体中文, 한국어 or 日本語. Settings lets you change this later. Create a wallet or use **Restore from words**. The **?** beside the input shows how to separate recovery words. During verification, the wallet shows a yellow indicator. When it has caught up and the balance is ready, the connection and sync panel shows a green indicator and a readiness message. The badge above the balance and the badge in Details show the same verification status. You can enable automatic replies to authenticated messages from saved Nostr contacts. Incoming payments sent directly to the wallet’s Tor address ask for your approval.

**Downloads.** Windows x64 uses the portable EXE or the installer. On Linux x86-64, choose the Debian package, RPM or tar archive. The Android APK is for arm64 devices. The universal macOS DMG is intended for Intel and Apple silicon. Match the filename and the full hash from `SHA256SUMS.txt` before opening a download.

```powershell
Get-FileHash -Algorithm SHA256 .\GrinSight-0.4.7A-windows-x64-portable.exe
```

The source archive and the forward patch from 0.4.6 are included. See the [acceptance report](https://github.com/DanilaGrinRus/GrinSight/blob/v0.4.7A/Documents/BOOTSTRAP-0.4.7A-ACCEPT.md), [security review](https://github.com/DanilaGrinRus/GrinSight/blob/v0.4.7A/Documents/RELEASE-0.4.7A-SECURITY.md), [post-audit fixes and build checks (Russian)](https://github.com/DanilaGrinRus/GrinSight/blob/v0.4.7A/Documents/SOURCE-AUDIT-0.4.7A-FIXES.ru.md) and [заметки по-русски](https://github.com/DanilaGrinRus/GrinSight/blob/v0.4.7A/Documents/RELEASE_NOTES_RU.md).

The macOS package includes the wallet's Tor process. Bridge transports that require the separate Lyrebird helper are available in the Windows, Linux and Android packages.

Windows executables and Linux packages ship unsigned. The macOS app uses an ad-hoc signature and has no Apple notarization. The Android APK uses the same developer certificate as 0.4.6.
