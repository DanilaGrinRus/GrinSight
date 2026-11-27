<p align="center"><b>English</b> · <a href="README.ru.md">Русский</a> · <a href="https://danilagrinrus.github.io/GrinSight/en/">Website</a></p>

# GrinSight 0.4.7A

GrinSight checks Grin headers, unspent outputs and the selected chain tip on your device. It works with standard public nodes. Verification from genesis also produces a local checkpoint you can export with its proof.

<p align="center">
  <img src="assets/readme/hero.png" width="100%" alt="GrinSight 0.4.6: a light Grin wallet that verifies the chain on your device. Below the title, the main window with sample values: balance, a verified tip, payments waiting for a signature.">
</p>

## Downloads

[Downloads for this version](https://github.com/DanilaGrinRus/GrinSight/releases/tag/v0.4.7A) · [SHA256SUMS.txt](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.7A/SHA256SUMS.txt) · [Source archive](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.7A/GrinSight-0.4.7A-source.zip)

## Wallet guide

- **Start**. Choose a language, then create a wallet or restore one. Windows portable keeps the profile in the data folder next to the EXE.
- **Restore**. Enter the recovery words in their original order. The ? next to the field shows an example. Choose a password for this device.
- **Check the status**. The status above the balance and in Details uses the same wallet observation. Yellow means verification is pending. Green VERIFIED means the wallet has completed its check.
- **Receive**. Share your receiving address or exchange a Slatepack manually. You can enable automatic replies to contacts in Settings.
- **Send**. Check the amount, fee and recipient before signing. The payment history shows the state of each operation.
- **Transfer a checkpoint**. Save the checkpoint and its proof as one file in Settings. The second wallet checks it before using it. Keep your recovery words separately.

## Evidence

The author reported Mainnet payments to another wallet, back and to the same wallet. The Windows upgrade test compared the receiving address, three operations, available funds, reserved outputs and a saved signed transaction across two opens.

The independent human cryptographic audit is still open. An imported checkpoint has a different trust basis from a full local check starting at genesis. If public witnesses or time checks are unavailable, Details shows the reason. Verify your download against the release file hashes.

[Release notes](Documents/RELEASE_NOTES_EN.md) · [Acceptance](Documents/BOOTSTRAP-0.4.7A-ACCEPT.md) · [Security review](Documents/RELEASE-0.4.7A-SECURITY.md)

## License

Free to use, change and share **with attribution to the author (DanilaBear)**: GrinSight's own code — [MIT](LICENSE); documentation and diagrams — [CC BY 4.0](LICENSE-DOCS.md); third-party components keep their own licenses — [NOTICE](NOTICE.md). The packages include the Slint toolkit under GPLv3, so **the packages as a whole are distributed under the GPL, version 3**; the source of each release is in its `source.zip`.
