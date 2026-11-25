GrinSight is a light wallet for [Grin](https://grin.mw). It needs no full node of its own: it checks the header chain from a built-in point to the tip, confirms the tip with public nodes, collects and verifies the state its outputs depend on, and sends transactions through its own Tor.

0.4.4 is the same wallet as 0.4.3 with a reworked window: more is said on the main screen, Tor and Nostr can be switched off, and a signed payment that Tor did not send no longer hangs without a way out. It uses the same wallet folder as 0.4.3, and the wallet file format did not change. It is a research wallet. Nothing here is signed, and **the code added since 0.4.3 has not been through the external review rounds that 0.4.3 went through**; what has never been run outside tests is listed under [Not checked yet](#not-checked-yet).

## Download

| System | File | Size |
|---|---|---|
| **Windows 10/11 x64** — installer, no administrator rights | [GrinSight-0.4.4-windows-x64-setup.exe](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.4/GrinSight-0.4.4-windows-x64-setup.exe) | 31.1 MB |
| **Windows x64** — portable, one file | [GrinSight-0.4.4-windows-x64-portable.exe](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.4/GrinSight-0.4.4-windows-x64-portable.exe) | 45.6 MB |
| **Linux** — Debian 10+, Ubuntu 20.04+ | [GrinSight-0.4.4-linux-amd64.deb](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.4/GrinSight-0.4.4-linux-amd64.deb) | 33.4 MB |
| **Linux** — Fedora, RHEL 8+, openSUSE | [GrinSight-0.4.4-linux-x86_64.rpm](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.4/GrinSight-0.4.4-linux-x86_64.rpm) | 48.6 MB |
| **Linux** — any with glibc 2.28+, Arch | [GrinSight-0.4.4-linux-x86_64.tar.gz](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.4/GrinSight-0.4.4-linux-x86_64.tar.gz) | 48.8 MB |
| **Android 8+** (arm64) | [GrinSight-0.4.4-android-arm64.apk](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.4/GrinSight-0.4.4-android-arm64.apk) | 50.7 MB |
| **macOS 11+** — Apple silicon and Intel, without Tor bridges | [GrinSight-0.4.4-macos-universal.dmg](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.4/GrinSight-0.4.4-macos-universal.dmg) | 91.3 MB |

The files are not signed: the checksum is the only way to know you have the file published here. Windows will warn about an unknown publisher; the APK carries a debug key and installs by sideloading.

```text
78b659260c646df1ff56519998a8f4932c41a5d88bc3a7c1d7d1886e33c80a35  GrinSight-0.4.4-android-arm64.apk
949c380cb21f9abdbceea97b2d98917734663b2f22679962e6650aa475bafd9c  GrinSight-0.4.4-linux-amd64.deb
d727813d150b6c10aac1c879a396d97711a83c64261b6d1a0eabae55ab3d99cb  GrinSight-0.4.4-linux-x86_64.rpm
bcc6ed136e6e52aa3c70615befc8e594f1bfb8a57f93d5ab4c4e117c2769fff2  GrinSight-0.4.4-linux-x86_64.tar.gz
038e80626192b81b03d358e8074c0268089a0678b4f5a29439d9e076e8fd00a9  GrinSight-0.4.4-macos-universal.dmg
dcc036b194b24f465f118ead8b424ed6a21360c4581005b361604f0af9025cb0  GrinSight-0.4.4-source.zip
6efef43ddff4e0cb1526f3cf8b15fdaa98ff6c8511c4292d9771cceb589ca119  GrinSight-0.4.4-windows-x64-portable.exe
a49aad0919e2322a2754b2d6305f13dcfeaf51b1530b964ca571dd766365da07  GrinSight-0.4.4-windows-x64-setup.exe
```

```powershell
Get-FileHash .\GrinSight-0.4.4-windows-x64-setup.exe -Algorithm SHA256
```

```sh
sha256sum --check --ignore-missing SHA256SUMS.txt
```

## What changed since 0.4.3

**A payment that is signed but did not go out**

- When Tor does not come up, the signed payment appears under *Waiting for you* with three ways out: wait and send through Tor again; send this one payment directly (the wallet asks first, the consent is for that payment only, the others still wait for Tor); or switch Tor off for all payments.
- A signed payment that waits for a block can be sent to the network again from its own window.

**Tor and Nostr can be switched off**

- Two switches, on the login screen and in an open wallet. A part that is switched off is not started at all. Without Tor, transactions go to the network directly and the window says in the warning colour that the node sees your address; messages and the `grin1…` address do not work without Tor and are shown as such, not as broken. Switching in an open wallet locks it and asks for the password again.

**Every payment keeps its texts and shows its confirmations**

- The Slatepack texts the wallet made for a payment — the request, the final signed text, your reply to an incoming payment — can be shown again from *Recent payments* and from *All payments*; the reply is now kept by the wallet and survives a restart.
- A payment in a block shows how many confirmations it has. How many make an incoming payment "received" is your choice, from 1 up (10 until you choose); it changes the word shown and nothing about what can be spent.
- While the wallet catches up with the tip, a payment that is already in a block is no longer shown as unconfirmed.

**The window**

- The stages of synchronisation are listed in order in the *Connection and synchronisation* card, each with its mark; Tor that is still starting is not shown as broken. The marks have the same colours in every theme: green — done, blue ring — under way, amber — needs attention, grey ring — not used.
- Details are behind a "?" next to each item instead of long text on the screen; the options on the login screen now fit a phone screen.
- The main screen on a wide window ends on one line at the bottom, with nothing removed.
- *Password and words* is in the top bar. It now shows where the wallet's files are, and has **Delete this wallet**: the password and two of the 24 words by their numbers are asked first.
- **Your own starting point** can be made by a button in an open wallet at a confirmed tip, to start another GrinSight from it. (Fixed on the way: the window refused a starting point longer than 8 KB, and a real one is about 9 KB.)
- A hint about the characters of a password; internal names are gone from the descriptions.

A fuller guide to the window, in English and Russian, is planned for the next version; the guides of 0.4.3 do not show the new screens.

## What was checked

| What | Result |
|---|---|
| Tests on Windows | 630 tests, none failed |
| The window against the real wallet process (two throw-away wallets, no network) | 62 steps out of 62 on Windows, on Linux and on macOS (Apple silicon, on GitHub's build machine) |
| Windows installer | built; the install check was skipped because GrinSight was already installed on the build machine |
| Android | x86_64 emulator: the app and the wallet process start; after a full stop the Keystore key opens the same guard |
| Rules | 192 rules of the core and 45 display rules of the window. The new ones (deleting a wallet, the starting point, the switches, confirmations and texts, the consent to send one payment directly) each have tests and deliberate breakages that the tests must catch: 85 breakages, all caught |
| The direct way for one payment | the chain program as a whole on the automated-test network: nothing goes out without the consent; with it, that transaction goes out and another one still waits |
| Tor switched off | the chain program as a whole on the automated-test network: the transaction goes over the program's own connections, no public node is asked through Tor |
| Source | `GrinSight-0.4.4-source.zip` is the tree the macOS image was built from on GitHub |

## Not checked yet

- **No signatures.** Windows and Linux builds are unsigned, the APK has a debug key.
- **No review of the new code.** The five review rounds by an AI reviewer covered 0.4.3. Everything added since — the list above — was checked by its author's tests only. A review is planned before the next version.
- **Nothing new was pressed in a live window.** The window scenario does not go through deleting a wallet, the starting-point button, the Tor and Nostr switches, sending again, the three ways out, the confirmations setting or the buttons of the payment texts. They were checked by tests and on sample screens.
- **No payment by this build on a live network.** Not through Tor, not with Tor switched off, not with the consent for one payment. The line under *Waiting for you* for a payment Tor did not send was not seen with a real Tor that failed to come up.
- **The starting point** was made on the automated-test network only, not on Mainnet.
- **Android.** The service was changed for the two switches; the emulator run starts the app and does not touch them. No real phone.
- **macOS.** Built and run through the window scenario on GitHub's macOS machine (Apple silicon). Not started on a real Mac, not on Intel, not with the network. No Tor bridges.
- **The portable Windows file and the installer** of this version were not started or installed by anyone yet.
- **The statement that the recipient can post the final text themselves** is not made in the window: it was not tried with any other wallet.

## Known limits

- The consent to send one payment directly lives until the wallet is closed; after a restart it is given again.
- The number of confirmations you chose is kept by the window next to the profile and told to the wallet at every start.
- The text the sender gave you for an incoming payment is not kept (only its fingerprint) and cannot be shown again.
- A signed payment cannot be cancelled yet; a prepared one can.
- Messages work between contacts only; there is no "read" mark, and a message the relay did not take in time is marked as not sent and is not retried.
- Payments to an address over Tor: no invoices. A payment from someone who is not a saved contact waits for your yes about 40 seconds. While the wallet is open with Tor on, its address is announced in Tor.
- An incoming payment you accepted cannot be dropped by a button; it closes when its seven days run out. The recipient is not told when you cancel a payment.
- On Linux the rollback guard is bound to the password only.
- The Tor fallback path to Mainnet nodes did not work in the last live run of 0.4.3 (0 of 4); posting through a public node's API over Tor did. Not run again for this version.
- The portable Windows program has no icon of its own in Explorer.
- CentOS 7 (glibc 2.17) is not supported.

## License

GrinSight's own code is MIT. The packages published here include the Slint toolkit under GPLv3, so the packages as a whole are distributed under the GPL, version 3; the license text is inside every package and the source is `GrinSight-0.4.4-source.zip`.
