GrinSight is a light wallet for [Grin](https://grin.mw). It needs no full node of its own: it checks the header chain from a built-in point to the tip, confirms the tip with public nodes, collects and verifies the state its outputs depend on, and sends transactions through its own Tor. Payments and messages between contacts travel over Nostr, also through Tor.

0.4.3 is a new wallet under the same name: a new core and a new window. It is a research wallet. Nothing here is signed and the code has not been audited by a human; what has never been run outside tests is listed under [Not checked yet](#not-checked-yet).

## Download

| System | File | Size |
|---|---|---|
| **Windows 10/11 x64** — installer, no administrator rights | [GrinSight-0.4.3-windows-x64-setup.exe](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.3/GrinSight-0.4.3-windows-x64-setup.exe) | 30.9 MB |
| **Windows x64** — portable, one file | [GrinSight-0.4.3-windows-x64-portable.exe](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.3/GrinSight-0.4.3-windows-x64-portable.exe) | 45.2 MB |
| **Linux** — Debian 10+, Ubuntu 20.04+ | [GrinSight-0.4.3-linux-amd64.deb](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.3/GrinSight-0.4.3-linux-amd64.deb) | 33.2 MB |
| **Linux** — Fedora, RHEL 8+, openSUSE | [GrinSight-0.4.3-linux-x86_64.rpm](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.3/GrinSight-0.4.3-linux-x86_64.rpm) | 48.2 MB |
| **Linux** — any with glibc 2.28+, Arch | [GrinSight-0.4.3-linux-x86_64.tar.gz](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.3/GrinSight-0.4.3-linux-x86_64.tar.gz) | 48.5 MB |
| **Android 8+** (arm64) | [GrinSight-0.4.3-android-arm64.apk](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.3/GrinSight-0.4.3-android-arm64.apk) | 50.3 MB |
| **macOS 11+** — Apple silicon and Intel, without Tor bridges | [GrinSight-0.4.3-macos-universal.dmg](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.3/GrinSight-0.4.3-macos-universal.dmg) | 90.4 MB |

The files are not signed: the checksum is the only way to know you have the file published here. Windows will warn about an unknown publisher; the APK carries a debug key and installs by sideloading.

```text
ebdee46f300ec70c9bcdedec94a31545086ae3fc529f83e10084667b360c3458  GrinSight-0.4.3-android-arm64.apk
8e08d09804939bb793030404f9b5d16aae22fc645d1493b917575ea2f6d64ef6  GrinSight-0.4.3-linux-amd64.deb
428d45f993a866fae989f15b40ac671521b4701cd48cf72a030da1b6a26985ea  GrinSight-0.4.3-linux-x86_64.rpm
7b283399e727ae3c7a50b008ef8620f409ba8ab3a3ab0aade67a9d3152bffd4c  GrinSight-0.4.3-linux-x86_64.tar.gz
027a802adb3796e9ffeda1653201cdfd5b2269d14aa35cdb435b6f456573b2eb  GrinSight-0.4.3-macos-universal.dmg
1d005e75d28269fe3eeade55a9ee3d2d97da4e893b422f0fcbda3806d0610c0f  GrinSight-0.4.3-source.zip
531a2ee16e8d133124cdb022a104bc8757bed56b099abb16bc77fe5244b4d129  GrinSight-0.4.3-windows-x64-portable.exe
0975e0ea717d6873a117495510dd167fa9e9d88af89059272ff7b8de91d9adcd  GrinSight-0.4.3-windows-x64-setup.exe
```

```powershell
Get-FileHash .\GrinSight-0.4.3-windows-x64-setup.exe -Algorithm SHA256
```

```sh
sha256sum --check --ignore-missing SHA256SUMS.txt
```

## How long it takes

Measured on Mainnet, on Windows, on a home connection. Your numbers will differ with the network.

| What you do | Time |
|---|---|
| A new wallet until **Verified** | about 3.5 minutes |
| Restore from 24 words on an empty disk until the old outputs are found | about 7 minutes |
| A later start until **Verified** | about 3 minutes |
| A payment, from signing to a block | 30–80 seconds; a block comes about once a minute |

The balance is shown as soon as the wallet is at the tip. After a restore the search for old outputs still runs for a while: the line under the balance says so, and the sum can grow until it ends.

## Quick guide

1. **Check the file** against `SHA256SUMS.txt`, then install it, or put the portable file in a folder of its own, and start GrinSight.
2. **Create a wallet.** Any password is accepted; twelve characters or more are advised. Write the 24 words on paper: the wallet shows them once, and they are the only way back.
3. **Wait for Verified** under the balance: it is shown only when the wallet is at the tip and can send; before that the mark says Catching up or Searching, with the numbers. The *Synchronisation* block shows the whole path with numbers; *Problems* says what is wrong and what to try.
4. **Receive.** *Receive* → copy your address and give it to the sender. A payment sent to it over Tor — from Grim, grin-wallet, Grin++ or GrinSight — arrives by itself and waits for your yes under *Waiting for you*; the sender's wallet waits about 40 seconds. From a saved contact, with auto-receive on, it is accepted without asking. Or paste the Slatepack text they sent you and send the reply back.
5. **Send.** *Send* → the amount → the recipient's `grin1…` address: the payment goes over Tor to the wallet at that address, and its reply comes back for your signature under *Waiting for you*. Without an address, or with *By hand* chosen: *Make the Slatepack text* → pass it on and paste the reply. Either way you check the amount, the fee and the address, then *Sign and send*. To a saved contact the payment travels over Tor by itself and comes back for your signature.
6. **Restore.** *Restore* on the first screen → the 24 words → a new password.

On Windows and Linux this version installs as **GrinSight Light**, next to GrinSight 0.4.2 if you have it. The installed Windows copy keeps the wallet in `%LOCALAPPDATA%\GrinSightLight\data`, apart from the program; the portable copy keeps it in `data\` next to the program; Linux keeps it in `~/.local/share/grinsight-light`. A wallet of GrinSight 0.4.2 is not picked up by itself: restore it from its words.

## What changed since 0.4.2


- **A new core and a new window.** The payment core, the chain layer and the window are written anew in Rust; the window is drawn with Slint instead of Flutter.
- **Its own Tor.** A transaction goes out through the wallet's own Tor; a direct connection is used only if you allow it.
- **A built-in starting point** (Mainnet height 4 115 520) instead of the signed checkpoint file; the tip and the clock are confirmed with public nodes of different operators.
- **Payments to contacts over Nostr through Tor**, with messages between contacts; or by hand as Slatepack text — the choice is on the main screen.
- **Payments straight to a `grin1…` address over Tor**, the way grin-wallet, Grin++ and GrinSight 0.4.2 do it, and receiving at your own address. The wallet answers by itself only to saved contacts and only with auto-receive on; anyone else is asked about in the window (three at most, about 40 seconds each); amounts under 0.001 GRIN are refused. Each wallet keeps its own Tor folder, so two wallets on one computer do not disturb each other.
- **Invoices are paid from the window**, every prepared payment can be cancelled, unanswered incoming drafts close after seven days.
- **A rollback is noticed.** If the wallet file is replaced with an older copy, the wallet says so and will not sign payments it can no longer account for.
- **The whole path of synchronisation, the state of Tor and a list of problems** with two lines of help on the main screen; the chain process is quoted in its own words.
- **Tor bridges where Tor is blocked.** On the login screen: "Options" → "How Tor is reached" → "Bridges"; in an open wallet: "Tor bridges" in the Connection card. The built-in obfs4 and Snowflake bridges are those of Tor Browser; your own bridges are pasted as lines. One choice holds for everything the wallet does through Tor; with bridges chosen it never reaches Tor directly. The bridge program `lyrebird` is taken unchanged from the official Tor Expert Bundle 16.0.1.
- **A QR code** of the address and of the Slatepack text to pass on. There is no scanning with a camera.
- **Slatepack as a file:** "To a file" and "From a file", in the wallet's own folder `slatepack`.
- **Packages:** a portable Windows build in a single file, `.rpm` and `.tar.gz` next to the `.deb`, an image for macOS.

Not in this version, and present in 0.4.2: scanning QR codes, GlauxNet (shown as "soon"), "Check myself" from the first block, "Try the future", issuing an invoice from the window.

## How it is built


Five programs run on your device. The window holds no keys. The wallet process keeps the keys, signs, and writes the journal, encrypted with your password. The chain process verifies headers and state and posts transactions. The mailbox delivers payments and messages. A fifth program, the address process, announces your `grin1…` address in Tor and carries payments to and from addresses; it holds the address key only and decides nothing. Our own code denies `unsafe`, with two marked exceptions: the Windows DPAPI call in the rollback guard and the entry-point name Android looks for.

## What was checked

| What | Result |
|---|---|
| Tests on Windows | 599 tests in 23 sections, none failed |
| The window against the real wallet process (two throw-away wallets, no network) | 62 steps out of 62 on Windows, Debian 10 and macOS (Apple silicon, on GitHub's build machine) |
| Windows installer | silent install, the scenario from the installed programs, uninstall left no files — on an earlier build of this version (1553); the published installer was built without that check because GrinSight was already installed on the build machine |
| Android | x86_64 emulator: the app and the wallet process start; after a full stop the Keystore key opens the same guard (checked on an earlier build of this version) |
| Tor bridges | live on Windows: Tor came up through the 7 built-in obfs4 bridges in 33 s and through Snowflake in 26 s; the address process announced its address through obfs4 and answered itself over the Tor network |
| The bridge program | the Tor Expert Bundle 16.0.1 archives are checked against pinned checksums at every build; the signature of the checksum list by the Tor Browser developers' key was verified |
| Rules | 168 rules of the core and 32 display rules of the window; the core rules and the new window rules each have a test and a deliberate breakage that the test must catch |
| External review | five rounds by an AI reviewer, 50 findings, all fixed; in the last two rounds every Rust file was read |
| Dependencies | compared with the RustSec database on 24 November: 11 advisories in 7 crates, none reachable from this code |
| Exchange with another wallet | with Grim 0.3.7 on Mainnet, over Tor, on 24 November: a payment from GrinSight to Grim and a payment from Grim to the GrinSight address both went through (Windows) |
| First run by the author | a Mainnet wallet restored from its words on 24 November reached the tip and showed its balance |

## Not checked yet

- **No signatures.** Windows and Linux builds are unsigned, the APK has a debug key.
- **No human audit.** The five review rounds were done by an AI reviewer.
- **Payments by this exact build on a live network.** The author sent and received over Tor on Mainnet with the build before the published one (it differs in window wording and in how the address process is split for tests). Paying an invoice and cancelling are covered by tests and by measurements of an earlier revision (23 November), not by a live run of this build.
- **Payments to an address over Tor with other wallets.** Checked with Grim 0.3.7 only, on Windows. An exchange with grin-wallet, Grin++ or GrinSight 0.4.2 was not run; neither was receiving from Grim on Linux, Android or macOS.
- **No real phone.** Android was run on an x86_64 emulator; the published APK is the same programs for arm64 only.
- **macOS.** The image was built from the published source on GitHub's macOS 15 machine (Apple silicon); the window scenario passed there. It has the fix that lets Grim send to the address, and no Tor bridges. It was not started on a real Mac, not on Intel, and not with the network (chain, Tor, payments).
- **Bridges where Tor really is blocked.** The check ran on a network where Tor is reachable directly as well: it shows that the wallet goes through bridges, not that bridges get past a block. On Linux and Android bridges were not run live; nor from the wallet window (the live runs used test programs).
- **The portable Windows file** was built from the folder that passed the scenario and was started by the author on his own Windows machine; it was not tried on a clean machine.
- **Windows installer on a clean machine, and next to an installed GrinSight 0.4.2,** was not tried.
- **Late changes not seen on a real wallet:** the line for money held by a payment under way, the Russian wording of what came to the address, the bridges button on the main screen.

## Known limits

- Messages work between contacts only; there is no "read" mark, and a message the relay did not take in time is marked as not sent and is not retried.
- Payments to an address over Tor: no invoices. A payment from someone who is not a saved contact waits for your yes about 40 seconds; after that the sender has to send again. While the wallet is open its address is announced in Tor: someone who knows the address can tell the wallet is online.
- The Slatepack text of a payment prepared by hand can be shown again from *All payments*; your reply to an incoming payment — only until the window is restarted.
- An incoming payment you accepted cannot be dropped by a button; it closes when its seven days run out. The recipient is not told when you cancel a payment.
- On Linux the rollback guard is bound to the password only.
- The portable Windows program has no icon of its own in Explorer.
- The Tor fallback path to Mainnet nodes did not work in the last live run (0 of 4); posting through a public node's API over Tor did.
- CentOS 7 (glibc 2.17) is not supported.

## License

GrinSight's own code is MIT. The packages published here include the Slint toolkit under GPLv3, so the packages as a whole are distributed under the GPL, version 3; the license text is inside every package and the source is `GrinSight-0.4.3-source.zip`.
