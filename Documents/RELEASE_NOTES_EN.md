# GrinSight 0.4.7A

GrinSight checks Grin headers, unspent outputs and the selected chain tip on your device. It works with standard public nodes. Verification from genesis also produces a local checkpoint you can export with its proof.

Windows portable can be updated by closing the wallet and replacing its EXE next to the existing data folder. The migration test preserved the receiving address, history, reserved inputs and signed transaction. An unsigned draft from an earlier signing session keeps its reserve and cannot be signed again in that session.

On first opening, choose English, Russian, German, French, Simplified Chinese, Korean or Japanese. You can change the language later in Settings. The recovery form has a formatting example. The connection and sync panel shows a yellow indicator during verification. Once the wallet is ready, the panel shows a green indicator and “Ready to use”. The panel updates automatically in every theme. Automatic replies to contacts remain optional.

[Release files](https://github.com/DanilaGrinRus/GrinSight/releases/tag/v0.4.7A) · [Verification report](BOOTSTRAP-0.4.7A-ACCEPT.md) · [Security review](RELEASE-0.4.7A-SECURITY.md)

---

## Previous release · 0.4.6

GrinSight is a light wallet for [Grin](https://grin.mw). It needs no full node of its own: it checks the chain of headers from a built-in point to the tip, confirms the tip with public nodes, collects and checks the state its outputs depend on, and sends transactions through its own Tor.

0.4.6 is the first release after 0.4.4; 0.4.5 was not released on its own, and everything made for it is in here. The main new thing: **the history before the built-in point is no longer taken on trust — it is checked by sampling its work** (after the FlyClient scheme), with the proof shipped inside the program. The wallet folder is the one of 0.4.4; wallet files are read as they are. This is a research wallet. Nothing here is signed, and **the code added in 0.4.6 has not been reviewed by anyone else**; what has never run outside tests is listed under [Not checked](#not-checked).

## Download

| System | File | Size |
|---|---|---|
| **Windows 10/11 x64** — installer, no administrator rights needed | [GrinSight-0.4.6-windows-x64-setup.exe](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.6/GrinSight-0.4.6-windows-x64-setup.exe) | 38.8 MB |
| **Windows x64** — portable, one file | [GrinSight-0.4.6-windows-x64-portable.exe](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.6/GrinSight-0.4.6-windows-x64-portable.exe) | 54.2 MB |
| **Linux** — Debian 10+, Ubuntu 20.04+ | [GrinSight-0.4.6-linux-amd64.deb](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.6/GrinSight-0.4.6-linux-amd64.deb) | 40.9 MB |
| **Linux** — Fedora, RHEL 8+, openSUSE | [GrinSight-0.4.6-linux-x86_64.rpm](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.6/GrinSight-0.4.6-linux-x86_64.rpm) | 57.0 MB |
| **Linux** — any with glibc 2.28+, Arch | [GrinSight-0.4.6-linux-x86_64.tar.gz](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.6/GrinSight-0.4.6-linux-x86_64.tar.gz) | 57.3 MB |
| **Android 8+** (arm64) | [GrinSight-0.4.6-android-arm64.apk](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.6/GrinSight-0.4.6-android-arm64.apk) | 59.2 MB |
| **macOS 11+** — Apple silicon and Intel, no Tor bridges | [GrinSight-0.4.6-macos-universal.dmg](https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.6/GrinSight-0.4.6-macos-universal.dmg) | 109.0 MB |

The files are not signed: the checksum is the only way to know you have the file published here. Windows warns about an unknown publisher; the APK is signed with a debug key and is installed by hand.

```text
7962f6e9736b647365bd63b03f95ee9610f62574116680510434b3091db0963c  GrinSight-0.4.6-android-arm64.apk
2ba6e024661b965e91f81ccd33b65e0f345d902bdfdce3506dfc4ecaa72eb411  GrinSight-0.4.6-linux-amd64.deb
5e93405a5e02be7c02346ce74ee33bebe828f8e5e420478f15d8544d53fff03a  GrinSight-0.4.6-linux-x86_64.rpm
cd66a4942947b7c0a64f85c1eac4b6cd1655612a26b91798796bbe21763e6b29  GrinSight-0.4.6-linux-x86_64.tar.gz
4d1607358530325f5b20d16e31beac45d82950e440f74da9026aff60d9e90d40  GrinSight-0.4.6-macos-universal.dmg
06125a1433e54f79d548bed9453b58d276a3bffc2592d9d795188c80d45914b1  GrinSight-0.4.6-source.zip
49ccfde95da8d5199761cbd0f48949cc6a05cb9d2cf4d3bfbb72028a10d7d7f8  GrinSight-0.4.6-windows-x64-portable.exe
1f4e0c97d5960ada4dbac8e0c210bb2424c6cacdadfc18c7422f8c2dc84bd7ec  GrinSight-0.4.6-windows-x64-setup.exe
```

```powershell
Get-FileHash .\GrinSight-0.4.6-windows-x64-setup.exe -Algorithm SHA256
```

```sh
sha256sum --check --ignore-missing SHA256SUMS.txt
```

## What changed since 0.4.4

**The history before the point — checked, not trusted**

- The Mainnet program carries a proof of the history before the built-in point (about 8 MB). When the chain is opened the wallet checks it in under a second: with a seed taken from the point itself it picks 420 places across all the accumulated work, and for each checks the headers, the difficulty rule and the header's place in the tree the point commits to. "Details" has a line "History before the starting point".
- It follows the FlyClient scheme but is not the paper: the proof is non-interactive and made in advance, for the release. **The number of samples (420) is a margin, not yet derived for a stated error bound** — the code says so too. The hash of the built-in point itself is still chosen by the release.
- If the check fails, the wallet does not stop: it says "not checked" and works from the point as before.
- A starting point of your own now carries the path to the built-in one, so its history stays proved: by sampling up to the built-in point, and checked by your wallet from there. It is made with a button in "Details"; on another device of yours it is pasted under "Options → Own nodes and a point from another device".

**Conversations and contacts**

- Contacts on the left, the conversation on the right; search by name, time of the last message, the number of new ones. The chosen contact has signs: send GRIN, change details, delete. The head of a conversation has "Send GRIN", a window of its own (up to three on a computer) and a "⋯" menu.
- A payment to the contact stands in the conversation; days are marked "Today", "Yesterday".
- Deleting a contact is always asked in a window of its own.
- "All contacts": the whole list, delete one or all, add a list.
- Checking a contact: a six-word code, the same on both sides; the "checked" mark goes when their address changes.
- An invoice from the "Receive" window; a QR code saved as a picture.

**Money**

- "Outputs": the list of outputs, a "do not spend" mark, paying with exactly the chosen outputs, "Collect into one" and a switch to take small outputs along with payments.
- An unsigned payment is cancelled from its line; a signed one that is not in a block can be taken back — by a second transaction of the same inputs to yourself, with a full warning.
- Money of your own with no payment record (auto-receive, another copy of the wallet) shows as a line in the payments; "All payments" is a table with filters.
- Agreement to send one payment directly survives a restart. When Tor does not work, the signing window says so before signing and offers ways out, among them Tor bridges the wallet tries by itself.
- The sender's text of an incoming payment is kept and can be shown again.

**The window**

- The state ("VERIFIED" and so on) stands above the balance; "Details", "?" and "Settings" open as windows on top, with larger text.
- "Copy the words" in the "Your 24 words" window: after a minute and on lock the wallet empties the clipboard if it still holds those words.
- Tor is switched on and off without unlocking again.
- A login screen that fits a narrow screen; files held by another process are named in plain words; a "Restart the wallet" button.

## What was checked

| What | Result |
|---|---|
| Tests on Windows | 682 tests, none failed |
| The window against the real wallet process (throwaway wallets, no network) | 86 steps of 86 on Windows and Linux; macOS — the GitHub build |
| The history check | the whole history of Mainnet (4,123,322 headers) checked by the program on a synced node; the proof for the point checks in 0.6 s; an own point above the built-in one — on real Mainnet headers |
| Rules | 202 core rules and 75 display rules. The new ones have tests and deliberate breakages the tests must catch; all were caught |
| Outside review | six rounds by an AI reviewer (0.4.3–0.4.5): 53 findings, all fixed. What was added in 0.4.6 has not been reviewed. No human audit |
| Sources | `GrinSight-0.4.6-source.zip` — the tree the macOS image was built from on GitHub |

## Not checked

- **No signatures.** The Windows and Linux builds are not signed; the APK has a debug key.
- **Nobody outside has reviewed what is new in 0.4.6**: the history check, the path of an own point, the new conversations.
- **The argument for the number of samples** has not been written for Grin; 420 is a margin, not a calculation.
- **The live network.** No payment was made by this build: neither over Tor nor directly. Taking a payment back, collecting outputs, an invoice between two wallets and checking a contact between two live wallets were not run.
- **The window** was run by the author on Windows; Android only on an emulator, no real phone; macOS only on GitHub's build machine.
- **That the recipient can send the final text to the network themselves** is not claimed in the window: it was not checked with another wallet.

## Known limits

- "New" messages are counted in memory from the unlock; nothing is written to disk.
- An incoming payment is not shown in the conversation: the wallet does not know who sent it.
- The time of a payment in the conversation is taken from its block height, roughly.
- A fresh point and proof come only with a release; the older the release, the longer the first start (about 525,000 headers a year).
- Messages work between contacts only; there is no "read" mark.
- On Linux the rollback guard is tied to the password only. CentOS 7 (glibc 2.17) is not supported.

## License

GrinSight's own code is MIT. The published packages include the Slint library under GPLv3, so the packages as a whole are distributed under the GPL version 3; the license text is in every package, the sources are `GrinSight-0.4.6-source.zip`.
