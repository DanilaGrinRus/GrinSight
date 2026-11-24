# GrinSight — "Revelio for your coins" 🐻

This text describes version 0.4.3.

## What is it?

GrinSight is a light wallet for Grin. It does not run a full node and does not ask a server for your balance. It takes headers, state and blocks from Grin nodes, verifies them on your device and shows a balance only on a tip it has verified and public nodes have confirmed.

## How does it work?

Five programs start when you open the wallet:

- **the window** — what you see; it holds no keys;
- **the wallet process** — keeps the keys, signs, writes the journal encrypted with your password;
- **the chain process** — checks every header from a built-in starting point to the tip, collects the coin state at the nodes' archive point, checks every block after it, asks public nodes of different operators for the tip and the time, and sends transactions through its own Tor;
- **the mailbox** — delivers payments and messages between contacts over Nostr through Tor;
- **the address process** — announces your `grin1…` address in Tor while the wallet is open, carries payments sent to it and payments you send to another address. It decides nothing: the wallet process does.

The main screen shows where this path is: the *Synchronisation* block lists the chain process, the chosen tip, the wallet's block, the search for old outputs, the time and the delivery; the *Problems* block names what went wrong and what to try.

## Your keys

The 24 words are created on your device and shown once. With them the wallet can be restored anywhere; without them and without the password the money is gone. The wallet file is encrypted with the password: any length is accepted, twelve characters or more are advised.

If the wallet file is replaced with an older copy of itself, the wallet notices it and will not sign payments prepared before that copy was taken.

## How to use it

1. **Check the download** against `SHA256SUMS.txt`. The files are not signed.
2. **Create a wallet**, choose a password, write down the 24 words, answer the three words the wallet asks for.
3. **Wait for "Verified"** under the balance: about 3.5 minutes for a new wallet on mainnet. It is shown only when the wallet is at the tip and can send; before that the mark says "Catching up" or "Searching".
4. **Receive.** Open *Receive* and copy your address for the sender (or show it as a QR code). A payment sent to it over Tor — from Grim, grin-wallet, Grin++ or GrinSight — arrives by itself and waits for your yes under *Waiting for you*; the sender's wallet waits about 40 seconds. If they send you a Slatepack text instead, paste it there (or take it *From a file*), check the amount and the sender, accept, and send the reply back.
5. **Send.** Open *Send*, enter the amount and the recipient's `grin1…` address: the payment goes over Tor to the wallet at that address, which must be open, and its reply comes back under *Waiting for you*. Without an address, or with *By hand* chosen: *Make the Slatepack text*, pass it on, paste the reply. Either way the wallet shows what the recipient gets, the fee, the total and the address. Check them and press *Sign and send*.
6. **Contacts.** Add a contact by their message key; a payment to a contact is delivered over Tor by itself and comes back under *Waiting for you* for your signature. Choose *By hand* on the main screen if you always want to pass the text yourself.
7. **Pay an invoice.** *Receive* → paste the invoice text → check the amount and the fee → *Sign the payment*.
8. **Cancel.** Every prepared payment under *Waiting for you* can be cancelled; the money returns from the reserve.
9. **Where Tor is blocked.** *Options* on the login screen → *How Tor is reached* → *Bridges*, or *Tor bridges* in the Connection card: the built-in obfs4 and Snowflake bridges of Tor Browser, or your own. With bridges chosen the wallet reaches Tor through them only.
10. **Restore.** *Restore* on the first screen → the 24 words → a new password. After the wallet reaches the tip, the search for old outputs runs for a few more minutes; the line under the balance says so, and the sum can grow until it ends.

## Where the wallet is kept

| System | Place |
|---|---|
| Windows, installed | `%LOCALAPPDATA%\GrinSightLight\data` |
| Windows, portable | `data\` next to the program |
| Linux | `~/.local/share/grinsight-light` |
| Android | the app's own storage |

Uninstalling or updating the program does not touch the wallet.

## Status

A research wallet. Five review rounds by an AI reviewer, no audit by a human. Nothing is signed. Android was run on an emulator only; the macOS image was built and its window scenario run on GitHub's machine, not started on a real Mac. Payments over Tor were exchanged with Grim 0.3.7 on mainnet in both directions; other wallets were not tried. Details: [release notes](RELEASE_NOTES_EN.md), [mathematics and trust boundaries](MATHEMATICS_EN.md).
