# GrinSight — "Revelio for your coins" 🐻

**How it works and how to use it**

## What is it?

GrinSight is a light Grin wallet that checks everything itself. You don't need your own node, and you don't need to trust anyone else's. It shows your balance only after proving it against the chain.

## How does it work?

1. **Headers.** The wallet downloads block headers from several independent public peers and checks each one: proof of work, difficulty and links. It accepts the heaviest chain only if peers from different networks agree on it.
2. **Coin state.** It rebuilds the current set of unspent outputs and checks it against the commitment in the block header (`output_root`). A peer can't slip in a fake coin or hide a real one.
3. **Your coins.** It finds your outputs with your own seed. It never asks a server "what's my balance?", so nobody learns your addresses.
4. **Every new block** is checked against its header (`output_root` / `kernel_root`). If a check fails, the wallet shows no balance rather than a wrong one.

## Your keys

Your 24-word phrase is encrypted with your password and never leaves your device.

## How to use it

- **Start:** create a new wallet (write down the 24 words) or restore one from your phrase, then set a password.
- **Update:** the first time takes a few minutes, while the wallet builds a verified state. After that it only checks new blocks, which takes seconds.
- **Receive:** share your address, or paste the sender's slatepack and send back the answer. The coins appear once the transaction is in a block.
- **Send:** enter an address and amount, give the slatepack to the receiver, then paste their answer. The wallet signs and broadcasts the transaction.
- **Invoices:** request a payment or pay someone's invoice.
- **Confirmations:** the wallet checks that your transaction really is in a block of the verified chain. If that block later drops out of the chain (a reorg), the wallet notices.
- **GlauxNet (on by default, can be turned off):** while the wallet is open it keeps your own
  encrypted mailbox behind your Tor onion; slatepacks reach your contacts and theirs reach
  you automatically, without a third-party server.

## Status

GrinSight works on Grin mainnet. A proven balance and real payments have been checked on the live network: five transactions sent from the wallet were confirmed in mainnet blocks 4,100,766 to 4,100,860. It works on testnet (Floonet) too: install, updates and a proven balance against the live network.
