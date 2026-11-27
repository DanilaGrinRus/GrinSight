# Wallet acceptance on an autonomous local chain

The cross-workspace integration test restores a funded legacy phrase and pays a fresh profile. Both wallet hosts launch the real chain executable over its standard IPC. The isolated network starts at Grin automated-testing genesis. Two loopback Grin peers serve P2P data. Five local HTTPS fixtures simulate the registered tip/time observers with a local test CA. Both profiles start empty. No release checkpoint, saved chain, proof provider, remote relay or external funds are used.

The chain mines an ordinary output on a legacy derivation path at height 19, retains it in the archive at height 20, and advances to height 40. The payer restores the fixture entropy through the mnemonic API, finds exactly one old output in authenticated data, and checks its amount. The recipient creates a new profile. After selection, the two hosts exchange a manual Slatepack, the node receives the exact finalized transaction through P2P, the Grin chain validates a block containing it, and both wallet journals reflect the payment (sender confirmed and recipient credited).

The test host accepts the automated network and uses cheaper test password derivation. Supplying the chain executable replaces its fallback view, clock and broadcaster with the real IPC link. There is no synthetic funding injected into either wallet. The link uses production verification and payments code. The independent real-world availability of time and quorum sources, download time on a public network, and the desktop UI are separate acceptance items.

## Repeat on Windows

From the repository root, with its vendored dependencies available, run:

```powershell
$src = (Resolve-Path Source).Path
$env:CARGO_TARGET_DIR = Join-Path $src 'target\autonomous-wallet-e2e'
Push-Location (Join-Path $src 'paycore\host')
try {
    cargo build --locked --offline --features test-chain --bin fly-paycore-host-test
    if ($LASTEXITCODE) { throw 'wallet test host build failed' }
} finally { Pop-Location }
$env:FLY_AUTOMATED_HOST = Join-Path $env:CARGO_TARGET_DIR 'debug\fly-paycore-host-test.exe'
Push-Location (Join-Path $src 'chain\fly-chain')
try {
    cargo test --locked --offline --features test-net --test select autonomous_wallet::old_phrase_genesis_restore_and_payment -- --ignored --exact
    if ($LASTEXITCODE) { throw 'autonomous wallet acceptance failed' }
} finally { Pop-Location }
```

This one test explicitly opts into its sibling workspace's host executable. A plain workspace test run will list it as ignored. The separately run `fly-paycore-host` regression suite passed 16 offline host tests and skipped its 5 opt-in cases.
