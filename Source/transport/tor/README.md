# Fly shared Tor foundation

This independent native crate is an initial integration of Arti 0.48.0. The
Nostr SDK's separate built-in Tor feature remains disabled; its optional older
Arti dependency is not used. It is not yet
linked to Fly, Nostr, a wallet, or any app. `SharedTor::bootstrap` constructs
one Arti client rooted in a caller-supplied existing Fly data directory;
clones share that instance. `connect_domain` delegates hostname resolution and
connection to Arti, has an explicit deadline, and has no direct or SOCKS
fallback. Both methods need a Tokio runtime. TLS, WebSocket, DNS registry,
onion service, bridges and Android lifecycle are not implemented here.

Windows release compilation and four local unit tests passed with Arti 0.48.0
using the pinned lockfile and offline vendor. A separate opt-in live test
bootstrapped Tor and opened one TCP stream to example.com:443 in 11.71 seconds,
using a fresh isolated test directory. It does not perform TLS or HTTP and does
not monitor other network paths. The first live attempt failed before bootstrap
because no Rustls provider was installed; the code now explicitly initializes a
provider and the repeated test passed. An offline `cargo check --release` for
`aarch64-linux-android` passed with the isolated NDK 27.2 toolchain. This is not
an APK, device run, or proof of bridge and onion-service support. Integration
and application-wide leak resistance remain unverified; do not use this as a
privacy guarantee.
Onion client support does not mean an onion service can receive payments.
Tor relay nodes see the connecting IP; direct PWA support is out of scope here.
Caller must ensure the Fly root and ancestors stay trusted and stable: these
path checks do not prevent directory replacement or hostile ancestors. The root
must not be a user's existing wallet directory. Caller must enforce a single
bootstrap per storage; multiple independent calls do not share a client.

## Preparing an isolated vendor

This procedure was run for Arti 0.48.0. Network access is needed for initial
dependency acquisition. Do not run simultaneously with other
builds. Review crate license and verify source/checksums. All mutable paths are
inside the Fly root, and use the current approved project root.

```powershell
. 'C:\DHW\GrinSight\FlyClient\repo\tools\env.ps1'
$torStage = 'C:\DHW\GrinSight\FlyClient\.tmp\tor-v48-stage'
New-Item -ItemType Directory -Force -Path (Join-Path $torStage 'src') | Out-Null
Copy-Item -LiteralPath 'C:\DHW\GrinSight\FlyClient\repo\tor\Cargo.toml' -Destination (Join-Path $torStage 'Cargo.toml')
Copy-Item -LiteralPath 'C:\DHW\GrinSight\FlyClient\repo\tor\src\lib.rs' -Destination (Join-Path $torStage 'src\lib.rs')
Copy-Item -LiteralPath 'C:\DHW\GrinSight\FlyClient\repo\tor\src\native.rs' -Destination (Join-Path $torStage 'src\native.rs')
Set-Location -LiteralPath $torStage
cargo --config net.offline=false vendor --versioned-dirs 'C:\DHW\GrinSight\FlyClient\.tools\tor-v48-cargo-vendor'
```

After successful vendoring, inspect the resulting lockfile and copy it to
`repo/tor/Cargo.lock`; configure `repo/tor/.cargo/config.toml` to replace
crates.io with `../../.tools/tor-v48-cargo-vendor` and `net.offline = true`.
Then test with `cargo test --release --offline --locked --jobs 2` in
`repo/tor`. The tests make synthetic paths and do not bootstrap or connect to
Tor. Real-network tests need an explicit bounded plan that accounts for the
connecting IP being visible to Tor relays.

Before integration: independent security review; native Windows and Android
builds; shared lifecycle with the wallet; no-leak network monitoring of DNS and
outbound sockets; TLS and Nostr transport; reviewed storage, bridge and onion
service design. In particular, plain testing of these helpers does not prove
the rest of the application routes all its traffic through Tor.
