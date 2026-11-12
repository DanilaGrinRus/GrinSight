# GrinSight PWA diagnostic shell

This is a static shell around the tested browser module, not the wallet UI.

- `worker.mjs` runs the Wasm core in a module Web Worker;
- `core/` is copied from `web-core/browser/` by `build_pwa.ps1`;
- `sw.js` caches the shell + core for offline start; version the cache after every
  core rebuild;
- `manifest.webmanifest` + icons make it installable when served over HTTPS
  (or localhost).

Run the worker test:

```powershell
node worker-selftest.mjs
```

Expected:

```json
{"id":1,"ok":true,"result":{"abi":1,"headerHash":"2d71d799...","address":"tgrin1...","s1Length":2021,"checkpointHeight":3318854,"recentHeaders":62,"utxoFixture":2251}}
```

`s1Length` varies; it proves the S1 signing path executed.

Serve the directory over HTTPS for a real iPhone test; plain `file://` cannot
register a service worker. This page does not hold keys and is not a payment
confirmation. Full wallet UI/backend, Storage/Transport and gateway are still
missing.


## Transport (contract + loopback test)

`transport.mjs` is the browser gateway client: UTF-8 JSON frames, request ids,
20 s default timeout, 1 MiB frame limit, explicit `timeout`/`too_large`/
`transport`/`closed` errors, no keys and no verification.

`gateway-mock.mjs` is a test-only loopback WebSocket server (manual handshake,
no TLS). `transport-selftest.mjs` verifies:

```text
TRANSPORT_SELFTEST=PASS
```

This is the client contract for the future WSS gateway. It is not the gateway
itself and not a payment confirmation.


## Live gateway test

Start `grinsight-gateway` (see `../../web-gateway/README.md`) and run:

```powershell
$env:GRINSIGHT_GATEWAY_URL='ws://127.0.0.1:8787'
node gateway-live-selftest.mjs
```

Expected: `GATEWAY_SELFTEST=PASS checkpoint=4095360 headers=62`.
The gateway is untrusted and serves shipped data only; WSS/TLS is terminated by
a reverse proxy for now.


## Multi-gateway pool

`GatewayPool` queries several URLs independently, returns every source with
`ok/error`, and can require consistent results (`consistent:true`) without
treating majority as proof. `gateway-pool-selftest.mjs`:

```text
GATEWAY_POOL_SELFTEST=PASS
```

The UI must show which source supplied data; a single gateway is never treated
as independent confirmation.


## Wasm live-header verification

With a live gateway running:

```powershell
$env:GRINSIGHT_GATEWAY_URL='ws://127.0.0.1:8787'
node gateway-verify-selftest.mjs
```

Expected: `LIVE_HEADERS_WASM_VERIFY=PASS tip=3318859`.


## Full live chain test

```powershell
$env:GRINSIGHT_GATEWAY_URL='ws://127.0.0.1:8787'
node gateway-chain-selftest.mjs
```

Expected: `LIVE_CHAIN_WASM_VERIFY=PASS start=3318854 tip=3333291 batches=29`.


## WSS test

```powershell
$env:GRINSIGHT_GATEWAY_URL='wss://127.0.0.1:9443'
node wss-selftest.mjs
```

Expected: `WSS_SELFTEST=PASS checkpoint=3318854`. For a self-signed test cert,
set `NODE_TLS_REJECT_UNAUTHORIZED=0` (test only); production uses a real cert.
