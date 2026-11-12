# GrinSight data gateway (prototype)

An **untrusted** data source for the browser core. It never sees seed/keys and
never performs verification: the browser verifies checkpoint, headers, PIBD and
signatures itself.

Current backend: shipped `release/checkpoint.rwm` + `release/recent-headers.bin`
(62 headers at height 3318854), or live headers when `--peer IP:PORT` is set.
Live P2P code exists (handshake + GetHeaders) and a sequential peer pool. **Live headers are verified**
against a local testnet node (`127.0.0.1:13414`) using `--locator genesis`: it
returned headers 3318855..3318859 from the Floonet checkpoint with `source:"live-peer"`. It is not yet synced to the
shipped Floonet checkpoint; public peers still timed out/closed the handshake.
Static mode is tested separately.

## Run

```powershell
cd C:\DHW\GrinFlyClient\GrinSight\web-gateway
cargo build
.\target\debug\grinsight-gateway.exe --bind 127.0.0.1:8787 --release-dir ..\checkpoints\floonet
```

The listener is plain WebSocket. Production must put a TLS reverse proxy
(Caddy/nginx) in front; clients then use `wss://…`. TLS is not terminated by
this process yet.

## Protocol

UTF-8 JSON frames, request id, max request 1 MiB:

```json
{"id":1,"method":"hello","params":{"protocol":1,"network":"floonet"}}
{"id":2,"method":"checkpoint"}
{"id":3,"method":"headers","params":{"from":4095300,"count":5}}
```

Responses: `{id, ok:true, result}` or `{id, ok:false, error:{code,message}}`.
Events are not implemented.

`hello` returns capabilities `["checkpoint","headers"]`,
`source:"shipped-release"`, `verified_by:"browser"`.

## Limits / gaps

- no rate limit or auth yet; peer pool is a simple sequential fallback;
- only 62 shipped recent headers; `more:false`;
- no PIBD/block/broadcast;
- live P2P path exists but is not verified against a reachable Floonet peer;
- no TLS/rate limit/auth/peer pool;
- no multi-gateway UI;
- no WSS/TLS termination in-process;
- not a payment confirmation and never a trusted verifier.


## WSS (tested via TLS proxy)

`tls_proxy.py` is a reference TLS terminator for local tests:

```powershell
python tls_proxy.py --listen 127.0.0.1:9443 --cert cert.pem --key key.pem --upstream 127.0.0.1:8787
```

Production must use Caddy/nginx with a real certificate. With a self-signed test
certificate, Node tests use `NODE_TLS_REJECT_UNAUTHORIZED=0` (test only).

Verified:
- `wss://` hello + checkpoint: PASS;
- full live Floonet chain over WSS: `LIVE_CHAIN_WASM_VERIFY=PASS start=3318854 tip=3333295 batches=29`.


## PIBD (code added, live NOT VERIFIED)

`pibd` request: `{archive: hash, leaf: N}` → gateway fetches one bitmap segment
(height 9) and one output segment (height 11) via PIBD_HIST and returns a `UPB1`
bundle (hex). The browser must verify the roots.

Live test is blocked in this environment: the reachable local node is
Grin++ 2.0.0 with `caps=0x7`, `pibd=no`; a MW/Grin node is syncing from an old
height. So `pibd` live is **NOT VERIFIED** here. The Wasm UTXO/PIBD path is
verified only on the synthetic fixture (`UTXO_FIXTURE=2251`).


## Limits

- `--max-requests-per-conn N` (default 128): excess requests get
  `{"code":"rate_limited"}` on the same request id, then the connection closes.
- `--max-connections N` (default 64): excess connections are dropped.
- Max frame remains 1 MiB; response size is bounded by the header count.


## Public PIBD peers found, gateway PIBD handshake still failing

DNS seeds expose MW/Grin Floonet peers with PIBD:
`203.88.118.159:13414`, `96.44.159.174:13414` (`caps=0x5f`, `pibd=yes`).
The header-sync probe connects, but the gateway's PIBD connection gets
`handshake UnexpectedEof`; a local Grin++ node has no PIBD and a fresh MW node
did not finish synchronization. Live PIBD is therefore still **NOT VERIFIED**.


## PIBD retry diagnostic

`fetch_pibd` now retries 4 times (like header-sync), but public MW/Grin peers
still close the handshake (`UnexpectedEof`) from the gateway. A direct
header-sync sync to 3332160 returned headers, but writing a checkpoint was
refused by its two-independent-network policy. Live PIBD remains **NOT VERIFIED**.


## Mainnet read-only mode

`--mainnet` selects the mainnet checkpoint (`release/checkpoint.rwm`, height
4095360) and mainnet chain type. Verified mainnet headers from public peers:
`4095360 → 4102863`. Mainnet PIBD is NOT VERIFIED; peers rejected the handshake
after the initial tests. No user wallets/keys are used.


## Auto-discovery (no local node)

Without `--peer`, the gateway resolves the network DNS seeds, probes candidates
in parallel (6 s), keeps peers advertising `PIBD_HIST`, and selects up to 5 from
distinct /16 groups. Failed candidates are probed once more after a short pause.
The discovery thread refreshes the pool every `--discovery-interval` seconds
(default 300). `--peer` is a manual override (no discovery); `--no-discovery`
without `--peer` leaves the pool empty and WS requests return
`peers_not_found` instead of falling back silently.

Mainnet run (2026-11-12): 11 candidates, 3 PIBD peers, live header sync PASS.
Mainnet PIBD segments still time out. Evidence:
`evidence/auto-discovery-2026-11-12/REPORT_RU.md`.
