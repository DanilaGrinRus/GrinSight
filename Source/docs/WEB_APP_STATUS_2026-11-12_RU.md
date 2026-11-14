# GrinSight WebApp — статус на 2026-11-12 (RU)

Это не отчёт о готовности. Полный Floonet E2E и iPhone-приёмка **не выполнены**.

## Проверено

| Компонент | Статус | Доказательство |
|---|---|---|
| Rust core → Wasm (Emscripten) | PASS | `web-core` build; 1 383 850 байт |
| Без LMDB/store в web | PASS | `cargo tree --features web` — 0 `grin_store`/`heed`/`lmdb` |
| Floonet checkpoint | PASS | `CHECKPOINT_HEIGHT=3318854` |
| Recent headers | PASS | `RECENT_HEADERS=62` |
| Address/key derivation | PASS | `tgrin1c2cdgqt0z0gcfx...` native=Wasm |
| S1 signing (real secp/slatepack) | PASS | `S1_LEN≈2000`, `BEGINSLATEPACK.` native=Wasm |
| Host storage (localStorage) | PASS | `STORAGE={"ok":true,"value":"storage-ok"}` |
| Full live Floonet header chain | PASS | `LIVE_CHAIN_WASM_VERIFY=PASS start=3318854 tip≈3333291..3333316 batches=29` |
| WSS transport (TLS proxy) | PASS | `WSS_SELFTEST=PASS checkpoint=3318854`; full chain over WSS PASS |
| Web Worker/PWA | PASS (diagnostic) | `worker-selftest.mjs`, `utxoFixture=2251` |
| Gateway peer pool/limits | PASS | fallback с мёртвого peer; `rate_limited` |
| UTXO/PIBD (synthetic fixture) | PASS | `UTXO_FIXTURE=2251` |
| Live PIBD/UTXO | **NOT VERIFIED** | peers `pibd=yes`, gateway handshake `UnexpectedEof` |
| Broadcast | NOT DONE | — |
| Flutter Web backend | NOT DONE | только `backend_stub.dart` |
| IndexedDB/OPFS | NOT DONE | Wasm — MemoryStorage/localStorage |
| iPhone Safari/PWA | NOT TESTED | устройство не предоставлено |

## Ключевые артефакты

- core Wasm `B61E9FF8…`? Актуальный: `2028178BF8BDCBFABB18D3C47A09B7D85EF04AF3A44DEF2A4E0B3F91D15BA4E1`
  (1 383 850 байт)
- browser/PWA Wasm `EFF426EC4F0C13E5399B3C05CBC3E84E18C2AE07613F3E5C9211C0A7ABD012B5`
  (1 284 546 байт)
- gateway `3F41F99B5ECE965D5BC90A569F7735E2C1845B6D291354BE694D05612F5ED7CA`
  (1 029 632 байта)
- Floonet checkpoint: `checkpoints/floonet/checkpoint.rwm` (3 318 854).

## Блокеры

1. **Live PIBD**: публичные MW/Grin Floonet peers (`caps=0x5f`, `pibd=yes`) принимают probe/header-sync, но gateway PIBD handshake получает `UnexpectedEof`; локальный Grin++ не имеет PIBD. Header-sync от публичного peer дошёл до 3332160, но запись checkpoint отклонена политикой «два независимых /16»; PIBD-сегменты по локальному archive header дали timeout. Нужен доступный Grin node с PIBD и синхронизированной цепью.
2. **iPhone**: Safari/PWA/установка/память не проверялись; iPhone не предоставлен.
3. **Flutter Web backend** не подключён; UI на web не является рабочим кошельком.
4. **WSS/TLS**: проверено через тестовый TLS reverse proxy; production Caddy/nginx с доверенным сертификатом не развёрнут.

## Нельзя утверждать

- «WebApp готов к Floonet»;
- «live UTXO проверен»;
- «iPhone работает»;
- «gateway доверенный» — он недоверенный и не проверяет цепочку.


## Mainnet read-only tests (2026-11-12)

По запросу пользователя выполнены без локального узла:

- Mainnet checkpoint `4095360`, public peers `107.172.238.20:3414` и др.
  (`caps=0x7f`, `pibd=yes`, `block_hist=yes`).
- Gateway `--mainnet`; публичные headers получены.
- Wasm mainnet chain:
  `MAINNET_CHAIN=PASS start=4095360 tip=4102863 batches=15`
  (позже tip 4102868); PoW/linkage/difficulty проверены в Wasm.
- Mainnet PIBD: **NOT VERIFIED**. После серии запросов публичные peers
  закрывают handshake (`UnexpectedEof`); gateway PIBD-запрос не получил bundle.
- Пользовательские кошельки/ключи/seed не использовались.


## Mainnet peer discovery (2026-11-12)

DNS seeds resolved 11 mainnet peers. PIBD-capable (`caps=0x5f`, `pibd=yes`):
`151.243.213.16:3414`, `185.177.219.185:3414`,
`192.227.211.112:3414`, `91.249.87.143:3414`.
Header-capable with block_hist: `107.172.238.20:3414`,
`107.172.44.229:3414`, `107.175.115.89:3414`, `141.11.100.9:3414`.

Mainnet headers через эти peers проверены в Wasm
(`4095360 → 4102863/4102868`). Mainnet PIBD всё ещё не получен: gateway
handshake к PIBD-пирам даёт `UnexpectedEof` даже после retry с паузой 7 с;
вероятно, peer удерживает предыдущее соединение/банит IP, либо проблема в
gateway handshake. PIBD bundle не получен.


## Auto-discovery (2026-11-12)

Gateway without `--peer` on mainnet discovered 3 PIBD peers from DNS seeds:
`195.201.2.51:3414`, `192.3.118.156:3414`, `103.7.54.154:3414`.
Live mainnet headers via auto pool:
`MAINNET_CHAIN_WASM_VERIFY=PASS start=4095360 tip=4102910 batches=15`.
`--peer` override and `--no-discovery` behavior tested. Mainnet PIBD segments
still not obtained.


## Feel the Future (2026-11-12)

- `verify_mode` (`checkpoint`/`header_proof`) is persisted, returned in status,
  and shown as a permanent FUTURE badge; toggles survive reload.
- Header-proof verifier: MMR membership + PoW + WTEMA, wire structs/codec, and
  bit-0x100 DNS discovery (`--header-proof-peers`, service endpoint).
- Live discovery: GCP nodes `34.136.136.137:3414`, `34.72.157.76:3414`
  are patched (`caps=0x15f`, `header_proof=yes`); local manual discovery =
  `checked=7`, `patched=2`.
- Earlier `patched=0` was a local false negative: stock `Capabilities` lacked
  `0x100`, so `from_bits_truncate` cut `0x15F` to `0x5F`. Fixed.
- GCP `header_proof_probe`: `LIVE HEADER-PROOF: PASS`, 3/3 memberships;
  PoW binding skipped by that tool (no in-process context).
- Vertical status text fixed; regression test exists.
- `flutter analyze` PASS; `flutter test` not runnable in this environment.


## Web wallet stage 1 (PIBD via gateway) — 2026-11-12

- Archive header 4 099 680: `00081e4c...b15e49`.
- GCP nodes are PIBD/header-proof ready, but after repeated probes their inbound
  slots are full and handshakes from our egress get `UnexpectedEof` / no Shake.
- Gateway reconnect storms removed: one attempt per request.
- Full PIBD bundle and Wasm UTXO are NOT obtained (BLOCKED).
- Evidence: `evidence/web-wallet-2026-11-12/REPORT_RU.md`.

## PIBD via gateway — UTXO PASS (2026-11-13)

- `:3416`, archive 4 099 680, 18 bitmap + 4 583 output segments.
- GPF1 116 767 218 bytes, 828 s; Wasm `utxoBundle` -> **350 448 UTXO**,
  `output_root` checked, 5 s.
- `PIBD_VIA_GATEWAY=PASS` for UTXO. Rangeproof/kernel still to fetch.


## 2026-11-13: HTTPS PWA + real browser wallet

- `backend_web.dart` uses the Wasm BIP39/ExtKeychain ABI and IndexedDB
  (PBKDF2 + AES-GCM). Create/list/unlock/phrase roundtrip pass in the browser.
- HTTPS local CA: `https://192.168.1.33:8443/`;
  install `/grinsight-local-ca.mobileconfig` on iPhone, then trust the CA.
- PWA artifact: `dist/grinsight-webapp-pwa-2026-11-13.zip`.
- Remaining: PIBD balance scan, send/receive, iPhone install/acceptance.


## 2026-11-13: CSP + local CanvasKit + update persistence

- PWA CSP restricts scripts/styles/connections; CanvasKit is local, not gstatic.
- Offline reload and wallet persistence across SW rebuild verified.
- Current artifact: `dist/grinsight-webapp-pwa-2026-11-13.zip`,
  SHA-256 `20B720A502CF2BBD3E3E4C08C939B0AF7A4E57CC012EA59A3A8C98424311B578`.
- Next: helper node for matching PIBD/rangeproof, then Web Worker scan.

## 2026-11-14 migration into canonical Source

- Copied the tested web stack from the old tree: `web-core` wallet ABI/scan,
  `web-gateway` PIBD/rproof/block endpoints, `backend_web.dart`, PWA bridge,
  gateway transport, CSP/local-CanvasKit index and service worker.
- Added `discover_single` to `grinsight-state` for Wasm (no threads).
- `web-core` Wasm and browser module build: PASS.
- `web-gateway` build: PASS.
- `flutter analyze`: PASS.
- `flutter build web --release --pwa-strategy=none --no-web-resources-cdn`: PASS.
- New UI changes were not overwritten; only web backend/bridge files were added.
- Not done: block window beyond the public-peer rate limit; send/tx relay; iPhone acceptance.


## 2026-11-14 canonical tree verification

- New canonical `Source` builds: web-core Wasm, browser module, gateway, Flutter web.
- Funded mainnet scan in the migrated Wasm on the filtered PIBD bundle:
  **9 757 500 000 nanoGRIN (9.7575 GRIN), 4 UTXOs**, 448 213 247-byte bundle.
- PWA artifact: `dist/grinsight-webapp-pwa-2026-11-14.zip`
  (15 870 563 bytes, SHA-256
  `C1EF4CD7F8A952F2DB3D800AA635D17570D4D34E6EE4FFECB16F8F6DE43624EA`).
- Blocks for send remain blocked by public-peer connection limits; no send yet.
