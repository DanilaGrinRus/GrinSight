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
