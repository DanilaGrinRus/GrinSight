# GrinSight Web App — рабочая ветка

Статус: **spike / NOT READY**. Это не готовая iPhone-версия.

## Что уже доказано

- Полный `grinsight-state` (заголовки, MMR, PIBD/UTXO, keychain, slatepack) компилируется
  для `wasm32-unknown-emscripten` с C-зависимостями:
  `croaring-sys`, `grin_secp256k1zkp`, `lmdb-master-sys` (LMDB — только транзитивная
  зависимость, для browser-core её нужно убрать).
- Сборка: `web-core/build_wasm.ps1`; результат — Emscripten side module
  `grinsight_web_core.wasm` (≈280 КБ) и экспорты `gs_header_hash`, `gs_test_address`.
- Нативные эталонные значения: см. `web-core/README.md`; их должен повторить Wasm.

## Чего ещё нет

- JS-runtime Emscripten side module и вызов экспортов из Flutter Web.
- Storage-абстракции (IndexedDB/OPFS), worker, PWA, HTTPS-размещение.
- WSS-шлюза и реального P2P-обмена.
- Проверки на iPhone и Floonet E2E; ключи и проверка остаются только на устройстве.

## Шлюз: контракт следующего этапа

Транспорт: **WSS**, JSON-кадры UTF-8 (бинарный формат — после профилирования).
Один кадр ≤ 1 МБ; handshake ≤ 64 КБ; per-client очередь ≤ 16 кадров; rate limit
и max peers на клиента задаются конфигом. Шлюз **не хранит** seed, пароль, ключи
и не выполняет проверку состояния.

```text
client → gateway
  {"id":1,"method":"hello","params":{"protocol":1,"network":"floonet"}}
  {"id":2,"method":"peers","params":{"limit":8}}
  {"id":3,"method":"headers","params":{"from":3318854,"count":512}}
  {"id":4,"method":"pibd","params":{"height":3318854,"kind":"output","index":0}}
  {"id":5,"method":"block","params":{"hash":"…"}}
  {"id":6,"method":"broadcast","params":{"tx":"…"}}
  {"id":7,"method":"cancel","params":{"id":3}}

gateway → client
  {"id":2,"ok":true,"result":{"peers":[{"addr":"…","pibd":true,"agent":"…"}]}}
  {"id":3,"ok":true,"result":{"headers":["<hex>"],"more":true}}
  {"id":3,"ok":false,"error":{"code":"timeout","message":"…"}}
  {"event":"peer-down","peer":"…"}
```

Правила:

- Клиент сам проверяет заголовки, PoW/difficulty/MMR, PIBD-корни, блоки и подписи.
- Ответ шлюза никогда не считается подтверждением платежа.
- Несколько независимых шлюзов; UI показывает источник каждого результата.
- Один шлюз видит все соединения клиента и может фильтровать данные; это не
  доказывает независимость источников.
- Логи: IP/время/размеры/хэши запросов; seed и slatepack-содержимое не логируются.
- Таймауты, reconnect с backoff, отмена запросов, лимиты на соединение и очередь.

Точный протокол, коды ошибок и тесты появятся вместе с gateway-крейтом; серверная
проверка или хранение ключей в нём не предусмотрены.


## PWA-оболочка (диагностика)

`web/pwa/` — статическая PWA вокруг browser-модуля: module Web Worker,
manifest, service worker, иконки. Собирается `pwa\build_pwa.ps1` из
`web-core/browser/`. Worker прогнан в Node (`worker-selftest.mjs`), но в
Safari/iPhone не проверялся; это ещё не кошелёк и не полный UI.
