# Unity — исследовательский лёгкий клиент Grin

**Статус: прототип / RESEARCH / NOT VERIFIED.** Testnet (mainnet — только чтение, в подготовке), отдельная директория, без изменений консенсуса. Не полная нода; кошелёк — исследовательский режим без интеграции с grin-wallet.

**UI-прототип (2026-11-11):** бренд **GrinSight** («Revelio for your coins»). HTML-макет — `UI/prototype/index.html` (предыдущая итерация); текущая реализация — Flutter `UI/flutter_app/`: доказанный баланс и проверка (блок, пиры, output_root, ROOTS_OK, GAP_WALLET), история операций со статусами S2/финализация/блок/подтверждения/reorg, вход в трёх сценариях (открыть/восстановить/создать) с защищённым seed, автоприём на 3 режима, свой пир 3414, отправка с доставкой и шагами S2, лента контакта; RU/EN; живое ядро `grinsight-service` (Testnet, 1394.710999 GRIN). Проверены `dart analyze`, 7 виджет-тестов, web- и Windows-сборка, запуск Windows-приложения; бэкенд подключён — `UI/flutter_app/BACKEND_PLAN_RU.md`. Ключи/фраза — в сервисе. Бриф — [UI/DESIGN_BRIEF_RU.md](UI/DESIGN_BRIEF_RU.md), скриншоты — `UI/flutter_app/shots/`.

**Обновление 2026-11-10, вечер: состояние до tip доказывается.** Режим `unity.py gap` восстанавливает множество UTXO на архивной высоте по PIBD-сегментам обычных пиров, сверяет его с `output_root`, затем применяет каждый блок до вершины и на каждом блоке сверяет `output_root` и `kernel_root` с заголовком. Состояние сохраняется (`--state-dir`) и обновляется инкрементально. Режим кошелька (`--seeds`) находит свои outputs по seed (rangeproof-сегменты, проверенные по `range_proof_root`), считает доказанный баланс и может собрать и разослать самоперевод. Всё проверено вживую на Testnet; результаты, команды и ограничения — в [GAP_EXPERIMENT_2026-11-10_RU.md](GAP_EXPERIMENT_2026-11-10_RU.md), план развития — в [PLAN_VERIFIED_LIGHT_MODE_RU.md](PLAN_VERIFIED_LIGHT_MODE_RU.md). Разделы ниже про `verify-state`/PIBD описывают более ранний этап и остаются верными для него.

**Обновление 2026-11-10:** реализована привязка state proof к проверенной сессии и получение bitmap/output PIBD-сегментов от обычного пира без локального TxHashSet. Детали и команды: [PIBD_SESSION_2026-11-10_RU.md](PIBD_SESSION_2026-11-10_RU.md). Результат подтверждает состояние на архивной высоте, а не актуальный unspent на tip.

**Аудит 2026-11-10:** исправления и результаты повторных проверок описаны в [audit/RESULTS_2026-11-10.md](audit/RESULTS_2026-11-10.md). Статус sync относится только к проверке от внешнего checkpoint, а не к доказательству глобальной каноничности.

## Выбранная схема

1. Доверенный полный checkpoint и история предшественников фиксируются внешними SHA-256 пинами. Это явно задаёт доверие; нет подписанного реестра и автоматического выпуска checkpoint.
2. Копия проверенного в reverseWTEMA P2P header-sync последовательно получает заголовки обычных Testnet-пиров и проверяет PoW, difficulty, linkage и header MMR. Unity требует как минимум два непересекающихся разрешённых IP, сверяет полные заголовки каждой проверенной ветви до общей высоты, SHA-256 входных файлов и переходы сложности. `PASS` требует также свежий timestamp и достижения как минимум двух заявленных пирами высот и величин работы. Два IP не являются доказательством независимости и не защищают от eclipse. Любой успешно проверенный пир, предложивший отличающуюся ветвь, вызывает FAIL всей синхронизации: это позволяет одному пиру сорвать запуск. Высота и работа пиров являются их заявлениями; свежий timestamp сам по себе не доказывает каноничность.
3. Отдельный `unity-state-verify` проверяет output inclusion и bitmap proof против одного явно закреплённого **полного** заголовка. Учитывается merged output root, размер PMMR и связка позиции/индекса/commitment. Бит без доказанной привязки output к позиции даёт `UNKNOWN_IDENTITY_UNBOUND`, а не `SPENT`.
4. `unity.py verify-state` принимает локальный файл proof или URL. Удалённый URL требует HTTPS; HTTP разрешён только на loopback. Поставщик данных не доверенный, доказательство проверяется локально.

## Проверено 2026-11-10

- Header-sync: 37 unit tests PASS, 4 ignored в стандартном запуске (2 прежних + 2 бенчмарка); `load_real_floonet_checkpoint` ранее дополнительно запускался с Unity-фикстурой и прошёл, `real_block_binding` отдельно не запускался.
- Archive → tip на живом Testnet (подробности в отчёте эксперимента): восстановление 2 954 587 UTXO по сегментам с совпадением `output_root`; тела всех блоков промежутка от двух пиров с совпадением `output_root` и `kernel_root` на каждом блоке; различение «не потрачен до вершины» / «потрачен в промежутке»; инкрементальный запуск от сохранённого состояния — секунды.
- Кошелёк на живом Testnet: поиск своих outputs по трём тестовым фразам (2 954 587 rangeproofs, сегменты проверены по `range_proof_root`), доказанный баланс; самоперевод собран, разослан через P2P, включён в блок 3330664; трата и новый output доказаны по `output_root`, kernel — по `kernel_root`.
- ReverseWTEMA full-header commitment regression: **15 tests PASS**, including the real C32 mined segment and hidden-header mutation. These test commitment binding, not consensus rejection by Unity header-sync; full C32 differential testing remains open.
- На двух Testnet-пирах: от закреплённого локального checkpoint 3318854 получены и проверены **512 заголовков** до 3319366; 512 PoW/target, 512 network difficulty, 512 MMR, unchecked=0. Сырые строки: `sessions/sync-wsvkajpz/sync.log`. Исторический запуск до исправления не выполнял автоматическое сравнение полных заголовков; он не подтверждает независимость пиров или глобальную каноничность.
- State: 3 unit tests PASS. На реальном Testnet output 3317318: `UNSPENT_AT_PINNED_HEADER`; файл proof получен от локального Bearnet sidecar с **копии** `.data/floonet_node`, после чего sidecar остановлен. `test_real.py`: проверка реального proof, 8 отрицательных сценариев и loopback-источник. Серверные verdicts не используются.
- Проверка неверного checkpoint pin и повторённого адреса пира → FAIL_CLOSED.

**Это две отдельные проверки.** Пример proof привязан к историческому header 3317318, в то время как live-sync начинался с другого checkpoint 3318854. Связь одной и той же live-головы с удалённым state proof не установлена. Текущее состояние пользователя/свежесть не доказаны. Наличие или корректность всей истории до trusted checkpoint не устанавливаются.

## Запуск / сборка

Требуются Rust MSVC и Python 3. Исходники Grin и offline-зависимости скопированы в `Unity/vendor` и `Unity/local-vendor`; другие проекты для сборки не нужны. Генерация новых sidecar evidence через `capture_real_proof.py` отдельно требует предоставленные пользователем Bearnet-сервер, checkpoint и данные состояния; проверка сохранённого evidence этого не требует. Происхождение зависимостей crates.io отдельно не аудировалось.

```powershell
cd C:\DHW\GrinFlyClient\Unity
$env:CARGO_TARGET_DIR="$PWD\.build\target"
$env:CARGO_HOME="$PWD\.build\cargo-home"
cargo build --offline --locked --manifest-path header-sync\Cargo.toml
cargo build --offline --locked --manifest-path state-verify\Cargo.toml
cargo test --offline --locked --manifest-path header-sync\Cargo.toml
cargo test --offline --locked --manifest-path state-verify\Cargo.toml
cargo test --offline --locked --manifest-path rust-v2\Cargo.toml
python test_real.py
python test_session.py
python test_pibd_real.py
python test_audit.py
```

Пример исторического proof (пин должен быть получен пользователем по доверенному каналу):

```powershell
python unity.py verify-state `
  --header evidence\real-header.bin `
  --header-sha256 cb8f67b2fd6b07d8d3630055dc780ae0bd1a508f3ca31d00767e8e9c32d706b4 `
  --commitment 09baa6696c739b6647c843a651ef1acad67303b5b8e1999be28d82cf94cc7339f2 `
  --proof evidence\real-proof.json
```

Header sync (пример только для исследовательских данных):

```powershell
python unity.py sync --checkpoint evidence\floonet-checkpoint.rwm `
  --checkpoint-sha256 271e40ceb31ca99978d7a320e50970dfdf8b10f9ce8622e6dff7d5f9b9728f66 `
  --history evidence\floonet-history.bin `
  --history-sha256 3e69fc015f25f45cb2dc2010bf569a967f3284f54377d8414b1c857e6567dc7e `
  --peer 96.44.159.174:13414 --peer 66.154.127.84:13414
```

Эти файлы и пины являются исследовательской фикстурой, а не подписанным выпуском checkpoint. Для реального использования оба пина должны быть получены по доверенному каналу, а не рассчитываться по файлам неизвестного происхождения непосредственно перед проверкой. `--help` показывает параметры.

В sync по умолчанию предел 1000 батчей и 600 секунд, порог возраста — три часа (`--max-tip-age-sec`). При недостижении заявлений двух пиров или устаревшей вершине выводится `PARTIAL` и код 3; `--allow-partial` сохранён для совместимости и не меняет код 3 для `PARTIAL`. Timestamp зависит от локальных часов и не подтверждает честность пиров. Если время запуска закончилось, команда завершается с ошибкой, а не выдаёт частичную сессию как PASS. Логи сессий содержат IP.

`full_header_sha256` и `manifest_sha256` являются идентификаторами результата и сами по себе не создают доверенный checkpoint. Manifest должен приходить по доверенному каналу; проверить опубликованный вместе с недоверенной сессией hash недостаточно. `verify-state --session` сообщает `CURRENT_TIP_STATE=AT_VERIFIED_TIP_ONLY` лишь для успешно проверенного proof на свежей вершине сессии `PASS`; каноничность при этом остаётся недоказанной. При старой или частичной сессии, другом height и ошибке proof статус `NOT_PROVEN`. Повторная проверка актуальности и reorg для сохранённого результата пока не автоматизирована.

Коды `verify-state`: **0** — `UNSPENT_AT_PINNED_HEADER`, **5** — `SPENT_AT_PINNED_HEADER`, **3** — `UNKNOWN`, **1** — ошибка. Это состояние на закреплённом заголовке: код 0 без проверки свежести и цепи не означает пригодность к трате. Архивный PIBD подтверждает только состояние на архивной высоте. Для получения сегментов достаточно одного пира; адреса перебираются и дубли удаляются только по строке. Проверка сегментов выполняется локально, а недоступность или отказ пира влияет на доступность, не устанавливая независимость источников. `UNITY_BIN_DIR` задаёт каталог исполняемых файлов; по умолчанию используется `.build/target/debug` с платформенным суффиксом.

Низкоуровневый `reverse-wtema-header-sync.exe` сохраняется для тестов и имеет дополнительные исследовательские опции. Рекомендуемый вход для Unity — `unity.py`, который накладывает более строгую политику.

## Осталось до пользовательского клиента

Закрыто 2026-11-10 (см. отчёт эксперимента): состояние от архива до tip, сохраняемое и инкрементально обновляемое состояние с откатом на предыдущий снимок, поиск своих outputs по seed, доказанный баланс, построение и рассылка транзакции, подтверждение по `output_root` и `kernel_root`, зрелость coinbase по проверенным высотам создания.

Открыто:
- **Доверие к цепочке заголовков:** выбор канонической ветви среди многих пиров, защита от eclipse/Sybil; сейчас два пира и наибольшая работа.
- **Checkpoint:** mainnet-checkpoint создаётся синхронизацией от genesis и сверкой полей с публичными источниками (`run_mainnet_checkpoint.ps1`, ещё не запускался); подпись checkpoint, доверенные ключи и процедура выпуска — не сделаны.
- **Reorg вживую** не встречался: откат на `state.prev.ust` и пересборка проверены только тестами; reorg глубже двух снимков ведёт к полной пересборке.
- **Интеграция кошелька:** реализация `NodeClient` для grin-wallet, адаптер для Grin++, непрерывный режим, mobile/FFI (план в PLAN_VERIFIED_LIGHT_MODE_RU.md).
- Запрос proof по URL (`verify-state --proof-url`) может раскрывать сервису интерес к конкретному output; HTTPS этого не скрывает.
- Негативные тесты на реальном C32-контрпримере; сейчас импортированы только unit-регрессии reverseWTEMA.
- Внешний аудит, fuzz всех парсеров (сегменты, блоки, файл состояния, бандл, checkpoint), Git и воспроизводимые релизные сборки, `cargo audit`/`deny`.

## Происхождение

`header-sync/src`, `rust-v2/src`, Grin и offline-vendor скопированы из reverseWTEMA; header-sync расширен экспортом проверенной сессии и PIBD-проверкой. `state-verify/src/wallet_state.rs` скопирован из Bearnet; Unity добавляет строгую проверку позиции и размера, pinned full-header и CLI. `unity.py`, `state-verify/src/main.rs`, `header-sync/src/gap.rs` (archive → tip, сохраняемое состояние), `header-sync/src/wallet.rs` (режим кошелька), `checkpoint_crosscheck.py` и скрипты `run_*.ps1` написаны в Unity. Исходные Bearnet и reverseWTEMA не редактировались.

`.data/floonet_node` — отдельная копия (около 6,24 GB), использована только для подготовки evidence и **не нужна для проверки сохранённого proof**. Оригиналы не изменялись. Не удалять пользовательские данные без отдельного решения.
