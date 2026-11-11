# GrinSight: ядро кошелька для UI (`grinsight-service`)

`grinsight-service` — Rust-программа, которая заменяет `run_user.ps1` и `unity.py`.
Во время работы Python и PowerShell не нужны. Сборка комплекта: `.\make_service.ps1`,
результат в `dist\grinsight-core\`. Эту папку приложение кладёт рядом с `grinsight.exe`.

## Как приложение с ним говорит

1. Запуск: `grinsight-service.exe serve`. Данные лежат в `%APPDATA%\GrinSight`
   (можно задать `--data-dir`).
2. Сервис печатает две строки: `GRINSIGHT_SERVICE_PORT=…` и `GRINSIGHT_SERVICE_TOKEN=…`.
3. Вызовы идут по JSON-RPC 2.0: `POST http://127.0.0.1:<port>/rpc` с заголовком
   `Authorization: Bearer <token>`. Запросы из браузера (заголовок `Origin`) и
   с нелокальным `Host` отклоняются.
4. Когда приложение закрывается, оно закрывает stdin сервиса, и сервис
   останавливается. Отдельной команды для остановки не нужно.

Готовый клиент на Dart — `grinsight_service.dart`. Его нужно скопировать в
`lib/backend/` и заменить им `DemoWalletCore`.

## Ключи

- `wallet.new_phrase` выдаёт фразу из системного генератора. UI показывает её
  один раз и просит подтвердить слова.
- `wallet.create` или `wallet.restore` получает фразу один раз. Фраза
  шифруется паролем (scrypt + ChaCha20-Poly1305) в `vault.json`. Дальше
  нужен только пароль при `wallet.unlock`.
- Ядро (`reverse-wtema-header-sync`, `unity-tor`) получает фразу только через
  stdin (`--seeds -`). Открытым текстом на диске фразы нет.
- Новый кошелёк (фраза сгенерирована этим сервисом) может принимать платежи
  сразу. Восстановленный сначала проходит `wallet.open`: сканирование цепочки
  показывает, какие ключи уже использованы.

## Методы

Суммы указаны в nanogrin (1 GRIN = 10⁹). Долгие методы возвращают `{job}`.
Их ход отслеживается через `job.status {id}`: поля `state` (running / done /
failed / cancelled), `phase`, `lines` и `result`. Отмена: `job.cancel {id}`.
Одновременно может идти только одна операция, меняющая кошелёк.

| Метод | Параметры | Ответ / что делает |
|---|---|---|
| `service.info` | — | версия, профили, какой открыт |
| `wallet.new_phrase` | — | `{phrase}` |
| `wallet.check_phrase` | `phrase` | ошибка с номером неверного слова |
| `wallet.create` / `wallet.restore` | `name, network (mainnet/floonet), phrase, password (≥8)` | `{origin: new/restored}` |
| `wallet.unlock` | `name, network, password` | то же, что `wallet.status` |
| `wallet.lock` | — | забывает ключи, останавливает Tor |
| `wallet.status` | — | `balance` (available / reserved / incoming / immature / total), `proof` (последнее открытие, высота, `session.freshness` и `can_spend` на сейчас), адрес, Tor |
| `wallet.open` (job) | — | контрольная точка → пиры → проверенные заголовки → доказанный баланс. В первый раз — установка (долго), дальше только новые блоки |
| `wallet.address` | — | `{address}` (grin1… / tgrin1…) |
| `wallet.send` (job) | `to, amount` | открытие + S1: `{tx_id, slatepack, fee}` |
| `wallet.receive` | `slatepack` | ответ S2: `{tx_id, answer, amount, from, sender_verified}`. Повтор того же S1 возвращает тот же ответ |
| `wallet.finalize` (job) | `tx_id, answer, [broadcast]` | подпись S2 / I2. По умолчанию сразу рассылка (настройка `auto_broadcast`) |
| `wallet.broadcast` (job) | `tx_id` | рассылка пирам |
| `wallet.confirm` (job) | `tx_id` | `{state: in_block / confirmed / reorged / not_in_block, height, depth}`. Kernel ищется в доказанном блоке; прежнее подтверждение перепроверяется на текущей цепочке |
| `wallet.invoice` | `amount, [payer]` | счёт I1: `{tx_id, slatepack}` |
| `wallet.pay_invoice` (job) | `slatepack` или `inbox_file` | открытие + I2: `{tx_id, answer, amount}` |
| `wallet.release` | `tx_id, [force]` | отменить зависший платёж, освободить его входы |
| `wallet.payments` | — | история: `stage` (waiting_answer, finalized, broadcast, in_block, confirmed, reorged, waiting_sender, waiting_payer, waiting_issuer, cancelled), `depth`, `confirmation` |
| `wallet.slatepack` | `tx_id` | slatepack платежа, чтобы показать или скопировать снова |
| `wallet.settings` / `wallet.set_settings` | `auto_broadcast, extra_peers, glauxnet, glauxnet_relay` | настройки профиля; `glauxnet` (по умолчанию `true`) — свой почтовый ящик при открытии кошелька; `glauxnet_relay` — запасной удалённый GlauxNet (http(s) URL, пусто = нет) |
| `glauxnet.status` | — | `enabled, running, state, onion, messenger_address, relay, tor`; `state`: `off` (выключен), `stopped`, `starting`, `local` (свой ящик за своим onion), `remote` (запасной сервер), `failed` |
| `glauxnet.enable` | `enabled` | включить/выключить (сохраняется в профиле и применяется сразу) |
| `tor.start` / `tor.stop` / `tor.status` | `[relay]` | Tor-демон (он же GlauxNet); стартует сам в `wallet.unlock`, если `glauxnet` включён; `relay` по умолчанию из `glauxnet_relay`. В статусе адреса, события, входящие счета |
| `tor.deliver` | `tx_id, [messenger], [messenger_only]` | передать платёж или счёт демону: он доставит, примет ответ, финализирует и разошлёт |
| `contacts.list` / `add` / `remove` / `auto_accept` | `id, name, messenger, auto` / `mode: off / contacts / all` | адресная книга |

Порог подтверждения: глубина 10 (`confirmations_needed` в `wallet.payments`).

## Соответствие экранам UI

- **Главный экран:** `wallet.status`. Сумма — `balance.available_nanogrin`, под ней
  «Зарезервировано», «Входит» и «Созревает». Плашка «доказано» берётся из
  `proof.session` (`freshness`, `can_spend`, `tip_height`); при `can_spend = false`
  нужно предложить «Обновить» (`wallet.open`).
- **История:** `wallet.payments`. Значения `stage` соответствуют `TxStage` из
  `wallet_model.dart`: waitingAnswer = waiting_answer / waiting_sender / waiting_payer
  / waiting_issuer, broadcast = finalized / broadcast, inBlock, confirmed, reorged.
- **Отправка:** `wallet.send` → показать S1 или `tor.deliver` → `wallet.finalize`
  (ответ S2) → `wallet.confirm`.

## Проверено

- **Модульные тесты** (`cargo test --bin grinsight-service`): хранилище (неверный
  пароль, подмена файла, нереальные параметры scrypt), HTTP (токен, Host, Origin,
  лимиты), задачи (stdin, отмена, таймаут), выбор пиров, разбор ответов ядра.
- **Сквозной тест** (`cargo test --test service_e2e`) поднимает настоящий процесс
  сервиса. Два кошелька проходят создание, адрес, открытие, отправку S1, приём S2
  и повтор, финализацию с рассылкой, подтверждение и перепроверку, счёт, блокировку
  и остановку по закрытию stdin. Сеть имитируется. Подпись, проверка транзакции и
  slatepack выполняются настоящим ядром с фразой через stdin.
- **Живая проверка** на Floonet — командами ниже.

```powershell
cd C:\DHW\GrinFlyClient\Unity; .\make_service.ps1
```

```powershell
cd C:\DHW\GrinFlyClient\Unity; $env:GRINSIGHT_PASSWORD = 'floonet-test-1'; .\dist\grinsight-core\grinsight-service.exe import-seed-file --file TESTNET_FUNDED_SEEDS.local.txt --index 1 --name floonet1 --network floonet --data-dir .\evidence\grinsight-data
```

```powershell
cd C:\DHW\GrinFlyClient\Unity; $env:GRINSIGHT_PASSWORD = 'floonet-test-1'; .\dist\grinsight-core\grinsight-service.exe open --name floonet1 --network floonet --data-dir .\evidence\grinsight-data
```
