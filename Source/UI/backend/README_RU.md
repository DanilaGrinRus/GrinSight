# GrinSight: ядро кошелька для UI (`grinsight-service`)

`grinsight-service` — Rust-программа, которая заменяет `run_user.ps1` и `grinsight.py`.
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
- Ядро (`reverse-wtema-header-sync`, `grinsight-tor`) получает фразу только через
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
| `wallet.receive` | `slatepack` или `inbox_file` | ответ S2: `{tx_id, answer, amount, from, sender_verified}`. Повтор того же S1 возвращает тот же ответ. С `inbox_file` — принять платёж из входящих Tor: `{tx_id, answer, slatepack, amount, from, sender_verified, slate_id, resent}`, где `answer` и `slatepack` — один и тот же **S2 в броне** для ручной передачи отправителю (`grin-wallet finalize`); файл и его `.meta.json` удаляются. Счёт (`invoice-*.txt`) так принять нельзя |
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
| `tor.start` / `tor.stop` / `tor.status` | `[relay]` | Tor-демон (он же GlauxNet); стартует сам в `wallet.unlock`, если `glauxnet` включён; `relay` по умолчанию из `glauxnet_relay`. В статусе адреса, события, входящие счета, `pending_count` и `foreign_api: {address, onion}` |
| `tor.pending` | — | запросы, ждущие ручного «Да»: массив `[{slate_id, amount, fee, from, channel, expires_in_s, waiting, sender_verified, received_at}]`. `channel`: `tor-foreign` (адрес заявлен отправителем) или `messenger` (адрес подтверждён подписью). `waiting = true`, пока отправитель по Tor ещё держит запрос (окно 40 с, `expires_in_s` — сколько осталось); у конверта мессенджера `waiting = false`, `expires_in_s = 0` |
| `tor.decide` | `slate_id (UUID), accept, [add_contact = true], [name]` | ответ на запрос: `{accepted, answered_over_tor, contact_added}`. Решение пишется атомарно в `tor-wallet-1/decisions/<slate_id>.json`; при `accept` и `add_contact` отправитель добавляется в адресную книгу (`contact_added` — реальный успех `book add`). `answered_over_tor = true`, только если ответ успевает к ждущему отправителю (`tor-foreign` и окно не истекло); иначе он получил слейтпак, и платёж принимается вручную из входящих |
| `tor.inbox` | — | входящие платежи и счета: массив `[{file, kind, amount, fee, from, received_at}]`, `kind`: `payment` / `invoice`, новые сверху. Для платежа — `wallet.receive {inbox_file}`; для счёта — `wallet.pay_invoice {inbox_file}` |
| `tor.deliver` | `tx_id, [messenger], [messenger_only]` | передать платёж или счёт демону: он доставит, примет ответ, финализирует и разошлёт. Если `pay_invoice` без `messenger`, I2 уходит на onion адреса `grin1…` выпустившего (Foreign API `finalize_tx`, без `--messenger-only`); адрес берётся из I1 и сохраняется в `meta.json` (`to`). Нет адреса — ошибка «the invoice has no issuer address» |
| `contacts.list` / `add` / `remove` / `auto_accept` | `id, name, messenger, auto` / `mode: off, ask, contacts, all` | адресная книга. `ask` (по умолчанию) — первый платёж от незнакомого отправителя ждёт ручного «Да»; `contacts` — автоприём только контактов, незнакомые во входящие без вопроса; `all` — принимать всех; `off` — всё во входящие |

Порог подтверждения: глубина 10 (`confirmations_needed` в `wallet.payments`).

## Ручной приём по Tor (режим `ask`)

grin-wallet и Grin++ по Tor присылают `receive_tx` сами; в режиме `ask`
(`contacts.auto_accept`) первый платёж от незнакомого отправителя не принимается
молча. Демон `grinsight-tor` кладёт запрос в `tor-wallet-1/pending/` и держит
HTTP-запрос отправителя до 40 с (отправитель ждёт до 60 с):

- `pending/<slate_id>.json` — `{slate_id, amount, fee, from, channel, received_at,
  expires_at, sender_verified, peer}`; `peer` — адрес мессенджера, только для
  `channel = messenger`; рядом `<slate_id>.s1.json` (S1 JSON) или
  `<slate_id>.s1.txt` (броня). Эти файлы читает только сервис;
- сервис пишет решение `tor-wallet-1/decisions/<slate_id>.json` =
  `{slate_id, accept, add_contact, name}` **атомарно** (временный файл +
  переименование). Демон читает его, отвечает отправителю и удаляет `pending/`.
  Сервис `pending/` не удаляет — файл может исчезнуть сам, это нормально;
- UI опрашивает `tor.status`: `pending_count > 0` — раз в 2 с, иначе раз в 10 с,
  и показывает диалог по `tor.pending`; ответ — `tor.decide`. Для
  `tor-foreign` в диалоге виден обратный отсчёт (`expires_in_s`), для конверта
  мессенджера — нет;
- не успели за 40 с: отправитель получил слейтпак, платёж лежит во
  `tor-wallet-1/inbox/` (`<slate_id>.json` рядом с `<slate_id>.meta.json`:
  `kind, amount, fee, from, channel, received_at, slate_id, file`).
  `tor.inbox` показывает его, `wallet.receive {inbox_file}` принимает и отдаёт
  S2 в броне для ручной передачи (`grin-wallet finalize`). Счёт
  (`invoice-*.txt`) так принять нельзя — только оплатить;
- `tor.status.foreign_api` — тот же `grin1…`/`tgrin1…` адрес и onion, по которым
  к нам ходят grin-wallet и Grin++ (пока GrinSight открыт и GlauxNet включён).

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
  slatepack выполняются настоящим ядром с фразой через stdin. Поддельный
  `grinsight-tor` пишет те же файлы, что и настоящий демон: проверяются
  `tor.pending`, атомарный `tor.decide` с добавлением контакта, `tor.inbox`,
  `tor.status.pending_count`/`foreign_api`, режим `ask` и ручной приём реального
  S1 JSON из входящих (ответ — S2-броня, файлы удалены).
- **Живая проверка** на Floonet — командами ниже.

```powershell
cd C:\DHW\GrinFlyClient\GrinSight; .\make_service.ps1
```

```powershell
cd C:\DHW\GrinFlyClient\GrinSight; $env:GRINSIGHT_PASSWORD = 'floonet-test-1'; .\dist\grinsight-core\grinsight-service.exe import-seed-file --file TESTNET_FUNDED_SEEDS.local.txt --index 1 --name floonet1 --network floonet --data-dir .\dev-data
```

```powershell
cd C:\DHW\GrinFlyClient\GrinSight; $env:GRINSIGHT_PASSWORD = 'floonet-test-1'; .\dist\grinsight-core\grinsight-service.exe open --name floonet1 --network floonet --data-dir .\dev-data
```
