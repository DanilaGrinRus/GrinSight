# GrinSight — бэкенд подключён

**Статус: подключено.** Flutter-приложение работает с настоящим ядром через
`grinsight-service` (JSON-RPC 2.0). Демо-данные на экранах удалены; поддельное ядро
осталось только в `test/fake_core.dart`.

## Как устроено

```
Flutter UI (Dart)
├── backend/grinsight_service.dart   JSON-RPC клиент (HTTP loopback, Bearer token)
├── backend/real_core.dart           WalletCore поверх сервиса
├── backend/backend_io.dart          поиск exe/данных, запуск/остановка сервиса
└── backend/backend_stub.dart        заглушка для web (desktop-сервиса там нет)
        │
        ▼
grinsight-core/grinsight-service.exe serve [--data-dir …]
        ├── reverse-wtema-header-sync.exe   заголовки/доказательство
        ├── grinsight-tor.exe                   Tor/адресная книга
        └── checkpoints/
```

- Сервис печатает `GRINSIGHT_SERVICE_PORT` и `GRINSIGHT_SERVICE_TOKEN`; приложение
  отправляет JSON-RPC на `127.0.0.1:<port>/rpc` с Bearer-токеном.
- Фраза отправляется один раз в `wallet.create`/`wallet.restore`; vault шифруется
  паролем (scrypt + ChaCha20-Poly1305). Dart не хранит фразу после вызова.
- Суммы — только nanogrin (int); `nanoToGrin`/`grinToNano`, `double` не используется.
- Долгие операции — job: `wallet.open`, `wallet.send`, `wallet.finalize`,
  `wallet.broadcast`, `wallet.confirm`, `wallet.pay_invoice`; прогресс — `job.status`,
  отмена — `job.cancel`.

## Пути и данные

- exe: `GRINSIGHT_SERVICE_EXE`, затем `<папка grinsight.exe>\grinsight-core\…`,
  затем dev-путь `C:\DHW\GrinFlyClient\GrinSight\dist\grinsight-core\…`.
- data-dir: `GRINSIGHT_DATA_DIR`; в dev — `dev-data` (профиль
  `floonet1`), иначе `%APPDATA%\GrinSight`.
- Для проверки без ввода фразы:
  `GRINSIGHT_DATA_DIR=…\dev-data`,
  `GRINSIGHT_DEV_PROFILE=floonet1`,
  `GRINSIGHT_DEV_PASSWORD=<тестовый пароль>` (в код не записан),
  `GRINSIGHT_DEV_NETWORK=floonet`. Приложение само откроет кошелёк.
- Поставка: `grinsight-core` лежит рядом с `grinsight.exe`; пользовательские данные
  в архив не включаются.

## Что вызывается

| Экран | Методы |
|---|---|
| Вход | `service.info`, `wallet.unlock`, `wallet.new_phrase`, `wallet.check_phrase`, `wallet.create`, `wallet.restore` |
| Главная | `wallet.status`, `wallet.address`, `wallet.payments` |
| Обновить | `wallet.open` + `job.status`/`job.cancel` |
| Отправка | `wallet.send` → S1, `wallet.finalize` (S2), `wallet.confirm` |
| Приём | `wallet.receive` (S2), `wallet.invoice`, `wallet.pay_invoice` |
| Настройки | `wallet.lock`, `wallet.set_settings` (extra_peers), `contacts.auto_accept`, `contacts.list` |

Маппинг стадий: `waiting_answer|waiting_sender|waiting_payer|waiting_issuer|building →
TxStage.waitingAnswer`; неизвестная стадия тоже `waitingAnswer` (не «разослано»). `finalized|broadcast → broadcast`; `in_block → inBlock`;
`confirmed → confirmed`; `reorged → reorged`; `cancelled → cancelled`.
Глубина подтверждений — `depth`, порог — `confirmations_needed` (10). Флаг `proof` —
только `sender_verified`/payment proof, не факт включения в блок.

## Живая проверка

- Testnet, профиль `floonet1`, `wallet.unlock` → `wallet.status`.
- UI показал **1394.710999 tGRIN**, `can_spend=true`, доказательство на блоке
  **3 332 390**, 4 независимых сети, `FRESH`.
- «Обновить» в UI запустил `wallet.open`; прогресс `headers`/`peers` виден в листе,
  после завершения высота/возраст обновлены.
- Упакованный exe запускает `grinsight-core\grinsight-service.exe` из своей папки;
  после закрытия приложения сервис останавливается.

## Исправление клиента

В готовом `grinsight_service.dart` HTTP-запрос отправлялся chunked (`rq.write`),
сервис отвечал `400 chunked bodies are not accepted`. Исправлено: тело кодируется в
байты, выставляется `Content-Length`, затем `rq.add(payload)`. Исправление внесено и
в `UI/backend/grinsight_service.dart`, и в копию приложения.

## Мелкие исправления после ревью

- Баланс в UI усекается до сотых, а не округляется вверх.
- `building` → waitingAnswer; неизвестные стадии не считаются «разосланными».
- Проверка суммы: при `amount >= available` — «Недостаточно средств с учётом комиссии».
- Dev-автовход не подставляет первый профиль, если заданный не найден.
- Статус Tor — из `status().tor.running`; при выключенном — «не подключён» + `tor.start`.
- Возраст вершины форматируется (`45 мин`, `1 ч 5 мин`); на Testnet суммы — `tGRIN`,
  подпись сети — «Testnet» (внутренний id `floonet`).
- Тестов теперь 23 (QR-кодек, QR адреса/слейтпака, вход/профили, чекпоинт и прежние проверки).

## Тестовый перевод

11.11.2026 через UI: `floonet1 → floonet2`, 1 tGRIN, S1/S2/finalize/confirm.
Комиссия 0.023, блок 3 332 475, depth 14/16. Отчёт:
[TRANSFER_TEST_2026-11-11_RU.md](TRANSFER_TEST_2026-11-11_RU.md).

## Standalone

- Поставка запускается из отдельной папки без `GRINSIGHT_*` и без dev-путей;
  сервис берётся из `grinsight-core` рядом с exe, данные — из `%APPDATA%\GrinSight`.
- VC++ runtime (`MSVCP140`, `VCRUNTIME140*`) положен рядом с exe и в `grinsight-core`;
  UCRT — системный компонент Windows 10/11.

## Своя контрольная точка

Добавлены `wallet.checkpoint_info`, `wallet.own_checkpoint` (job, cancel = пауза,
повторный запуск продолжает) и `checkpoint_source` в `wallet.set_settings`.
`checkpoint()` использует свою точку при `source=own`. Факт показа карточки
предложения хранится в `checkpoint_offer_seen`. UI-блок в листе доказательства:
источник/высота/хеш, создание, прогресс/пауза, переключатель, предупреждение о
несовпадении. Полный genesis-проход не завершался; запуск/отмена и info проверены.

## Осталось

- Живой send/receive прогонялись (Testnet, 1 tGRIN, отчёт в `TRANSFER_TEST_2026-11-11_RU.md`);
  живые счета (invoice/pay_invoice) ещё не прогонялись.
- Контакты/мессенджер требуют запущенного Tor; Tor-демон из UI пока не стартует.
- Смена пароля и показ seed в настройках не реализованы.
- Полный own-checkpoint от genesis на Testnet завершён (3 327 840, matches=true).
- Альтернатива FFI (grinsight-ffi C ABI) не используется: выбран JSON-RPC, как в готовом
  ядре. Ранее описанный FFI-план остаётся возможным путём для мобильных сборок.

## QR (UI)

QR — только показ и ввод уже существующего текста; ядро не меняется.
`qr_flutter` рисует адрес (M) и slatepack (L); длинный slatepack — части `GS:`.
`mobile_scanner` только Android; на Windows кнопка сканирования скрыта.
Подробности и ограничения — `QR_REPORT_2026-11-11_RU.md`.
