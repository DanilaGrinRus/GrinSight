# GrinSight — Flutter-приложение (живое ядро)

**GrinSight · «Revelio for your coins».** Приложение больше не работает на демо-данных:
оно запускает `grinsight-service` и получает баланс, доказательство, историю и платежи
из JSON-RPC. Поддельное ядро осталось только в виджет-тестах (`test/fake_core.dart`).

## Что подключено

- **Старт/остановка сервиса.** `main()` находит `grinsight-core\grinsight-service.exe`
  (рядом с `grinsight.exe`, через `GRINSIGHT_SERVICE_EXE` или dev-путь
  `C:\DHW\GrinFlyClient\GrinSight\dist\grinsight-core`), запускает `serve` и читает
  порт/токен. На выходе приложения `close()` останавливает сервис; stdin-закрытие
  останавливает его и при аварийном завершении.
- **Вход.** `service.info` → список профилей; «Открыть» показывает реальный профиль
  (`floonet1`), пароль ≥8; `wallet.unlock`. «Восстановить» вызывает
  `wallet.check_phrase` (ошибка с номером слова) и `wallet.restore`. «Создать» берёт
  фразу только из `wallet.new_phrase`, показывает её, затем `wallet.create`.
  Dart не хранит фразу после передачи в create/restore.
- **Главный экран.** `wallet.status`: `available_nanogrin` крупно,
  `reserved/incoming/immature` строками, `total_nanogrin`; доказательство —
  `proof.session` (`tip_height`, `freshness`, `can_spend`, `tip_age_seconds`),
  `proof.last_open.sync.independent_nets` и `current_tip_state`.
  Если `can_spend=false` или сессии нет — кнопка «Обновить».
- **Обновление.** `wallet.open` → job; `job.status` даёт `phase`/`lines`,
  `job.cancel` — отмену. Прогресс показывается отдельным листом; первый запуск
  (установка) идёт минутами, дальше — секунды.
- **История.** `wallet.payments`; `stage` раскладывается в `TxStage`
  (`waiting_* → waitingAnswer`, `finalized/broadcast → broadcast`, `in_block`,
  `confirmed`, `reorged`, `cancelled`), глубина — из `depth`,
  порог `confirmations_needed`.
- **Отправка.** `wallet.send` (job) → S1 `slatepack` + `fee`; копирование S1,
  ввод ответа S2 → `wallet.finalize`; проверка подтверждения → `wallet.confirm`.
- **Приём.** `wallet.receive(slatepack)` сразу возвращает S2 `answer` для копирования;
  адрес — `wallet.address`.
- **Счета.** `wallet.invoice(amount)` (I1) и `wallet.pay_invoice` (job).
- **Настройки.** Профиль/сеть из статуса, «Свой пир» → `wallet.set_settings`
  (`extra_peers`), автоприём → `contacts.auto_accept`, «Обновить чекпоинт» → тот же
  `wallet.open`. Контакты — `contacts.list` (нужен запущенный Tor).
- **Суммы** — только nanogrin (int), `grinToNano`/`nanoToGrin`; `double` не используется.
  Ошибки сервиса показываются как `GrinSightError.message`.

## Исправления после ревью

- Баланс в UI усекается до сотых (`0.999 → 0.99`), а не округляется вверх; точное
  значение — в подсказке/`wallet.status`.
- Стадия `building` и неизвестные стадии маппятся в «ждём ответа», а не «разослано».
- При сумме ≥ доступного показывается «Недостаточно средств с учётом комиссии»
  (комиссия добавляется сверх суммы; окончательно решает ядро).
- Флаг `proof` в истории — только `sender_verified`/наличие payment proof, а не
  факт включения в блок.
- Dev-автовход больше не подставляет первый попавшийся профиль: если
  `GRINSIGHT_DEV_PROFILE` не найден, вход не выполняется.

## Исправления после ревью Tor/единиц

- Статус мессенджера берётся из `status().tor.running`: при выключенном Tor —
  «не подключён» и кнопка «Включить» (`tor.start`); после запуска статус обновляется.
- Возраст вершины человеческий: `45 с`, `45 мин`, `1 ч 5 мин`, `1 д 1 ч`.
- На Testnet суммы показываются в `tGRIN`, на Mainnet — в `GRIN`; подпись сети — «Testnet» (внутренний id сервиса остаётся `floonet`).

## Тестовый перевод 1 tGRIN (Testnet)

Проведён через UI между `floonet1` и `floonet2` (два окна, S1 → S2 → finalize →
confirm). Итог: A `1394.710999 → 1393.687999` (1 + комиссия 0.023), B
`1.367000 → 2.367000`; блок `3 332 475`, подтверждение depth 14/16; в истории A/B
метка доказательства. Подробно — [TRANSFER_TEST_2026-11-11_RU.md](TRANSFER_TEST_2026-11-11_RU.md).

`grinsight-core\checkpoints` в поставке проверен: `floonet` (pin) и `mainnet`
(signed release) на месте.

## Своя контрольная точка

Сервис теперь умеет:
- `wallet.checkpoint_info` — источник (`release`/`own`), высота и хеш точки из поставки,
  своя точка (готова/приостановлена), совпадение;
- `wallet.own_checkpoint` — job проверки всех заголовков от genesis
  (`--checkpoint genesis … --stop-below-tip 4320 --progress-dir`);
- `checkpoint_source` в `wallet.set_settings` — переключение источника без сброса кошелька;
- `checkpoint_offer_seen` — карточка предложения показывается один раз на профиль.

UI: в листе «Доказательство баланса» блок «Контрольная точка» — источник, высоты/хеши,
«Создать свою», прогресс и «Пауза» (cancel; повторный запуск продолжает), переключатель
«из поставки / своя», предупреждение при несовпадении. После первого открытия один раз
показывается карточка предложения с «Не сейчас»; факт показа сохраняется в
`settings.json` (`checkpoint_offer_seen`).

Проверено вживую:
- полный `own_checkpoint` на Testnet от genesis завершён: высота **3 327 840**,
  хеш `3b794fe1…2ecf51f4`, `matches: true`;
- открытие кошелька уже с `source=own` — `HEADER_SYNC=PASS`, баланс сохранён;
- переключение `own ↔ release` и `checkpoint_info` проверены;
- rolling-точка для own подхватывается (старая release-точка отброшена по base).

В поставке лежат обе точки: `checkpoints/floonet` (pin) и `checkpoints/mainnet`
(signed release).

## QR и сканирование

- **Адрес** в «Получить» — статичный QR (коррекция M, белый фон, тихая зона,
  280 px на телефоне / 360 px на десктопе), рядом адрес и «Копировать».
- **Slatepack** (S1, S2, I1, I2) — переключатель «Текст / QR»:
  до 1 000 символов один QR (L), длиннее — анимированные части по 500 символов
  `GS:<номер>/<всего>:<id>:<кусок>`, `id` — первые 8 hex SHA-256 всего текста;
  кадр каждые 400 мс, «Часть N из M», пауза и стрелки.
- **Android** — `mobile_scanner`: «Сканировать» у получателя, ответа финализации,
  S1 и оплаты счёта; сборка частей по `id`, проверка SHA-256, ошибка при
  повреждении, проверка сети адреса (`grin1`/`tgrin1`). После подстановки ничего
  не отправляется — пользователь жмёт «Принять»/«Финализировать»/«Оплатить».
- **Windows** — только показ QR; кнопка «Сканировать» скрыта.
- Android: проект переведён на боевое ядро. `applicationId`/`namespace` —
  `io.github.danilagrinrus.grinsight`, minSdk 24, ABI — из поставки ядра
  (`arm64-v8a` для телефонов и `x86_64` для эмулятора), есть `INTERNET`
  (release-сборка без него не выходит в сеть). Программы ядра лежат в
  `nativeLibraryDir` как `lib*.so` и запускаются оттуда, чекпоинты едут в assets и
  сверяются по SHA-256 при каждом запуске. Проверено: release-APK 42,73 МБ с
  `native-code: arm64-v8a, x86_64`. Подпись пока debug-ключом.
  Камера и QR-перевод на устройстве **не проверены** (отчёт:
  `evidence/android-2026-11-12/REPORT_RU.md`).
- Модальные листы не уезжают под системные области: `showUSheet` включает
  `useSafeArea` (верх/бока) и учитывает клавиатуру/панель снизу, поэтому заголовок
  и крестик не попадают под статус-бар и вырез. Регрессия —
  `test/insets_test.dart`.

Подробно: [QR_REPORT_2026-11-11_RU.md](QR_REPORT_2026-11-11_RU.md).

## Standalone-проверка

- Собран `dist\grinsight-windows-x64` и запущен из отдельной папки
  `C:\DHW\.tmp\standalone-grinsight-clean` с чистым `%APPDATA%`, без
  `GRINSIGHT_*`, с минимальным `PATH` (только Windows).
- Приложение стартует, `grinsight-service.exe` запускается **из папки поставки**
  (`…\grinsight-core\grinsight-service.exe serve`), без `--data-dir`; данные
  создались в изолированном `appdata\GrinSight`.
- Вход открылся, профилей нет: «No profiles. Create or restore a wallet» —
  сервис доступен, dev-путь `dist`/`evidence` не использовался.
- Зависимости: `dumpbin` показал у exe/ядра `MSVCP140`, `VCRUNTIME140`,
  `VCRUNTIME140_1`; VC++ runtime добавлен **app-local** в корень и в
  `grinsight-core` (иначе нужен установленный VC++ Redistributable).
- UCRT (`api-ms-win-crt-*`) — системный компонент Windows 10/11.

## Живая проверка

- Профиль `floonet1` из `dev-data`, сеть Testnet.
- Запуск с `--data-dir dev-data`, авто-вход через env:
  `GRINSIGHT_DATA_DIR`, `GRINSIGHT_DEV_PROFILE=floonet1`,
  `GRINSIGHT_DEV_PASSWORD=<пароль>` (в код не записан), `GRINSIGHT_DEV_NETWORK=floonet`.
- Получено в UI: **1394.71 tGRIN** (`1394.710999`), доказательство:
  «Доказан на проверенной вершине 3 332 390 · 4 независимых пира», `can_spend=true`.
- «Обновить» запускает реальный `wallet.open`: в листе видны фазы `headers`/`peers`,
  после завершения высота и возраст доказательства обновляются.
- Упакованное приложение использует `grinsight-core` рядом с exe; проверено, что
  сервис запускается из этой папки и останавливается вместе с приложением.
- В поставляемом Dart-клиенте исправлена реальная ошибка: HTTP-запрос уходил
  chunked (`rq.write`), сервис отвечал `chunked bodies are not accepted`. Теперь
  тело отправляется с `Content-Length`.

## Проверки

| Проверка | Результат |
|---|---|
| `dart analyze` | PASS, 0 issues |
| `flutter test` | PASS, 24/24 (QR-кодек, QR адреса/слейтпака, вход, чекпоинт, отступы листов) |
| `flutter build windows --release` | PASS |
| `flutter build apk --release` (arm64 + x86_64) | PASS: 42,73 МБ, debug-подпись |
| Установка APK на arm64-телефон | NOT VERIFIED (нет устройства) |
| Живой Testnet в UI | PASS: 1394.710999 tGRIN, `can_spend=true`, блок 3 332 390 |
| `wallet.open` из UI | PASS: лист прогресса `headers`/`peers`, обновление доказательства |
| Упакованный exe | PASS: `grinsight-core` рядом, сервис стартует/останавливается |
| Веб-сборка | только заглушка backend (desktop-сервис недоступен в браузере) |
| Демо-константы на экранах | нет; `kDemo*` остались только в тестовом fake |

## Запуск

```powershell
$env:FLUTTER_ROOT = 'C:\DHW\.toolchain\flutter'
$env:PUB_CACHE    = 'C:\DHW\.toolchain\pub-cache'
$env:APPDATA      = 'C:\DHW\.toolchain\appdata'
$env:LOCALAPPDATA = 'C:\DHW\.toolchain\appdata-local'
$env:TMP          = 'C:\DHW\.tmp\flutter-temp'

$dart = "$env:FLUTTER_ROOT\bin\cache\dart-sdk\bin\dart.exe"
$snap = "$env:FLUTTER_ROOT\bin\cache\flutter_tools.snapshot"
cd C:\DHW\GrinFlyClient\GrinSight\UI\flutter_app
& $dart $snap run -d windows
& $dart $snap test
& $dart $snap build windows --release
```

Для живого профиля добавьте `GRINSIGHT_DATA_DIR` и (для авто-входа в проверке)
`GRINSIGHT_DEV_*`. Для поставки скопируйте `dist\grinsight-core` в
`build\windows\x64\runner\Release\grinsight-core` (уже входит в
`dist\grinsight-windows-x64.zip`; пользовательские данные туда не кладутся).

Портативная сборка: `dist\grinsight-windows-x64.zip` (23,28 МБ, SHA-256
`ED959145421220415ADCC296C8945040EB574E79A65D4B0F047CA204CC4E9A2B`).

## Структура

```
lib/
  main.dart                 старт сервиса, состояние, вход/кошелёк, листы
  core.dart                 WalletCore + WalletJob (граница с ядром)
  wallet_model.dart         nanogrin, профили, баланс, proof, TxStage, платежи
  backend/
    grinsight_service.dart  JSON-RPC клиент ядра (с Content-Length)
    real_core.dart          WalletCore поверх сервиса
    backend_io.dart         поиск exe/data-dir, запуск сервиса
    backend_stub.dart       заглушка для web
  screens/login.dart        профиль/пароль/seed/создание через ядро
  screens/wallet.dart       live-баланс, доказательство, история
  qr_codec.dart             QR-формат GS:, сборка частей, проверка SHA-256
  qr_widgets.dart           QR адреса и slatepack (текст/QR, анимация)
  qr_scanner.dart           Android-камера и подстановка текста
  sheets.dart               отправка/приём/счёт/open-job/доказательство/настройки
test/
  widget_test.dart          виджет-тесты приложения
  qr_codec_test.dart        резка/сборка/повтор/неверный хеш
  fake_core.dart            поддельное ядро только для тестов
```

## Скриншоты

`shots/11-windows-app.png` — живое приложение на Testnet.
`shots/31-address-qr.png` — QR адреса в «Получить».
`shots/29-checkpoint-own.png` — блок контрольной точки с `source=own`;
`shots/30-wallet-own-checkpoint.png` — кошелёк с собственной точкой.
`shots/25-transfer-A-final.png`, `26-transfer-B-final.png` — итоговые балансы
после тестового перевода; `27-transfer-B-incoming.png` — B после S2;
`28-transfer-confirmed.png` — подтверждение в A (depth 14).
Остальные 01–24 — дизайн-прототип до подключения ядра; данные на них демонстрационные.

## Ограничения

- Отправка/приём живьём проверены на Testnet (см. отчёт); счета пока не прогонялись.
- Контакты/мессенджер требуют запущенного Tor; в проверке Tor не запускался.
- Смена пароля/показ seed в настройках пока не реализованы (честные сообщения об этом).
- Значок — из растрового референса; права и векторная перерисовка — до релиза.
- Старые скриншоты 01–24 отражают дизайн, а не live-данные.



