# Приёмка сборки: что проверено и чем

Один запуск проверяет всё автоматическое на одной зафиксированной сборке:

```
.\run_acceptance_tests.ps1
```

Результат: `evidence\acceptance-<время>\SUMMARY.txt`, в конце `ACCEPTANCE=PASS | FAIL | INCOMPLETE`.

- `BUILD_ID`: id пакета исходников (SHA-256 манифеста всех поставляемых файлов).
- В конце прогона id считается заново. Если исходники менялись во время прогона, результат FAIL.
- `INCOMPLETE`: какой-то набор пропущен, например C API без MSVC Build Tools.

## 1. Замечания аудита (15 пунктов) → исправление → тест

| № | Замечание | Исправление | Тест |
|---|---|---|---|
| 1 | `cmd /c` в `run_user.ps1` | Массив аргументов, прямой запуск, `.cmd`/`.bat` отклоняются | Проверка в PowerShell 7: `&`, `;`, `\|`, `&&` передаются как текст, маркер не создаётся. Своё правило приёмки: `run_acceptance_tests.ps1` тоже запускает без оболочки |
| 2 | GCP удаляет чужие ресурсы | Метка `grinsight_hp=1`. Немеченое не переиспользуется и не удаляется | `bash -n` (экспериментальный стенд, к приёмке кошелька не относится) |
| 3 | `grinsight gap` тратит по PARTIAL/старой сессии | Проверка PASS и свежести до запуска процесса (`Session::spend_gate` внутри `plan_gap`) | `grinsight-state` `session::tests::spend_refused_on_partial_or_stale_session` |
| 4 | `header-sync` PASS без проверки сложности | FAIL, state не пишется | `unchecked_difficulty_is_never_pass` |
| 5 | known-outputs без MAC при receive/invoice | MAC до выдачи ключа | `known_outputs_need_a_valid_mac_before_keys_are_handed_out` |
| 6 | Нестрогий журнал резервов | Строгий JSON, fail-closed, `--repair-pending` | `pending_journal_is_strict_and_repairable` |
| 7 | Паника потока сканирования скрывается | Ошибка; счётчик только после успеха | `panic_in_a_scan_thread_is_an_error` |
| 8 | Сбой между резервом и контекстом | Одна запись `payment`, порядок: контекст → запись → S1 | `send_crash_points_leave_a_safe_state`, `invoice_crash_points_and_lost_answer` |
| 9 | Messenger: ACK до обработки | Обработка по истории + устойчивый список id | `restart_after_ack_handles_the_stored_message_once`, `processed_messages_survive_a_restart` |
| 10 | Параллельный `finish` | Файловая блокировка на slate + маркер `FINALIZED` | `same_answer_from_three_paths_finalizes_once` (настоящий `Ctx::finish`; без блокировки тест падает: 3 финализации) |
| 11 | Inbox без квоты | Лимиты: 200 файлов, 16 МБ, 128 КБ на файл, 20 в минуту | `inbox_quota_and_rate` |
| 12 | `confirm_peer` без PoW/сложности | Полная проверка продолжения | `confirm_continuation_needs_valid_pow_and_difficulty` |
| 13 | Invoice в `paid` до доставки | Только после статуса DONE; повторная постановка неудачного ответа | Проверка в PowerShell; `failed_reply_can_be_queued_again_others_cannot` |
| 14 | PIBD-патч: пропуск при ошибке | `increment(error)`, fail-closed | Патч применяется, функция проверена отдельно |
| 15 | Строка seed-файла сдвигает номера | Ошибка с номером строки | `damaged_phrase_line_is_an_error_not_a_shift` |

## 2. Сбои платёжного процесса

| Сбой | Тест | Что доказывает |
|---|---|---|
| Прерывание после контекста, до резерва | `send_crash_points_leave_a_safe_state` | S1 не ушёл, input свободен, повтор работает |
| Прерывание после резерва, до S1 | то же | Резерв и контекст есть вместе. Input нельзя выбрать снова, штатная отмена (`--release-inputs --send-context`) работает |
| Invoice: прерывание после сохранённого ответа / после резерва | `invoice_crash_points_and_lost_answer` | Без резерва ничего не выдано. С резервом повтор выдаёт тот же сохранённый I2, второй платёж отклоняется |
| Потеря ответа получателя (S2) | `lost_receive_answer_is_resent_identically` | Повторный S1 даёт байт-в-байт тот же ответ, ключ один, ответ финализуется. **Тест нашёл ошибку:** раньше receive не сохранял ответ и повтор падал; исправлено |
| Потеря ответа на invoice (I2) | `invoice_crash_points_and_lost_answer` | Тот же I2 сколько угодно раз, резерв один |
| Перезапуск после ACK | `restart_after_ack_handles_the_stored_message_once` | Сохранённое, но необработанное сообщение обрабатывается ровно один раз |
| Две одновременные операции с одним input | `two_concurrent_payments_with_one_input` | Под блокировкой pending ровно одна успешна, резерв один |
| Один ответ пришёл тремя путями | `same_answer_from_three_paths_finalizes_once` | Одна финализация |

## 3. Reorg и восстановление

`run_with_state_dir_incremental_and_reorg_fallback` проходит управляемый сценарий через настоящий `gap::run` и state-dir:

1. Ветка A. Платёж тратит `id(10)` в блоке 725 и подтверждён.
2. Переход на ветку B: 725 заменён. `--gap-check-block 725:<hash A>` → `NOT_ON_VERIFIED_CHAIN`, input снова не потрачен, state откатывается на `state.prev` и догоняет.
3. Платёж снова майнится в 726 ветки B. State 726 совпадает с `output_root`, новый блок даёт `ON_VERIFIED_CHAIN depth=1`.
4. Подменённый state-файл не используется.

Сценарий синтетический. Живой reorg проверится сам, если попадёт в прогон: `-Confirm` перепроверяет блок подтверждения при каждом запуске.

## 4. Повтор на финальной версии

Всё перечисленное запускает `run_acceptance_tests.ps1`:

- grinsight-state (unit + платёжные сбои + fuzz);
- header-sync (reorg + fuzz P2P-сообщений);
- grinsight-ffi + C API (нужны MSVC Build Tools);
- grinsight-tor (+ fuzz сетевого входа);
- Python: `test_package_check` (инструмент упаковки). Политика сессии (бывший `grinsight.py`) теперь в Rust: `grinsight-state` `session::tests` и `header-sync` `--bin grinsight-sync`.
- Ядро для UI `grinsight-service` (замена `run_user.ps1`): `header-sync` `--bin grinsight-service` (хранилище seed, RPC, задачи, пиры) и `--test service_e2e` (весь путь платежа через настоящий процесс сервиса; сеть имитируется, подпись и slatepack делает настоящее ядро с фразой через stdin). `grinsight-tor` `seeds_from_stdin_reach_the_wallet_exe`.

## 5. Fuzzing

Детерминированный мутационный fuzz. Он берёт настоящие входы и тысячи раз портит их: инвертирует биты, режет, вставляет случайные байты и спецсимволы JSON, дублирует фрагменты, склеивает два входа. Проверяемое свойство одно: на любом входе вызов возвращает Ok или ошибку, без паники.

Число итераций задаётся переменной `GRINSIGHT_FUZZ_ITERS`, по умолчанию 1000–2000 на цель. Для долгого прогона: `$env:GRINSIGHT_FUZZ_ITERS=50000`.

| Что приходит извне | Тест |
|---|---|
| slatepack и slate JSON (S1, S2, I1, I2: receive / finalize / pay / info) | `fuzz::fuzz_slatepacks_and_slate_json` |
| Журнал pending, wallet-outputs (MAC), seed-файл | `fuzz::fuzz_wallet_files` |
| Checkpoint, recent-headers, state, bundle, release | `fuzz::fuzz_chain_files` |
| P2P от пиров: заголовки, блоки, транзакции, PIBD-сегменты, Hand/Shake, PeerAddrs, ответы сегментов (протоколы 1–3) | `gap::tests::fuzz_peer_messages` |
| HTTP-запросы Tor-слушателя | `fuzz_http_request_parser` |
| JSON-RPC Foreign API | `fuzz_foreign_api` |
| Конверты GrinMessenger | `fuzz_messenger_envelopes` |
| address-book.json | `fuzz_address_book` |

**Fuzz нашёл ошибку, исправлено:** разбор hex в checkpoint, MMR и release-файле падал (паника) на не-ASCII символе. Теперь это ошибка разбора.

## 6. Поставка и зависимости

- `python package_check.py pack` собирает пакет только по allow-list и пишет манифест с SHA-256 и id пакета. Если найдено что-то из списка ниже, пакет не создаётся:
  - seed-фразы (12+ слов BIP39 подряд);
  - `*.local.txt`, `.seed`;
  - контексты подписи (`sec_key`/`sec_nonce`) и напечатанные секретные ключи;
  - slatepack;
  - записи журнала, wallet-outputs, address-book, state-файлы;
  - папки `evidence`, `sessions`, `user-run-*`, `tor-wallet-*`.
- `python package_check.py scan <папка|zip>` проверяет любую поставку тем же сканером.
- `python package_check.py deps --advisory-db C:\DHW\advisory-db` описывает все 5 `Cargo.lock` и сверяет их с базой RustSec (локальный клон, офлайн).
  - **Ошибкой считается:** git-источник, неизвестный реестр, нет checksum, база старше 30 дней, или уязвимость, которой нет в `deps-accepted.txt`.
  - В `deps-accepted.txt` запись привязана к точной версии и содержит причину.

### Уязвимости зависимостей на 2026-11-11

| Advisory | Крейт | Решение |
|---|---|---|
| RUSTSEC-2026-0459 | libsqlite3-sys (SQLite в Tor-клиенте) | **Исправлено.** SQLite 3.54.1 через `tor/patches/libsqlite3-sys`. Тест `bundled_sqlite_has_the_cve_fix` |
| RUSTSEC-2024-0344 | curve25519-dalek 3.2.0 | Не достигается: путь только age → X25519, а там нет `Scalar::sub` |
| RUSTSEC-2026-0367/0368/0369/0429 | zip 0.5.13 | Не достигается: GrinSight не распаковывает zip (только PIBD-сегменты) |
| RUSTSEC-2023-0071 | rsa 0.9.10 | Не достигается: только проверка подписи публичным ключом, закрытого RSA-ключа нет |
| RUSTSEC-2026-0387 | crypto-bigint 0.5.5 | Есть в lock-файле, но в grinsight-tor не компилируется |
| RUSTSEC-2026-0097 (unsound) | rand 0.7.3 | Нужен собственный логгер, вызывающий `thread_rng`; такого нет |

Unmaintained-крейты выводятся как предупреждения.

Новая advisory или новая версия любого из этих крейтов роняет проверку, пока её не рассмотрят.

Подготовка базы, один раз:

```
git clone https://github.com/rustsec/advisory-db C:\DHW\advisory-db
```

Обновление перед приёмкой:

```
git -C C:\DHW\advisory-db pull
```

## 5. Tor-совместимость с grin-wallet и Grin++ (2026-11-12)

| Что | Тест |
|---|---|
| Точный протокол foreign API grin-wallet 5.5.1 | `grinsight-tor` `grin_wallet_5_5_1_{check_version,receive_tx,finalize_tx}` на доктест-байтах `api/src/foreign_rpc.rs` (commit f097811, `tor/grinsight-tor/tests/fixtures/`); ответ разбирается `grin_wallet_libwallet::VersionedSlate` в `header-sync/tests/tor_foreign_format.rs` |
| Политика `off/ask/contacts/all`, миграция книги `contacts→ask`, доверие заявленному адресу контакта, счёт не принимается автоматически | `policy_table`, `book_v1_migration_and_default`, `invoice_is_never_received_automatically` |
| Ручной приём: «Да» за 40 с, отказ, таймаут в inbox, лимиты 3/час 10, конверт мессенджера | `ask_accept_within_the_hold_…`, `ask_declined_by_the_user`, `ask_timeout_keeps_the_payment_in_the_inbox`, `ask_limits_stop_spam`, `messenger_ask_receives_once_and_keeps_the_answer` |
| Сервис: `tor.pending/decide/inbox`, `wallet.receive {inbox_file}`, `tor.status` | `service_e2e` (фейковый демон с реальным файловым контрактом) |
| Живые floonet-сценарии | `evidence/tor-compat-2026-11-12/REPORT_RU.md`: **6 из 6 PASS** (grin-wallet 5.5.1: ручное «Да», второй перевод без вопроса, таймаут → слейтпак → приём из входящих → finalize, выход с доказательством платежа, счёт по Tor; Grin++ 2.0.0: 5b kernel `090f36a8…` блок 3 333 495, 5a после фикса fee — kernel `085e3222…` блок 3 333 545) |
| Grin++ echo compact S2: не добавлять наши элементы повторно | `compact_s2_elements_are_detected_not_readded` (вместе с `finalize`, чинившим `Fee Dispute Error: 23500000, 34000000`) |

Приёмка 2026-11-12 прогнана на замороженной копии дерева (`evidence/acceptance-20261112-031031-frozen/`,
build `7983bb8a…`): в это же дерево параллельно писала другая сессия (web/PWA), поэтому
self-check «исходники не менялись» на живом дереве падал, хотя все шаги были PASS.
После того как та сессия затихла, **живое дерево прошло приёмку полностью**:
`ACCEPTANCE=PASS`, build `d81da19c…` — `evidence/acceptance-20261112-035915/`
(и повторно `d8d95c9e…` — `evidence/acceptance-20261112-040554/`).
Итоговая приёмка после правок документации: `ACCEPTANCE=PASS`, build
`b1a58d0284f969f40915e4220b3772f097ab31dd9263fd28935f9aa77ef9c3e8` —
`evidence/acceptance-20261112-065829/`.
После фикса Grin++ fee (S2 echo: не добавлять наши элементы повторно) и правок
документации: `ACCEPTANCE=PASS`, build
`fc0013ca7355dcb9fed0f1e3487d5a1ec6a06117756208587e03119285f89c87` —
`evidence/acceptance-20261112-072553/` (grinsight-state 85, header-sync 39).

