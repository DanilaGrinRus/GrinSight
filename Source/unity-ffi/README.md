# unity-ffi — C ABI ядра Unity (этап 2)

`include/unity_state.h` — интерфейс для C/C++ (Grin++), мобильных обёрток и любых других хостов.
Хост отвечает за сеть, выбор пиров, файлы и часы; модуль — за всё, что решает «что правда»:
цепочку заголовков (PoW, сложность, связность, MMR заголовков), состояние UTXO из сегментов PIBD
и блоки, которые меняют состояние только если воспроизводят корни заголовка.

Сборка: `cargo build --release --offline` → `unity_state_ffi.dll`/`.so`/`.a`/`.lib`.

Проверка (C-программа против Rust): строит состояние из сохранённых сегментов, применяет блоки,
сравнивает корень, число UTXO и позиции с тем, что посчитал Rust; проверяет отказы
(блок, прячущий трату; блок не по порядку; недостающий сегмент; заголовок без PoW;
испорченный чекпоинт; подделанный файл состояния; сохранение под чужим заголовком).

- Linux/macOS: `tests/run_c_test.sh`
- Windows (MSVC Build Tools): `.\unity-ffi\tests\run_c_test.ps1`

Тестовые данные (`us-fixture`, функция `testkit`) — синтетическая цепочка, в сети недействительна.

## Session and balance (2026-11-11)

`unity.py` was ported to Rust (`unity_state::session`, CLI `unity` in header-sync).
The app reaches the same decisions through the C ABI:

* `us_session_open` / `us_session_summary` / `us_session_spend_gate`: open a
  session by its manifest pin; the summary says whether the wallet may spend
  NOW (PASS session, fresh tip at the host's clock);
* `us_wallet_balance`: available / reserved / incoming / immature from the
  known-outputs file and the pending journal, for the balance screen.
