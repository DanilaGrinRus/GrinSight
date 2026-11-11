# GrinSight — "Revelio for your coins" 🐻

**A light Grin wallet that checks everything itself.** No own node, no trusted node:
GrinSight downloads data from public Grin peers and verifies it locally — headers,
proof of work, the unspent-output state against `output_root`, every new block
against `output_root` / `kernel_root`. It shows a balance only after proving it.

**Лёгкий кошелёк Grin, который всё проверяет сам.** Своя нода не нужна, чужой
доверять не нужно: баланс показывается только после доказательства по цепочке.

![GrinSight overview](Documents/diagrams/01-overview.svg)

## Download / Скачать

All files are on the [Releases](../../releases) page / Все файлы — на странице релизов.

| | File / Файл |
|---|---|
| **Windows 10/11 x64** — ready to run, mainnet checkpoint inside / готово к запуску, контрольная точка внутри | `GrinSight-0.1.0-windows-x64.zip` → unzip, run `grinsight.exe` |
| Android 7+ (arm64) | coming soon / скоро |
| Documents / Документы | `GrinSight-0.1.0-documents.zip` (also in [Documents](Documents)) |
| Source code / Исходники | `GrinSight-0.1.0-source.zip` (also in [Source](Source)) |

Check the files against `SHA256SUMS.txt` / Сверьте файлы с `SHA256SUMS.txt`.

## Repository / Репозиторий

```
Documents/   how it works, mathematics, release notes, diagrams, dependencies
Source/      code: core (Rust), Tor/GlauxNet, C API, Flutter app, build scripts
```

## Documentation / Документация

| | English | Русский |
|---|---|---|
| How it works and how to use it | [HOW_IT_WORKS_EN](Documents/HOW_IT_WORKS_EN.md) | [HOW_IT_WORKS_RU](Documents/HOW_IT_WORKS_RU.md) |
| Mathematics and trust boundaries | [MATHEMATICS_EN](Documents/MATHEMATICS_EN.md) | [MATHEMATICS_RU](Documents/MATHEMATICS_RU.md) |
| Release notes | [RELEASE_NOTES_EN](Documents/RELEASE_NOTES_EN.md) | [RELEASE_NOTES_RU](Documents/RELEASE_NOTES_RU.md) |

How the balance is calculated / Как появляется баланс:

![Balance](Documents/diagrams/02-balance.svg)

How a payment works / Как проходит платёж:

![Payment](Documents/diagrams/03-payment.svg)

## License / Лицензия

Free to use, change and share **with attribution to the author (DanilaBear)**:

- code — [MIT](LICENSE);
- documentation and diagrams — [CC BY 4.0](LICENSE-DOCS.md);
- third-party components keep their own licenses — [NOTICE](NOTICE.md).

Свободная лицензия с обязательным указанием автора (DanilaBear): код — MIT,
документация и схемы — CC BY 4.0.
