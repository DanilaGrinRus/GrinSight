"""Check the single-line UI catalogues using only Python's standard library."""
import json
import re
import sys
from pathlib import Path

APP = Path(__file__).resolve().parents[1]
LANGUAGES = ("de", "fr", "zh", "ko", "ja")
QUOTED = r'"(?:[^"\\]|\\.)*"'
STATIC = re.compile(r"@tr\(\s*(" + QUOTED + ")")
DYNAMIC = re.compile(r"\b(?:tr|note)\(\s*(?:&?\w+\s*,\s*)?(" + QUOTED + r")\s*,\s*(" + QUOTED + ")")
VERBATIM = ("BEGINSLATEPACK", "ENDSLATEPACK.", "apple river stone", "GrinSight",
            "Slatepack", "GRIN", "Nostr", "Tor", "GSHP1", "PIBD", "Mainnet", "grin1",
            "checkpoint.json", "history.proof")


def keys(pattern, sources):
    found = set()
    for source in sources:
        for match in pattern.finditer(source.read_text(encoding="utf8")):
            if pattern is DYNAMIC and not re.search("[А-Яа-яЁё]", match[2]):
                continue
            found.add(json.loads(match[1]))
    return found - {""}


def entries(lang):
    path = APP / "lang" / lang / "LC_MESSAGES" / "fly-ui.po"
    result = {}
    runtime = set()
    for entry in path.read_text(encoding="utf8").split("\n\n"):
        source = re.search(r"^msgid (.+)$", entry, re.M)
        translation = re.search(r"^msgstr (.+)$", entry, re.M)
        if not source or not translation:
            raise ValueError("Malformed PO entry")
        key = json.loads(source[1])
        if not key:
            continue
        if key in result:
            raise ValueError("Duplicate PO key")
        result[key] = json.loads(translation[1])
        if "#. runtime" in entry.splitlines():
            runtime.add(key)
    return result, runtime


def main():
    static_keys = keys(STATIC, (APP / "ui").glob("*.slint"))
    dynamic_keys = keys(DYNAMIC, (APP / "src").rglob("*.rs"))
    reference = None
    for lang in LANGUAGES:
        translated, runtime = entries(lang)
        errors = []
        for missing in static_keys - translated.keys():
            errors.append(("missing static", missing))
        for missing in dynamic_keys - runtime:
            errors.append(("missing runtime", missing))
        if reference is not None and translated.keys() != reference:
            errors.append(("inconsistent catalogue keys", lang))
        reference = translated.keys()
        for key, value in translated.items():
            if not value.strip() or key.count("{}") != value.count("{}"):
                errors.append(("empty or broken format", key))
            if any(marker in value for marker in ("▁", "<unk>", "\ufffd")):
                errors.append(("invalid spelling", key))
            if any(term in key and term not in value for term in VERBATIM):
                errors.append(("lost literal", key))
        if errors:
            for issue, source in errors:
                print(lang, issue, ascii(source), file=sys.stderr)
            raise SystemExit(1)
        print(f"{lang}: {len(translated)} messages, {len(runtime)} runtime entries, "
              f"all {len(static_keys)} Slint literals present")


if __name__ == "__main__":
    main()
