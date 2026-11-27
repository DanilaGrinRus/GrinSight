"""Test the five new languages in actual packaged windows without creating any wallet or using the network."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from check_import_and_sync import require
from check_public_wallet_window import sha
from upgrade_window import observe_window


LOCALES = {"zh": "简体中文", "ko": "한국어", "ja": "日本語", "de": "Deutsch", "fr": "Français"}
EXPECTED = dict(create="Create a wallet", restore="Restore a wallet from words", options="Options", hide_options="Hide options",
                words="24 words, separated by spaces", ask="What is this?",
                example="Enter your 24 recovery words in their original order, with one space between words. For example: apple river stone …")


def labels(code):
    catalog = Path(__file__).resolve().parents[1] / "ui" / "app" / "lang" / code / "LC_MESSAGES" / "fly-ui.po"
    raw = catalog.read_text(encoding="utf-8-sig")
    strings = {json.loads(msgid): json.loads(msgstr)
               for msgid, msgstr in re.findall(r'^msgid (".*")\nmsgstr (".*")$', raw, re.M)}
    translations = {k:strings[v] for k,v in EXPECTED.items()}
    require(all(translations.values()) and all(translations[k] != EXPECTED[k] for k in ("create", "restore", "example")),
            "missing translations for " + code)
    require("apple river stone" in translations["example"], "recovery example words changed in " + code)
    return translations


def run(args, root):
    local = root / "local"
    local.mkdir()
    env = dict(os.environ, LOCALAPPDATA=str(local), APPDATA=str(root / "roaming"))
    Path(env["APPDATA"]).mkdir()
    subprocess.run([args.exe, "--prepare-only"], env=env, cwd=root, check=True, capture_output=True, timeout=120)
    built, = local.rglob("bin/fly-paycore-host.exe")
    print(json.dumps(dict(exe_sha256=sha(args.exe))), flush=True)
    for code,native in LOCALES.items():
        work = root / code
        work.mkdir()
        argv = [args.exe, "--host", built, "--profile", work / "empty", "--guard-dir", work / "guard"]
        spec = dict(native=native, login_capture=str(args.out / f"{code}-login.png"),
                    help_capture=str(args.out / f"{code}-restore-help.png"), **labels(code))
        result = observe_window(argv, built.parent.parent, work, env, "", None, 45, language_check=spec)
        result["language_persisted"] = ("lang=" + code in
            (work / "ui.txt").read_text(encoding="utf-8").splitlines()) if (work / "ui.txt").exists() else False
        print(json.dumps(dict(locale=code, **result)), flush=True)
        require(result["window_stage"] == "accepted" and result["exit_code"] == 0 and result["language_persisted"],
                "locale window failed: " + code)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=lambda s: Path(s).resolve(strict=True), required=True)
    parser.add_argument("--out", type=lambda s: Path(s).resolve(), required=True)
    args = parser.parse_args()
    args.out.mkdir(exist_ok=True, parents=True)
    with tempfile.TemporaryDirectory(prefix="grinsight-languages-") as tmp:
        run(args, Path(tmp))
