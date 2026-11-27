"""Create the RustSec input for the shipped binaries from their pinned lockfiles."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tomllib


def main():
    args = argparse.ArgumentParser()
    args.add_argument("database", type=Path)
    args.add_argument("output", type=Path)
    options = args.parse_args()
    source = Path(__file__).resolve().parents[1]
    locks = ["chain/fly-chain", "paycore/host", "ui/app", "transport/mailbox-nostr",
             "onion", "tor-bridges"]
    packages = {}
    paths = []
    for component in locks:
        path = source / component / "Cargo.lock"
        name = path.relative_to(source.parent).as_posix()
        paths.append(name)
        with path.open("rb") as stream:
            for item in tomllib.load(stream)["package"]:
                key = item["name"], item["version"], item.get("source", "")
                record = packages.setdefault(key, dict(name=key[0], version=key[1], source=key[2], locks=[]))
                record["locks"].append(name)
    out = options.output.resolve()
    out.mkdir(exist_ok=True, parents=True)
    inventory = out / "release-locks.json"
    inventory.write_text(json.dumps(dict(locks=paths, packages=list(packages.values()))), encoding="utf-8")
    with (out / "rustsec.txt").open("wb") as report:
        subprocess.run([sys.executable, "-X", "utf8", Path(__file__).with_name("rustsec_check.py"),
                        options.database.resolve(), inventory], check=True, cwd=out, stdout=report)


if __name__ == "__main__":
    main()
