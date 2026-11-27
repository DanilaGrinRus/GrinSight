"""Offline regression for the trust boundary between the provider and the wallet.

Run with the release grin-proof-provider and fly-chain binaries. No profile
argument is accepted. The only profile used is created by TemporaryDirectory.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile


def invoke(exe, args, folder, expected):
    result = subprocess.run(
        [str(exe), *map(str, args)], cwd=folder, capture_output=True,
        text=True, errors="replace", timeout=45,
    )
    if result.returncode != expected:
        raise RuntimeError(f"{exe.name} {args[0]}: exit {result.returncode}, "
                           f"expected {expected}\n{result.stdout}\n{result.stderr}")
    return result


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def check(provider, chain, fixtures, work):
    profile = work / "clean-profile"
    profile.mkdir()
    point = profile / "own-point.json"
    proof = profile / "history.proof"
    shutil.copyfile(fixtures / "main.json", point)
    shutil.copyfile(fixtures / "main.history", proof)
    record = json.loads(point.read_bytes())
    require(record["height"] == 4115520, "unexpected mainnet fixture")
    original_digests = [hashlib.sha256(p.read_bytes()).digest() for p in (point, proof)]

    # The provider exercises checkpoint::check and proof::check_for for this
    # exact pair. All generated metadata is outside the recipient profile.
    expected = (f"research candidate main {record['height']} "
                f"{bytes(record['header_hash']).hex()} (GSHP1 sample; freshness unknown)")
    publication = work / "publication"
    for args in (["bundle", "main", point, proof, publication], ["check", "main", publication]):
        result = invoke(provider, args, work, 0)
        require(result.stdout.strip() == expected, "incorrect claim for a valid sample")
    print("PASS: provider verified the sample for the expected checkpoint.")

    changed = work / "changed-work.json"
    changed.write_text(json.dumps(dict(record, total_work=record["total_work"] + 1)), encoding="utf-8")
    truncated = work / "truncated.proof"
    truncated.write_bytes(proof.read_bytes()[:-1])
    for net, checkpoint, sample in (("test", point, proof), ("main", changed, proof),
                                    ("main", point, truncated)):
        result = invoke(provider, ["bundle", net, checkpoint, sample, work / "rejected"], work, 1)
        require("checkpoint rejected" in result.stderr or "history sample failed" in result.stderr,
                f"unexpected cause of refusal: {result.stderr}")
        require(not (work / "rejected" / "manifest.json").exists(), "published rejected data")
    print("PASS: wrong network, altered work and truncated proof were rejected.")

    require(set(profile.iterdir()) == {point, proof}, "recipient must receive exactly two files")
    # Both startup modes get the same unreachable peer. Heights distinguish
    # the bundled release point from the user's explicit genesis choice.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as unused:
        unused.bind(("127.0.0.1", 0))
        peer = f"127.0.0.1:{unused.getsockname()[1]}"
        fresh = work / "default-mainnet"
        fresh.mkdir()
        release = invoke(chain, ["headers", "--network", "main", "--data", fresh,
                                 "--peer", peer, "--seconds", "2"], work, 1)
        require(f"timeout: height={record['height']} hash={bytes(record['header_hash']).hex()} "
                in release.stdout, f"unexpected default starting point: {release.stdout}")
        require(not (fresh / "autonomous-headers-v1.bin").exists(), "ordinary startup replayed genesis")
        print("PASS: empty Mainnet profile starts at the exact bundled release checkpoint.")
        (profile / "genesis-main-v1.intent").touch(exist_ok=False)
        observed = invoke(chain, ["headers", "--network", "main", "--data", profile,
                                  "--peer", peer, "--seconds", "2"], work, 1)
    report = re.search(r"^timeout: height=(\d+) hash=([a-f0-9]{64}) \(([^\r\n]+)\)$",
                       observed.stdout, re.MULTILINE)
    require(report is not None and report.group(1) == "0"
            and report.group(2) == bytes(record["genesis"]).hex()
            and "tip freshness unknown" in report.group(3),
            f"unexpected wallet history or freshness outcome: {observed.stdout}")
    journal = (profile / "autonomous-headers-v1.bin").read_bytes()
    require(len(journal) > 2 and int.from_bytes(journal[:2], "big") == len(journal) - 2,
            "expected a single framed genesis header")
    require([hashlib.sha256(p.read_bytes()).digest() for p in (point, proof)] == original_digests,
            "wallet changed the received files")
    print("PASS: separate wallet process stayed at exact mainnet genesis with unknown freshness.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", required=True, type=Path)
    parser.add_argument("--chain", required=True, type=Path)
    args = parser.parse_args()
    fixtures = Path(__file__).resolve().parents[1] / "chain" / "headers" / "points"
    with tempfile.TemporaryDirectory(prefix="grinsight-two-file-") as temp:
        check(args.provider.resolve(strict=True), args.chain.resolve(strict=True), fixtures, Path(temp))
