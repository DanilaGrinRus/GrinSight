"""Run the stock portable twice with one new, empty Mainnet profile on reviewed public sources."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time

from check_import_and_sync import Host, require
from upgrade_window import observe_window


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1 << 20), b""):
            digest.update(part)
    return digest.hexdigest()


def verify_default_point(profile):
    """Read the public network tag, height and hash that initialize the header cache."""
    origin = Path(__file__).resolve().parents[1] / "chain" / "headers" / "points" / "main.origin.json"
    expected = json.loads(origin.read_bytes())
    cache, = profile.rglob("headers.dat")
    with cache.open("rb") as stream:
        header = stream.read(49)
    require(len(header) == 49 and header[:8] == b"FLYHDR1\n", "unrecognized header cache")
    actual = header[8], int.from_bytes(header[9:17], "little"), header[17:].hex()
    require(actual == (expected["network"], expected["height"], expected["hash"]), "different starting point")
    proof = origin.with_name("main.history")
    return dict(network=actual[0], cache_height=actual[1], cache_block_hash=actual[2],
                release_origin_identical=True, proof_bytes=proof.stat().st_size, proof_sha256=sha(proof))


def run(args, root):
    def log(stage, **facts):
        print(json.dumps(dict(stage=stage, **facts), ensure_ascii=True), flush=True)

    peers = []
    for text in args.peer:
        address = ipaddress.IPv4Address(text)
        require(address.is_global and text not in args.exclude, "public independent peers required")
        peers.append(f"{address}:3414")
    require(len(set(peers)) == len(peers), "duplicate peer")
    local = root / "local"
    local.mkdir()
    env = dict(os.environ, LOCALAPPDATA=str(local), APPDATA=str(root / "roaming"))
    Path(env["APPDATA"]).mkdir()
    subprocess.run([args.exe, "--prepare-only"], cwd=root, env=env, check=True, capture_output=True,
                   timeout=120, creationflags=subprocess.CREATE_NO_WINDOW)
    chain, = local.rglob("bin/fly-chain.exe")
    host = chain.with_name("fly-paycore-host.exe")
    installed = root / "GrinSight.exe"
    shutil.copyfile(args.exe, installed)
    require(sha(installed) == sha(args.exe), "portable test copy differs")
    profile = root / "data" / "profile"
    profile.parent.mkdir()
    require(not profile.exists(), "expected empty profile")
    password = secrets.token_urlsafe()
    with Host(host, chain, root, env, peers, profile=profile) as wallet:
        wallet.call("host.profile.create", dict(network="main", password=password))
        if args.point:
            wallet.call("host.unlock", dict(password=password))
            accepted = wallet.call("host.import_checkpoint", dict(file_path=str(args.point)))
            require(accepted.get("imported") and accepted.get("locked"), "checkpoint did not verify")
    log("new_empty_wallet", exe_sha256=sha(installed), point_sha256=sha(args.point) if args.point else None,
        checkpoint=accepted["height"] if args.point else "application default", public_peers=peers)
    argv = [installed, "--guard-dir", root / "guard"]
    for peer in peers:
        argv += ["--chain-peer", peer]
    for label in ("first", "restart"):
        t = time.monotonic()
        result = observe_window(argv, chain.parent.parent, root, env, password, None, args.seconds,
                                public_progress=args.progress, ready_panel=args.first_language,
                                inspect_details=args.inspect_details)
        log("window_" + label, elapsed_s=round(time.monotonic() - t, 1), **result)
        stage = "compared" if args.inspect_details else "home-observed"
        require(result["window_stage"] == stage and result["exit_code"] == 0,
                f"live display check failed on {label}")
        status = result["status"]
        require(status["details_checked"] is args.inspect_details, "details inspection mode mismatch")
        if args.inspect_details:
            require(status["details"] == status["home"] and status["details_height"] == status["home_height"],
                    "inconsistent status in Details")
            point_prefix = ("Imported checkpoint at block ", "Импортирована точка на блоке ") if args.point else (
                "Release starting point.", "Точка из выпуска.")
            require(status["starting_point_detail"].startswith(point_prefix), "unexpected starting point in Details")
        else:
            require(status["details"] is None, "unexpected Details observation")
        if not args.point:
            log("default_point_" + label, **verify_default_point(profile))
        if args.first_language:
            chosen = result.get("language_chosen")
            require((chosen == "English") if label == "first" else (chosen is None),
                    f"unexpected language selection on {label}")
            require("lang=en" in (profile.parent / "ui.txt").read_text(encoding="utf-8").splitlines(),
                    "selected language was not stored for this profile")
            require(result["status"]["ready_explanation"], "wallet readiness explanation is missing")
            panel = result["status"]["ready_panel"]
            require(panel["stable"] and panel["modal_absent"] and panel["green_text_pixels"] >= 3 and panel["green_dot_pixels"] >= 3,
                    "persistent ready panel did not pass its window check")
    require(not any(profile.rglob("autonomous-headers-v1.bin")), "unexpected genesis history")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=lambda s: Path(s).resolve(strict=True))
    parser.add_argument("--point", type=lambda s: Path(s).resolve(strict=True),
                        help="optional public checkpoint to import; default is the packaged starting point")
    parser.add_argument("--peer", required=True, action="append")
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("--progress", required=True, type=Path)
    parser.add_argument("--seconds", type=int, default=1200)
    parser.add_argument("--first-language", action="store_true", help="verify the first-run chooser and readiness message")
    parser.add_argument("--inspect-details", action="store_true", help="open Details and compare it with the home status")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="grinsight-public-window-") as tmp:
        run(args, Path(tmp))
