"""Read-only public Mainnet acceptance on a new profile, then the same profile reopened.

Pass reviewed public P2P IPv4 endpoints explicitly. No extra quorum sources are configured.
The profile is temporary and empty of funds. Output contains only chain status and timings.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

from check_import_and_sync import Host, require


def verify_tip(host, label, deadline):
    start = time.monotonic()
    while time.monotonic() - start < deadline:
        state = host.call("paycore.wallet.chain_status")
        chain = host.call("host.status")["chain"]
        height = state.get("tip_height")
        selected = state.get("selected_height")
        print(json.dumps(dict(profile=label, elapsed=round(time.monotonic() - start, 1),
                              wallet=state["state"], height=height, selected=selected,
                              stage=chain["phase"], detail=chain.get("problem"))), flush=True)
        if state["state"] == "at_tip" and height and height == selected:
            return
        time.sleep(12)
    raise TimeoutError(f"{label}: no selected tip during the observation window")


def run(args, root):
    local = root / "local"
    local.mkdir()
    env = dict(os.environ, LOCALAPPDATA=str(local))
    subprocess.run([args.exe, "--prepare-only"], check=True, cwd=root, env=env, timeout=90)
    chain, = local.rglob("bin/fly-chain.exe")
    host = chain.with_name("fly-paycore-host.exe")
    password = secrets.token_urlsafe()
    peers = []
    for text in args.peer:
        address = ipaddress.IPv4Address(text)
        require(address.is_global, "expected a public IPv4 address")
        peers.append(f"{address}:3414")
    require(len(set(peers)) == len(peers), "duplicate public peer")
    print(json.dumps(dict(public_peers=peers)), flush=True)
    with Host(host, chain, root, env, peers) as wallet:
        wallet.call("host.profile.create", dict(network="main", password=password))
        wallet.call("host.unlock", dict(password=password))
        imported = wallet.call("host.import_checkpoint", dict(file_path=str(args.point)))
        require(imported.get("imported") and imported.get("locked"), "checkpoint import failed")
        wallet.call("host.unlock", dict(password=password))
        verify_tip(wallet, "new", args.seconds)
    with Host(host, chain, root, env, peers) as wallet:
        wallet.call("host.unlock", dict(password=password))
        verify_tip(wallet, "reopened", args.seconds)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=lambda s: Path(s).resolve(strict=True))
    parser.add_argument("--point", required=True, type=lambda s: Path(s).resolve(strict=True))
    parser.add_argument("--peer", required=True, action="append")
    parser.add_argument("--seconds", default=600, type=int)
    with tempfile.TemporaryDirectory(prefix="grinsight-public-only-") as folder:
        run(parser.parse_args(), Path(folder))
