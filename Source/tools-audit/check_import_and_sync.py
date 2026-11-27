"""Acceptance test for Windows portable. Uses a new empty wallet, never signs or sends.

The two inputs are the PUBLIC exported checkpoint and sample. The read-only
network part starts only with --live. It writes a sanitized JSONL report.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Host:
    def __init__(self, exe, chain, work, env, peer=None, *, profile=None):
        args = [exe, "--profile", profile or work / "wallet", "--guard-dir", work / "guard", "--chain", chain]
        if peer:
            for address in ([peer] if isinstance(peer, str) else peer):
                args += ["--chain-peer", address]
        self.proc = subprocess.Popen(args, cwd=work, env=env, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     encoding="utf-8", bufsize=1,
                                     creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        self.responses = queue.Queue()
        self.sequence = 0
        threading.Thread(target=self.read_responses, daemon=True).start()

    def read_responses(self):
        try:
            for line in self.proc.stdout:
                response = json.loads(line)
                if "id" in response:
                    self.responses.put(response)
        finally:
            self.responses.put(None)

    def call(self, method, params=None):
        self.sequence += 1
        obj = dict(jsonrpc="2.0", id=self.sequence, method=method, params=params or {})
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()
        response = self.responses.get(timeout=150)
        require(response and response.get("id") == self.sequence, f"no matching reply for {method}")
        if "error" in response:
            kind = response["error"].get("data", {}).get("kind", "unknown")
            raise ValueError(f"{method} refused: {kind}")
        return response["result"]

    def __enter__(self):
        return self

    def __exit__(self, *ignored):
        self.proc.stdin.close()
        try:
            self.proc.wait(60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            raise


def run(args, work, env):
    exe = args.exe.resolve(strict=True)
    profile = work / "wallet"
    require(not profile.exists(), "recipient must be empty")
    subprocess.run([exe, "--prepare-only"], check=True, env=env, cwd=work, timeout=90)
    chain, = Path(env["LOCALAPPDATA"]).rglob("bin/fly-chain.exe")
    host = chain.with_name("fly-paycore-host.exe")
    password = secrets.token_urlsafe()
    point = work / "sender-copy" / "checkpoint.json"
    proof = point.with_name("history.proof")
    point.parent.mkdir()
    shutil.copyfile(args.point, point)
    shutil.copyfile(args.proof, proof)
    record = json.loads(point.read_bytes())
    height, block_hash = record["height"], bytes(record["header_hash"]).hex()
    began = time.monotonic()
    def log(stage, **items):
        row = dict(stage=stage, seconds=round(time.monotonic() - began, 1), **items)
        print(json.dumps(row), flush=True)

    log("clean_recipient", portable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),
        checkpoint_height=height, checkpoint_hash=block_hash)
    with socket.socket() as offline:
        offline.bind(("127.0.0.1", 0))
        peer = f"127.0.0.1:{offline.getsockname()[1]}"
        # An old export takes one JSON selection. The sender then saves a
        # portable single file using the same RPC the Settings screen uses.
        sender_root = work / "sender"
        sender_root.mkdir()
        bundle = work / "shared checkpoint.gshp"
        with Host(host, chain, sender_root, env, peer) as sender:
            sender_password = secrets.token_urlsafe()
            sender.call("host.profile.create", {"network": "main", "password": sender_password})
            sender.call("host.unlock", {"password": sender_password})
            legacy = sender.call("host.import_checkpoint", {"file_path": str(point)})
            require(legacy.get("locked") and legacy.get("hash") == block_hash, "legacy selection failed")
            point.unlink()
            proof.unlink()
            sender.call("host.unlock", {"password": sender_password})
            saved = sender.call("host.export_checkpoint", {"file_path": str(bundle)})
            require(saved.get("exported") and saved.get("height") == height and saved.get("hash") == block_hash,
                    "wrong exported checkpoint")
            require(sender.call("host.status").get("profile") == "unlocked", "export ended the session")
            log("single_file_export", height=height, samples=saved["samples"], size=bundle.stat().st_size,
                sha256=hashlib.sha256(bundle.read_bytes()).hexdigest())
        verification = subprocess.run([exe, "--verify-checkpoint", "main", bundle], capture_output=True,
                                      text=True, cwd=work, env=env, timeout=45)
        require(verification.returncode == 0 and f"height={height} hash={block_hash}" in verification.stdout,
                "standalone verification of the exported file failed")
        with Host(host, chain, work, env, peer) as wallet:
            wallet.call("host.profile.create", {"network": "main", "password": password})
            wallet.call("host.unlock", {"password": password})
            imported = wallet.call("host.import_checkpoint", {"file_path": str(bundle)})
            require(imported["imported"] and imported["locked"] and imported["height"] == height
                    and imported["hash"] == block_hash and imported["samples"] > 0, "incorrect import response")
            log("verified_and_installed", height=height, hash=block_hash, samples=imported["samples"])
        # The recipient must no longer depend on any external source file.
        bundle.unlink()
        chain_dir, = profile.glob("chain-*")
        probe = subprocess.run([chain, "headers", "--network", "main", "--data", chain_dir,
                                "--peer", peer, "--seconds", "3"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", cwd=work, env=env, timeout=35)
        require(probe.returncode == 1 and f"timeout: height={height} hash={block_hash} " in probe.stdout
                and "imported" in probe.stdout.lower() and "sample" in probe.stdout.lower(),
                "offline reopen from the imported sample failed: " + probe.stdout[-800:])
        log("reopened_offline", height=height, hash=block_hash, original_files_absent=True)
    def check_journal():
        require(not any(profile.rglob("autonomous-headers-v1.bin")), "genesis journal was created")
    check_journal()
    if not args.live:
        return
    start = time.monotonic()
    with Host(host, chain, work, env) as wallet:
        wallet.call("host.unlock", {"password": password})
        while time.monotonic() - start < args.seconds:
            check_journal()
            c = wallet.call("paycore.wallet.chain_status")
            status = wallet.call("host.status")["chain"]
            note = status.get("problem") or ""
            header = re.search(r"headers verified to (\d+)", note)
            blocks = re.search(r"blocks applied to (?:the tip, )?(\d+)", note)
            segments = re.search(r"(\d+) of (\d+) pieces", note)
            log("progress", state=c["state"], header=int(header[1]) if header else None,
                wallet=c["tip_height"], selected=c["selected_height"], phase=status["phase"],
                blocks=int(blocks[1]) if blocks else None,
                segments=[int(n) for n in segments.groups()] if segments else None,
                public_nodes_confirmed="tip is confirmed by public nodes" in note)
            tip = c["tip_height"]
            if c["state"] == "at_tip" and isinstance(tip, int) and tip > height and c["selected_height"] == tip:
                check_journal()
                log("wallet_at_selected_tip", height=tip, advance=tip-height,
                    seconds_after_unlock=round(time.monotonic()-start, 1), genesis_journal=False)
                return
            time.sleep(10)
        raise TimeoutError("wallet did not reach the selected public tip within the test interval")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--point", required=True, type=Path)
    parser.add_argument("--proof", required=True, type=Path)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--seconds", type=int, default=1800)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="grinsight-import-") as tmp:
        root = Path(tmp)
        local = root / "local"
        local.mkdir()
        run(args, root, dict(os.environ, LOCALAPPDATA=str(local)))
