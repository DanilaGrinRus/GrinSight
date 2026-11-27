"""Compare a used profile across two actual Windows one-file packages, offline."""
import argparse
from copy import deepcopy
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time

from check_import_and_sync import Host, require


@contextmanager
def temporary_install():
    parent = Path(tempfile.gettempdir()).resolve()
    root = Path(tempfile.mkdtemp(dir=parent, prefix="grinsight-exe-upgrade-")).resolve()
    require(root.parent == parent and root.name.startswith("grinsight-exe-upgrade-"), "wrong test path")
    try:
        yield root
    finally:
        # Windows can release a just-closed EXE mapping after its process exits.
        deadline = time.monotonic() + 15
        while root.exists():
            try:
                shutil.rmtree(root)
            except PermissionError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.25)


def sha(path):
    with path.open("rb") as stream:
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
        return digest.hexdigest()


def inventory(root):
    return {p.relative_to(root): sha(p) for p in root.rglob("*") if p.is_file()}


def check_fields(old, new, path):
    """Old public RPC fields must survive. A newer host may expose extra fields."""
    if isinstance(old, dict):
        require(isinstance(new, dict) and old.keys() <= new.keys(), f"missing field at {path}")
        for key in old:
            check_fields(old[key], new[key], f"{path}.{key}")
    elif isinstance(old, list):
        require(isinstance(new, list) and len(old) == len(new), f"count changed at {path}")
        def order(rows):
            for key in ("op", "commit", "slate_id"):
                if rows and all(isinstance(row, dict) and row.get(key) for row in rows):
                    return sorted(rows, key=lambda row: row[key])
            return rows
        for i, (a, b) in enumerate(zip(order(old), order(new))):
            check_fields(a, b, f"{path}[{i}]")
    else:
        require(old == new, f"value changed at {path}")


def wait_ready(host):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        history = host.call("paycore.history")
        tip = history["tip_height"]
        search = host.call("paycore.search.status")["state"]
        if (tip == 105 and history["k_conf"] == 3 and search in ("none", "done")
                and host.call("paycore.chain.status")["state"] == "at_tip"):
            return
        time.sleep(0.25)
    chain = host.call("paycore.chain.status")
    raise ValueError(f"wallet did not reach fixture tip: tip={tip}, search={search}, chain={chain.get('state')}")


def observation(host, ops, fixture):
    snapshot = dict(address=host.call("paycore.address")["address"],
                balance=host.call("paycore.balance"), history=host.call("paycore.history"),
                outputs=host.call("paycore.outputs.list"),
                details={kind: host.call("paycore.send.status", {"op": op}) for kind, op in ops.items()},
                signed=host.call("paycore.send.result", {"op": ops["finalized"]})["tx"])
    posts = list((fixture / "posted").glob("*.tx"))
    require(len(posts) == snapshot["details"]["finalized"]["broadcasts"]["accepted"],
            "delivery receipts disagree with the local chain")
    require(all(p.read_bytes() == bytes.fromhex(snapshot["signed"]) for p in posts),
            "local chain received a different transaction")
    return snapshot


def compare_wallets(before, after, stage):
    # Background delivery can run while a real window is open. A new local
    # receipt is accounted for separately and must correspond to the same bytes.
    expected = deepcopy(before)
    old_receipts = expected["details"]["finalized"]["broadcasts"]
    latest = after["details"]["finalized"]["broadcasts"]["accepted"]
    require(latest >= old_receipts["accepted"], "lost delivery receipt")
    old_receipts["accepted"] = latest
    check_fields(expected, after, stage)


def run(args, root):
    def log(stage, **facts):
        print(json.dumps(dict(stage=stage, **facts)), flush=True)

    source, copy, receiver = [root / name for name in ("source", "upgrade", "receiver")]
    for folder in (source, receiver):
        (folder / "data").mkdir(parents=True)
    fixture = root / "chain"
    peer = f"dir:{fixture}"
    env = dict(os.environ, LOCALAPPDATA=str(root / "local"), APPDATA=str(root / "roaming"))
    for key in ("LOCALAPPDATA", "APPDATA"):
        Path(env[key]).mkdir()
    cache = Path(env["LOCALAPPDATA"]) / "GrinSightLight" / "portable-runtime"

    def extract(package):
        before = set(cache.glob("*/bin/fly-paycore-host.exe"))
        subprocess.run([package, "--prepare-only"], cwd=package.parent, env=env,
                       check=True, timeout=120, capture_output=True)
        found = set(cache.glob("*/bin/fly-paycore-host.exe")) - before
        require(len(found) == 1, "expected a distinct packaged runtime")
        return found.pop()

    def wallet(host, folder):
        return Host(host, args.chain, folder, env, peer, profile=folder / "data" / "profile")

    exe_name = "GrinSight.exe"
    shutil.copyfile(args.old, source / exe_name)
    old = extract(source / exe_name)
    password, receiver_pw = secrets.token_urlsafe(), secrets.token_urlsafe()
    with wallet(old, source) as payer:
        phrase = payer.call("host.profile.create", {"network": "test", "password": password})["mnemonic"]
        subprocess.run([args.fixture, fixture], input=phrase.encode("utf-8"), capture_output=True,
                       check=True, timeout=30)
        del phrase
    with wallet(old, source) as payer, wallet(old, receiver) as other:
        other.call("host.profile.create", {"network": "test", "password": receiver_pw})
        other.call("host.unlock", {"password": receiver_pw})
        payer.call("host.unlock", {"password": password})
        wait_ready(payer)
        wait_ready(other)
        require(payer.call("paycore.balance")["spendable"] == "15000000000", "fixture funding absent")
        def prepare():
            return payer.call("paycore.send.prepare", {"amount": "1000000000"})
        cancelled = prepare()["op"]
        payer.call("paycore.send.cancel", {"op": cancelled})
        send = prepare()
        answer = other.call("paycore.receive.draft", {"slate": send["slate"]})
        final = payer.call("paycore.send.finalize", {"op": send["op"], "slate": answer["slate"]})
        ops = dict(cancelled=cancelled, finalized=send["op"], prepared=prepare()["op"])
        initial = observation(payer, ops, fixture)
        require(initial["signed"] and initial["signed"] == final["tx"], "final result was not saved")
        require(len(set(ops.values())) == 3 and len(initial["history"]["sends"]) == 3,
                "expected three distinct payments")
        require(all(initial["details"][k]["state"] == k for k in ops), "fixture states incorrect")
        require(int(initial["balance"]["spendable"]) > 0 and int(initial["balance"]["reserved"]) > 0,
                "fixture needs both available and reserved outputs")
        require(len(bytes.fromhex(initial["address"])) == 32, "missing receiving address")
    log("old_profile_has_history", portable_sha256=sha(source / exe_name), host_sha256=sha(old))
    original = inventory(source)
    shutil.copytree(source, copy)
    require(inventory(copy) == original, "profile copy differs")

    def read(host, folder):
        with wallet(host, folder) as p:
            p.call("host.unlock", {"password": password})
            wait_ready(p)
            return observation(p, ops, fixture)

    def open_window(host, label):
        from upgrade_window import probe_portable
        expected = {"spendable": ["Available 5.00 GRIN", "Доступно 5.00 GRIN"],
                    "reserved": ["spendable · reserved 10.00 · maturing 0.00",
                                 "можно тратить · в резерве 10.00 · созревает 0.00"]}
        result = probe_portable(copy / exe_name, host.parent.parent, copy, copy / "data" / "profile",
                                copy / "guard", args.chain, peer, env, password, expected=expected)
        log("window", version=label, **result)
        require(result["home_opened"], "could not open wallet home in " + label)
        require(all(result["visible"].get(k) for k in expected), "wallet home values missing in " + label)
        require(result["exit_code"] == 0, "window did not exit normally in " + label)

    if args.window:
        open_window(old, "0.4.6")
    before = read(old, copy)
    compare_wallets(initial, before, "reopen_old")
    first_files = inventory(copy)
    shutil.copyfile(args.new, copy / exe_name)
    second_files = inventory(copy)
    changed = {k for k in first_files.keys() | second_files.keys() if first_files.get(k) != second_files.get(k)}
    require(changed == {Path(exe_name)} and second_files[Path(exe_name)] == sha(args.new),
            "files other than the portable executable changed")
    new = extract(copy / exe_name)
    log("only_exe_replaced", portable_sha256=sha(copy / exe_name), host_sha256=sha(new),
        other_files_unchanged=len(first_files)-1)
    if args.window:
        open_window(new, "0.4.7A")
    after = read(new, copy)
    # The new format retires the signing session of an unarmed old draft.
    # Account for this one directional change, without ignoring the field on
    # other operations or allowing reserved coins to be released.
    draft_before, = [r for r in before["history"]["sends"] if r["op"] == ops["prepared"]]
    draft_after, = [r for r in after["history"]["sends"] if r["op"] == ops["prepared"]]
    require(draft_before["locked"] is False and draft_after["locked"] is True
            and after["details"]["prepared"]["session_expired"] is True
            and after["details"]["prepared"]["reserve"] == before["details"]["prepared"]["reserve"],
            "unexpected transition of pending draft")
    draft_before["locked"] = True
    compare_wallets(before, after, "upgrade")
    again = read(new, copy)
    compare_wallets(after, again, "restart_new")
    require(original == inventory(source), "original test profile was modified")
    log("wallet_comparison_pass", address_identical=True, output_list_identical=True,
        balance_nanogrin=after["balance"], history_and_operation_ids_identical=True,
        operations={k:v["state"] for k,v in after["details"].items()},
        output_counts={s:sum(o["state"] == s for o in after["outputs"]["outputs"])
                       for s in ("spendable", "reserved", "immature")},
        finalized_transaction_byte_identical=True, pending_session_expired=after["details"]["prepared"].get("session_expired"),
        identical_on_second_open=True, original_unchanged=True, fixture_height=105,
        local_delivery_receipts=[s["details"]["finalized"]["broadcasts"]["accepted"]
                                 for s in (initial, before, after, again)])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("old", "new", "chain", "fixture"):
        parser.add_argument("--" + name, type=lambda v: Path(v).resolve(strict=True), required=True)
    parser.add_argument("--window", action="store_true")
    args = parser.parse_args()
    with temporary_install() as directory:
        run(args, directory)
