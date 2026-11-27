"""Run the research verifier as a fresh user with just the two supplied data files.

Linux/WSL test harness. Run as root. The verifier is a trusted local build,
not an executable supplied with the checkpoint. The child has no network
interfaces, host mounts, home directory, Cargo cache, or header dump.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


def install_runtime(root, verifier):
    binary = root / "bin" / "check"
    binary.parent.mkdir()
    shutil.copyfile(verifier, binary)
    binary.chmod(0o555)
    libraries = subprocess.run(["ldd", str(verifier)], capture_output=True, text=True)
    listed = libraries.stdout + libraries.stderr
    if libraries.returncode and "not a dynamic executable" not in listed:
        raise RuntimeError(listed.strip())
    if "not found" in listed:
        raise RuntimeError("Missing verifier library")
    for name in re.findall(r"(?:^|\s)(/[^\s]+)\s+\(", listed, re.MULTILINE):
        dst = root / name.lstrip("/")
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(name, dst)


def run_case(root, network, label, should_accept):
    command = ["unshare", "--net", "chroot", "--userspec=65534:65534", str(root),
               "/bin/check", "verify", network, "/profile/checkpoint.bin", "/profile/history.receipt"]
    begin = time.monotonic()
    proc = subprocess.run(command, cwd="/", env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/bin"},
                          capture_output=True, text=True, timeout=120)
    elapsed = round(time.monotonic() - begin, 4)
    # A signal, command failure, or a missing loader is never a valid rejection.
    if (proc.returncode not in (0, 1)
            or (proc.returncode == 0) != should_accept
            or (not should_accept and not proc.stderr.startswith("refused: "))):
        raise RuntimeError(f"{label}: exit {proc.returncode}: {proc.stdout} {proc.stderr}")
    print(json.dumps({"test": label, "exit": proc.returncode, "wall_seconds": elapsed,
                      "output": (proc.stdout + proc.stderr).strip()}))


def compare_first_checkpoint(point):
    # Expected results of the separate native GenesisVerifier on the public h=1
    # fixture. These fixed values belong to the acceptance test, never the prover.
    if len(point) != 520 or point[:8] != b"GSZ1MH01":
        raise ValueError("unexpected h=1 research checkpoint format")
    fields = {
        "height": (int.from_bytes(point[8:16], "big"), 1),
        "genesis": (point[16:48].hex(), "40adad0aec27797b48840aa9e00472015c21baea118ce7a2ff1a82c0f8f5bf82"),
        "full_header_sha256": (hashlib.sha256(point[48:448]).hexdigest(),
                               "d87529d60d35ce611088a38628bda9e2767c3abfa5fd62b2c6c8d1e23e48a8cc"),
        "header_id": (point[448:480].hex(), "000000bf7e67a6c9323f26e1eb26fa73f73640349710ea5a9f589c12a812a4b5"),
        "total_work": (int.from_bytes(point[480:488], "big"), 34359738368),
        "header_pmmr": (point[488:].hex(), "d3cf8afdf907266d022e0c3b035c3fc74fa941e5b3ccc4e2e1ea978333d004d5"),
    }
    for field, (actual, expected) in fields.items():
        if actual != expected:
            raise ValueError(f"native oracle mismatch: {field}")


def compare_second_checkpoint(point):
    # Values from the native Grin reference run over the public h=0..3 fixture.
    if len(point) != 1104 or point[:8] != b"GSZ2MH02":
        raise ValueError("unexpected linked checkpoint format")
    parent = point[584:]
    compare_first_checkpoint(parent)
    expected_id = "000000563d23bdcc0301571feb1ebcef08aed18efe48d671493de1e227a616cb"
    expected_wire = "f7b8df5570b2fe8b6648af781f332ce6a4505192c2138a8e100fe1503b9d79eb"
    expected_root = "d2cc273a5ef57cb0a5f2a2e22683465503d644996a17b05e1813643c516fb2df"
    expected_leaf = "77859a5798cb4bde54cd81bb223a6eb658edffdda623b01a966d91a206014e9d"
    if (int.from_bytes(point[8:16], "big") != 2
            or point[16:48] != parent[16:48]
            or hashlib.sha256(point[48:448]).hexdigest() != expected_wire
            or point[448:480].hex() != expected_id
            or int.from_bytes(point[480:488], "big") != 42949672960
            or point[488:520].hex() != expected_root
            or point[520:552] != parent[488:520]
            or point[552:584].hex() != expected_leaf):
        raise ValueError("linked checkpoint disagrees with native Grin")


def compare_batch_checkpoint(point, reference):
    # The separately built native oracle emits the expected full continuation.
    # It and its header fixture are available to the test driver only.
    if point != reference.read_bytes():
        raise ValueError("batch checkpoint differs from native Grin")
    if len(point) < 562 or point[:8] != b"GSZBMH01":
        raise ValueError("bad batch checkpoint")
    height = int.from_bytes(point[40:48], "big")
    leaves = height + 1
    rows = point[560]
    peak_count_offset = 561 + rows * 21
    if rows != min(leaves, 61) or peak_count_offset >= len(point):
        raise ValueError("wrong difficulty window")
    peaks = point[peak_count_offset]
    if (peaks != bin(leaves).count("1") or len(point) != peak_count_offset + 1 + 32 * peaks
            or int.from_bytes(point[520:528], "big") != 2 * leaves - peaks):
        raise ValueError("wrong PMMR frontier")
    return [("authorized-program", 8), ("height", 47), ("genesis", 48),
            ("full-header", 130), ("header-id", 480), ("work", 519),
            ("pmmr-size", 527), ("header-pmmr", 528), ("window-length", 560),
            ("latest-time", 568), ("latest-difficulty", 576), ("scaling", 580),
            ("secondary-flag", 581), ("oldest-row", peak_count_offset - 2),
            ("peak-count", peak_count_offset), ("last-peak", len(point) - 1)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("verifier", type=Path)
    parser.add_argument("point", type=Path)
    parser.add_argument("receipt", type=Path)
    schema = parser.add_mutually_exclusive_group()
    schema.add_argument("--linked", type=Path, metavar="FIRST_RECEIPT",
                        help="test the h=2 proof, including rejection of the valid h=1 proof")
    schema.add_argument("--batch-reference", type=Path, metavar="NATIVE_POINT",
                        help="compare the bounded batch checkpoint against native Grin")
    parser.add_argument("--prior-proof", type=Path, help="parent receipt of the tested batch")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("needs chroot and network namespace privileges")
    if bool(args.batch_reference) != bool(args.prior_proof):
        parser.error("--batch-reference and --prior-proof must be supplied together")
    if not 0 < args.point.stat().st_size <= 65536 or not 0 < args.receipt.stat().st_size <= 64 * 1024**2:
        parser.error("input files exceed test limits or are empty")
    point, proof = args.point.read_bytes(), args.receipt.read_bytes()
    fields = [("height", 15), ("genesis", 16), ("full-header", 110),
              ("header-id", 450), ("work", 487), ("header-pmmr", 519)]
    if args.batch_reference:
        fields = compare_batch_checkpoint(point, args.batch_reference)
    elif args.linked:
        compare_second_checkpoint(point)
        fields.extend([("left-peak", 520), ("right-peak", 552),
                       ("boundary-parent-timestamp", 584 + 48 + 17),
                       ("boundary-parent-work", 584 + 487),
                       ("boundary-parent-header-pmmr", 584 + 519)])
    else:
        compare_first_checkpoint(point)
    print(json.dumps({"checkpoint_bytes": len(point), "proof_bytes": len(proof),
                      "checkpoint_sha256": hashlib.sha256(point).hexdigest(),
                      "proof_sha256": hashlib.sha256(proof).hexdigest()}))
    with tempfile.TemporaryDirectory(prefix="grinsight-two-file-") as stage:
        root = Path(stage)
        root.chmod(0o755)
        install_runtime(root, args.verifier.resolve(strict=True))
        profile = root / "profile"
        profile.mkdir(mode=0o755)
        checkpoint, receipt = profile / "checkpoint.bin", profile / "history.receipt"
        checkpoint.write_bytes(point)
        receipt.write_bytes(proof)
        for path in (checkpoint, receipt):
            path.chmod(0o444)
        run_case(root, "main", "exact-pair", True)
        run_case(root, "test", "wrong-network", False)
        for field, offset in fields:
            changed = bytearray(point)
            changed[offset] ^= 1
            checkpoint.write_bytes(changed)
            run_case(root, "main", "altered-" + field, False)
        checkpoint.write_bytes(point)
        changed_proof = bytearray(proof)
        changed_proof[len(proof) // 2] ^= 1
        receipt.write_bytes(changed_proof)
        run_case(root, "main", "altered-proof", False)
        receipt.write_bytes(proof[:len(proof)//2])
        run_case(root, "main", "truncated-proof", False)
        receipt.write_bytes(proof + b"\x00")
        run_case(root, "main", "trailing-proof-byte", False)
        if args.prior_proof:
            receipt.write_bytes(args.prior_proof.read_bytes())
            run_case(root, "main", "previous-receipt-with-later-checkpoint", False)
        if args.linked:
            receipt.write_bytes(args.linked.read_bytes())
            run_case(root, "main", "first-proof-with-second-checkpoint", False)
            checkpoint.write_bytes(point[584:])
            run_case(root, "main", "valid-first-pair-as-second", False)


if __name__ == "__main__":
    main()
