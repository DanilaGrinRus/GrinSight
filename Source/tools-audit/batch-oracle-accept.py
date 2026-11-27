"""Compare a receipt verifier's authenticated Mainnet batch point and extend it offline."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile


def take_frame(reader):
    size = reader.read(2)
    if len(size) != 2:
        raise ValueError("missing frame")
    length = int.from_bytes(size, "big")
    wire = reader.read(length)
    if len(wire) != length or not 400 <= length <= 600:
        raise ValueError("invalid frame")
    return wire


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("oracle", "fixture", "image", "point"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--height", type=int, required=True)
    args = parser.parse_args()
    if not 3 <= args.height <= 999:
        raise ValueError("unsupported height")
    oracle = args.oracle.resolve()
    fixture = args.fixture.resolve()
    point = args.point.read_bytes()
    image = args.image.read_text(encoding="ascii").strip()
    with fixture.open("rb") as reader:
        for _ in range(args.height + 1):
            take_frame(reader)
        successor = take_frame(reader)
        following = take_frame(reader)
    height = args.height + 1
    digest = hashlib.blake2b(successor[247:], digest_size=32).hexdigest()
    if (int.from_bytes(successor[2:10], "big") != height
            or int.from_bytes(following[2:10], "big") != height + 1
            or following[18:50].hex() != digest):
        raise ValueError("unexpected link in reference chain")
    td = int.from_bytes(successor[226:234], "big")
    expected = (f"height={height} hash={digest} td={td} rows={min(height + 1, 61)} "
                f"peaks={bin(height + 1).count('1')} root={following[50:82].hex()}")
    subprocess.run([oracle, "compare", image, fixture, str(args.height), args.point.resolve()],
                   check=True, timeout=60)
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        (root / "checkpoint.bin").write_bytes(point)
        (root / "next-header.bin").write_bytes(successor)
        run = subprocess.run([oracle, "resume", image, "checkpoint.bin", "next-header.bin"],
                             cwd=root, capture_output=True, text=True, check=True, timeout=60)
        if run.stdout.strip() != expected:
            raise ValueError(f"unexpected successor: {run.stdout} expected {expected}")
        print("PASS archive-free child process:", run.stdout.strip())
        (root / "next-header.bin").write_bytes(following)
        bad = subprocess.run([oracle, "resume", image, "checkpoint.bin", "next-header.bin"],
                             cwd=root, capture_output=True, text=True, timeout=60)
        if bad.returncode == 0 or bad.stdout.strip() or not bad.stderr.strip():
            raise ValueError("wrong-height successor not rejected as expected")
        print("PASS wrong successor rejected")


if __name__ == "__main__":
    main()
