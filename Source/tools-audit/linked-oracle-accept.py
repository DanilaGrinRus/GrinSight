"""Offline H2/H3 boundary comparison against native Grin. Python 3.9+."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile


EXPECTED_H2 = "9cff59d82d292efbf3d312261226c0bac565040d4d555457165d3d04cc26b92d"
EXPECTED_H3 = (
    "height=3 timestamp=1547574887 "
    "hash=0000021a57cc6ad5fce868b9cc12e196faa0b235691681069c7c6ac7fad69949 "
    "td=48916910435 achieved=14671771345 scaling=1839 edge_bits=29 pmmr_size=7 "
    "root=f86f12725fe8a31585161ca9b934c6b0e8dcc0875904e85d850467256272a81b"
)


def flipped(blob, offset):
    changed = bytearray(blob)
    changed[offset] ^= 1
    return bytes(changed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--guest-point", type=Path, help="Journal extracted from verified receipt")
    args = parser.parse_args()
    oracle, fixture = args.oracle.resolve(), args.fixture.resolve()

    with tempfile.TemporaryDirectory() as workspace:
        base = Path(workspace)
        reference = base / "native"
        subprocess.run([oracle, "export", fixture, reference], cwd=base, check=True)
        point = (reference / "checkpoint.bin").read_bytes()
        if hashlib.sha256(point).hexdigest() != EXPECTED_H2:
            raise ValueError("native H2 boundary changed")
        if args.guest_point:
            guest = args.guest_point.read_bytes()
            if guest != point:
                raise ValueError("guest and native H2 journals differ")
            point = guest
            print("PASS guest/native H2 journal: all 1104 bytes equal")
        next_header = (reference / "next-header.bin").read_bytes()
        clean = base / "reader"
        clean.mkdir()
        checkpoint, successor = clean / "checkpoint.bin", clean / "next-header.bin"

        def check(label, supplied, raw, expected):
            checkpoint.write_bytes(supplied)
            successor.write_bytes(raw)
            run = subprocess.run(
                [oracle, "resume", checkpoint.name, successor.name],
                cwd=clean, capture_output=True, text=True, timeout=30,
            )
            if expected:
                if run.returncode or run.stdout.strip() != EXPECTED_H3:
                    raise ValueError(f"{label}: {run.returncode} {run.stdout} {run.stderr}")
            elif run.returncode == 0 or not run.stderr.strip() or run.stdout.strip():
                raise ValueError(f"{label}: unexpected verdict {run.returncode} {run.stdout}")
            print(f"PASS {label}")

        check("native H3 continuation", point, next_header, True)
        for label, offset in (
            ("H2 network", 16), ("H2 work", 480), ("H2 PMMR root", 488),
            ("H2 left peak", 520), ("H2 right peak", 552),
            ("prior header timestamp", 584 + 48 + 17), ("prior PMMR root", 584 + 488),
        ):
            check("reject changed " + label, flipped(point, offset), next_header, False)
        for label, offset in (
            ("H3 predecessor", 18), ("H3 previous root", 50),
            ("H3 expected difficulty", 233), ("H3 scaling", 237), ("H3 PoW", 250),
        ):
            check("reject changed " + label, point, flipped(next_header, offset), False)
        check("reject H2 as H3", point, point[48:448], False)
        check("reject trailing point bytes", point + b"\0", next_header, False)
        check("reject truncated successor", point, next_header[:-1], False)


if __name__ == "__main__":
    main()
