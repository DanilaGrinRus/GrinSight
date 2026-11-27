"""Schedule local proof generation from completed, atomically replaced header exports.

The input is the GrinSight genesis replay journal, not a wallet profile. Point the
export path at an offline snapshot, never at a file a chain process can rewrite.
"""
import argparse
import mmap
from pathlib import Path
import subprocess
import time

MAX_HEIGHT = 16_000_000  # same publisher-side resource budget as generate.rs
MAX_HEADER_LEN = 1024


def last_complete_height(data):
    pos = 0
    count = 0
    size = len(data)
    while pos < size:
        if size - pos < 2:
            raise ValueError("header length prefix truncated")
        length = (data[pos] << 8) | data[pos + 1]
        pos += 2
        if length < 1 or length > MAX_HEADER_LEN or length > size - pos:
            raise ValueError("incomplete or oversized header frame")
        pos += length
        count += 1
        if count > MAX_HEIGHT + 1:
            raise ValueError("export exceeds publisher height budget")
    if count == 0:
        raise ValueError("empty header export")
    return count - 1


def refresh(args):
    identity = None
    while True:
        try:
            with args.dump.open("rb") as file:
                import os
                stat = os.fstat(file.fileno())
                new = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
                if new != identity:
                    if not 0 < stat.st_size <= (MAX_HEIGHT + 1) * (2 + MAX_HEADER_LEN):
                        raise ValueError("header export outside size bounds")
                    with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as data:
                        height = last_complete_height(data) - args.depth
                    if height < 3:
                        raise ValueError("not enough headers for requested depth")
                    subprocess.run([str(args.program), "generate", args.network, str(args.dump),
                                    str(height), str(args.out)], check=True)
                    identity = new
            if args.once:
                return
        except (OSError, ValueError, subprocess.CalledProcessError) as exc:
            if args.once:
                raise
            print(f"Refresh deferred ({exc}); last published manifest retained.", flush=True)
        time.sleep(args.interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("program", type=Path)
    parser.add_argument("network", choices=["main", "test"])
    parser.add_argument("dump", type=Path, help="completed export, atomically replaced between runs")
    parser.add_argument("out", type=Path)
    parser.add_argument("--depth", type=int, default=0, help="publisher target below last exported header")
    parser.add_argument("--interval", type=int, default=86400, help="seconds between export checks")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if not args.program.is_absolute() or args.depth < 0 or args.interval <= 0:
        parser.error("supply an absolute provider executable, nonnegative depth and positive interval")
    refresh(args)
