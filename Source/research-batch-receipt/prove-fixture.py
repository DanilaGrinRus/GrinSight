"""Prove a contiguous slice of the historical Grin vector, with CPU/RSS measurement."""
import argparse
import os
from pathlib import Path
import resource
import shutil
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument("parent", type=Path, help="directory containing the two predecessor files")
parser.add_argument("start", type=int, help="first input header height")
parser.add_argument("count", type=int, choices=range(1, 9))
parser.add_argument("out", type=Path)
args = parser.parse_args()
if not 3 <= args.start <= args.start + args.count - 1 <= 1000:
    parser.error("supported heights are 3..1000")
src = Path(__file__).resolve().parent
target = Path(os.environ.get("BATCH_RESEARCH_TARGET", "/var/tmp/grinsight-batch-receipt"))
tool = Path(os.environ.get("BATCH_HOST_TARGET", target / "host")) / "release/research-grin-batch-receipt"
env = dict(os.environ)
env["PATH"] = str(Path.home() / ".cargo/bin") + os.pathsep + env.get("PATH", "")
env["RISC0_SERVER_PATH"] = shutil.which("r0vm", path=env["PATH"]) or "r0vm"
env["BATCH_GUEST_ELF"] = str(target / "guest.elf")
env.pop("RISC0_DEV_MODE", None)
with tempfile.TemporaryDirectory(dir=target) as scratch:
    raw = Path(scratch) / "input.bin"
    with (src.parent / "chain/headers/tests/mainnet/first-4100-headers.bin").open("rb") as chain, raw.open("wb") as headers:
        for height in range(args.start + args.count):
            size = int.from_bytes(chain.read(2), "big")
            frame = chain.read(size)
            if size == 0 or len(frame) != size:
                raise ValueError("incomplete framed header")
            if height >= args.start:
                if size != 400 or int.from_bytes(frame[2:10], "big") != height:
                    raise ValueError("unexpected C29 frame")
                headers.write(frame)
    start = time.perf_counter()
    result = subprocess.run([tool, "prove", args.parent / "checkpoint.bin", args.parent / "history.receipt", raw, args.out], env=env)
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    print(f"exit={result.returncode} wall_s={time.perf_counter()-start:.3f} max_rss_kib={usage.ru_maxrss} cpu_user_s={usage.ru_utime:.3f} cpu_sys_s={usage.ru_stime:.3f}", flush=True)
    raise SystemExit(result.returncode)
