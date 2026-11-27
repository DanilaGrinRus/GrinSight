"""Compare two Windows x64 fly-history binaries against the same local header dump."""
import argparse
import ctypes as ct
from ctypes import wintypes as wt
import hashlib
import json
import os
import pathlib
import statistics
import subprocess
import time


class Memory(ct.Structure):
    _fields_ = [("cb", wt.DWORD), ("PageFaultCount", wt.DWORD)] + [
        (name, ct.c_size_t) for name in (
            "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage",
            "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]


def run(exe, headers):
    start = time.perf_counter_ns()
    with subprocess.Popen([str(exe), str(headers)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          creationflags=subprocess.CREATE_NO_WINDOW) as child:
        stdout, stderr = child.communicate()
        elapsed = (time.perf_counter_ns() - start) / 1e6
        if child.returncode:
            raise RuntimeError(stderr.decode(errors="replace"))
        handle = wt.HANDLE(int(child._handle))
        creation, exit_time, kernel, user = [ct.c_uint64() for _ in range(4)]
        memory = Memory()
        memory.cb = ct.sizeof(memory)
        if not ct.windll.kernel32.GetProcessTimes(handle, ct.byref(creation), ct.byref(exit_time),
                                                ct.byref(kernel), ct.byref(user)):
            raise ct.WinError()
        if not ct.windll.psapi.GetProcessMemoryInfo(handle, ct.byref(memory), memory.cb):
            raise ct.WinError()
        common = [x for x in stdout.decode().splitlines() if x.startswith(
            ("headers:", "last hash:", "total difficulty at the end:", "header tree:"))]
        return common, dict(elapsed_ms=round(elapsed, 3),
                            cpu_ms=round((kernel.value + user.value) / 10000, 3),
                            peak_working_set_bytes=memory.PeakWorkingSetSize)


def sha(path):
    with path.open("rb") as stream:
        digest = hashlib.sha256()
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(part)
        return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    for param in ("old", "new", "dump"):
        parser.add_argument(param, type=pathlib.Path)
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()
    if os.name != "nt" or args.runs < 1:
        parser.error("requires Windows and at least one measured run per program")
    result = dict(file_bytes=args.dump.stat().st_size, file_sha256=sha(args.dump),
                  network_bytes=0, old_sha256=sha(args.old), new_sha256=sha(args.new))
    expected, _ = run(args.old, args.dump)
    assert len(expected) == 4 and run(args.new, args.dump)[0] == expected
    sets = {"old": [], "new": []}
    for i in range(args.runs):
        for label in (("old", "new") if not i % 2 else ("new", "old")):
            observed, costs = run(getattr(args, label), args.dump)
            if observed != expected:
                raise RuntimeError("different validated tips")
            sets[label].append(costs)
    result.update(tip=expected, measurements=sets, median={
        l: {k: statistics.median(row[k] for row in rows) for k in rows[0]}
        for l, rows in sets.items()})
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
