"""Measure one supported Rust integration test, including its children, on Windows x64."""
import argparse
from contextlib import ExitStack
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import msvcrt
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time
import _winapi

CASES = {
    "wallet": "autonomous_wallet::old_phrase_genesis_restore_and_payment",
    "fork": "autonomous_genesis_switches_a_heavier_branch_below_the_archive",
    "old-outputs": "the_wallet_is_given_the_old_outputs",
}
SIZE = c.c_size_t
I64 = c.c_int64


class Accounting(c.Structure):
    _fields_ = [(s, I64) for s in ("user", "kernel", "period_user", "period_kernel")]
    _fields_ += [(s, w.DWORD) for s in ("faults", "processes", "active", "terminated")]


class BasicLimits(c.Structure):
    _fields_ = [
        ("process_time", I64), ("job_time", I64), ("flags", w.DWORD),
        ("min_ws", SIZE), ("max_ws", SIZE), ("process_limit", w.DWORD),
        ("affinity", SIZE), ("priority", w.DWORD), ("scheduling", w.DWORD),
    ]


class ExtendedLimits(c.Structure):
    _fields_ = [
        ("basic", BasicLimits), ("io", c.c_uint64 * 6),
        ("process_limit", SIZE), ("job_limit", SIZE),
        ("peak_process", SIZE), ("peak_job", SIZE),
    ]


api = c.WinDLL("kernel32", use_last_error=True)


def bind(name, result, *params):
    function = getattr(api, name)
    function.restype = result
    function.argtypes = params
    return function


create_job = bind("CreateJobObjectW", w.HANDLE, c.c_void_p, w.LPCWSTR)
assign = bind("AssignProcessToJobObject", w.BOOL, w.HANDLE, w.HANDLE)
configure = bind("SetInformationJobObject", w.BOOL, w.HANDLE, c.c_int, c.c_void_p, w.DWORD)
query = bind("QueryInformationJobObject", w.BOOL, w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p)
resume = bind("ResumeThread", w.DWORD, w.HANDLE)
BASIC_ACCOUNTING, EXTENDED_LIMITS = 1, 9
CREATE_SUSPENDED, KILL_ON_JOB_CLOSE = 4, 0x2000


def checked(result):
    if not result:
        raise c.WinError(c.get_last_error())
    return result


def info(job, kind, struct_type):
    data = struct_type()
    checked(query(job, kind, c.byref(data), c.sizeof(data), None))
    return data


def digest(path):
    with path.open("rb") as file:
        h = hashlib.sha256()
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            h.update(chunk)
        return h.hexdigest()


def measure(case, exe, host, temp_root, timeout):
    test = CASES[case]
    command = [str(exe), test, "--exact", "--test-threads=1"]
    if case == "wallet":
        command.append("--ignored")
    with ExitStack() as stack:
        tmp = stack.enter_context(tempfile.TemporaryDirectory(prefix="flyjob-", dir=temp_root))
        env = dict(os.environ, TMP=tmp, TEMP=tmp)
        if host:
            env["FLY_AUTOMATED_HOST"] = str(host)
        log = stack.enter_context(tempfile.TemporaryFile("w+b", dir=tmp))
        stdin = stack.enter_context(open(os.devnull, "rb"))
        startup = subprocess.STARTUPINFO()
        startup.dwFlags = subprocess.STARTF_USESTDHANDLES
        startup.hStdInput = msvcrt.get_osfhandle(stdin.fileno())
        startup.hStdOutput = startup.hStdError = msvcrt.get_osfhandle(log.fileno())
        startup.lpAttributeList = {"handle_list": [startup.hStdInput, startup.hStdOutput]}
        job = checked(create_job(None, None))
        stack.callback(_winapi.CloseHandle, job)
        limits = ExtendedLimits()
        limits.basic.flags = KILL_ON_JOB_CLOSE
        checked(configure(job, EXTENDED_LIMITS, c.byref(limits), c.sizeof(limits)))
        for handle in startup.lpAttributeList["handle_list"]:
            os.set_handle_inheritable(handle, True)
        try:
            start = time.perf_counter()
            process, thread, _, _ = _winapi.CreateProcess(
                str(exe), subprocess.list2cmdline(command), None, None, True,
                CREATE_SUSPENDED, env, None, startup,
            )
        finally:
            for handle in startup.lpAttributeList["handle_list"]:
                os.set_handle_inheritable(handle, False)
        stack.callback(_winapi.CloseHandle, process)
        stack.callback(_winapi.CloseHandle, thread)
        if not assign(job, process):
            error = c.WinError(c.get_last_error())
            _winapi.TerminateProcess(process, 1)
            raise error
        if resume(thread) == 0xffffffff:
            raise c.WinError(c.get_last_error())
        if _winapi.WaitForSingleObject(process, int(timeout * 1000)) != 0:
            raise TimeoutError("root test process exceeded its deadline")
        exit_code = _winapi.GetExitCodeProcess(process)
        # Descendants can outlive the root. Collect counters only after all exit.
        while True:
            accounting = info(job, BASIC_ACCOUNTING, Accounting)
            if not accounting.active:
                break
            if time.perf_counter() - start >= timeout:
                raise TimeoutError("a test descendant remained active")
            time.sleep(.01)
        wall = time.perf_counter() - start
        peak = info(job, EXTENDED_LIMITS, ExtendedLimits).peak_job
        log.seek(0)
        output = log.read().decode("utf-8", errors="replace")
        passed = (exit_code == 0 and f"test {test} ... ok" in output
                  and "test result: ok. 1 passed; 0 failed" in output)
        # Do not copy wallet test output or inherited environment into the results.
        return {
            "test": test, "passed": passed, "exit_code": exit_code,
            "wall_seconds": round(wall, 4),
            "job_cpu_seconds": (accounting.user + accounting.kernel) / 10_000_000,
            "job_peak_committed_bytes": peak, "processes": accounting.processes,
            "active_at_end": accounting.active,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=CASES)
    parser.add_argument("exe", type=Path)
    parser.add_argument("--host", type=Path, help="fly-paycore-host-test.exe for the wallet case")
    parser.add_argument("--temp-root", type=Path, help="existing short writable test directory")
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    if args.case == "wallet" and not args.host:
        parser.error("--host is required for the wallet test")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    exe = args.exe.resolve(strict=True)
    host = args.host.resolve(strict=True) if args.host else None
    chain = exe.parent.parent / "fly-chain.exe"
    # Run test binaries in place at their original Cargo target, not copied elsewhere.
    hashes = {path.name: digest(path) for path in [exe, chain] + ([host] if host else [])}
    result = measure(args.case, exe, host, args.temp_root, args.timeout)
    result.update(windows=platform.version(), python=platform.python_version(), sha256=hashes)
    print(json.dumps(result, ensure_ascii=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
