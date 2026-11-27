"""Open an existing, private test profile through an unmodified Windows portable.

The caller prepares the synthetic chain, isolated environment and test password.
Only the portable's own direct UI child is inspected. Windows UI Automation
targets the password field and button directly, without global keyboard input.
"""

from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import _winapi


class _ProcessEntry(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260),
    ]


def _ui_pid(parent):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    for fn in (kernel.Process32FirstW, kernel.Process32NextW):
        fn.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry)]
        fn.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)  # TH32CS_SNAPPROCESS
    if snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        row = _ProcessEntry()
        row.dwSize = ctypes.sizeof(row)
        ok = kernel.Process32FirstW(snapshot, ctypes.byref(row))
        while ok:
            if row.th32ParentProcessID == parent and row.szExeFile.casefold() == "grinsight.exe":
                return row.th32ProcessID
            ok = kernel.Process32NextW(snapshot, ctypes.byref(row))
    finally:
        kernel.CloseHandle(snapshot)
    return None


@contextmanager
def _portable_job(args, cwd, env):
    """Put the launcher into a private job before its first instruction is run."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel.ResumeThread.restype = wintypes.DWORD
    kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    process = thread = None
    try:
        command = subprocess.list2cmdline([str(value) for value in args])
        process, thread, pid, _ = _winapi.CreateProcess(
            str(args[0]), command, None, None, False,
            4 | subprocess.CREATE_NO_WINDOW, env, str(cwd), subprocess.STARTUPINFO())
        if not kernel.AssignProcessToJobObject(job, process):
            raise ctypes.WinError(ctypes.get_last_error())
        if kernel.ResumeThread(thread) == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        yield pid, process
    finally:
        try:
            if process is not None:
                # Also covers a failed job assignment while the launcher is suspended.
                if _winapi.WaitForSingleObject(process, 0) == _winapi.WAIT_TIMEOUT:
                    _winapi.TerminateProcess(process, 1)
                if not kernel.TerminateJobObject(job, 1):
                    raise ctypes.WinError(ctypes.get_last_error())
                _winapi.WaitForSingleObject(process, 8000)
                # JOBOBJECT_BASIC_ACCOUNTING_INFORMATION's ActiveProcesses,
                # immediately after 4 LARGE_INTEGERs and 2 DWORDs.
                accounting = ctypes.create_string_buffer(48)
                deadline = time.monotonic() + 8
                while True:
                    if not kernel.QueryInformationJobObject(job, 1, accounting, len(accounting), None):
                        raise ctypes.WinError(ctypes.get_last_error())
                    if wintypes.DWORD.from_buffer(accounting, 40).value == 0:
                        break
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Test window process tree did not exit")
                    time.sleep(0.05)
        finally:
            for handle in (thread, process, job):
                if handle:
                    _winapi.CloseHandle(handle)


_WINDOW_PROBE = r"""
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding  = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -Namespace UpgradeProbe -Name Window -MemberDefinition @'
[DllImport("user32.dll")]
public static extern uint GetWindowThreadProcessId(IntPtr handle, out uint pid);
[DllImport("user32.dll", SetLastError=true)]
public static extern bool PostMessage(IntPtr handle, uint message, IntPtr wparam, IntPtr lparam);
'@
$result = [ordered]@{window_opened=$false; login_found=$false; home_opened=$false; visible=@{}; stage='window'}
$diagnostic = [ordered]@{windows=0; controls=0; password_edits=0; edits=0; buttons=0; known=@()}
$known = @('Password','Пароль','Unlock','Войти','Create wallet','Создать кошелёк','Options','Опции','Send','Отправить','Receive','Получить','Cancel','Отмена','OK','ОК','GrinSight','Mainnet','Testnet','Close','Закрыть')
$deadline = [DateTime]::UtcNow.AddSeconds($request.timeout)
$ui = $null
$root = $null
function Children($element) {
    $element.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition)
}
function Compact([string]$text) {
    ($text -replace '\s+', '').ToLowerInvariant()
}
try {
    while ([DateTime]::UtcNow -lt $deadline -and $null -eq $ui) {
        $child = [Diagnostics.Process]::GetProcessById([int]$request.ui_pid)
        if ($child.MainModule.FileName -ne $request.ui) { throw 'unexpected-child' }
        if ($child.MainWindowHandle -ne [IntPtr]::Zero) {
            $ui = $child
        }
        if ($null -eq $ui) { Start-Sleep -Milliseconds 150 }
    }
    if ($null -eq $ui) { throw 'window' }
    $result.window_opened = $true
    $result.stage = 'login-controls'
    $desktop = [Windows.Automation.AutomationElement]::RootElement
    $matchPid = [Windows.Automation.PropertyCondition]::new(
        [Windows.Automation.AutomationElement]::ProcessIdProperty, [int]$ui.Id)
    $edit = $null
    $unlock = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $windows = @($desktop.FindAll([Windows.Automation.TreeScope]::Children, $matchPid))
        if ($windows.Count -eq 0) {
            $windows = @([Windows.Automation.AutomationElement]::FromHandle($ui.MainWindowHandle))
        }
        $diagnostic.windows = $windows.Count
        foreach ($candidate in $windows) {
            $edit = $null
            $unlock = $null
            $items = @(Children $candidate)
            $diagnostic.controls = [Math]::Max($diagnostic.controls,$items.Count)
            $edits = $buttons = $passwords = 0
            foreach ($item in $items) {
                $c = $item.Current
                if ($c.Name -in $known -and $c.Name -notin $diagnostic.known) {
                    $diagnostic.known += $c.Name
                }
                if ($c.ControlType -eq [Windows.Automation.ControlType]::Edit) {
                    $edits++
                    if ($c.IsPassword) { $passwords++ }
                    if ($c.IsPassword -or $c.Name -in @('Password','Пароль')) { $edit = $item }
                }
                if ($c.ControlType -eq [Windows.Automation.ControlType]::Button) {
                    $buttons++
                    if ($c.Name -in @('Unlock','Войти')) { $unlock = $item }
                }
            }
            $diagnostic.edits = [Math]::Max($diagnostic.edits,$edits)
            $diagnostic.password_edits = [Math]::Max($diagnostic.password_edits,$passwords)
            $diagnostic.buttons = [Math]::Max($diagnostic.buttons,$buttons)
            if ($request.public_status -and -not $result.language_chosen) {
                $languages = @($items | Where-Object { $_.Current.ControlType -eq [Windows.Automation.ControlType]::Button -and $_.Current.Name -in @('English','Deutsch','日本語','한국어','Français','Русский') })
                $english = @($languages | Where-Object { $_.Current.Name -eq 'English' })
                if ($languages.Count -ge 3 -and $english.Count -eq 1) {
                    $english[0].GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
                    $result.language_chosen = 'English'
                    $edit = $null; $unlock = $null
                    break
                }
            }
            if ($null -ne $edit -and $null -ne $unlock) { $root = $candidate; break }
        }
        if ($null -ne $edit -and $null -ne $unlock) { break }
        Start-Sleep -Milliseconds 150
    }
    if ($null -eq $edit -or $null -eq $unlock) { throw 'login-controls' }
    $result.login_found = $true
    $result.stage = 'set-password'
    $edit.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).SetValue([string]$request.password)
    $request.password = $null
    $result.stage = 'invoke-unlock'
    $unlock.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
    $result.stage = 'home'
    while ([DateTime]::UtcNow -lt $deadline) {
        $names = @(foreach ($item in (Children $root)) { $item.Current.Name })
        if (($names -contains 'Send' -or $names -contains 'Отправить') -and
            ($names -contains 'Receive' -or $names -contains 'Получить')) {
            $result.home_opened = $true
            $joined = Compact ($names -join ' ')
            $missing = $false
            foreach ($prop in $request.expected.psobject.Properties) {
                $found = $false
                foreach ($translation in @($prop.Value)) {
                    if ($joined.Contains((Compact $translation))) { $found = $true; break }
                }
                $result.visible[$prop.Name] = $found
                if (-not $found) { $missing = $true }
            }
            if (-not $missing) { break }
        }
        Start-Sleep -Milliseconds 250
    }
    if ($result.home_opened) { $result.stage = 'home-opened' }
    if ($result.home_opened -and $request.public_status) {
        $result.stage = 'observe-home'
        $result.status = Read-PublicStatus $root $deadline $request.progress
        $result.stage = if ($request.inspect_details) { 'compared' } else { 'home-observed' }
    }
} catch {
    # The UI Automation exception might include edit-field content.
    $result.failure = $_.Exception.GetBaseException().GetType().Name
    $result.uia = $diagnostic
} finally {
    if ($null -ne $ui -and -not $ui.HasExited) {
        try {
            $wh = if ($null -ne $root) { [IntPtr]$root.Current.NativeWindowHandle } else { [IntPtr]::Zero }
            [uint32]$ownerPid = 0
            if ($wh -ne [IntPtr]::Zero -and
                [UpgradeProbe.Window]::GetWindowThreadProcessId($wh,[ref]$ownerPid) -ne 0 -and
                $ownerPid -eq $ui.Id) {
                $result.close_requested = [UpgradeProbe.Window]::PostMessage($wh,0x10,[IntPtr]::Zero,[IntPtr]::Zero)
            } else {
                $result.close_requested = $ui.CloseMainWindow()
            }
        } catch { $result.close_requested = $false }
    }
}
[Console]::WriteLine(($result | ConvertTo-Json -Compress))
"""


def probe_portable(package, runtime, cwd, profile, guard, stub, peer, env,
                   password, expected=None, timeout=55):
    """Test a real login; expected maps keys to screen text or alternate translations."""
    cwd = Path(cwd).resolve(strict=True)
    profile = Path(profile).resolve(strict=True)
    guard = Path(guard).resolve(strict=True)
    runtime = Path(runtime).resolve()
    package = Path(package).resolve(strict=True)
    stub = Path(stub).resolve(strict=True)
    if stub.name.lower() != "host-chain-stub.exe" or not str(peer).startswith("dir:"):
        raise ValueError("The window check requires the local fixture chain")
    if not Path(str(peer)[4:]).is_dir() or not profile.is_dir() or not any(profile.iterdir()):
        raise ValueError("Missing local chain fixture or existing test profile")
    if not guard.is_dir() or not password:
        raise ValueError("Missing test guard or password")
    child_env = dict(os.environ, **env)
    args = [package, "--host", runtime / "bin" / "fly-paycore-host.exe",
            "--profile", profile, "--guard-dir", guard, "--chain", stub, "--chain-peer", str(peer)]
    return observe_window(args, runtime, cwd, child_env, password, expected, timeout)


def observe_window(args, runtime, cwd, child_env, password, expected, timeout, *, public_progress=None, language_check=None, ready_panel=False, inspect_details=False):
    """Open this invocation and observe only its own UI child. Live progress is sanitized."""
    with _portable_job(args, cwd, child_env) as (launcher_pid, launcher_handle):
        deadline = time.monotonic() + timeout
        pid = None
        while _winapi.WaitForSingleObject(launcher_handle, 0) == _winapi.WAIT_TIMEOUT and time.monotonic() < deadline:
            pid = _ui_pid(launcher_pid)
            if pid is not None:
                break
            time.sleep(0.1)
        if pid is None:
            return {"window_opened": False, "home_opened": False, "login_found": False,
                    "window_stage": "window-child", "visible": {},
                    "exit_code": _winapi.GetExitCodeProcess(launcher_handle)}
        request = {"ui_pid": pid, "ui": str(runtime / "GrinSight.exe"),
                   "timeout": timeout, "password": password, "expected": expected or {}}
        probe = _WINDOW_PROBE
        if public_progress is not None:
            request.update(public_status=True, progress=str(public_progress), inspect_details=inspect_details)
            if ready_panel:
                request["python"] = sys.executable
                request["ready_pixels"] = str(Path(__file__).with_name("check_ready_colors.py").resolve(strict=True))
            probe = Path(__file__).with_name("read_live_status.ps1").read_text(encoding="utf-8") + "\n" + probe
        if language_check is not None:
            request["language_check"] = language_check
            probe = Path(__file__).with_name("read_language_window.ps1").read_text(encoding="utf-8")
        # Only static observer code goes on disk. Secret inputs travel through the private pipe.
        with tempfile.TemporaryDirectory(prefix="window-observer-") as scratch:
            observer = Path(scratch) / "observe.ps1"
            observer.write_text(probe, encoding="utf-8-sig")
            check = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(observer)],
                input=json.dumps(request).encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=timeout + 25, creationflags=subprocess.CREATE_NO_WINDOW, check=True)
        result = json.loads(check.stdout.decode("utf-8-sig"))
        result["window_stage"] = result.pop("stage")
        # The application's own CLOSE_GRACE is 12s for its wallet child to wind down.
        exited = _winapi.WaitForSingleObject(launcher_handle, 25000) == _winapi.WAIT_OBJECT_0
        result["exit_code"] = _winapi.GetExitCodeProcess(launcher_handle) if exited else None
        return result
