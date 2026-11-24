# Exercise the actual single-file application using only an isolated cache and profiles.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Exe,
    [Parameter(Mandatory)][string]$Zip,
    [Parameter(Mandatory)][string]$Work
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Assert-Plain([string]$Path) {
    $attrs = [IO.File]::GetAttributes($Path)
    if (($attrs -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Unexpected filesystem link in the test path: $Path"
    }
}

$exeSource = (Get-Item -LiteralPath $Exe).FullName
$zipSource = (Get-Item -LiteralPath $Zip).FullName
$dist = (Get-Item -LiteralPath 'C:\DHW\dist').FullName
$root = [IO.Path]::GetFullPath($Work).TrimEnd('\')
if ([IO.Path]::GetDirectoryName($root) -ne $dist) {
    throw 'Work must be a new, direct child of C:\DHW\dist.'
}
Assert-Plain $dist
if (Test-Path -LiteralPath $root) { throw 'Work already exists. Use a new test folder.' }
$null = New-Item -ItemType Directory -Path $root
$appDir = Join-Path $root 'portable with spaces'
$localDir = Join-Path $root 'local app data'
$null = [IO.Directory]::CreateDirectory($appDir)
$null = [IO.Directory]::CreateDirectory($localDir)
$outer = Join-Path $appDir 'GrinSight.exe'
[IO.File]::Copy($exeSource, $outer, $false)
$zipHash = (Get-FileHash -LiteralPath $zipSource -Algorithm SHA256).Hash.ToLowerInvariant()
$runtime = Join-Path $localDir ("GrinSightLight\portable-runtime\" + $zipHash)

function Start-TestProcess([string[]]$Argv, [string]$AppData = $localDir) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $outer
    $info.WorkingDirectory = $appDir
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    # All arguments below are switches or canonical file paths with no trailing slash.
    $info.Arguments = (($Argv | ForEach-Object { '"' + $_ + '"' }) -join ' ')
    $info.EnvironmentVariables['LOCALAPPDATA'] = $AppData
    $process = [Diagnostics.Process]::Start($info)
    $process.BeginOutputReadLine()
    $process.BeginErrorReadLine()
    return $process
}

function Wait-TestProcess([Diagnostics.Process]$Process, [string]$Stage) {
    try {
        if (-not $Process.WaitForExit(300000)) {
            $Process.Kill()
            $Process.WaitForExit()
            throw "$Stage exceeded its five-minute limit."
        }
        if ($Process.ExitCode -ne 0) { throw "$Stage failed (exit $($Process.ExitCode))." }
    } finally {
        $Process.Dispose()
    }
}

$expected = @{}
$digester = [Security.Cryptography.SHA256]::Create()
$archive = [IO.Compression.ZipFile]::OpenRead($zipSource)
try {
    foreach ($entry in $archive.Entries) {
        $name = $entry.FullName.Replace('\','/')
        if ($name -notmatch '^(?:[^/]+/)?(?<file>GrinSight\.exe|bin/fly-(?:chain|mailbox|paycore-host|onion)\.exe|README\.txt|LICENSE-GPL-3\.0\.txt|SHA256SUMS\.txt)$') { continue }
        $relative = $Matches.file.Replace('/','\')
        if ($expected.ContainsKey($relative)) { throw "Duplicate entry for $relative." }
        $stream = $entry.Open()
        try {
            $expected[$relative] = [BitConverter]::ToString($digester.ComputeHash($stream)).Replace('-','')
        } finally { $stream.Dispose() }
    }
} finally { $archive.Dispose(); $digester.Dispose() }
foreach ($name in @('GrinSight.exe', 'bin\fly-chain.exe', 'bin\fly-paycore-host.exe', 'bin\fly-mailbox.exe',
    'README.txt', 'LICENSE-GPL-3.0.txt', 'SHA256SUMS.txt')) {
    if (-not $expected.ContainsKey($name)) { throw "Reference ZIP is missing $name." }
}

function Get-RuntimeTimes {
    $times = @{}
    foreach ($name in $expected.Keys) {
        $path = Join-Path $runtime $name
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        if ($actual -ne $expected[$name]) { throw "Cached $name differs from the reference ZIP." }
        $times[$name] = [IO.File]::GetLastWriteTimeUtc($path).Ticks
    }
    return $times
}

$timer = [Diagnostics.Stopwatch]::StartNew()
$first = Start-TestProcess @('--prepare-only')
$second = Start-TestProcess @('--prepare-only')
try { Wait-TestProcess $first 'First concurrent prepare' }
finally { Wait-TestProcess $second 'Second concurrent prepare' }
$coldMs = $timer.ElapsedMilliseconds
$before = Get-RuntimeTimes
$timer.Restart()
Wait-TestProcess (Start-TestProcess @('--prepare-only')) 'Warm prepare'
$warmMs = $timer.ElapsedMilliseconds
$after = Get-RuntimeTimes
foreach ($name in $before.Keys) {
    if ($before[$name] -ne $after[$name]) { throw "Warm start rewrote $name." }
}

# Recreate the residue of a stopped extraction. Only remove the disposable copy
# that this invocation extracted under Work; verify its entire path before doing so.
$bin = Join-Path $runtime 'bin'
$victim = [IO.Path]::GetFullPath((Join-Path $bin 'fly-mailbox.exe'))
$parent = $victim
while ($parent -ne $root) {
    if (-not $parent.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Repair fixture escaped its isolated work directory.'
    }
    Assert-Plain $parent
    $parent = [IO.Path]::GetDirectoryName($parent)
}
Assert-Plain $root
$partial = $victim + '.partial'
if (Test-Path -LiteralPath $partial) { throw 'Unexpected partial file after a successful prepare.' }
[IO.File]::Delete($victim)
[IO.File]::WriteAllBytes($partial, [byte[]]@(0, 1, 2))
Wait-TestProcess (Start-TestProcess @('--prepare-only')) 'Partial file recovery'
$repaired = Get-RuntimeTimes
if (Test-Path -LiteralPath $partial) { throw 'Recovery left the unfinished file in place.' }
foreach ($name in $before.Keys) {
    if ($name -ne 'bin\fly-mailbox.exe' -and $before[$name] -ne $repaired[$name]) {
        throw "Partial recovery rewrote unrelated $name."
    }
}

# In a separate cache, also try to interrupt the unpacking process while it
# holds an unfinished runtime file. Fast disks may finish before it is observed.
$killLocal = Join-Path $root 'interruption cache'
$null = [IO.Directory]::CreateDirectory($killLocal)
$killRuntime = Join-Path $killLocal ("GrinSightLight\portable-runtime\" + $zipHash)
$unfinished = @('GrinSight.exe.partial','bin\fly-chain.exe.partial','bin\fly-mailbox.exe.partial','bin\fly-paycore-host.exe.partial') |
    ForEach-Object { Join-Path $killRuntime $_ }
$child = Start-TestProcess @('--prepare-only') $killLocal
$observation = [Diagnostics.Stopwatch]::StartNew()
$killed = $false
try {
    while (-not $child.HasExited -and $observation.Elapsed.TotalSeconds -lt 15) {
        foreach ($file in $unfinished) {
            if ([IO.File]::Exists($file) -and -not $child.HasExited) {
                try { $child.Kill(); $killed = $true } catch [InvalidOperationException] { }
                break
            }
        }
        if ($killed) { break }
        Start-Sleep -Milliseconds 5
    }
    if (-not $child.WaitForExit(15000)) { $child.Kill(); throw 'The interrupted-prepare probe timed out.' }
    if (-not $killed -and $child.ExitCode -ne 0) { throw 'The interrupted-prepare probe failed before intervention.' }
} finally { $child.Dispose() }
if ($killed) {
    Wait-TestProcess (Start-TestProcess @('--prepare-only') $killLocal) 'Reopen after actual process kill'
    foreach ($name in $expected.Keys) {
        if ((Get-FileHash -LiteralPath (Join-Path $killRuntime $name) -Algorithm SHA256).Hash -ne $expected[$name]) {
            throw 'Restored runtime after actual process kill differs from ZIP.'
        }
    }
    Write-Output 'PASS: stopped our own preparing process after observing a partial file; relaunch recovered.'
} else {
    Write-Output 'Actual process interruption not observed; seeded partial recovery tested separately.'
}

# Double-click equivalent. Both paths are unique to this test, so it cannot
# close a different wallet. Require a visible child window AND the embedded host.
$uiPath = Join-Path $runtime 'GrinSight.exe'
$hostPath = Join-Path $bin 'fly-paycore-host.exe'
function Find-TestProcess([string]$File) {
    $name = [IO.Path]::GetFileNameWithoutExtension($File)
    Get-Process -Name $name -ErrorAction SilentlyContinue | Where-Object {
        try { $_.Path -eq $File } catch { $false }
    } | Select-Object -First 1
}
$gui = Start-TestProcess @()
$ui = $null
$timer.Restart()
try {
    do {
        if ($gui.HasExited) { throw 'No-argument launcher exited before the window opened.' }
        $ui = Find-TestProcess $uiPath
        $walletHost = Find-TestProcess $hostPath
        if ($ui -and $ui.MainWindowTitle -like '*GrinSight*' -and $ui.MainWindowHandle -ne [IntPtr]::Zero -and $walletHost) { break }
        Start-Sleep -Milliseconds 100
    } while ($timer.Elapsed.TotalSeconds -lt 30)
    if (-not $ui -or $ui.MainWindowTitle -notlike '*GrinSight*' -or $ui.MainWindowHandle -eq [IntPtr]::Zero -or -not $walletHost) {
        throw 'The clean no-argument launch did not open a wallet window with its embedded host.'
    }
    if (-not $ui.CloseMainWindow()) { throw 'Windows declined WM_CLOSE for the wallet window.' }
    if (-not $ui.WaitForExit(30000)) { throw 'The wallet window process remained active after WM_CLOSE.' }
    if (-not $gui.WaitForExit(5000)) { throw 'Launcher remained active after wallet shutdown.' }
    if ($gui.ExitCode -ne 0) { throw "Window exit $($ui.ExitCode), launcher exit $($gui.ExitCode)." }
} finally {
    foreach ($file in @($uiPath, $hostPath)) {
        $owned = Find-TestProcess $file
        if ($owned -and -not $owned.HasExited) { $owned.Kill(); $owned.WaitForExit(5000) | Out-Null }
    }
    if (-not $gui.HasExited) { $gui.Kill(); $gui.WaitForExit(5000) | Out-Null }
    $gui.Dispose()
}
Write-Output 'PASS: no-argument launch opened the wallet window and host on a clean profile; window closed normally.'

$scenario = Join-Path $root 'offline scenario'
$guards = Join-Path $root 'test guards'
$timer.Restart()
Wait-TestProcess (Start-TestProcess @('--scenario', $scenario, '--guard-dir', $guards)) 'Offline wallet UI'
$scenarioMs = $timer.ElapsedMilliseconds
$summary = Get-Content -LiteralPath (Join-Path $scenario 'scenario.log') -Tail 1
if ($summary -notmatch '^passed (\d+), failed 0$') { throw 'The wallet scenario did not report success.' }
$passed = [int]$Matches[1]
if ($passed -lt 52) { throw "Only $passed scenario checks passed; at least 52 are expected." }
foreach ($id in @('a','b')) {
    $profile = Join-Path $appDir "data\profile\$id"
    if (-not [IO.Directory]::Exists($profile) -or @(Get-ChildItem -LiteralPath $profile -Force).Count -eq 0) {
        throw 'The wallet did not persist both synthetic profiles beside the outer EXE.'
    }
}
if (Test-Path -LiteralPath (Join-Path $runtime 'data\profile')) { throw 'Profile data found in the versioned program cache.' }
Write-Output "PASS: $($before.Count) cached files match the ZIP; concurrent cold prepare ${coldMs} ms; warm prepare ${warmMs} ms."
Write-Output "PASS: warm files preserved; missing executable and seeded partial repaired."
Write-Output "PASS: $passed offline UI checks, two portable profiles, ${scenarioMs} ms."
