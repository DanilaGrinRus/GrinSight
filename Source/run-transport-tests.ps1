# GrinSight v0.2: build and test the working copy of the message transport on Windows.
# Run from any folder:  powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\run-transport-tests.ps1
# The first build is long (the Tor client is compiled). Uses the vendored crates of
# C:\DHW\GrinSight\FlyClient\.tools; downloads nothing. Writes one log next to this script.
# Temporary files go to target-transport\test-tmp (one probe file is created and removed in the shell's own TEMP).
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$log = Join-Path $root "transport-tests-$stamp.log"
$env:CARGO_TARGET_DIR = Join-Path $root 'target-transport'
$env:RUST_BACKTRACE = '0'

# The tests and the C compiler need a writable temporary folder. The one the
# shell hands over is recorded and probed, then replaced for this run by a
# folder inside the build output, so the run does not depend on it.
$oldTmp = $env:TMP; $oldTemp = $env:TEMP
$probe = 'no temporary folder set'
if ($oldTemp) {
    $probeFile = Join-Path $oldTemp ("fly-probe-" + [guid]::NewGuid().ToString('N') + ".tmp")
    try { [IO.File]::WriteAllText($probeFile, 'x'); Remove-Item -LiteralPath $probeFile -Force; $probe = 'writable' }
    catch { $probe = 'NOT writable: ' + $_.Exception.Message }
}
$scratch = Join-Path $env:CARGO_TARGET_DIR 'test-tmp'
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
$env:TMP = $scratch; $env:TEMP = $scratch

function Say($text) { $text | Out-File -FilePath $log -Append -Encoding utf8; Write-Host $text }

Say "started $(Get-Date -Format s)"
Say "shell TEMP: '$oldTemp' TMP: '$oldTmp' ($probe); this run uses '$scratch'"
Say ("user: " + [Environment]::UserName + "  elevated: " + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
Say ("rustc: " + (cmd /c "rustc -V 2>&1"))
$summary = @()
foreach ($crate in 'tor', 'nostr', 'mailbox-nostr') {
    $dir = Join-Path $root "transport\$crate"
    Say "=== transport/$crate ==="
    Push-Location $dir
    $started = Get-Date
    cmd /c "cargo test --no-fail-fast 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
    $code = $LASTEXITCODE
    Pop-Location
    $secs = [int]((Get-Date) - $started).TotalSeconds
    $summary += "transport/$crate exit=$code seconds=$secs"
}
$results = Select-String -Path $log -Pattern '^test result:' | Where-Object { $_.Line -notmatch ' 0 passed; 0 failed' } | ForEach-Object { $_.Line }
$failed = Select-String -Path $log -Pattern '^test .* FAILED$' | ForEach-Object { $_.Line }
$errors = Select-String -Path $log -Pattern '^error|: error [A-Z]+[0-9]+|Command line error|fatal error' | Select-Object -First 20 | ForEach-Object { $_.Line }
Say "=== summary ==="
$summary | ForEach-Object { Say $_ }
Say "note: 32 storage tests of transport/nostr need the original FlyClient folder and fail here by design (FLY_ROOT)"
$results | ForEach-Object { Say $_ }
$failed | ForEach-Object { Say $_ }
$errors | ForEach-Object { Say $_ }
Say "finished $(Get-Date -Format s)"
Write-Host ""
Write-Host "Log: $log"
