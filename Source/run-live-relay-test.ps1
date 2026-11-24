# GrinSight v0.2: a payment between two wallet processes over a REAL Nostr relay, through Tor.
# THIS ONE USES THE NETWORK AND PUBLISHES: two sealed messages (a test payment and its answer) are sent
# to the relay named below. No real wallet and no funds: both profiles are throw-away ones on the test chain.
# Run from any folder:  powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\run-live-relay-test.ps1
# Another relay:        ... -File C:\DHW\GrinFlySight\core-v0.2\run-live-relay-test.ps1 -Relay wss://relay.nostr.net
# Builds the transport program first (long if it was not built before). Uses the vendored crates;
# downloads nothing. Writes one log next to this script. Temporary files go to target\test-tmp
# (one probe file is created and removed in the shell's own TEMP).
param([string]$Relay = 'wss://relay.floonet.dev')
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$log = Join-Path $root "live-relay-test-$stamp.log"
$env:RUST_BACKTRACE = '0'
$coreTarget = Join-Path $root 'target'
$transportTarget = Join-Path $root 'target-transport'

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
$scratch = Join-Path $coreTarget 'test-tmp'
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
$env:TMP = $scratch; $env:TEMP = $scratch

function Say($text) { $text | Out-File -FilePath $log -Append -Encoding utf8; Write-Host $text }

Say "started $(Get-Date -Format s)"
Say "shell TEMP: '$oldTemp' TMP: '$oldTmp' ($probe); this run uses '$scratch'"
Say ("user: " + [Environment]::UserName + "  elevated: " + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
Say ("rustc: " + (cmd /c "rustc -V 2>&1"))
$summary = @()

Say "=== transport/mailbox-nostr: build fly-mailbox ==="
$env:CARGO_TARGET_DIR = $transportTarget
Push-Location (Join-Path $root 'transport\mailbox-nostr')
$started = Get-Date
cmd /c "cargo build --bin fly-mailbox 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
$code = $LASTEXITCODE
Pop-Location
$secs = [int]((Get-Date) - $started).TotalSeconds
$summary += "build fly-mailbox exit=$code seconds=$secs"
$program = Join-Path $transportTarget 'debug\fly-mailbox.exe'

if (($code -eq 0) -and (Test-Path -LiteralPath $program)) {
    Say "=== paycore/host: live payment over $Relay with $program ==="
    $env:FLY_RELAY = $Relay
    $env:CARGO_TARGET_DIR = $coreTarget
    $env:FLY_MAILBOX_EXE = $program
    Push-Location (Join-Path $root 'paycore\host')
    $started = Get-Date
    cmd /c "cargo test --features test-chain --test host live_a_payment_crosses_a_real_relay -- --ignored --nocapture 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
    $code = $LASTEXITCODE
    Pop-Location
    $secs = [int]((Get-Date) - $started).TotalSeconds
    $summary += "live relay test exit=$code seconds=$secs"
} else {
    $summary += "live relay test not run: the transport program was not built"
}
$results = Select-String -Path $log -Pattern '^test result:|^relay:|transports ready in|^payment sealed|^\s*[0-9.]+ s  [ab]: |the transport says|^the answer came back|^payment over a real relay|^both locked in|no answer came back|not ready in|the transport is down' | ForEach-Object { $_.Line }
$failed = Select-String -Path $log -Pattern '^test .* FAILED$' | ForEach-Object { $_.Line }
$errors = Select-String -Path $log -Pattern '^error|: error [A-Z]+[0-9]+|Command line error|fatal error' | Select-Object -First 20 | ForEach-Object { $_.Line }
Say "=== summary ==="
$summary | ForEach-Object { Say $_ }
$results | ForEach-Object { Say $_ }
$failed | ForEach-Object { Say $_ }
$errors | ForEach-Object { Say $_ }
Say "finished $(Get-Date -Format s)"
Write-Host ""
Write-Host "Log: $log"
