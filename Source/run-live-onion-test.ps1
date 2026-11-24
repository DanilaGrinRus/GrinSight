# GrinSight: the Tor process for payments to an address answers itself through the Tor network.
# THIS ONE USES THE NETWORK: it brings up Tor, announces an onion service of a key made for this run
# (no wallet, no funds) and posts one request to it. Run from any folder:
#   powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\run-live-onion-test.ps1
# Builds offline from vendor-crates. Writes one log next to this script.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$log = Join-Path $root "live-onion-test-$stamp.log"
$env:CARGO_TARGET_DIR = Join-Path $root 'target'
$env:RUST_BACKTRACE = '0'
$scratch = Join-Path $env:CARGO_TARGET_DIR 'test-tmp'
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
$env:TMP = $scratch; $env:TEMP = $scratch
function Say($text) { $text | Out-File -FilePath $log -Append -Encoding utf8; Write-Host $text }
Say "started $(Get-Date -Format s)"
Say ("rustc: " + (cmd /c "rustc -V 2>&1"))
$env:FLY_ALLOW_TOR = '1'
Push-Location (Join-Path $root 'onion')
$started = Get-Date
cmd /c "cargo test live_ -- --ignored --nocapture 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
$code = $LASTEXITCODE
Pop-Location
Say "exit=$code seconds=$([int]((Get-Date) - $started).TotalSeconds)"
Say "finished $(Get-Date -Format s)"
exit $code
