# GrinSight v0.2: CAN THE CHAIN PROGRAM SEND THROUGH TOR? Everything a transaction would need, without one.
# The chain program brings Tor up the way it does before it sends a transaction, asks every public node of
# its list what its tip is THROUGH TOR, by HTTPS, and shakes hands THROUGH TOR with two nodes of the network
# found by the network's seed names (the names are looked up here, as the program looks them up anyway).
#
# THIS ONE USES THE NETWORK: the Tor network (its relays see this computer's address) and, through Tor, the
# public nodes of the list and two nodes of the network. No wallet, no keys, no funds; nothing is sent to the
# chain. Tor keeps its state in target\live-tor\<network>\tor.
#
# Lines to look at:
#   tor: up seconds=...                                 Tor came up
#   api: <node> (<operator>) height=... seconds=...     a public node answered through Tor
#   network: <address> height=... agent=... seconds=... a node of the network took a connection through Tor
#   summary: tor=up api=N/M network=N/2 seconds=...
#
# Run from any folder:   powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\run-live-tor-send-test.ps1
# One network only:      ... -Network main      (or test)
# Builds the program first (a few minutes the first time: Tor is a large piece of code). Uses the vendored
# crates; downloads no code. Writes one log next to this script.
param([ValidateSet('both', 'test', 'main')][string]$Network = 'both')
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$log = Join-Path $root "live-tor-send-test-$stamp.log"
$env:CARGO_TARGET_DIR = Join-Path $root 'target'
$env:RUST_BACKTRACE = '0'
$scratch = Join-Path $env:CARGO_TARGET_DIR 'test-tmp'
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
$env:TMP = $scratch; $env:TEMP = $scratch

function Say($text) { $text | Out-File -FilePath $log -Append -Encoding utf8; Write-Host $text }

Say "started $(Get-Date -Format s)"
Say ("rustc: " + (cmd /c "rustc -V 2>&1"))
Say "=== chain/fly-chain: build (release) ==="
Push-Location (Join-Path $root 'chain\fly-chain')
$started = Get-Date
cmd /c "cargo build --release 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
$code = $LASTEXITCODE
Pop-Location
Say ("exit=$code seconds=" + [int]((Get-Date) - $started).TotalSeconds)
$exe = Join-Path $env:CARGO_TARGET_DIR 'release\fly-chain.exe'
if ($code -ne 0 -or -not (Test-Path $exe)) {
    Select-String -Path $log -Pattern '^error' | Select-Object -First 20 | ForEach-Object { Say $_.Line }
    Say "the program was not built"
    Write-Host ""; Write-Host "Log: $log"
    exit 1
}
$summary = @()
$nets = if ($Network -eq 'both') { @('test', 'main') } else { @($Network) }
foreach ($net in $nets) {
    $data = Join-Path $env:CARGO_TARGET_DIR "live-tor\$net"
    New-Item -ItemType Directory -Force -Path $data | Out-Null
    Say "=== $net ==="
    $started = Get-Date
    & $exe tor --network $net --data $data 2>&1 | ForEach-Object { Say "$_" }
    $code = $LASTEXITCODE
    $secs = [int]((Get-Date) - $started).TotalSeconds
    Say "exit=$code seconds=$secs"
    $summary += "$net exit=$code seconds=$secs"
}
Say "=== summary ==="
$summary | ForEach-Object { Say $_ }
$lines = @(Select-String -Path $log -Pattern '^(tor|api|network|summary|failed):' | ForEach-Object { $_.Line })
$lines | ForEach-Object { Say $_ }
Say "finished $(Get-Date -Format s)"
Write-Host ""
Write-Host "Log: $log"
