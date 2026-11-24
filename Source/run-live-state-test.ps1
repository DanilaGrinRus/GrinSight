# GrinSight v0.2: the chain process collects the STATE of the real networks at the nodes' archive header.
# THIS ONE USES THE NETWORK. It connects DIRECTLY (not through Tor) to public Grin nodes, as an ordinary
# Grin peer: those nodes see this computer's address. It asks for block headers and for the segments of the
# state (the bitmap of unspent outputs, the unspent outputs, the ends of two more trees): a few thousand
# small requests on Mainnet, some megabytes in all. No wallet, no keys, no funds are involved, and nothing
# is sent to the chain. The starting points are DEVELOPMENT points: nobody vouches for them.
#
# Run from any folder:   powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\run-live-state-test.ps1
# One network only:      ... -File C:\DHW\GrinFlySight\core-v0.2\run-live-state-test.ps1 -Network test      (or main)
# A node of your own:    ... -File C:\DHW\GrinFlySight\core-v0.2\run-live-state-test.ps1 -Network test -Peer 192.168.1.5:13414
# From an empty disk:    ... -Fresh    Headers and state are fetched anew into a directory of this run
#                        (target\live-fresh\...), so that the collection is measured; target\live-headers is left as it is.
# Builds the program first (a few minutes if it was not built before). Uses the vendored crates; downloads
# nothing. Writes one log next to this script. Headers and state are kept in target\live-headers (the same
# directory the header test uses), so a second run shows what a restart finds ("state: ... kept=...") and
# goes on where the first one stopped.
param([ValidateSet('both', 'test', 'main')][string]$Network = 'both', [string[]]$Peer = @(), [int]$Seconds = 1800, [switch]$Fresh)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$log = Join-Path $root "live-state-test-$stamp.log"
$env:CARGO_TARGET_DIR = Join-Path $root 'target'
$env:RUST_BACKTRACE = '0'
$scratch = Join-Path $env:CARGO_TARGET_DIR 'test-tmp'
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
$env:TMP = $scratch; $env:TEMP = $scratch

function Say($text) { $text | Out-File -FilePath $log -Append -Encoding utf8; Write-Host $text }

Say "started $(Get-Date -Format s)"
Say ("rustc: " + (cmd /c "rustc -V 2>&1"))
if ($Network -eq 'both' -and $Peer.Count -gt 0) {
    Say "-Peer names a node of one network: give -Network test or -Network main with it"
    exit 2
}
Say "=== chain/fly-chain: build (release: checking a few million hashes is slow otherwise) ==="
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
    $data = if ($Fresh) { Join-Path $env:CARGO_TARGET_DIR "live-fresh\$net-$stamp" } else { Join-Path $env:CARGO_TARGET_DIR "live-headers\$net" }
    New-Item -ItemType Directory -Force -Path $data | Out-Null
    $arguments = @('state', '--network', $net, '--data', $data, '--seconds', "$Seconds")
    foreach ($p in $Peer) { $arguments += @('--peer', $p) }
    Say "=== $net ==="
    $started = Get-Date
    & $exe @arguments 2>&1 | ForEach-Object { Say "$_" }
    $code = $LASTEXITCODE
    $secs = [int]((Get-Date) - $started).TotalSeconds
    Say "exit=$code seconds=$secs"
    $file = Join-Path $data 'state.dat'
    $size = if (Test-Path $file) { (Get-Item $file).Length } else { 0 }
    $summary += "$net exit=$code seconds=$secs state_file_bytes=$size"
}
Say "=== summary ==="
$summary | ForEach-Object { Say $_ }
# read the log to the end first: writing into it while it is being read would never finish
$lines = @(Select-String -Path $log -Pattern '^(start|opened|synced|state|collected|timeout|failed):' | ForEach-Object { $_.Line })
$lines | ForEach-Object { Say $_ }
Say "finished $(Get-Date -Format s)"
Write-Host ""
Write-Host "Log: $log"
