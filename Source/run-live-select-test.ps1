# GrinSight v0.2: IS THE TIP CALLED SELECTED ON THE REAL NETWORKS? The whole of step 5.7 at once.
# The chain process follows a network to its tip, as in run-live-blocks-test.ps1, and then does what it does
# for a wallet: it asks the public nodes of its built-in list what the tip is, takes the time from their
# answers, and calls the tip SELECTED when two independent operators named exactly it, enough of the list
# answered, nobody named more work, and the time is confirmed.
#
# THIS ONE USES THE NETWORK. It connects DIRECTLY (not through Tor) to public Grin nodes as an ordinary Grin
# peer, and by HTTPS to the public nodes of the list:
#   main network: grincoin.org, mainnet.grinffindor.org, api.grin.money, main.grin.raubritter.org,
#                 mainnet.grin-coffee.com
#   test network: testnet.grinffindor.org, testapi.grin.money
# All of them see this computer's address. The one question asked by HTTPS (get_tip) says nothing about a
# wallet. No wallet, no keys, no funds are involved, and nothing is sent to the chain. The starting points
# are DEVELOPMENT points: nobody vouches for them, and whatever is selected is marked provisional.
#
# Lines to look at:
#   selected: height=... hash=... confirmed_time=... seconds=...     the tip is selected; seconds from the start
#   said: ...; the tip is confirmed by public nodes                  the same in the words a wallet is given
#   timeout: ... (...)                                               not selected in time; the words say why
# In the data directory, tips.state keeps the number of the last asking, the confirmed time and unsettled
# claims between runs.
#
# Run from any folder:   powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\run-live-select-test.ps1
# One network only:      ... -File C:\DHW\GrinFlySight\core-v0.2\run-live-select-test.ps1 -Network main      (or test)
# A node of your own:    ... -File C:\DHW\GrinFlySight\core-v0.2\run-live-select-test.ps1 -Network test -Peer 192.168.1.5:13414
#                        (with one node only, the sign "nodes of fewer than three networks" is up: every new
#                        tip is then asked about, which is what the program should do)
# Builds the program first (a few minutes if it was not built before). Uses the vendored crates; downloads
# nothing. Writes one log next to this script. Headers, state and blocks are kept in target\live-headers (the
# same directory the other live tests use), so what they collected is not fetched again.
param([ValidateSet('both', 'test', 'main')][string]$Network = 'both', [string[]]$Peer = @(), [int]$Seconds = 1800)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$log = Join-Path $root "live-select-test-$stamp.log"
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
    $data = Join-Path $env:CARGO_TARGET_DIR "live-headers\$net"
    New-Item -ItemType Directory -Force -Path $data | Out-Null
    $arguments = @('select', '--network', $net, '--data', $data, '--seconds', "$Seconds")
    foreach ($p in $Peer) { $arguments += @('--peer', $p) }
    Say "=== $net ==="
    $started = Get-Date
    & $exe @arguments 2>&1 | ForEach-Object { Say "$_" }
    $code = $LASTEXITCODE
    $secs = [int]((Get-Date) - $started).TotalSeconds
    Say "exit=$code seconds=$secs"
    $file = Join-Path $data 'tips.state'
    $size = if (Test-Path $file) { (Get-Item $file).Length } else { 0 }
    $summary += "$net exit=$code seconds=$secs tips_state_bytes=$size"
}
Say "=== summary ==="
$summary | ForEach-Object { Say $_ }
# read the log to the end first: writing into it while it is being read would never finish
$lines = @(Select-String -Path $log -Pattern '^(start|opened|synced|state|blocks|selected|said|timeout|failed):' | ForEach-Object { $_.Line })
$lines | ForEach-Object { Say $_ }
Say "finished $(Get-Date -Format s)"
Write-Host ""
Write-Host "Log: $log"
