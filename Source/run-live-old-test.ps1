# GrinSight v0.2: the chain process reads the OLD OUTPUTS of the real networks - the range proofs of
# everything that is unspent and older than the blocks it has - the way a wallet restored from its phrase
# would ask for them.
# THIS ONE USES THE NETWORK, AND IT DOWNLOADS A LOT: about 250 MB on Mainnet and about 2 GB on the test
# network (the test network has almost three million unspent outputs). It connects DIRECTLY (not through
# Tor) to public Grin nodes, as an ordinary Grin peer: those nodes see this computer's address.
# No wallet, no keys, no funds are involved, and nothing is sent to the chain. Nothing of what is read is
# kept on disk. The starting points are DEVELOPMENT points: nobody vouches for them.
#
# Run from any folder:   powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\run-live-old-test.ps1
#                        (Mainnet only: the smaller download)
# The test network:      ... -File C:\DHW\GrinFlySight\core-v0.2\run-live-old-test.ps1 -Network test
# Nodes of your own:     ... -File C:\DHW\GrinFlySight\core-v0.2\run-live-old-test.ps1 -Network main -Peer 192.168.1.5:3414,10.0.0.7:3414
#                        With -Peer ONLY the named nodes are used: the seed names of the network are not asked.
# From an empty disk:    ... -Fresh    Headers, state and blocks are fetched anew into a directory of this run
#                        (target\live-fresh\...), so that every stage is measured; target\live-headers is
#                        left as it is. Use it to compare nodes: one run without -Peer, one with.
# Builds the program first. Uses the vendored crates; downloads no code. Writes one log next to this
# script. Headers, state and blocks are kept in target\live-headers (the directory the other live tests
# use), so what they collected is not fetched again.
param([ValidateSet('both', 'test', 'main')][string]$Network = 'main', [string[]]$Peer = @(), [int]$Seconds = 7200, [switch]$Fresh)
$ErrorActionPreference = 'Continue'
# started with -File, PowerShell hands "a,b" over as one text: take it apart
$Peer = @($Peer | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$log = Join-Path $root "live-old-test-$stamp.log"
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
$nets = if ($Network -eq 'both') { @('main', 'test') } else { @($Network) }
foreach ($net in $nets) {
    $data = if ($Fresh) { Join-Path $env:CARGO_TARGET_DIR "live-fresh\$net-$stamp" } else { Join-Path $env:CARGO_TARGET_DIR "live-headers\$net" }
    New-Item -ItemType Directory -Force -Path $data | Out-Null
    $arguments = @('old', '--network', $net, '--data', $data, '--seconds', "$Seconds")
    foreach ($p in $Peer) { $arguments += @('--peer', $p) }
    $from = @(Get-Content -LiteralPath $log).Count
    Say "=== $net ==="
    Say ("data: $data" + $(if ($Fresh) { ' (empty: everything is fetched anew)' } else { '' }))
    Say ("nodes: " + $(if ($Peer.Count -gt 0) { ($Peer -join ', ') + ' (only these)' } else { 'the seed names of the network' }))
    $started = Get-Date
    & $exe @arguments 2>&1 | ForEach-Object { Say "$_" }
    $code = $LASTEXITCODE
    $secs = [int]((Get-Date) - $started).TotalSeconds
    Say "exit=$code seconds=$secs"
    $summary += "$net exit=$code seconds=$secs"
    # where the stages end, from the progress lines of this run: the state is collected when blocks begin to
    # be counted, the blocks are at the tip when the first piece of the old outputs is asked for
    $own = @(Get-Content -LiteralPath $log | Select-Object -Skip $from)
    $stateDone = $own | Where-Object { $_ -match '^\s*([\d.]+)s .* blocks=\d+/\d+' } | Select-Object -First 1
    $oldBegun = $own | Where-Object { $_ -match '^\s*([\d.]+)s old: piece=' } | Select-Object -First 1
    $t1 = if ($stateDone -match '^\s*([\d.]+)s') { $Matches[1] } else { '?' }
    $t2 = if ($oldBegun -match '^\s*([\d.]+)s') { $Matches[1] } else { '?' }
    $most = ($own | ForEach-Object { if ($_ -match ' peers=(\d+)') { [int]$Matches[1] } } | Measure-Object -Maximum).Maximum
    $summary += "$net stages: headers and state done at ${t1}s, blocks done at ${t2}s, all done at ${secs}s; most nodes connected at once: $most"
}
Say "=== summary ==="
$summary | ForEach-Object { Say $_ }
# read the log to the end first: writing into it while it is being read would never finish
$lines = @(Select-String -Path $log -Pattern '^(start|opened|synced|state|blocks|old|timeout|failed):' | ForEach-Object { $_.Line })
$lines | ForEach-Object { Say $_ }
Say "finished $(Get-Date -Format s)"
Write-Host ""
Write-Host "Log: $log"
