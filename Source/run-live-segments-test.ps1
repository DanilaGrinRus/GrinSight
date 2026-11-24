# GrinSight v0.2: DO NODES GIVE LARGER PIECES OF THE STATE? A measurement.
# This program collects the state of the chain in segments of 2048 leaves (height 11), as a Grin node does,
# and it is the number of requests - not the amount of data - that holds it back. This script asks nodes
# for segments of the output tree and of the rangeproof tree of heights 11 to 16 (2048 to 65536 leaves)
# and checks every answer exactly as the usual ones are checked: against the roots in the verified header,
# with the verified bitmap of unspent outputs. Nothing here is used by the wallet.
#
# THIS ONE USES THE NETWORK. The program connects DIRECTLY (not through Tor) to public Grin nodes, as an
# ordinary Grin peer. It first collects the state the usual way (a few minutes on the main network the
# first time; later runs find it in the file while the nodes' archive header has not moved), then connects
# to nodes one at a time. A node takes one connection from an address and lets go of a closed one only
# after a while, so right after the state is collected most nodes refuse at first: the script waits and
# tries again for up to a minute and a half.
#
# Lines to look at:
#   segments: how many of each height the whole tree takes ...     what larger segments would save
#   segments: node=... kind=rangeproofs|outputs height=N whole_tree=... asked=3 answered=... valid=...
#             leaves=... bytes=... largest=... ms_median=... ms_max=...
#   segments: node=... kind=... given and valid at heights: ...     the answer
# A request a node will not answer is ignored by it: "no answer" for a height means that node does not
# give that height.
#
# Run from any folder:
#   powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\run-live-segments-test.ps1
# The test network:  ... -Network test        (it can run while another live test is going on the main
#                    network, and the other way round: the two networks have different nodes)
# Nodes of your own: ... -Peer 34.29.132.45:3414
# More nodes:        ... -Nodes 4              (2 by default; each takes up to a couple of minutes)
# Builds the program first, INTO A DIRECTORY OF ITS OWN (target-proofs), so that it can be run while another
# live test is going. Uses the vendored crates; downloads no code. Writes one log next to this script.
param([ValidateSet('test', 'main')][string]$Network = 'main', [string[]]$Peer = @(), [ValidateRange(1, 8)][int]$Nodes = 2, [int]$Seconds = 900)
$ErrorActionPreference = 'Continue'
# started with -File, PowerShell hands "a,b" over as one text: take it apart
$Peer = @($Peer | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$log = Join-Path $root "live-segments-test-$stamp.log"
$env:CARGO_TARGET_DIR = Join-Path $root 'target-proofs'
$env:RUST_BACKTRACE = '0'
$scratch = Join-Path $env:CARGO_TARGET_DIR 'test-tmp'
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
$env:TMP = $scratch; $env:TEMP = $scratch

function Say($text) { $text | Out-File -FilePath $log -Append -Encoding utf8; Write-Host $text }

Say "started $(Get-Date -Format s)"
Say ("rustc: " + (cmd /c "rustc -V 2>&1"))
Say "=== chain/fly-chain: build (release, into target-proofs; a few minutes the first time) ==="
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
$data = Join-Path $env:CARGO_TARGET_DIR "live-segments\$Network"
New-Item -ItemType Directory -Force -Path $data | Out-Null
$arguments = @('segments', '--network', $Network, '--data', $data, '--seconds', "$Seconds", '--nodes', "$Nodes")
foreach ($p in $Peer) { $arguments += @('--peer', $p) }
Say "=== $Network ==="
if ($Peer.Count -gt 0) { Say ("nodes: " + ($Peer -join ', ') + " (only these)") } else { Say "nodes: the seed names of the network" }
$started = Get-Date
& $exe @arguments 2>&1 | ForEach-Object { Say "$_" }
$code = $LASTEXITCODE
$secs = [int]((Get-Date) - $started).TotalSeconds
Say "exit=$code seconds=$secs"
Say "=== summary ==="
Say "$Network exit=$code seconds=$secs"
# read the log to the end first: writing into it while it is being read would never finish
$lines = @(Select-String -Path $log -Pattern '^(collected|node|segments|failed|timeout):' | ForEach-Object { $_.Line })
$lines | ForEach-Object { Say $_ }
Say "finished $(Get-Date -Format s)"
Write-Host ""
Write-Host "Log: $log"
