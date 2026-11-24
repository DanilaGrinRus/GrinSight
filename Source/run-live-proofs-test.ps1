# GrinSight v0.2: HEADER PROOFS of nodes with the HEADER_PROOF_HIST extension (mimblewimble/grin pull
# request 3963), asked for, checked and timed.
# THIS ONE USES THE NETWORK. The program connects DIRECTLY (not through Tor) to the nodes you name, as an
# ordinary Grin peer: they see this computer's address. It first follows the block headers from its
# starting point (seconds), then asks each node for headers with their paths in the header MMR:
#   one-old, many-old           headers from before the starting point, which this program cannot verify
#                               by itself (3 and 63 headers in one request);
#   one-verified, many-verified headers it has verified itself: the node's must be the same, byte for byte;
#   before-hf4                  headers from before the fourth hard fork: members of the MMR, no more is
#                               claimed for them;
#   unknown-anchor              a request the node cannot answer: it must be ignored, and the next one served.
# Every answer is checked: each header is a leaf of the header MMR the anchor commits to, carries a proof
# of work for its fields, and - with its two predecessors in the same answer - passes the node's full check.
# No wallet, no keys, no funds are involved, and nothing is sent to the chain.
#
# Run from any folder:
#   powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\run-live-proofs-test.ps1 -Peer 34.10.50.171:3414,34.29.132.45:3414
# The test network:  ... -Network test -Peer host:13414
# More rounds:       ... -Rounds 20        (each request is made that many times; 5 by default)
# A sample instead:  ... -Sample 1000      Instead of the requests above: that many heights drawn at random
#                    over the WHOLE history below the anchor, each with its two predecessors, asked for in
#                    requests of 21 and every answer checked. The line "sample: node=..." gives the bytes,
#                    the seconds and the time of checking: what proofs for so many headers cost, next to
#                    downloading every header. From 1 to 20000; every named node is asked the same heights.
# Builds the program first, INTO A DIRECTORY OF ITS OWN (target-proofs), so that it can be run while another
# live test is going: that one keeps target\release\fly-chain.exe busy. The first build there takes a few
# minutes. Uses the vendored crates; downloads no code. Writes one log next to this script. Headers are
# kept in target-proofs\live-proofs, apart from the other live tests.
param([ValidateSet('test', 'main')][string]$Network = 'main', [Parameter(Mandatory = $true)][string[]]$Peer, [int]$Rounds = 5, [int]$Seconds = 600, [ValidateRange(0, 20000)][int]$Sample = 0)
$ErrorActionPreference = 'Continue'
# started with -File, PowerShell hands "a,b" over as one text: take it apart
$Peer = @($Peer | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$log = Join-Path $root "live-proofs-test-$stamp.log"
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
$data = Join-Path $env:CARGO_TARGET_DIR "live-proofs\$Network"
New-Item -ItemType Directory -Force -Path $data | Out-Null
$arguments = @('proofs', '--network', $Network, '--data', $data, '--seconds', "$Seconds", '--rounds', "$Rounds")
if ($Sample -gt 0) { $arguments += @('--sample', "$Sample") }
foreach ($p in $Peer) { $arguments += @('--peer', $p) }
Say "=== $Network ==="
Say ("nodes: " + ($Peer -join ', ') + " (only these)")
$started = Get-Date
& $exe @arguments 2>&1 | ForEach-Object { Say "$_" }
$code = $LASTEXITCODE
$secs = [int]((Get-Date) - $started).TotalSeconds
Say "exit=$code seconds=$secs"
Say "=== summary ==="
Say "$Network exit=$code seconds=$secs"
# read the log to the end first: writing into it while it is being read would never finish
$lines = @(Select-String -Path $log -Pattern '^(synced|anchor|node|proofs|sample|failed|timeout):' | ForEach-Object { $_.Line })
$lines | ForEach-Object { Say $_ }
Say "finished $(Get-Date -Format s)"
Write-Host ""
Write-Host "Log: $log"
