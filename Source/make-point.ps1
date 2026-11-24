# GrinSight v0.2: MAKE A STARTING POINT from the real network (ed. 0.34, section 7.22 of the specification).
# The chain process follows the network's headers, as in run-live-headers-test.ps1, from the starting point it
# has, takes the header where nodes give their state out now (or -Height, no higher), writes the record of a
# starting point at it, and asks the public nodes of its built-in list for the header at that height:
#   -Kind release   a point for a release: two operators on different networks have to name the same header
#                   and nobody another. Writes <network>.json and <network>.origin.json; to compile them in,
#                   copy both over chain\headers\points\ and build again.
#   -Kind own       a point of your own: nobody may name another header. Writes own-point.json; put it into
#                   the data directory of a wallet and the chain process starts from it.
#
# THIS ONE USES THE NETWORK. It connects DIRECTLY (not through Tor) to public Grin nodes as an ordinary Grin
# peer, and by HTTPS to the public nodes of the list:
#   main network: grincoin.org, mainnet.grinffindor.org, api.grin.money, main.grin.raubritter.org,
#                 mainnet.grin-coffee.com
#   test network: testnet.grinffindor.org, testapi.grin.money
# All of them see this computer's address. The one question asked by HTTPS (get_header at one height) says
# nothing about a wallet. No wallet, no keys, no funds are involved, and nothing is sent to the chain.
#
# Lines to look at:
#   point: height=... hash=... work=... tip=...          the header the point is made at
#   said: <node> (<operator>): the same header           what each public node said about that height
#   made: height=... hash=... kind=... confirmed_by=...  the point is written
#   failed: ...                                          nothing is written; the words say why
#
# Run from any folder:   powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\make-point.ps1
# Options:               -Network main|test (default main)  -Kind release|own (default release)  -Height N
#                        -Peer host:port (nodes to follow; by default the network's seed names)
# Builds the program first (a few minutes if it was not built before). Uses the vendored crates; downloads
# nothing. Headers are kept in target\live-headers (the same directory the other live tests use). The files
# made and the log go to points-out\<network>-<kind>-<time> next to this script.
param([ValidateSet('test', 'main')][string]$Network = 'main', [ValidateSet('release', 'own')][string]$Kind = 'release',
      [long]$Height = -1, [string[]]$Peer = @(), [int]$Seconds = 1800)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$out = Join-Path $root "points-out\$Network-$Kind-$stamp"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$log = Join-Path $out "make-point-$stamp.log"
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
$data = Join-Path $env:CARGO_TARGET_DIR "live-headers\$Network"
New-Item -ItemType Directory -Force -Path $data | Out-Null
$arguments = @('point', '--network', $Network, '--data', $data, '--seconds', "$Seconds", '--kind', $Kind, '--out', $out)
if ($Height -ge 0) { $arguments += @('--height', "$Height") }
foreach ($p in $Peer) { $arguments += @('--peer', $p) }
Say "=== $Network, $Kind ==="
$started = Get-Date
& $exe @arguments 2>&1 | ForEach-Object { Say "$_" }
$code = $LASTEXITCODE
Say ("exit=$code seconds=" + [int]((Get-Date) - $started).TotalSeconds)
Say "=== summary ==="
# read the log to the end first: writing into it while it is being read would never finish
$lines = @(Select-String -Path $log -Pattern '^(start|replaced|synced|point|said|written|made|failed|timeout):' | ForEach-Object { $_.Line })
$lines | ForEach-Object { Say $_ }
Get-ChildItem -Path $out -Filter '*.json' | ForEach-Object { Say ("file: " + $_.Name + " bytes=" + $_.Length) }
Say "finished $(Get-Date -Format s)"
Write-Host ""
Write-Host "Folder: $out"
Write-Host "Log: $log"
exit $code
