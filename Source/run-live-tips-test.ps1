# GrinSight v0.2: DO THE PUBLIC NODES OF THE BUILT-IN LIST ANSWER, AND WHAT? A check of the list.
# The program will ask named operators of public Grin nodes what the tip of the chain is, over HTTPS, and
# take the time from the same answers. This script asks every node of the built-in list once and prints
# what came back. It decides nothing, writes no state and touches no wallet.
#
# THIS ONE USES THE NETWORK. It connects DIRECTLY (not through Tor) by HTTPS to the public nodes of the list:
#   main network: grincoin.org, mainnet.grinffindor.org, api.grin.money, main.grin.raubritter.org,
#                 mainnet.grin-coffee.com
#   test network: testnet.grinffindor.org, testapi.grin.money
# Each sees this computer's address and the one question every node answers (get_tip); nothing else is
# sent. Then it asks the public DNS service of Team Cymru which network (autonomous system) each node's
# address belongs to: those questions name the NODES' addresses, not yours.
#
# Lines to look at:
#   tips: source=... group=... address=... height=... hash=... total_difficulty=... date=...
#         date_minus_clock_s=... took_ms=...          one node's answer; date_minus_clock_s is how far the
#                                                    node's time is from this computer's clock
#   tips: source=... failed: ...                     no answer, and why
#   tips: answered=A/N needed=... most_on_one_tip=... date_spread_s=S      the whole picture
#   asn:  source=... ip=... asn=... prefix=... name=...                    the network of each node
# The networks are part of the list: two nodes count as two voices only if both their operators and their
# networks differ. When a node has moved to another network, the list has to be corrected.
#
# Run from any folder:
#   powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\run-live-tips-test.ps1
# The test network:        ... -Network test
# A node of your own too:  ... -Own https://node.example:3413
# Wait longer per node:    ... -Within 40          (20 seconds by default)
# Builds the program first, INTO A DIRECTORY OF ITS OWN (target-tips), so that it can be run while another
# test is going. Uses the vendored crates; downloads no code. Writes one log next to this script.
param([ValidateSet('test', 'main')][string]$Network = 'main', [string[]]$Own = @(), [ValidateRange(1, 300)][int]$Within = 20)
$ErrorActionPreference = 'Continue'
# started with -File, PowerShell hands "a,b" over as one text: take it apart
$Own = @($Own | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
# seconds in the name: two runs of this script, one for each network, take less than a minute together
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = Join-Path $root "live-tips-test-$stamp.log"
$env:CARGO_TARGET_DIR = Join-Path $root 'target-tips'
$env:RUST_BACKTRACE = '0'

function Say($text) { $text | Out-File -FilePath $log -Append -Encoding utf8; Write-Host $text }

Say "started $(Get-Date -Format s)"
Say ("rustc: " + (cmd /c "rustc -V 2>&1"))
Say "=== chain/tips: build (release, into target-tips; a minute or two the first time) ==="
Push-Location (Join-Path $root 'chain\tips')
$started = Get-Date
cmd /c "cargo build --release 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
$code = $LASTEXITCODE
Pop-Location
Say ("exit=$code seconds=" + [int]((Get-Date) - $started).TotalSeconds)
$exe = Join-Path $env:CARGO_TARGET_DIR 'release\fly-tips-check.exe'
if ($code -ne 0 -or -not (Test-Path $exe)) {
    Select-String -Path $log -Pattern '^error' | Select-Object -First 20 | ForEach-Object { Say $_.Line }
    Say "the program was not built"
    Write-Host ""; Write-Host "Log: $log"
    exit 1
}

Say "=== the built-in list: $Network ==="
$arguments = @('--network', $Network, '--within', "$Within") + $Own
$lines = @(& $exe @arguments 2>&1 | ForEach-Object { "$_" })
$code = $LASTEXITCODE
$lines | ForEach-Object { Say $_ }
Say "exit=$code"

Say "=== the networks of the nodes that answered ==="
foreach ($line in $lines) {
    if ($line -notmatch '^tips: source=(\S+) .* address=(\S+) of=') { continue }
    $source = $Matches[1]
    $address = $Matches[2]
    if ($address -notmatch '^(\d+)\.(\d+)\.(\d+)\.(\d+):\d+$') {
        Say "asn:  source=$source ip=$address not looked up (not an IPv4 address)"
        continue
    }
    $ip = "$($Matches[1]).$($Matches[2]).$($Matches[3]).$($Matches[4])"
    $question = "$($Matches[4]).$($Matches[3]).$($Matches[2]).$($Matches[1]).origin.asn.cymru.com"
    $origin = $null
    try { $origin = (Resolve-DnsName -Type TXT -Name $question -ErrorAction Stop | Where-Object { $_.Strings } | Select-Object -First 1).Strings -join '' } catch { }
    if (-not $origin) { Say "asn:  source=$source ip=$ip no answer about its network"; continue }
    $fields = @($origin -split '\|' | ForEach-Object { $_.Trim() })
    $asn = ($fields[0] -split ' ')[0]
    $name = ''
    try { $name = (Resolve-DnsName -Type TXT -Name "AS$asn.asn.cymru.com" -ErrorAction Stop | Where-Object { $_.Strings } | Select-Object -First 1).Strings -join '' } catch { }
    $name = (@($name -split '\|') | Select-Object -Last 1)
    if ($name) { $name = $name.Trim() }
    Say "asn:  source=$source ip=$ip asn=$asn prefix=$($fields[1]) country=$($fields[2]) name=$name"
}

Say "finished $(Get-Date -Format s)"
Write-Host ""
Write-Host "Log: $log"
exit $code
