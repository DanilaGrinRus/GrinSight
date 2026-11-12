# recheck_checkpoint.ps1 - run the cross-check again for an ALREADY BUILT
# mainnet checkpoint (no new sync from genesis). For a run whose sync passed
# but whose cross-check failed only because a source could not be read.
#
#   .\recheck_checkpoint.ps1                       newest evidence\mainnet-cp-run-*
#   .\recheck_checkpoint.ps1 -Run evidence\mainnet-cp-run-20261112-152503
#
# Sources: grinnode.live (node API) + scan.grin.money (explorer JSON API),
# every header field compared. On PASS the run's summary.txt gets
# CROSSCHECK=PASS (the old result stays in 11-crosscheck.log), so
# .\make_release.ps1 can sign it.
param([string]$Run = '')
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot
if (-not $Run) {
    $r = Get-ChildItem -Directory (Join-Path $PSScriptRoot 'evidence') -Filter 'mainnet-cp-run-*' | Sort-Object Name | Select-Object -Last 1
    if (-not $r) { throw 'no evidence\mainnet-cp-run-* (run .\run_mainnet.ps1 -NewCheckpoint -CheckpointOnly)' }
    $Run = $r.FullName
}
$Run = (Resolve-Path $Run).Path
$cp = Join-Path $Run 'checkpoint\checkpoint.rwm'
$summary = Join-Path $Run 'summary.txt'
if (-not (Test-Path $cp) -or -not (Test-Path $summary)) { throw "$Run has no checkpoint\checkpoint.rwm or summary.txt" }
$s = Get-Content $summary -Raw
$a = (Get-FileHash -Algorithm SHA256 $cp).Hash.ToLower()
if ($s -notmatch "checkpoint_sha256=$a") { throw "checkpoint.rwm in $Run does not match its summary (changed after the sync?)" }
# The core that validates the checkpoint file itself (PoW, MMR) before comparing.
foreach ($d in '.build\target\release', '.build\target-mainnet\release', 'dist\grinsight-core') {
    if (Test-Path (Join-Path $PSScriptRoot "$d\reverse-wtema-header-sync.exe")) { $env:GRINSIGHT_BIN_DIR = Join-Path $PSScriptRoot $d; break }
}
if (-not $env:GRINSIGHT_BIN_DIR) { throw 'no reverse-wtema-header-sync.exe: run .\make_service.ps1 first' }
$log = Join-Path $Run '12-recheck.log'
# The URLs are quoted: an unquoted {height} is a PowerShell script block.
$pyArgs = @('checkpoint_crosscheck.py', '--mainnet', '--checkpoint', $cp,
    '--api', 'grinnode=https://grinnode.live/v2/foreign',
    '--json', 'scan=https://scan.grin.money/api/block/{height}')
$ErrorActionPreference = 'Continue'
$out = & python @pyArgs 2>&1 | ForEach-Object { "$_" }
$ErrorActionPreference = 'Stop'
$out | Set-Content -Path $log -Encoding UTF8
$out | ForEach-Object { Write-Host $_ }
if (($out -join "`n") -notmatch 'CROSSCHECK=PASS') { throw "cross-check did not PASS (see $log)" }
$s = $s -replace 'CROSSCHECK=FAIL', 'CROSSCHECK=PASS'
if ($s -notmatch 'CROSSCHECK=PASS') { $s += "CROSSCHECK=PASS`r`n" }
$s += "rechecked=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) sources=grinnode(api),scan(json) log=12-recheck.log`r`n"
Set-Content -Path $summary -Value $s -Encoding ASCII -NoNewline
Write-Host "summary updated: $summary  (now .\make_release.ps1)"
