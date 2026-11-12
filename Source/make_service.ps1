# GrinSight wallet core for the app: builds grinsight-service, the core
# (reverse-wtema-header-sync) and grinsight-tor (release, offline, locked) and
# assembles dist\grinsight-core\ - the folder the Flutter app ships next to
# grinsight.exe. No Python is needed at run time.
#
#   .\make_service.ps1            all three programs
#   .\make_service.ps1 -NoTor     without grinsight-tor (Tor / messenger off)
#   -AllowOldCheckpoint            build even if the mainnet checkpoint is older than 90 days
#
# A new wallet checks every header from the shipped checkpoint to the tip
# (one run takes up to ~355 days of headers; the balance step only needs the
# last ~3 days). Release policy: a checkpoint is at most 90 days old when the
# app is built. A user with an older one builds his own in the app
# («Проверить сам»: every header from genesis). Fresh one:
#   .\run_mainnet.ps1 -NewCheckpoint -CheckpointOnly; .\make_release.ps1
#
# dist\grinsight-core\
#   grinsight-service.exe  reverse-wtema-header-sync.exe  grinsight-tor.exe
#   checkpoints\floonet\   checkpoint.rwm recent-headers.bin pin.txt
#   checkpoints\mainnet\   signed release (release\) or the developer pin
param([switch]$NoTor, [switch]$AllowOldCheckpoint)
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot
$env:CARGO_TARGET_DIR = "$PSScriptRoot\.build\target"
$env:CARGO_HOME = "$PSScriptRoot\.build\cargo-home"

function Build([string[]]$argv) {
    Write-Host "cargo $($argv -join ' ')"
    & cargo @argv
    if ($LASTEXITCODE -ne 0) { throw "build failed: cargo $($argv -join ' ')" }
}
Build @('build', '--offline', '--locked', '--release', '--manifest-path', 'header-sync\Cargo.toml')
if (-not $NoTor) {
    Build @('--config', 'tor\vendor.toml', 'build', '--offline', '--locked', '--release', '--manifest-path', 'tor\Cargo.toml', '-p', 'grinsight-tor')
}

$rel = "$PSScriptRoot\.build\target\release"
$out = Join-Path $PSScriptRoot 'dist\grinsight-core'
$fl = Join-Path $out 'checkpoints\floonet'
$mn = Join-Path $out 'checkpoints\mainnet'
foreach ($d in $out, $fl, $mn) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
Copy-Item "$rel\grinsight-service.exe", "$rel\reverse-wtema-header-sync.exe" $out -Force
if (-not $NoTor) { Copy-Item "$rel\grinsight-tor.exe" $out -Force }

function Sha($f) { (Get-FileHash -Algorithm SHA256 $f).Hash.ToLower() }

# Floonet: the checkpoint the testnet runs use, with its pins.
$fcp = Join-Path $PSScriptRoot 'evidence\floonet-checkpoint.rwm'
$fhi = Join-Path $PSScriptRoot 'evidence\floonet-history.bin'
if ((Test-Path $fcp) -and (Test-Path $fhi)) {
    $a = Sha $fcp; $b = Sha $fhi
    if ($a -ne '271e40ceb31ca99978d7a320e50970dfdf8b10f9ce8622e6dff7d5f9b9728f66' -or $b -ne '3e69fc015f25f45cb2dc2010bf569a967f3284f54377d8414b1c857e6567dc7e') {
        throw 'evidence\floonet-checkpoint.rwm / floonet-history.bin do not match their pins'
    }
    Copy-Item $fcp (Join-Path $fl 'checkpoint.rwm') -Force
    Copy-Item $fhi (Join-Path $fl 'recent-headers.bin') -Force
    Set-Content -Path (Join-Path $fl 'pin.txt') -Value @("checkpoint_sha256=$a", "history_sha256=$b") -Encoding ASCII
    Write-Host "floonet checkpoint: ok"
} else { Write-Host 'floonet checkpoint: evidence\floonet-checkpoint.rwm / floonet-history.bin not found (Floonet wallets will not open)' }

# Mainnet: the signed release when there is one, else the cross-checked
# developer checkpoint the user scenario already pinned.
$relDir = Join-Path $PSScriptRoot 'release'
$devCp = Join-Path $PSScriptRoot 'evidence\user-mainnet\checkpoint'
Get-ChildItem $mn -File -ErrorAction SilentlyContinue | Remove-Item -Force
if (Test-Path (Join-Path $relDir 'release.txt')) {
    Copy-Item (Join-Path $relDir '*') $mn -Force
    Write-Host 'mainnet checkpoint: signed release'
} elseif (Test-Path (Join-Path $devCp 'pin.txt')) {
    $pin = Get-Content (Join-Path $devCp 'pin.txt') -Raw
    $a = Sha (Join-Path $devCp 'checkpoint.rwm'); $b = Sha (Join-Path $devCp 'recent-headers.bin')
    if ($pin -notmatch "checkpoint_sha256=$a" -or $pin -notmatch "history_sha256=$b") { throw 'evidence\user-mainnet\checkpoint does not match its pin' }
    Copy-Item (Join-Path $devCp 'checkpoint.rwm'), (Join-Path $devCp 'recent-headers.bin'), (Join-Path $devCp 'pin.txt') $mn -Force
    Write-Host 'mainnet checkpoint: developer pin (no signed release yet)'
} else { Write-Host 'mainnet checkpoint: none (mainnet wallets will not open)' }

# Age of each shipped checkpoint: the timestamp in its header (bytes 10..18).
function Cp-Age($rwm) {
    $line = Get-Content $rwm | Where-Object { $_ -like 'header *' } | Select-Object -First 1
    $hex = $line.Substring(7).Trim()
    $height = [Convert]::ToInt64($hex.Substring(4, 16), 16)
    $ts = [Convert]::ToInt64($hex.Substring(20, 16), 16)
    $days = ((Get-Date).ToUniversalTime() - [DateTimeOffset]::FromUnixTimeSeconds($ts).UtcDateTime).TotalDays
    return @{ Height = $height; Days = [math]::Round($days, 1) }
}
foreach ($net in 'mainnet', 'floonet') {
    $f = Join-Path $out "checkpoints\$net\checkpoint.rwm"
    if (-not (Test-Path $f)) { continue }
    $age = Cp-Age $f
    Write-Host ("{0} checkpoint: height {1}, {2} days old" -f $net, $age.Height, $age.Days)
    if ($age.Days -gt 90) {
        $msg = "$net checkpoint is $($age.Days) days old (release policy: at most 90)"
        if ($net -eq 'mainnet' -and -not $AllowOldCheckpoint) { throw "$msg. Fresh one: .\run_mainnet.ps1 -NewCheckpoint -CheckpointOnly; .\make_release.ps1 (or -AllowOldCheckpoint)" }
        Write-Host "WARNING: $msg"
    }
}

Write-Host ""
Write-Host "ready: $out"
Get-ChildItem $out -Recurse -File | ForEach-Object { Write-Host ("  {0,12:N0}  {1}" -f $_.Length, $_.FullName.Substring($out.Length + 1)) }
