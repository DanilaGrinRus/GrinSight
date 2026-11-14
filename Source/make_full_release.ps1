# make_full_release.ps1 - the whole release in one run:
#   1. app widget tests (flutter test)            -SkipTests to skip
#   2. core + Windows app + installer + Android APK (make_app.ps1 -Android; it runs make_service.ps1)
#   3. Linux .deb in WSL (make_deb.sh)            -NoDeb to skip
#   4. release folder + source package + checksums (make_github_release.ps1)
# Result: C:\DHW\GrinSight\GrinSight-<version>\  (setup.exe, apk, deb, source.zip, CHECKPOINT, SHA256SUMS)
#         and dist\release\<version>\ for publish_github.ps1
#
#   .\make_full_release.ps1 -Version 0.4.1-ThxWiesche
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [switch]$SkipTests,
    [switch]$NoDeb,
    [switch]$SkipAcceptanceCheck = $true
)
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot
$t0 = Get-Date
function Step([string]$name) { Write-Host ""; Write-Host "==== $name  ($([int]((Get-Date) - $t0).TotalMinutes) min) ====" -ForegroundColor Cyan }

if (-not $SkipTests) {
    Step '1/4 flutter test'
    Push-Location (Join-Path $PSScriptRoot 'UI\flutter_app')
    try {
        & flutter test
        if ($LASTEXITCODE -ne 0) { throw 'flutter test failed: fix the tests or run with -SkipTests' }
    } finally { Pop-Location }
}

Step '2/4 core + Windows + Android (make_app.ps1)'
& (Join-Path $PSScriptRoot 'make_app.ps1') -Version $Version -Android

if (-not $NoDeb) {
    Step '3/4 Linux .deb (WSL)'
    $p = $PSScriptRoot -replace '\\', '/'
    $wslRepo = '/mnt/' + $p.Substring(0, 1).ToLower() + $p.Substring(2)
    & wsl bash -lc "cd '$wslRepo' && bash make_deb.sh --version '$Version' --repo '$wslRepo'"
    if ($LASTEXITCODE -ne 0) { throw "make_deb.sh failed (exit $LASTEXITCODE)" }
}

Step '4/4 release + sources (make_github_release.ps1)'
if ($SkipAcceptanceCheck) {
    & (Join-Path $PSScriptRoot 'make_github_release.ps1') -Version $Version -SkipAcceptanceCheck
} else {
    & (Join-Path $PSScriptRoot 'make_github_release.ps1') -Version $Version
}

$top = Join-Path (Split-Path $PSScriptRoot -Parent) "GrinSight-$Version"
Write-Host ""
Write-Host "DONE in $([int]((Get-Date) - $t0).TotalMinutes) min: $top" -ForegroundColor Green
Get-ChildItem $top -File | ForEach-Object { Write-Host ("  {0,14:N0}  {1}" -f $_.Length, $_.Name) }
Write-Host "publish: .\publish_github.ps1 -Version $Version"
