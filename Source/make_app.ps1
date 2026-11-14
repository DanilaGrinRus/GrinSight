# make_app.ps1 - release build of the GrinSight app. Every package it makes
# carries the signed mainnet checkpoint from release\ (and refuses to build
# without one, or with one older than 90 days - see make_service.ps1).
#
#   .\make_app.ps1 -Version 0.2.0   Windows: core + app (GS_RELEASE) + GrinSight-setup.exe (Inno Setup 6)
#   .\make_app.ps1 -Android    also the APK (make_android.ps1 + flutter build apk)
#   .\make_app.ps1 -Android -NoWindows
#
# Out: UI\flutter_app\dist\GrinSight-setup.exe   (installer; the zip next to it is for checks)
#      UI\flutter_app\dist\grinsight-windows-x64.zip
#      UI\flutter_app\build\app\outputs\flutter-apk\app-release.apk
#      UI\flutter_app\dist\CHECKPOINT.txt   (which signed checkpoint is inside)
# A fresh checkpoint first:  .\run_mainnet.ps1 -NewCheckpoint -CheckpointOnly; .\make_release.ps1
param([switch]$Android, [switch]$NoWindows, [string]$Version = '')
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

$rel = Join-Path $PSScriptRoot 'release'
$relTxt = Join-Path $rel 'release.txt'
if (-not (Test-Path (Join-Path $rel 'release.sig')) -or -not (Test-Path $relTxt)) {
    throw 'no signed mainnet checkpoint in release\ : .\run_mainnet.ps1 -NewCheckpoint -CheckpointOnly; .\make_release.ps1'
}
$relSha = (Get-FileHash -Algorithm SHA256 $relTxt).Hash
function Same-Release([string]$txt) {
    (Test-Path $txt) -and ((Get-FileHash -Algorithm SHA256 $txt).Hash -eq $relSha)
}
$app = Join-Path $PSScriptRoot 'UI\flutter_app'
$define = '--dart-define=GS_RELEASE=true'
# The real flutter executable (a function must not share its name: PowerShell
# names are case-insensitive, so it would call itself).
$flutterExe = (Get-Command flutter -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
function Invoke-Flutter([string[]]$argv) {
    Push-Location $app
    try {
        Write-Host "flutter $($argv -join ' ')"
        & $flutterExe @argv
        if ($LASTEXITCODE -ne 0) { throw "flutter $($argv -join ' ') failed" }
    } finally { Pop-Location }
}

if (-not $NoWindows) {
    # Core + checkpoints (signature, age) -> dist\grinsight-core
    & (Join-Path $PSScriptRoot 'make_service.ps1')
    $core = Join-Path $PSScriptRoot 'dist\grinsight-core'
    if (-not (Same-Release (Join-Path $core 'checkpoints\mainnet\release.txt'))) {
        throw 'dist\grinsight-core has a different mainnet checkpoint than release\ (make_service.ps1 did not ship the signed release)'
    }
    Invoke-Flutter @('build', 'windows', '--release', $define)
    $runner = Join-Path $app 'build\windows\x64\runner\Release'
    $dst = Join-Path $runner 'grinsight-core'
    if (Test-Path $dst) { Remove-Item -Recurse -Force $dst }
    Copy-Item -Recurse $core $dst
    # VC++ runtime next to the app and the core (no Redistributable needed).
    foreach ($dll in 'msvcp140.dll', 'vcruntime140.dll', 'vcruntime140_1.dll') {
        $src = Join-Path $env:WINDIR "System32\$dll"
        if (-not (Test-Path $src)) { throw "$src not found (install the VC++ 2015-2022 x64 runtime once)" }
        Copy-Item $src $runner -Force
        Copy-Item $src $dst -Force
    }
    $outDir = Join-Path $app 'dist'
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $zip = Join-Path $outDir 'grinsight-windows-x64.zip'
    if (Test-Path $zip) { Remove-Item -Force $zip }
    Compress-Archive -Path (Join-Path $runner '*') -DestinationPath $zip
    Write-Host ("windows: {0} ({1:N1} MB)" -f $zip, ((Get-Item $zip).Length / 1MB))
    # Installer for the release page: one GrinSight-setup.exe (Inno Setup 6).
    $iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
              "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $iscc) { throw 'Inno Setup 6 not found (installer GrinSight-setup.exe): winget install JRSoftware.InnoSetup' }
    $ver = (Get-Content (Join-Path $app 'pubspec.yaml') | Where-Object { $_ -match '^version:' } | Select-Object -First 1) -replace '^version:\s*', '' -replace '\+.*$', ''
    if ($Version) { $ver = $Version }
    $setup = Join-Path $outDir 'GrinSight-setup.exe'
    if (Test-Path $setup) { Remove-Item -Force $setup }
    & $iscc "/DAppVersion=$ver" "/DSourceDir=$runner" "/DOutDir=$outDir" "/DIconFile=$(Join-Path $app 'windows\runner\resources\app_icon.ico')" (Join-Path $PSScriptRoot 'installer\grinsight.iss') | Out-Host
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $setup)) { throw 'the installer was not built (ISCC)' }
    Write-Host ("windows installer: {0} ({1:N1} MB, version {2})" -f $setup, ((Get-Item $setup).Length / 1MB), $ver)
}

if ($Android) {
    # Core for Android + the same checkpoints as app assets.
    & (Join-Path $PSScriptRoot 'make_android.ps1')
    if (-not (Same-Release (Join-Path $app 'assets\checkpoints\mainnet\release.txt'))) {
        throw 'the APK assets have a different mainnet checkpoint than release\ (run make_service.ps1, then this again)'
    }
    Invoke-Flutter @('build', 'apk', '--release', '--target-platform', 'android-arm64,android-x64', $define)
    $apk = Join-Path $app 'build\app\outputs\flutter-apk\app-release.apk'
    Write-Host ("android: {0} ({1:N1} MB)" -f $apk, ((Get-Item $apk).Length / 1MB))
}

# What is inside: shown on the release page and checked by make_github_release.ps1.
$t = Get-Content $relTxt
$note = @(
    "mainnet checkpoint shipped in this build (signed):",
    ($t | Where-Object { $_ -match '^(height|header_hash|checkpoint_sha256|history_sha256|sequence|key_id)=' }),
    "release_txt_sha256=$($relSha.ToLower())",
    "built=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
)
New-Item -ItemType Directory -Force -Path (Join-Path $app 'dist') | Out-Null
Set-Content -Path (Join-Path $app 'dist\CHECKPOINT.txt') -Value $note -Encoding ASCII
$note | ForEach-Object { Write-Host $_ }
