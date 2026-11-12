# GrinSight for Android: builds the wallet core with the NDK for each ABI and
# lays it out for the Flutter app:
#
#   dist\android\jniLibs\<abi>\libgrinsight_service.so
#   dist\android\jniLibs\<abi>\libreverse_wtema_header_sync.so
#   dist\android\jniLibs\<abi>\libgrinsight_tor.so    (Tor + GlauxNet; -NoTor skips it)
#   dist\android\checkpoints\{mainnet,floonet}\...     (copied from dist\grinsight-core)
#
# ABIs (default both): arm64-v8a for real phones, x86_64 for the emulator. The
# .so files are programs (Android lets an app run files only from its native
# library folder); the app starts libgrinsight_service.so like on Windows.
#
# grinsight-tor is built with the NDK as well: on Android it uses rustls (pure
# Rust TLS, feature `rustls`) instead of OpenSSL, so no perl/make and no WSL.
#
# Needs: ANDROID_HOME with ndk\27.2.12479018, the rustup targets
# aarch64-linux-android and x86_64-linux-android, and dist\grinsight-core\checkpoints
# (run .\make_service.ps1 -NoTor once).
#
#   .\make_android.ps1                 both ABIs
#   .\make_android.ps1 -Abis x86_64    emulator only (faster)
#   .\make_android.ps1 -NoTor          without grinsight-tor
param(
    [string]$Ndk = '27.2.12479018',
    [int]$Api = 24,
    [ValidateSet('arm64-v8a', 'x86_64')][string[]]$Abis = @('arm64-v8a', 'x86_64'),
    [switch]$NoTor,
    [switch]$WithTor
)
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot
$env:CARGO_TARGET_DIR = "$PSScriptRoot\.build\target"
$env:CARGO_HOME = "$PSScriptRoot\.build\cargo-home"

$sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { 'C:\DHW\.toolchain\android-sdk' }
$ndkBin = Join-Path $sdk "ndk\$Ndk\toolchains\llvm\prebuilt\windows-x86_64\bin"
if (-not (Test-Path $ndkBin)) { throw "NDK not found: $ndkBin (install ndk;$Ndk with sdkmanager)" }

$log = Join-Path $PSScriptRoot 'dist\android-build.log'
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
Remove-Item $log -ErrorAction SilentlyContinue
$out = Join-Path $PSScriptRoot 'dist\android'

# ABI -> (rust target triple, NDK tool prefix)
$triple = @{ 'arm64-v8a' = 'aarch64-linux-android'; 'x86_64' = 'x86_64-linux-android' }

function Invoke-CargoLogged([string[]]$CargoArgs) {
    $ErrorActionPreference = 'Continue'
    # Tee passes the cargo output through; send it to the host so it does NOT
    # become this function's return value (only $code must be returned).
    & cargo @CargoArgs 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $log -Append | Out-Host
    $code = $LASTEXITCODE
    $script:ErrorActionPreference = 'Stop'
    return $code
}

foreach ($abi in $Abis) {
    $t = $triple[$abi]
    $clang = Join-Path $ndkBin "$t$Api-clang.cmd"
    $ar = Join-Path $ndkBin 'llvm-ar.exe'
    if (-not (Test-Path $clang)) { throw "NDK tool not found: $clang" }

    # cc crate (secp256k1-zkp, CRoaring) and the Rust linker use the NDK. The env
    # var names carry the triple with underscores, e.g. CC_x86_64_linux_android.
    $u = $t.Replace('-', '_')
    Set-Item "env:CC_$u" $clang
    Set-Item "env:CXX_$u" (Join-Path $ndkBin "$t$Api-clang++.cmd")
    Set-Item "env:AR_$u" $ar
    Set-Item "env:CARGO_TARGET_$($u.ToUpper())_LINKER" $clang

    Write-Host "cargo build ($t, API $Api, NDK $Ndk)"
    $code = Invoke-CargoLogged @('build', '--offline', '--locked', '--release', '--target', $t,
        '--manifest-path', 'header-sync\Cargo.toml', '--bin', 'grinsight-service', '--bin', 'reverse-wtema-header-sync')
    if ($code -ne 0) { throw "android build failed for $abi (full output: $log)" }

    $rel = "$PSScriptRoot\.build\target\$t\release"
    $jni = Join-Path $out "jniLibs\$abi"
    New-Item -ItemType Directory -Force -Path $jni | Out-Null
    Copy-Item "$rel\grinsight-service" (Join-Path $jni 'libgrinsight_service.so') -Force
    Copy-Item "$rel\reverse-wtema-header-sync" (Join-Path $jni 'libreverse_wtema_header_sync.so') -Force

    # -WithTor is accepted for old command lines: Tor is built by default now.
    if (-not $NoTor) {
        Write-Host "grinsight-tor ($t, rustls, no OpenSSL)"
        $code = Invoke-CargoLogged @('--config', 'tor\vendor.toml', 'build', '--offline', '--locked', '--release',
            '--target', $t, '--manifest-path', 'tor\Cargo.toml', '-p', 'grinsight-tor', '--no-default-features', '--features', 'rustls')
        if ($code -ne 0) { throw "grinsight-tor android build failed for $abi (full output: $log)" }
        Copy-Item "$rel\grinsight-tor" (Join-Path $jni 'libgrinsight_tor.so') -Force
    }
}

$cpSrc = Join-Path $PSScriptRoot 'dist\grinsight-core\checkpoints'
if (-not (Test-Path $cpSrc)) { throw 'dist\grinsight-core\checkpoints not found: run .\make_service.ps1 -NoTor first' }
$cpOut = Join-Path $out 'checkpoints'
if (Test-Path $cpOut) { Remove-Item -Recurse -Force $cpOut }
Copy-Item -Recurse $cpSrc $cpOut

# The Flutter app ships the same checkpoints as assets: the Android service gets
# them in filesDir\checkpoints and re-checks them by SHA-256 on every start
# (see lib\backend\checkpoints_assets.dart). Never copied into git by hand.
$assetsCp = Join-Path $PSScriptRoot 'UI\flutter_app\assets\checkpoints'
if (Test-Path $assetsCp) { Remove-Item -Recurse -Force $assetsCp }
New-Item -ItemType Directory -Force -Path $assetsCp | Out-Null
Copy-Item -Path (Join-Path $cpOut '*') -Destination $assetsCp -Recurse -Force

Write-Host ""
Write-Host "ready: $out  (ABIs: $($Abis -join ', '))"
Get-ChildItem $out -Recurse -File | ForEach-Object { Write-Host ("  {0,12:N0}  {1}" -f $_.Length, $_.FullName.Substring($out.Length + 1)) }
