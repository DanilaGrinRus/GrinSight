# GrinSight for Android (arm64): builds the wallet core for aarch64-linux-android
# with the NDK and lays it out for the Flutter app:
#
#   dist\android\jniLibs\arm64-v8a\libgrinsight_service.so
#   dist\android\jniLibs\arm64-v8a\libreverse_wtema_header_sync.so
#   dist\android\checkpoints\{mainnet,floonet}\...   (copied from dist\grinsight-core)
#
# The .so files are programs (Android lets an app run files only from its
# native library folder); the app starts libgrinsight_service.so like on
# Windows.
#
#   .\make_android.ps1 -WithTor   also libunity_tor.so, built in WSL (Ubuntu) by
#                                  tor\build_android_wsl.sh: OpenSSL for Android
#                                  needs perl and make, which Windows lacks.
#
# Needs: ANDROID_HOME with ndk\27.2.12479018, rustup target aarch64-linux-android,
# and dist\grinsight-core\checkpoints (run .\make_service.ps1 -NoTor once).
param([string]$Ndk = '27.2.12479018', [int]$Api = 24, [switch]$WithTor)
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot
$env:CARGO_TARGET_DIR = "$PSScriptRoot\.build\target"
$env:CARGO_HOME = "$PSScriptRoot\.build\cargo-home"

$sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { 'C:\DHW\.toolchain\android-sdk' }
$bin = Join-Path $sdk "ndk\$Ndk\toolchains\llvm\prebuilt\windows-x86_64\bin"
$clang = Join-Path $bin "aarch64-linux-android$Api-clang.cmd"
$clangxx = Join-Path $bin "aarch64-linux-android$Api-clang++.cmd"
$ar = Join-Path $bin 'llvm-ar.exe'
foreach ($f in $clang, $ar) { if (-not (Test-Path $f)) { throw "NDK tool not found: $f (install ndk;$Ndk with sdkmanager)" } }

# The cc crate (C parts: secp256k1-zkp, CRoaring) and the Rust linker use the NDK.
$env:CC_aarch64_linux_android = $clang
$env:CXX_aarch64_linux_android = $clangxx
$env:AR_aarch64_linux_android = $ar
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = $clang

Write-Host "cargo build (aarch64-linux-android, API $Api, NDK $Ndk)"
# Full compiler output goes to dist\android-build.log (errors are easy to send).
$log = Join-Path $PSScriptRoot 'dist\android-build.log'
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
$ErrorActionPreference = 'Continue'
& cargo build --offline --locked --release --target aarch64-linux-android --manifest-path header-sync\Cargo.toml --bin grinsight-service --bin reverse-wtema-header-sync 2>&1 |
    ForEach-Object { "$_" } | Tee-Object -FilePath $log
$code = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($code -ne 0) { throw "android build failed (full output: $log)" }

$rel = "$PSScriptRoot\.build\target\aarch64-linux-android\release"
$out = Join-Path $PSScriptRoot 'dist\android'
$jni = Join-Path $out 'jniLibs\arm64-v8a'
New-Item -ItemType Directory -Force -Path $jni | Out-Null
Copy-Item "$rel\grinsight-service" (Join-Path $jni 'libgrinsight_service.so') -Force
Copy-Item "$rel\reverse-wtema-header-sync" (Join-Path $jni 'libreverse_wtema_header_sync.so') -Force

if ($WithTor) {
    Write-Host 'unity-tor for Android (WSL)'
    & wsl.exe bash /mnt/c/DHW/GrinFlyClient/Unity/tor/build_android_wsl.sh
    if ($LASTEXITCODE -ne 0) { throw 'unity-tor android build (WSL) failed' }
}

$cpSrc = Join-Path $PSScriptRoot 'dist\grinsight-core\checkpoints'
if (-not (Test-Path $cpSrc)) { throw 'dist\grinsight-core\checkpoints not found: run .\make_service.ps1 -NoTor first' }
$cpOut = Join-Path $out 'checkpoints'
if (Test-Path $cpOut) { Remove-Item -Recurse -Force $cpOut }
Copy-Item -Recurse $cpSrc $cpOut

Write-Host ""
Write-Host "ready: $out"
Get-ChildItem $out -Recurse -File | ForEach-Object { Write-Host ("  {0,12:N0}  {1}" -f $_.Length, $_.FullName.Substring($out.Length + 1)) }
