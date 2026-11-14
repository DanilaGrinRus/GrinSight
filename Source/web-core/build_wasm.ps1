# Build the GrinSight web-core spike for Emscripten.
# Usage: .\build_wasm.ps1
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $env:EMSDK) { $env:EMSDK = 'C:\DHW\.toolchain\emsdk' }
$emcc = Join-Path $env:EMSDK 'upstream\emscripten\emcc.exe'
$emxx = Join-Path $env:EMSDK 'upstream\emscripten\em++.exe'
$emar = Join-Path $env:EMSDK 'upstream\emscripten\emar.exe'
if (-not (Test-Path $emcc)) { throw "emcc not found at $emcc; install/activate emsdk first" }
$env:PATH = "$env:EMSDK;$env:EMSDK\upstream\emscripten;$env:PATH"
$env:CC_wasm32_unknown_emscripten = $emcc
$env:CXX_wasm32_unknown_emscripten = $emxx
$env:AR_wasm32_unknown_emscripten = $emar
$env:CARGO_TARGET_WASM32_UNKNOWN_EMSCRIPTEN_LINKER = $emcc
# C objects of the crypto/bitmap libraries must be PIC for the Rust side module.
$env:CFLAGS_wasm32_unknown_emscripten = '-fPIC'
$env:CXXFLAGS_wasm32_unknown_emscripten = '-fPIC'
Set-Location $here
cargo build --release --offline --target wasm32-unknown-emscripten
if ($LASTEXITCODE -ne 0) { throw 'web-core Wasm build failed' }
$out = Join-Path $here 'target\wasm32-unknown-emscripten\release\grinsight_web_core.wasm'
if (-not (Test-Path $out)) { throw "missing $out" }
Get-Item $out | Select-Object FullName,Length
