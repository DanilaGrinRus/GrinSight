# Build the browser ES module around the Rust/Wasm core.
# Usage: .\build_browser.ps1   (after .\build_wasm.ps1)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $env:EMSDK) { $env:EMSDK = 'C:\DHW\.toolchain\emsdk' }
$emcc = Join-Path $env:EMSDK 'upstream\emscripten\emcc.exe'
if (-not (Test-Path $emcc)) { throw "emcc not found at $emcc" }
$env:PATH = "$env:EMSDK;$env:EMSDK\upstream\emscripten;$env:PATH"
Set-Location $here
$out = Join-Path $here 'browser'
New-Item -ItemType Directory -Force $out | Out-Null
$args = @(
    'test\bridge.c',
    'target\wasm32-unknown-emscripten\release\libgrinsight_web_core.a',
    '--no-entry', '-O2', '-fwasm-exceptions',
    '-o', 'browser\grinsight_core.js',
    '-sMODULARIZE=1',
    '-sEXPORT_ES6=1',
    '-sEXPORT_NAME=createGrinSightCore',
    '-sENVIRONMENT=web,node',
    '-sALLOW_MEMORY_GROWTH=1',
    '-sSTACK_SIZE=16777216',
    '-sINITIAL_MEMORY=67108864',
    '-sNO_EXIT_RUNTIME=1',
    '-sEXPORTED_FUNCTIONS=["_gs_abi_version","_gs_header_hash","_gs_test_address","_gs_test_s1","_gs_wallet_set_phrase","_gs_wallet_clear","_gs_wallet_address","_gs_wallet_new_phrase","_gs_wallet_scan_bundle","_gs_checkpoint_height","_gs_restore_recent","_gs_storage_selftest","_gs_verify_headers","_gs_set_network","_gs_chain_start","_gs_chain_append","_gs_chain_tip","_gs_utxo_fixture","_gs_utxo_bundle","_gs_chain_header","_gs_chain_header_hash","_malloc","_free"]',
    '-sEXPORTED_RUNTIME_METHODS=["ccall","cwrap","UTF8ToString","HEAPU8"]'
)
& $emcc @args
if ($LASTEXITCODE -ne 0) { throw 'browser module link failed' }
Get-ChildItem $out -File | Select-Object Name, Length





