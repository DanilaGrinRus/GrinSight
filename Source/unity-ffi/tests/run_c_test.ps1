# Stage 2 check on Windows (MSVC Build Tools): the C side builds the state
# from saved segments, applies blocks and must get the same results as Rust.
#   .\unity-ffi\tests\run_c_test.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ffi = Join-Path $root 'unity-ffi'
$env:CARGO_TARGET_DIR = Join-Path $root '.build\target-ffi'
$env:CARGO_HOME = Join-Path $root '.build\cargo-home'
Push-Location $ffi
cmd /c "cargo build --release --offline --features testkit 1> ..\.build\ffi-build.log 2>&1"
if ($LASTEXITCODE -ne 0) { Get-Content ..\.build\ffi-build.log -Tail 20; throw 'cargo build failed' }
$rel = Join-Path $env:CARGO_TARGET_DIR 'release'
$fx = Join-Path $root '.build\ffi-fixture'
if (Test-Path $fx) { Remove-Item -Recurse -Force $fx }
& (Join-Path $rel 'us-fixture.exe') $fx | Out-Null
$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
$exe = Join-Path $fx 'test_abi.exe'
cmd /c "`"$vcvars`" >nul && cl /nologo /W3 /I include tests\test_abi.c `"$rel\unity_state_ffi.dll.lib`" /Fe:`"$exe`" /Fo:`"$fx\\`""
if ($LASTEXITCODE -ne 0) { throw 'C compile failed' }
Copy-Item (Join-Path $rel 'unity_state_ffi.dll') $fx
& $exe $fx
$code = $LASTEXITCODE
Pop-Location
exit $code
