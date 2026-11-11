# run_acceptance_tests.ps1 - every automated check of the build, on ONE fixed
# source state, with the results in one folder.
#
#   .\run_acceptance_tests.ps1
#
# 1. fixes the build: source package + manifest (SHA-256 of every shipped
#    file, package id), refused if user data or secrets would go with it;
# 2. dependency inventory of every Cargo.lock (sources, checksums) and the
#    RustSec advisories against it (each one fixed or reviewed);
# 3. unit / integration / fuzz tests: unity-state (incl. payment-failure tests
#    and fuzzing of every parser of foreign / on-disk data),
#    header-sync (incl. reorg + payment confirmation), unity-ffi + C API,
#    unity-tor (incl. restart after ACK, double finalize, fuzzing of the HTTP /
#    foreign API / messenger input), Python policy tests;
#    longer fuzzing:  $env:UNITY_FUZZ_ITERS=50000  before the run;
# 4. checks that the sources did not change during the run (same package id).
#
# Result: evidence\acceptance-<time>\SUMMARY.txt  (ACCEPTANCE=PASS|FAIL|INCOMPLETE)
# No network, no wallet files, no seeds are used.
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = Join-Path $PSScriptRoot "evidence\acceptance-$stamp"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$summary = Join-Path $out 'SUMMARY.txt'
$results = [ordered]@{}

function Note($s) { Write-Host $s; Add-Content -Path $summary -Value $s -Encoding UTF8 }

# Runs a program directly (argument array, no command shell); log per step.
function Run-Step($name, $exe, [string[]]$argv, $dir = $PSScriptRoot) {
    $log = Join-Path $out "$name.log"
    Write-Host "== $name"
    Push-Location $dir
    $ErrorActionPreference = 'Continue'
    try {
        & $exe @argv 2>&1 | ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { "$_" } } |
            Set-Content -Path $log -Encoding UTF8
        $code = $LASTEXITCODE
    }
    catch { "$_" | Set-Content -Path $log -Encoding UTF8; $code = -1 }
    $ErrorActionPreference = 'Stop'
    Pop-Location
    $text = Get-Content $log -Raw
    $passed = ([regex]::Matches($text, 'test result: ok\. (\d+) passed') | ForEach-Object { [int]$_.Groups[1].Value } | Measure-Object -Sum).Sum
    $ran = [regex]::Match($text, 'Ran (\d+) tests?')
    $detail = if ($passed) { "$passed tests passed" } elseif ($ran.Success) { "$($ran.Groups[1].Value) tests" } else { '' }
    $verdict = if ($code -eq 0) { 'PASS' } else { "FAIL (exit $code, see $name.log)" }
    $results[$name] = $verdict
    Note ("{0,-22} {1} {2}" -f $name, $verdict, $detail)
}

Note "ACCEPTANCE RUN $stamp on $env:COMPUTERNAME"
Note ("rustc: " + ((& rustc --version) -join ' '))
Note ("cargo: " + ((& cargo --version) -join ' '))
Note ("python: " + ((& python --version 2>&1) -join ' '))

# 1. fixed build + supply check
Run-Step 'package' 'python' @('package_check.py', 'pack', '--out', (Join-Path $out 'unity-src.zip'))
function Pack-Id($log) {
    $m = Select-String -Path (Join-Path $out $log) -Pattern '^PACK_ID=(.*)$' | Select-Object -First 1
    if ($m) { return $m.Matches[0].Groups[1].Value } else { return 'NONE' }
}
$pkgId = Pack-Id 'package.log'
Note "BUILD_ID (package id) = $pkgId"
# Known vulnerabilities (RustSec): a local clone of the advisory database,
# kept current with  git -C C:\DHW\advisory-db pull  (older than 30 days: FAIL).
# Every advisory must be fixed or reviewed in deps-accepted.txt.
$advDb = if ($env:UNITY_ADVISORY_DB) { $env:UNITY_ADVISORY_DB } else { Join-Path (Split-Path (Split-Path $PSScriptRoot)) 'advisory-db' }
if (Test-Path (Join-Path $advDb 'crates')) {
    Run-Step 'dependencies' 'python' @('package_check.py', 'deps', '--advisory-db', $advDb, '--out', (Join-Path $out 'DEPENDENCIES.txt'))
} else {
    Run-Step 'dependencies' 'python' @('package_check.py', 'deps', '--out', (Join-Path $out 'DEPENDENCIES.txt'))
    $results['advisories'] = 'SKIPPED'
    Note ("{0,-22} SKIPPED (no advisory database: git clone https://github.com/rustsec/advisory-db {1})" -f 'advisories', $advDb)
}

# 2. tests
Run-Step 'unity-state' 'cargo' @('test', '--offline', '--locked', '--features', 'testkit', '--lib') (Join-Path $PSScriptRoot 'unity-state')
Run-Step 'header-sync' 'cargo' @('test', '--offline', '--locked') (Join-Path $PSScriptRoot 'header-sync')
Run-Step 'unity-ffi' 'cargo' @('test', '--offline', '--locked') (Join-Path $PSScriptRoot 'unity-ffi')
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    Run-Step 'c-api' 'powershell' @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'unity-ffi\tests\run_c_test.ps1'))
} else {
    $results['c-api'] = 'SKIPPED'
    Note ("{0,-22} SKIPPED (no MSVC Build Tools: vswhere.exe not found)" -f 'c-api')
}
Run-Step 'unity-tor' 'cargo' @('--config', 'tor\vendor.toml', 'test', '--offline', '--locked', '--manifest-path', 'tor\Cargo.toml', '-p', 'unity-tor')
Run-Step 'python' 'python' @('-m', 'unittest', 'test_package_check')

# 3. the sources are still the ones that were tested
Run-Step 'package-after' 'python' @('package_check.py', 'pack', '--out', (Join-Path $out 'unity-src-after.zip'))
$after = Pack-Id 'package-after.log'
if ($after -ne $pkgId -or $after -eq 'NONE') { $results['same-sources'] = 'FAIL'; Note "SOURCES CHANGED DURING THE RUN ($pkgId -> $after)" }
else { $results['same-sources'] = 'PASS'; Remove-Item (Join-Path $out 'unity-src-after.zip') -ErrorAction SilentlyContinue }

$failed = @($results.GetEnumerator() | Where-Object { $_.Value -like 'FAIL*' })
$skipped = @($results.GetEnumerator() | Where-Object { $_.Value -eq 'SKIPPED' })
$verdict = if ($failed.Count) { 'FAIL' } elseif ($skipped.Count) { 'INCOMPLETE' } else { 'PASS' }
Note "ACCEPTANCE=$verdict (build $pkgId)"
Note "results: $out"
if ($verdict -eq 'FAIL') { exit 1 }
exit 0
