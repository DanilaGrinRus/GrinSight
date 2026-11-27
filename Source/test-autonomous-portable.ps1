# Isolated offline smoke test of the delivered one-file executable. No existing profiles.
param([Parameter(Mandatory)][string]$Executable,[Parameter(Mandatory)][string]$TestRoot)
$ErrorActionPreference = 'Stop'
$exe = (Resolve-Path -LiteralPath $Executable).Path
if ((Get-Item -LiteralPath $exe).VersionInfo.ProductVersion -ne '0.4.7A') {throw 'Unexpected product version'}
$test = Join-Path $TestRoot ('autonomous-smoke-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($test)
$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = $exe
$start.WorkingDirectory = $test
$start.UseShellExecute = $false
$local = Join-Path $test 'local'
[void][IO.Directory]::CreateDirectory($local)
$start.EnvironmentVariables['LOCALAPPDATA'] = $local
$argsForScenario = '--scenario "{0}\checks" --profile "{0}\profiles" --guard-dir "{0}\guard"' -f $test
$pair = Join-Path $test 'received checkpoint'
[void][IO.Directory]::CreateDirectory($pair)
$fixtures = Join-Path $PSScriptRoot 'chain\headers\points'
Copy-Item -LiteralPath (Join-Path $fixtures 'main.json') -Destination (Join-Path $pair 'checkpoint.json')
Copy-Item -LiteralPath (Join-Path $fixtures 'main.history') -Destination (Join-Path $pair 'history.proof')
foreach ($mode in @('--prepare-only', ('--verify-checkpoint main "{0}"' -f $pair),
                    ('--verify-checkpoint test "{0}"' -f $pair), $argsForScenario)) {
    $expected = if ($mode.StartsWith('--verify-checkpoint test')) {1} else {0}
    $start.Arguments = $mode
    $start.RedirectStandardOutput = $mode.StartsWith('--verify-checkpoint')
    $proc = [Diagnostics.Process]::Start($start)
    try {
        if (!$proc.WaitForExit(300000)) {throw "Timeout in $mode"}
        $code = $proc.ExitCode
        if ($code -ne $expected) {throw "Exit $code in $mode, expected $expected. Inspect $test\checks\scenario.log"}
        if ($mode.StartsWith('--verify-checkpoint main') -and
            $proc.StandardOutput.ReadToEnd() -notmatch 'GSHP1 sample verified: height=4115520 hash=000622ed34fb7c40c407c79d70b27bcf5841d1c2893da88c191779b7b4761482 samples=420') {
            throw 'The portable verifier did not return the expected Mainnet checkpoint'
        }
    } finally {$proc.Dispose()}
}
$log = Join-Path $test 'checks\scenario.log'
if (!(Test-Path -LiteralPath $log -PathType Leaf)) {throw 'Missing scenario log'}
Get-Content -LiteralPath $log -Tail 1
Write-Output "SCENARIO_LOG=$log"
