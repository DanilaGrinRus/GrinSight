# Exercise only the directory reservation, not a build, package or program.
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'run-portable.ps1'
$lines = [IO.File]::ReadAllLines($source)
$start = [Array]::FindIndex($lines, [Predicate[string]]{param($line) $line.StartsWith('$pack = ')})
$end = [Array]::FindIndex($lines, [Predicate[string]]{param($line) $line.StartsWith('$log = ')})
if ($start -lt 0 -or $end -le $start) { throw 'Missing reservation section' }
$reserve = [ScriptBlock]::Create(($lines[$start..($end - 1)] -join [Environment]::NewLine))
$dist = Join-Path $env:TEMP ('portable-reservation-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $dist)
$name = 'GrinSight-same-minute'
& $reserve
$bin = Join-Path (Join-Path $dist $name) 'bin'
if (-not [IO.Directory]::Exists($bin)) { throw 'Fresh build directory was not created' }
$note = Join-Path $bin 'previous-run.txt'
[IO.File]::WriteAllText($note, 'innocuous fixture')
$refused = $false
try { & $reserve } catch [IO.IOException] { $refused = $true }
if (-not $refused) { throw 'The next build adopted the earlier directory and its extra file' }
if ([IO.File]::ReadAllText($note) -ne 'innocuous fixture') { throw 'Earlier contents changed' }
Write-Output 'PASS: fresh directory reserved; second build refused; previous file preserved'
