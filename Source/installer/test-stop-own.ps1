# Offline uninstall-path contract. No installer, registry or real processes.
$ErrorActionPreference = 'Stop'
$iss = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'grinsight.iss') -Raw
$action = ($iss -split '\[UninstallRun\]', 2)[1]
$ordinaryDirectory = "C:\Users\O'Brien\Apps\Grin"
if ($action -match '-Command ""([^\r\n]+?)"""') {
    # Parse only. Also accept paired right braces here so that either treatment
    # of a trailing right brace tests the ordinary path case independently.
    $source = $Matches[1].Replace('{{','{').Replace('}}','}').Replace('{app}', $ordinaryDirectory)
    $issues = $null
    [void][Management.Automation.Language.Parser]::ParseInput($source,[ref]$null,[ref]$issues)
    if ($issues.Count) { throw "Cannot parse uninstall action for O'Brien ($($issues[0].ErrorId))." }
}
if ($action -notmatch '(?i)-File ""\{app\}\\stop-own\.ps1""' -or
    $action -match '(?i)-Command') { throw 'The uninstall action must pass the installation path as file data.' }
if ($iss -notmatch 'Source: "stop-own\.ps1"; DestDir: "\{app\}"') {throw 'Missing uninstall helper.'}

$case = Join-Path ([IO.Path]::GetTempPath()) ("Grin O'Brien " + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $case)
$helper = Join-Path $case 'stop-own.ps1'
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'stop-own.ps1') -Destination $helper
$own = @('GrinSight.exe','bin\fly-paycore-host.exe','bin\fly-chain.exe','bin\fly-mailbox.exe','bin\fly-onion.exe','bin\lyrebird.exe') |
    ForEach-Object { Join-Path $case $_ }
$others = @((Join-Path $case 'nested\GrinSight.exe'), (Join-Path ($case + '-2') 'bin\fly-chain.exe'))
$seen = [Collections.Generic.List[string]]::new()
function Get-Process {
    param($Name,$ErrorAction)
    foreach ($image in ($own + $others)) { [pscustomobject]@{ Path = $image } }
}
function Stop-Process {
    param($InputObject,[switch]$Force,$ErrorAction)
    $seen.Add($InputObject.Path)
}
& $helper
if ($seen.Count -ne $own.Count -or (Compare-Object $own $seen)) {throw 'The set of process paths differs.'}
Write-Output 'PASS: exactly six installed binaries selected in a folder containing spaces and an apostrophe.'
