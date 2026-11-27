# Build and check the complete Windows release from the selected checkout.
param([ValidateSet('Core','All')][string]$Phase = 'All',
      [Parameter(Mandatory)][string]$BaselinePortable,
      [Parameter(Mandatory)][string]$OutputDirectory,
      [string]$BuildCache = 'C:\DHW\dist')
$ErrorActionPreference = 'Stop'
$source = $PSScriptRoot
$version = [regex]::Match((Get-Content -LiteralPath "$source\ui\app\src\lib.rs" -Raw),
    '(?m)^pub const APP_VERSION: &str = "(\d+\.\d+\.\d+A?)";').Groups[1].Value
if (!$version) { throw 'Missing wallet version' }
$jobs = @(
    @{crate='paycore\host'; target='target-host'; bin='fly-paycore-host'},
    @{crate='chain\fly-chain'; target='target-chain'; bin='fly-chain'},
    @{crate='onion'; target='target-chain'; bin='fly-onion'},
    @{crate='transport\mailbox-nostr'; target='target-mailbox'; bin='fly-mailbox'})
if ($Phase -eq 'All') { $jobs += @{crate='ui\app'; target='target-ui'; bin='fly-ui'} }
foreach ($job in $jobs) {
    Push-Location (Join-Path $source $job.crate)
    try {
        $env:CARGO_TARGET_DIR = Join-Path $BuildCache $job.target
        & cargo build --offline --locked --release --bin $job.bin
        if ($LASTEXITCODE -ne 0) { throw "Build failed: $($job.bin)" }
    } finally { Pop-Location }
}
if ($Phase -eq 'Core') { return }
$stage = Join-Path $BuildCache ('release-047A-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
$null = New-Item -ItemType Directory -Path $stage
$argsForPack = @{
    BaseExe=$BaselinePortable; OutputDir=$stage; WindowExe="$BuildCache\target-ui\release\fly-ui.exe"
    HostExe="$BuildCache\target-host\release\fly-paycore-host.exe"; ChainExe="$BuildCache\target-chain\release\fly-chain.exe"
    MailboxExe="$BuildCache\target-mailbox\release\fly-mailbox.exe"; OnionExe="$BuildCache\target-chain\release\fly-onion.exe"
}
& "$source\run-autonomous-portable.ps1" @argsForPack
$portableName = "GrinSight-$version-windows-x64-portable.exe"
$portable = Join-Path $stage $portableName
& "$source\test-autonomous-portable.ps1" -Executable $portable -TestRoot $stage
$dest = [IO.Directory]::CreateDirectory($OutputDirectory).FullName
function Deliver([string]$from, [string]$name) {
    $to = Join-Path $dest $name
    if (Test-Path -LiteralPath $to) { throw "Output file already exists: $name" }
    [IO.File]::Copy($from, $to, $false)
    if ((Get-FileHash -LiteralPath $from).Hash -ne (Get-FileHash -LiteralPath $to).Hash) {
        throw "Copy digest differs: $name"
    }
    Write-Output "CHECKED=$to"
}
Deliver $portable $portableName
$smokes = @(Get-ChildItem -LiteralPath $stage -Directory -Filter 'autonomous-smoke-*')
if ($smokes.Count -ne 1) { throw 'Expected one isolated portable runtime' }
$runtime = @(Get-ChildItem -LiteralPath (Join-Path $smokes[0].FullName 'local\GrinSightLight\portable-runtime') -Directory)
if ($runtime.Count -ne 1) { throw 'Expected one prepared catalog' }
$log = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$source\run-installer.ps1" -RuntimeDirectory $runtime[0].FullName
$log | ForEach-Object { Write-Output $_ }
if ($LASTEXITCODE -ne 0) { throw 'Windows setup check failed' }
$passed = @($log | Where-Object { $_ -like 'VERIFIED_SETUP=*' })
if ($passed.Count -ne 1) { throw 'Setup install/uninstall was not verified' }
Deliver $passed[0].Substring(15) "GrinSight-$version-windows-x64-setup.exe"
