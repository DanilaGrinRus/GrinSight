# GrinSight: packs the portable Windows version into an installer and checks it.
# Result: C:\DHW\dist\GrinSight-<time>-setup.exe (Inno Setup 6, for one user, no signature).
# Takes the newest C:\DHW\dist\GrinSight-<time> folder made by run-portable.ps1, or the one named by -Pack.
# The check: a silent install into a folder of its own, the files compared with the pack, the
# interface scenario run from the installed programs, a silent uninstall.
# Run: powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\run-installer.ps1
param([string]$Pack = '')
$ErrorActionPreference = 'Continue'
$core = Split-Path -Parent $MyInvocation.MyCommand.Path
$dist = 'C:\DHW\dist'
# the version is the window's own: one line of ui\app\src\lib.rs
$version = [regex]::Match((Get-Content -LiteralPath (Join-Path $core 'ui\app\src\lib.rs') -Raw), '(?m)^pub const APP_VERSION: &str = "(\d+\.\d+\.\d+)";').Groups[1].Value
if (-not $version) { Write-Host "no APP_VERSION in ui\app\src\lib.rs"; exit 2 }
$appId = '{5C098D7D-3200-4C3C-8D58-419A276DC6CF}'

if (-not $Pack) {
    $Pack = Get-ChildItem -LiteralPath $dist -Directory | Where-Object { $_.Name -match '^GrinSight-\d{8}-\d{4}$' } | Sort-Object Name | Select-Object -Last 1 | ForEach-Object Name
}
if ($Pack -notmatch '^GrinSight-\d{8}-\d{4}$') { Write-Host "no portable folder to pack: run run-portable.ps1 first"; exit 2 }
$src = Join-Path $dist $Pack
$name = "$Pack-setup"
$log = Join-Path $dist "$name-build.log"
Remove-Item -LiteralPath $log -ErrorAction SilentlyContinue
function Say($s) { Write-Host $s; Add-Content -Path $log -Value $s -Encoding utf8 }
function Sha($path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() }
Say "started $(Get-Date -Format s)"
Say "pack: $src"

$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe", "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") |
    Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if (-not $iscc) { Say "Inno Setup 6 is not installed (ISCC.exe not found). Install it: winget install JRSoftware.InnoSetup"; exit 3 }
Say "iscc: $iscc"

# the pack must be whole: its own sums
$programs = @('GrinSight.exe', 'bin\fly-paycore-host.exe', 'bin\fly-chain.exe', 'bin\fly-mailbox.exe', 'bin\fly-onion.exe', 'bin\lyrebird.exe', 'LICENSE-GPL-3.0.txt', 'LICENSE-lyrebird.txt')
$sums = @{}
Get-Content -LiteralPath (Join-Path $src 'SHA256SUMS.txt') -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_ -match '^([0-9a-f]{64})  (.+)$') { $sums[$Matches[2]] = $Matches[1] }
}
foreach ($f in $programs) {
    $p = Join-Path $src $f
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { Say "missing in the pack: $f"; exit 1 }
    if ($sums[$f] -ne (Sha $p)) { Say "the pack's own sum does not match: $f"; exit 1 }
}

# what the installed copy has of its own: its README, the mark, the sums of the installed set
$extra = Join-Path $dist "$name-extra"
Remove-Item -LiteralPath $extra -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $extra | Out-Null
Copy-Item -LiteralPath (Join-Path $core 'dist-files\README-installed.txt') -Destination (Join-Path $extra 'README.txt')
Set-Content -LiteralPath (Join-Path $extra 'installed.txt') -Encoding ascii -Value @(
    'GrinSight was put here by its installer.',
    'The wallet is not kept in this folder: it is in %LOCALAPPDATA%\GrinSightLight\data.',
    'Do not delete this file: without it the program looks for a wallet next to itself.')
$set = @{}
foreach ($f in $programs) { $set[$f] = $sums[$f] }
foreach ($f in 'README.txt', 'installed.txt') { $set[$f] = Sha (Join-Path $extra $f) }
$set['stop-own.ps1'] = Sha (Join-Path $core 'installer\stop-own.ps1')
$set['grinsight.ico'] = Sha (Join-Path $core 'installer\grinsight.ico')
($set.Keys | Sort-Object | ForEach-Object { "{0}  {1}" -f $set[$_], $_ }) | Out-File -FilePath (Join-Path $extra 'SHA256SUMS.txt') -Encoding ascii

$setup = Join-Path $dist "$name.exe"
Remove-Item -LiteralPath $setup -ErrorAction SilentlyContinue
$built = & $iscc "/DAppVersion=$version" "/DSourceDir=$src" "/DExtraDir=$extra" "/DOutDir=$dist" "/DOutName=$name" (Join-Path $core 'installer\grinsight.iss') 2>&1 | ForEach-Object { "$_" }
$code = $LASTEXITCODE
$built | Add-Content -Path $log -Encoding utf8
Say "iscc exit=$code"
if ($code -ne 0 -or -not (Test-Path -LiteralPath $setup)) { Say "the installer was not built"; exit 1 }
Say ("setup: $setup  {0:N0} bytes  sha256 {1}" -f (Get-Item -LiteralPath $setup).Length, (Sha $setup))
Say "version: $version"
# the installer itself must carry the project's mark: the largest picture of the .ico, byte for byte
$ico = [IO.File]::ReadAllBytes((Join-Path $core 'installer\grinsight.ico'))
$latin = [Text.Encoding]::GetEncoding(28591)
$at = [BitConverter]::ToInt32($ico, 18); $len = [BitConverter]::ToInt32($ico, 14)
$mark = $latin.GetString($ico, $at, $len)
$carries = $latin.GetString([IO.File]::ReadAllBytes($setup)).IndexOf($mark, [StringComparison]::Ordinal) -ge 0
Say ("icon: {0}" -f $(if ($carries) { "the installer carries grinsight.ico ($len bytes of its largest picture)" } else { 'THE INSTALLER DOES NOT CARRY grinsight.ico' }))
if (-not $carries) { exit 1 }

# ---- the check. An installed copy of this very program (another folder,
# the user's own) is not touched: then the check is skipped.
$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\${appId}_is1"
if (Test-Path -LiteralPath $key) {
    Say "GrinSight is installed on this computer already: the install check is skipped, the installer is built"
    Say "finished $(Get-Date -Format s)"
    exit 0
}
$check = Join-Path $dist "$name-check"
Remove-Item -LiteralPath $check -Recurse -Force -ErrorAction SilentlyContinue
$app = Join-Path $check 'app'
New-Item -ItemType Directory -Force -Path $check | Out-Null
function RunTimed($file, [string[]]$argv, [int]$seconds) {
    $p = Start-Process -FilePath $file -ArgumentList $argv -PassThru
    $null = $p.Handle
    if (-not $p.WaitForExit($seconds * 1000)) { try { $p.Kill() } catch {}; return 124 }
    $p.WaitForExit()
    return [int]$p.ExitCode
}
$failed = 0
$code = RunTimed $setup @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/NOICONS', '/CURRENTUSER', "/DIR=$app", "/LOG=$check\install.log") 300
Say "install exit=$code"
if ($code -ne 0) { $failed++ }
foreach ($f in ($set.Keys | Sort-Object)) {
    $p = Join-Path $app $f
    $same = (Test-Path -LiteralPath $p -PathType Leaf) -and ((Sha $p) -eq $set[$f])
    Say ("installed {0,-28} {1}" -f $f, $(if ($same) { 'same as packed' } else { 'DIFFERS OR MISSING' }))
    if (-not $same) { $failed++ }
}
$uninstaller = Join-Path $app 'unins000.exe'
if (-not (Test-Path -LiteralPath $uninstaller)) { Say "no uninstaller in the installed folder"; $failed++ }
# the installed programs, driven by the interface scenario, with profiles of the check's own
if ($failed -eq 0) {
    $scn = Join-Path $check 'scenario'
    $p = Start-Process -FilePath (Join-Path $app 'GrinSight.exe') -ArgumentList @('--scenario', "$scn\out", '--host', (Join-Path $app 'bin\fly-paycore-host.exe'), '--profile', "$scn\profiles", '--guard-dir', "$scn\guards") -Wait -PassThru -NoNewWindow -RedirectStandardError (Join-Path $check 'scenario.err')
    Say "scenario exit=$($p.ExitCode)"
    if ($p.ExitCode -ne 0) { $failed++ }
    if (Test-Path "$scn\out\scenario.log") { Get-Content "$scn\out\scenario.log" | Select-Object -Last 1 | ForEach-Object { Say "scenario: $_" } }
}
if (Test-Path -LiteralPath $uninstaller) {
    $code = RunTimed $uninstaller @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') 300
    # the uninstaller hands over to a copy of itself, returns at once and removes itself last
    for ($i = 0; $i -lt 60 -and @(Get-ChildItem -LiteralPath $app -Recurse -File -ErrorAction SilentlyContinue).Count -ne 0; $i++) { Start-Sleep 1 }
    $left = @(Get-ChildItem -LiteralPath $app -Recurse -File -ErrorAction SilentlyContinue)
    Say "uninstall exit=$code; files left in the program folder: $($left.Count)"
    if ($code -ne 0 -or $left.Count -ne 0) { $failed++; $left | ForEach-Object { Say "  left: $($_.FullName)" } }
    if (Test-Path -LiteralPath $key) { Say "the uninstall entry is still registered"; $failed++ }
}
Say "installer check: $(if ($failed -eq 0) { 'passed' } else { "FAILED ($failed)" })"
Say "finished $(Get-Date -Format s)"
if ($failed -ne 0) { exit 1 }
