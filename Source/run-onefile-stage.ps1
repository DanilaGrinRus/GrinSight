# Puts the newest portable ZIP of dist into releases-<version> under its release name,
# pins its checksum there and wraps it into the one-file portable EXE (run-onefile.ps1).
$ErrorActionPreference = 'Stop'
$core = $PSScriptRoot
$version = [regex]::Match((Get-Content -LiteralPath (Join-Path $core 'ui\app\src\lib.rs') -Raw), '(?m)^pub const APP_VERSION: &str = "(\d+\.\d+\.\d+A?)";').Groups[1].Value
if (-not $version) { 'no APP_VERSION in ui\app\src\lib.rs'; exit 2 }
if ($version.EndsWith("A")) { throw "Use run-autonomous-portable.ps1 with the pinned base and explicit binary paths for this candidate." }
$zip = Get-ChildItem 'C:\DHW\dist' -File -Filter 'GrinSight-20??????-????.zip' | Sort-Object Name | Select-Object -Last 1
if (-not $zip) { 'no portable ZIP in C:\DHW\dist'; exit 2 }
$folder = "releases-$version"
$release = Join-Path (Split-Path $core -Parent) $folder
[void][IO.Directory]::CreateDirectory($release)
$name = "GrinSight-$version-windows-x64-portable.zip"
Copy-Item -LiteralPath $zip.FullName -Destination (Join-Path $release $name) -Force
$hash = (Get-FileHash -LiteralPath (Join-Path $release $name) -Algorithm SHA256).Hash.ToLowerInvariant()
$sums = Join-Path $release 'SHA256SUMS.txt'
$kept = @()
if (Test-Path -LiteralPath $sums) { $kept = @(Get-Content -LiteralPath $sums | Where-Object { $_ -and $_ -notmatch ([regex]::Escape($name) + '$') }) }
[IO.File]::WriteAllLines($sums, [string[]]($kept + "$hash  $name"))
"staged: $($zip.Name) -> $folder\$name  sha256 $hash"
& (Join-Path $core 'run-onefile.ps1') -Version $version -Release $folder
