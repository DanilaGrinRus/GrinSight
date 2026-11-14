# GitHub release package of GrinSight. Collects, checks and hashes; uploads nothing.
#
#   .\make_github_release.ps1 -Version 0.1.0 -Author "Name or handle"
#
# Result in dist\release\<version>\:
#   assets\  files for the GitHub release (direct files; only the source is a zip):
#            GrinSight-<v>-windows-x64-setup.exe  installer, signed mainnet checkpoint inside
#            GrinSight-<v>-android-arm64.apk      (when built), same checkpoint
#            GrinSight-<v>-linux-amd64.deb        (when built by make_deb.sh), same checkpoint
#            GrinSight-<v>-CHECKPOINT.txt         which signed checkpoint is inside
#            GrinSight-<v>-source.zip             = repo\Source
#            SHA256SUMS.txt
#            (the documents are in the repository, Documents\, not an asset)
#   repo\    the repository (branch GrinSight):
#            README.md README.ru.md LICENSE LICENSE-DOCS.md NOTICE.md assets\readme\
#            Documents\  how it works, mathematics, release notes, diagrams, DEPENDENCIES.txt
#            Source\     the code (allow-listed core + the Flutter app), scanned for secrets
# Publish with .\publish_github.ps1 -Version <v>.
#
# Refuses when: the last acceptance run is not PASS (-SkipAcceptanceCheck to override),
# the Windows package is missing, or its mainnet checkpoint is older than 90 days.
# The author can also be kept in GrinSight\release-docs\AUTHOR.txt (one line).
param([Parameter(Mandatory = $true)][string]$Version, [string]$Author = '', [switch]$SkipAcceptanceCheck)
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot
if ($Version -notmatch '^\d+\.\d+\.\d+([-.][0-9A-Za-z.]+)?$') { throw "version like 0.1.0 or 0.1.0-beta.1, not '$Version'" }

$docs = Join-Path $PSScriptRoot 'GrinSight\release-docs'
if (-not $Author) {
    $af = Join-Path $docs 'AUTHOR.txt'
    if (Test-Path $af) { $Author = (Get-Content $af -TotalCount 1).Trim() }
}
if (-not $Author) { throw 'author is required (the license asks for attribution): -Author "Name" or GrinSight\release-docs\AUTHOR.txt' }

$out = Join-Path $PSScriptRoot "dist\release\$Version"
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
$assets = Join-Path $out 'assets'
$repo = Join-Path $out 'repo'
foreach ($d in $assets, $repo) { New-Item -ItemType Directory -Force -Path $d | Out-Null }

# 1. Acceptance ---------------------------------------------------------------------------
$acc = Get-ChildItem -Directory (Join-Path $PSScriptRoot 'evidence') -Filter 'acceptance-*' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
# This tree (C:\DHW\GrinSight\Source) may have no acceptance run at all: -SkipAcceptanceCheck
# then releases without one and says so (the release notes must say it too).
$deps = ''
if (-not $acc) {
    if (-not $SkipAcceptanceCheck) { throw 'no acceptance run: .\run_acceptance_tests.ps1 (or -SkipAcceptanceCheck)' }
    Write-Host 'WARNING: no acceptance run in this tree (skipped by -SkipAcceptanceCheck)'
} else {
    $sum = Get-Content (Join-Path $acc.FullName 'SUMMARY.txt') -Raw
    if ($sum -notmatch 'ACCEPTANCE=PASS') {
        if (-not $SkipAcceptanceCheck) { throw "last acceptance run $($acc.Name) is not PASS: .\run_acceptance_tests.ps1" }
        Write-Host "WARNING: acceptance $($acc.Name) is not PASS (skipped by -SkipAcceptanceCheck)"
    } else { Write-Host "acceptance: $($acc.Name) PASS" }
    $deps = Join-Path $acc.FullName 'DEPENDENCIES.txt'
}

# 2. Windows package + its mainnet checkpoint age ----------------------------------------
$win = Join-Path $PSScriptRoot 'UI\flutter_app\dist\grinsight-windows-x64.zip'
if (-not (Test-Path $win)) { throw 'no Windows package UI\flutter_app\dist\grinsight-windows-x64.zip (build the app first)' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($win)
try {
    $entry = $zip.Entries | Where-Object { ($_.FullName -replace '\\', '/') -like '*grinsight-core/checkpoints/mainnet/checkpoint.rwm' } | Select-Object -First 1
    if (-not $entry) { throw 'the Windows package has no mainnet checkpoint (grinsight-core\checkpoints\mainnet)' }
    $r = New-Object IO.StreamReader($entry.Open()); $rwm = $r.ReadToEnd(); $r.Close()
    $hasSig = [bool]($zip.Entries | Where-Object { ($_.FullName -replace '\\', '/') -like '*grinsight-core/checkpoints/mainnet/release.sig' })
    # The signed release in the package must be exactly the one in release\ (this version's checkpoint).
    $relEntry = $zip.Entries | Where-Object { ($_.FullName -replace '\\', '/') -like '*grinsight-core/checkpoints/mainnet/release.txt' } | Select-Object -First 1
    $pkgRel = if ($relEntry) { $rr = New-Object IO.StreamReader($relEntry.Open()); $x = $rr.ReadToEnd(); $rr.Close(); $x } else { '' }
    # The core in the zip must be the one just built and tested (dist\grinsight-core).
    $stale = @()
    foreach ($exe in 'grinsight-service.exe', 'reverse-wtema-header-sync.exe', 'grinsight-tor.exe') {
        $built = Join-Path $PSScriptRoot "dist\grinsight-core\$exe"
        if (-not (Test-Path $built)) { continue }
        $e = $zip.Entries | Where-Object { ($_.FullName -replace '\\', '/') -like "*grinsight-core/$exe" } | Select-Object -First 1
        if (-not $e) { $stale += "$exe (missing)"; continue }
        $sha = [Security.Cryptography.SHA256]::Create(); $st = $e.Open()
        $h = -join ($sha.ComputeHash($st) | ForEach-Object { $_.ToString('x2') }); $st.Close()
        if ($h -ne (Get-FileHash -Algorithm SHA256 $built).Hash.ToLower()) { $stale += $exe }
    }
} finally { $zip.Dispose() }
if ($stale) { throw "the Windows package has an old core: $($stale -join ', ') (copy dist\grinsight-core into the app package and zip it again)" }
$hex = (($rwm -split "`n") | Where-Object { $_ -like 'header *' } | Select-Object -First 1).Substring(7).Trim()
$cpHeight = [Convert]::ToInt64($hex.Substring(4, 16), 16)
$cpTs = [Convert]::ToInt64($hex.Substring(20, 16), 16)
$cpDays = [math]::Round(((Get-Date).ToUniversalTime() - [DateTimeOffset]::FromUnixTimeSeconds($cpTs).UtcDateTime).TotalDays, 1)
Write-Host "mainnet checkpoint in the package: height $cpHeight, $cpDays days old, signed release: $hasSig"
if (-not $hasSig) { throw 'the mainnet checkpoint in the package is not a signed release (.\make_release.ps1, .\make_service.ps1, rebuild the app)' }
$relTxtPath = Join-Path $PSScriptRoot 'release\release.txt'
if (-not (Test-Path $relTxtPath)) { throw 'no signed checkpoint in release\ (.\make_release.ps1)' }
$relNow = [IO.File]::ReadAllText($relTxtPath)
if ($pkgRel.Trim() -ne $relNow.Trim()) { throw 'the Windows package carries another signed checkpoint than release\: rebuild with .\make_app.ps1' }
if ($cpDays -gt 90) { throw "mainnet checkpoint is $cpDays days old: .\run_mainnet.ps1 -NewCheckpoint -CheckpointOnly; .\make_release.ps1; .\make_service.ps1; rebuild the app" }
# The asset is the installer built from the same app folder as the checked zip.
$setup = Join-Path $PSScriptRoot 'UI\flutter_app\dist\GrinSight-setup.exe'
if (-not (Test-Path $setup)) { throw 'no installer UI\flutter_app\dist\GrinSight-setup.exe: .\make_app.ps1 -Version <v>' }
if ((Get-Item $setup).LastWriteTime -lt (Get-Item $win).LastWriteTime) { throw 'the installer is older than the checked app package: .\make_app.ps1 -Version <v>' }
Copy-Item $setup (Join-Path $assets "GrinSight-$Version-windows-x64-setup.exe")

# 3. Android (optional) -------------------------------------------------------------------
$apk = Join-Path $PSScriptRoot 'UI\flutter_app\build\app\outputs\flutter-apk\app-release.apk'
if (Test-Path $apk) {
    # The APK must carry the same signed checkpoint (assets\checkpoints\mainnet).
    $az = [IO.Compression.ZipFile]::OpenRead($apk)
    try {
        $ae = $az.Entries | Where-Object { $_.FullName -like '*assets/checkpoints/mainnet/release.txt' } | Select-Object -First 1
        $as = [bool]($az.Entries | Where-Object { $_.FullName -like '*assets/checkpoints/mainnet/release.sig' })
        $apkRel = if ($ae) { $rr = New-Object IO.StreamReader($ae.Open()); $x = $rr.ReadToEnd(); $rr.Close(); $x } else { '' }
    } finally { $az.Dispose() }
    if (-not $as -or $apkRel.Trim() -ne $relNow.Trim()) { throw 'the APK has no signed checkpoint or another one than release\: .\make_app.ps1 -Android' }
    Copy-Item $apk (Join-Path $assets "GrinSight-$Version-android-arm64.apk"); Write-Host 'android: included (same signed checkpoint)'
}
else { Write-Host 'android: no APK yet, not included' }

# 3b. Linux (optional) ---------------------------------------------------------------------
# Built by make_deb.sh in WSL: dist\linux\grinsight_<version>_amd64.deb. make_deb.sh copies
# the signed checkpoint from release\, so the .deb ships the same one as the other packages.
$deb = Join-Path $PSScriptRoot "dist\linux\grinsight_${Version}_amd64.deb"
if (Test-Path $deb) {
    Copy-Item $deb (Join-Path $assets "GrinSight-$Version-linux-amd64.deb"); Write-Host 'linux: included'
}
else { Write-Host "linux: no dist\linux\grinsight_${Version}_amd64.deb yet, not included" }

# 4. Repository: root files + Documents\ (version, author, checkpoint filled in) ------------
$utf8 = New-Object Text.UTF8Encoding $false
$documents = Join-Path $repo 'Documents'
function Put-Doc([string]$src, [string]$dst) {
    New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
    if ([IO.Path]::GetExtension($src) -in '.md', '' ) {
        $t = [IO.File]::ReadAllText($src, [Text.Encoding]::UTF8)
        $t = $t.Replace('{{VERSION}}', $Version).Replace('{{AUTHOR}}', $Author).Replace('{{CP_HEIGHT}}', $cpHeight.ToString('N0', [Globalization.CultureInfo]::InvariantCulture))
        if ($t -match '\{\{[A-Z_]+\}\}') { throw "unfilled placeholder in $src" }
        [IO.File]::WriteAllText($dst, $t, $utf8)
    } else { Copy-Item $src $dst }
}
foreach ($f in 'README.md', 'README.ru.md', 'LICENSE', 'LICENSE-DOCS.md', 'NOTICE.md') { Put-Doc (Join-Path $docs $f) (Join-Path $repo $f) }
# README images (hero SVGs). The README also uses site\app-mark.png and site\app-wallet.png (step 5b).
Get-ChildItem (Join-Path $docs 'assets') -Recurse -File | ForEach-Object {
    Put-Doc $_.FullName (Join-Path $repo ('assets\' + $_.FullName.Substring((Join-Path $docs 'assets').Length + 1)))
}
foreach ($f in 'RELEASE_NOTES_EN.md', 'RELEASE_NOTES_RU.md') { Put-Doc (Join-Path $docs $f) (Join-Path $documents $f) }
Get-ChildItem (Join-Path $docs 'docs') -Recurse -File | ForEach-Object {
    Put-Doc $_.FullName (Join-Path $documents $_.FullName.Substring((Join-Path $docs 'docs').Length + 1))
}
if ($deps -and (Test-Path $deps)) { Copy-Item $deps (Join-Path $documents 'DEPENDENCIES.txt') }

# 5. Repository: Source\ = allow-listed core + the Flutter app (no builds, no keys) ----------
$source = Join-Path $repo 'Source'
$tmp = Join-Path $out 'pack-tmp.zip'
& python package_check.py pack --with-vendor --out $tmp
if ($LASTEXITCODE -ne 0) { throw 'source package failed (package_check.py pack)' }
Expand-Archive $tmp $source
Remove-Item $tmp, (Join-Path $out 'pack-tmp.manifest.txt') -ErrorAction SilentlyContinue
# The documents live in Documents\ only; the pack manifest describes the pack, not this tree.
Remove-Item -Recurse -Force (Join-Path $source 'GrinSight') -ErrorAction SilentlyContinue
Remove-Item -Force (Join-Path $source 'MANIFEST.sha256') -ErrorAction SilentlyContinue
& robocopy (Join-Path $PSScriptRoot 'UI\flutter_app') (Join-Path $source 'UI\flutter_app') /E /NFL /NDL /NJH /NJS /NP `
    /XD build .dart_tool dist shots .idea ephemeral .gradle .cxx .kotlin `
    /XF *.iml local.properties key.properties *.jks *.keystore .flutter-plugins-dependencies TRANSFER_TEST_*.md QR_REPORT_*.md | Out-Null
if ($LASTEXITCODE -ge 8) { throw "copying the Flutter app failed (robocopy $LASTEXITCODE)" }
# 5b. GitHub Pages site + its workflow: the site is deployed from this branch by Actions.
Copy-Item (Join-Path $PSScriptRoot 'site') (Join-Path $repo 'site') -Recurse -Force
Copy-Item (Join-Path $PSScriptRoot '.github') (Join-Path $repo '.github') -Recurse -Force
# Only the Flutter build output is ignored by name: a generic **/build/ also hid
# vendor/grin-5.5.2/p2p/src/build/build.rs (and src/build/) and the pushed source did not build.
[IO.File]::WriteAllText((Join-Path $repo '.gitignore'), "target/`n.build/`ndist/`nevidence/`nSource/UI/flutter_app/build/`n**/.dart_tool/`n*.local.txt`n*.jks`n*.keystore`nkey.properties`nlocal.properties`n", $utf8)

# Nothing secret may leave: seed phrases, seed files, keys.
& python package_check.py scan $repo
if ($LASTEXITCODE -ne 0) { throw "secret scan failed on $repo (see the FINDING lines above)" }

# 6. Archives + checksums -------------------------------------------------------------------
Compress-Archive -Path $source -DestinationPath (Join-Path $assets "GrinSight-$Version-source.zip")
# Which signed checkpoint this version ships (the same file is in every package).
$cpNote = Join-Path $PSScriptRoot 'UI\flutter_app\dist\CHECKPOINT.txt'
if (Test-Path $cpNote) { Copy-Item $cpNote (Join-Path $assets "GrinSight-$Version-CHECKPOINT.txt") }
else { Copy-Item (Join-Path $PSScriptRoot 'release\release.txt') (Join-Path $assets "GrinSight-$Version-CHECKPOINT.txt") }
$lines = Get-ChildItem $assets -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | Sort-Object Name | ForEach-Object {
    '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower(), $_.Name
}
[IO.File]::WriteAllText((Join-Path $assets 'SHA256SUMS.txt'), (($lines -join "`n") + "`n"), $utf8)

# The packages + sources also go next to Source\: C:\DHW\GrinSight\GrinSight-<version>\
$top = Join-Path (Split-Path $PSScriptRoot -Parent) "GrinSight-$Version"
if (Test-Path $top) { Remove-Item -Recurse -Force $top }
New-Item -ItemType Directory -Force -Path $top | Out-Null
Copy-Item (Join-Path $assets '*') $top
Write-Host ""
Write-Host "packages: $top"
Write-Host "release $Version ready: $out"
Write-Host "  assets\ (GitHub release):"
Get-ChildItem $assets -File | ForEach-Object { Write-Host ("    {0,14:N0}  {1}" -f $_.Length, $_.Name) }
Write-Host "  repo\   (branch GrinSight): README.md README.ru.md LICENSE LICENSE-DOCS.md NOTICE.md assets\ Documents\ Source\ site\"
Write-Host "next: .\publish_github.ps1 -Version $Version"
