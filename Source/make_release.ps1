# make_release.ps1 - developer side of the signed checkpoint release (stage 4).
#
#   .\make_release.ps1 -Keygen
#        once: new release key. The secret seed goes to C:\DHW\release-key\
#        (outside the app folder, never shipped, never in backups); its public
#        key is added to grinsight-state\release-keys.txt and compiled into the app.
#
#   .\make_release.ps1
#        take the newest cross-checked mainnet checkpoint (mainnet-cp-run-* with
#        CROSSCHECK=PASS), put it into release\, sign it, verify it as the app
#        would. Then ship release\ with the app.
#
#   -Seed <file>  -KeyId <n>  -From <mainnet-cp-run folder>   (optional)
param([switch]$Keygen, [string]$Seed = 'C:\DHW\release-key\grinsight-release.seed', [int]$KeyId = 1, [string]$From = '')

$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot
$env:CARGO_TARGET_DIR = "$PSScriptRoot\.build\target"
$env:CARGO_HOME = "$PSScriptRoot\.build\cargo-home"
$exe = "$PSScriptRoot\.build\target\release\reverse-wtema-header-sync.exe"
$keys = Join-Path $PSScriptRoot 'grinsight-state\release-keys.txt'

function Build() {
    cmd /c "cargo build --offline --locked --release --manifest-path header-sync\Cargo.toml 1> .build\release-build.log 2>&1"
    if ($LASTEXITCODE -ne 0) { Get-Content .build\release-build.log -Tail 20; throw 'build failed (.build\release-build.log)' }
}

if ($Keygen) {
    if ($Seed.StartsWith($PSScriptRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'keep the release key outside the app folder' }
    New-Item -ItemType Directory -Force -Path (Split-Path $Seed) | Out-Null
    Build
    $out = & $exe --mainnet --release-keygen $Seed
    $out | Where-Object { $_ -like 'RELEASE*' } | ForEach-Object { Write-Host $_ }
    $pk = ($out | Where-Object { $_ -like 'RELEASE_PUBKEY=*' } | Select-Object -First 1)
    if (-not $pk) { throw 'keygen failed' }
    Add-Content -Path $keys -Value "$KeyId $($pk.Substring(15))" -Encoding ASCII
    Write-Host "public key $KeyId added to grinsight-state\release-keys.txt (compiled into the app on the next build)"
    Write-Host "SECRET seed: $Seed - back it up offline; whoever has it can sign checkpoints for every user"
    exit 0
}

if (-not (Test-Path $Seed)) { throw "no release key $Seed (run .\make_release.ps1 -Keygen once)" }
if (-not $From) {
    $run = Get-ChildItem -Directory (Join-Path $PSScriptRoot 'evidence') -Filter 'mainnet-cp-run-*' | Sort-Object Name |
        Where-Object { (Test-Path (Join-Path $_.FullName 'summary.txt')) -and ((Get-Content (Join-Path $_.FullName 'summary.txt') -Raw) -match 'CROSSCHECK=PASS') } |
        Select-Object -Last 1
    if (-not $run) { throw 'no cross-checked checkpoint (run run_mainnet.ps1 -NewCheckpoint)' }
    $From = $run.FullName
}
$src = Get-Content (Join-Path $From 'summary.txt') -Raw
if ($src -notmatch 'CROSSCHECK=PASS') { throw "$From is not cross-checked" }
$a = (Get-FileHash -Algorithm SHA256 (Join-Path $From 'checkpoint\checkpoint.rwm')).Hash.ToLower()
$b = (Get-FileHash -Algorithm SHA256 (Join-Path $From 'checkpoint\recent-headers.bin')).Hash.ToLower()
if ($src -notmatch "checkpoint_sha256=$a" -or $src -notmatch "history_sha256=$b") { throw "files in $From do not match its summary" }

$rel = Join-Path $PSScriptRoot 'release'
New-Item -ItemType Directory -Force -Path $rel | Out-Null
Copy-Item (Join-Path $From 'checkpoint\checkpoint.rwm'), (Join-Path $From 'checkpoint\recent-headers.bin') $rel -Force
Build
& $exe --mainnet --sign-release $rel --seed $Seed --key-id $KeyId | ForEach-Object { Write-Host $_ }
if ($LASTEXITCODE -ne 0) { throw 'signing failed' }
& $exe --mainnet --verify-release $rel | ForEach-Object { Write-Host $_ }
if ($LASTEXITCODE -ne 0) { throw 'the app would reject this release (is the public key in release-keys.txt and the app rebuilt?)' }
Write-Host "release\ is signed and verifies (from $(Split-Path $From -Leaf)). Ship it with the app."
