# GrinSight: builds the portable Windows version and packs it.
# Result: C:\DHW\dist\GrinSight-<time>\ and GrinSight-<time>.zip next to it,
# with SHA256SUMS.txt inside. Then runs the interface scenario against the packed
# programs (two throwaway Testnet profiles, no funds, no network).
# Run: powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\run-portable.ps1
$ErrorActionPreference = 'Continue'
$core = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$dist = 'C:\DHW\dist'
$name = "GrinSight-$stamp"
$pack = Join-Path $dist $name
# A second run for this timestamp must never package an earlier run's files.
[void][IO.Directory]::CreateDirectory($dist)
New-Item -ItemType Directory -Path $pack -ErrorAction Stop | Out-Null
New-Item -ItemType Directory -Path "$pack\bin" -ErrorAction Stop | Out-Null
$log = Join-Path $dist "$name-build.log"
function Say($s) { Write-Host $s; Add-Content -Path $log -Value $s -Encoding utf8 }
Say "started $(Get-Date -Format s)"
Say ("rustc: " + (cmd /c "rustc --version 2>&1"))

function Build($what, $dir, $target, $extra, $fromRoot) {
    $env:CARGO_TARGET_DIR = $target
    $started = Get-Date
    if ($fromRoot) {
        # no offline set for the interface: from the drive root, where the
        # vendor configuration under C:\DHW does not apply.
        Push-Location ([System.IO.Path]::GetPathRoot($dir))
        cmd /c "cargo build --release --manifest-path `"$dir\Cargo.toml`" $extra 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
    } else {
        Push-Location $dir
        cmd /c "cargo build --release $extra 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
    }
    $code = $LASTEXITCODE
    Pop-Location
    Say "$what build exit=$code seconds=$([int]((Get-Date) - $started).TotalSeconds)"
    return $code
}

$failed = 0
if ((Build 'host' "$core\paycore\host" 'C:\DHW\dist\target-host' '--bin fly-paycore-host' $false) -ne 0) { $failed++ }
if ((Build 'chain' "$core\chain\fly-chain" 'C:\DHW\dist\target-chain' '' $false) -ne 0) { $failed++ }
if ((Build 'mailbox' "$core\transport\mailbox-nostr" 'C:\DHW\dist\target-mailbox' '--bin fly-mailbox' $false) -ne 0) { $failed++ }
# Tor for payments to and from the wallet's address; it shares the chain's build folder (the same Tor crates)
if ((Build 'onion' "$core\onion" 'C:\DHW\dist\target-chain' '--bin fly-onion' $false) -ne 0) { $failed++ }
# the interface offline from ui\vendor-crates when that set is there
$uiFromRoot = -not (Test-Path "$core\ui\vendor-crates")
if ((Build 'ui' "$core\ui\app" 'C:\DHW\dist\target-ui' '' $uiFromRoot) -ne 0) { $failed++ }
if ($failed -ne 0) { Say "builds failed: $failed"; exit 1 }

Copy-Item 'C:\DHW\dist\target-ui\release\fly-ui.exe' "$pack\GrinSight.exe"
Copy-Item 'C:\DHW\dist\target-host\release\fly-paycore-host.exe' "$pack\bin\"
Copy-Item 'C:\DHW\dist\target-chain\release\fly-chain.exe' "$pack\bin\"
Copy-Item 'C:\DHW\dist\target-mailbox\release\fly-mailbox.exe' "$pack\bin\"
Copy-Item 'C:\DHW\dist\target-chain\release\fly-onion.exe' "$pack\bin\"
# The program for Tor bridges (obfs4, Snowflake) is not built here: it is the lyrebird of the
# official Tor Expert Bundle, fetched and checked by get-tor-bridge-programs.ps1 (the archive's
# SHA-256 is pinned there; the list of checksums is signed by the Tor Browser developers).
powershell -NoProfile -ExecutionPolicy Bypass -File "$core\get-tor-bridge-programs.ps1" 2>&1 | ForEach-Object { Say "$_" }
if ($LASTEXITCODE -ne 0) { Say 'the Tor Expert Bundle was not accepted'; exit 1 }
$bundle = 'C:\DHW\dist\tor-expert-bundle\16.0.1\windows-x86_64\files'
Copy-Item "$bundle\tor\pluggable_transports\lyrebird.exe" "$pack\bin\"
Copy-Item "$bundle\docs\lyrebird.txt" "$pack\LICENSE-lyrebird.txt"
Copy-Item "$core\dist-files\README.txt" "$pack\"
Copy-Item "$core\dist-files\LICENSE-GPL-3.0.txt" "$pack\"

$sums = Get-ChildItem $pack -Recurse -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | ForEach-Object {
    $rel = $_.FullName.Substring($pack.Length + 1)
    "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $rel
}
$sums | Out-File -FilePath "$pack\SHA256SUMS.txt" -Encoding ascii
$sums | ForEach-Object { Say $_ }
Get-ChildItem $pack -Recurse -File | ForEach-Object { Say ("{0,12:N0}  {1}" -f $_.Length, $_.FullName.Substring($pack.Length + 1)) }

$zip = Join-Path $dist "$name.zip"
Compress-Archive -Path $pack -DestinationPath $zip -Force
Say ("zip: $zip  {0:N0} bytes  sha256 {1}" -f (Get-Item $zip).Length, (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower())

# The packed programs, driven by the interface scenario. Profiles live outside
# the packed folder, so the package stays clean.
$scn = Join-Path $dist "$name-scenario"
$err = Join-Path $dist "$name-scenario.err"
$p = Start-Process -FilePath "$pack\GrinSight.exe" -ArgumentList @('--scenario', "$scn\out", '--host', "$pack\bin\fly-paycore-host.exe", '--profile', "$scn\profiles", '--guard-dir', "$scn\guards") -Wait -PassThru -NoNewWindow -RedirectStandardError $err
Say "scenario exit=$($p.ExitCode)"
if (Test-Path "$scn\out\scenario.log") { Get-Content "$scn\out\scenario.log" | ForEach-Object { Say $_ } }
Say "finished $(Get-Date -Format s)"
Say "Folder: $pack"
