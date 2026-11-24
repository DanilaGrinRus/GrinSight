# GrinSight: Tor comes up through bridges (obfs4, then Snowflake) and a page comes back.
# THIS ONE USES THE NETWORK and, the first time, DOWNLOADS the official Tor Expert Bundle
# (see get-tor-bridge-programs.ps1). No wallet, no funds. Run from any folder:
#   powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\run-live-bridges-test.ps1
# Builds offline from vendor-crates. Writes one log next to this script.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$log = Join-Path $root "live-bridges-test-$stamp.log"
$env:CARGO_TARGET_DIR = Join-Path $root 'target'
$env:RUST_BACKTRACE = '0'
$scratch = Join-Path $env:CARGO_TARGET_DIR 'test-tmp'
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
function Say($text) { $text | Out-File -FilePath $log -Append -Encoding utf8; Write-Host $text }
Say "started $(Get-Date -Format s)"
$version = '16.0.1'; $platform = 'windows-x86_64'
powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'get-tor-bridge-programs.ps1') -Version $version -Platform $platform 2>&1 | ForEach-Object { Say "$_" }
if ($LASTEXITCODE -ne 0) { Say "the bundle was not accepted: exit=$LASTEXITCODE"; exit 2 }
$files = "C:\DHW\dist\tor-expert-bundle\$version\$platform\files"
$config = Get-ChildItem -LiteralPath $files -Recurse -Filter 'pt_config.json' | Select-Object -First 1
if (-not $config) { Say 'no pt_config.json in the bundle'; exit 2 }
$pt = Get-Content -LiteralPath $config.FullName -Raw | ConvertFrom-Json
Say "transport programs named by the bundle:"
$pt.pluggableTransports.PSObject.Properties | ForEach-Object { Say ("  {0}: {1}" -f $_.Name, $_.Value) }
Say "built-in bridges by kind:"
$pt.bridges.PSObject.Properties | ForEach-Object { Say ("  {0}: {1}" -f $_.Name, @($_.Value).Count) }
$env:TMP = $scratch; $env:TEMP = $scratch
$env:FLY_ALLOW_TOR = '1'
$worst = 0
foreach ($kind in @('obfs4', 'snowflake')) {
    $lines = @($pt.bridges.$kind)
    if ($lines.Count -eq 0) { Say "=== ${kind}: the bundle has no such bridges ==="; $worst = 1; continue }
    # the program the bundle names for this transport
    $entry = $pt.pluggableTransports.PSObject.Properties | Where-Object { $_.Value -match "ClientTransportPlugin\s+\S*\b$kind\b" } | Select-Object -First 1
    $exe = $null
    if ($entry -and $entry.Value -match 'exec\s+\$\{pt_path\}([A-Za-z0-9._-]+)') {
        $exe = $Matches[1] -replace '\$\{pt_extension\}$', ''
        if ($exe -notlike '*.exe') { $exe = $exe + '.exe' }
    }
    $program = if ($exe) { Get-ChildItem -LiteralPath $files -Recurse -Filter $exe | Select-Object -First 1 } else { $null }
    if (-not $program) { Say "=== ${kind}: no program for it in the bundle ==="; $worst = 1; continue }
    $list = Join-Path $scratch "bridges-$kind.txt"
    [IO.File]::WriteAllLines($list, [string[]]$lines)
    $env:FLY_LIVE_BRIDGES = $list
    $env:FLY_LIVE_PT = $program.FullName
    Say "=== ${kind}: $($lines.Count) bridges, program $($program.Name) ==="
    Push-Location (Join-Path $root 'chain\tor')
    $started = Get-Date
    cmd /c "cargo test live_tor_comes_up_through_bridges -- --ignored --nocapture 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
    $code = $LASTEXITCODE
    Pop-Location
    Say "${kind}: exit=$code seconds=$([int]((Get-Date) - $started).TotalSeconds)"
    if ($code -ne 0) { $worst = 1 }
}
# The process for payments to an address, as the wallet runs it: Tor through the built-in
# obfs4 bridges, an onion service of a key made for the run announced through them, and one
# request posted to it and answered. The program for bridges stands next to the test program.
if ($env:FLY_LIVE_PT) {
    $env:FLY_LIVE_BRIDGES = Join-Path $scratch 'bridges-obfs4.txt'
    Say "=== the address process through obfs4 ==="
    Push-Location (Join-Path $root 'onion')
    $started = Get-Date
    cmd /c "cargo test live_ -- --ignored --nocapture 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
    $code = $LASTEXITCODE
    Pop-Location
    Say "address process: exit=$code seconds=$([int]((Get-Date) - $started).TotalSeconds)"
    if ($code -ne 0) { $worst = 1 }
}
# read first, say after: saying writes to the very file that is being read
$found = @(Select-String -LiteralPath $log -Pattern '^Tor came up|^a page came back|^bridges given|^listening after|^attempt |^announced in|^test result:|panicked' | ForEach-Object { $_.Line })
Say "=== summary ==="
foreach ($line in $found) { Say $line }
Say "finished $(Get-Date -Format s)"
exit $worst
