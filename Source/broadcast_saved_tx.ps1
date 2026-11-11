# Send a saved Floonet transaction (from --gap-tx-out) to the peers, with retries.
# Builds into .build\target-tx so it never touches a binary another script is using.
#
# Start:  powershell -ExecutionPolicy Bypass -File .\broadcast_saved_tx.ps1 -Tx evidence\wallet-run-...\self-transfer.tx.hex
param([Parameter(Mandatory=$true)][string]$Tx)
Set-Location -Path $PSScriptRoot
$env:CARGO_TARGET_DIR = "$PSScriptRoot\.build\target-tx"
$env:CARGO_HOME = "$PSScriptRoot\.build\cargo-home"
$tmp = "$PSScriptRoot\.build\tmp"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$env:TEMP = $tmp
$env:TMP = $tmp
# rustup without a default toolchain (e.g. after a Windows profile reset):
# use the newest installed stable toolchain for this run instead of failing.
if (-not $env:RUSTUP_TOOLCHAIN) {
    $null = cmd /c "rustup default 2>&1"
    if ($LASTEXITCODE -ne 0) {
        $tcs = @(cmd /c "rustup toolchain list 2>&1" | ForEach-Object { ($_ -split '\s+')[0] } |
                 Where-Object { $_ -match '^(stable|1\.\d+)' })
        if ($tcs.Count -gt 0) {
            $env:RUSTUP_TOOLCHAIN = $tcs[-1]
            Write-Host "rustup: no default toolchain, using $($env:RUSTUP_TOOLCHAIN)"
        } else {
            Write-Host 'rustup: no Rust toolchain installed. Run once:  rustup default stable'
        }
    }
}
cargo build --offline --locked --release --manifest-path header-sync\Cargo.toml
if ($LASTEXITCODE -ne 0) { Write-Host 'build failed'; Read-Host 'Press Enter'; exit 1 }
& "$env:CARGO_TARGET_DIR\release\reverse-wtema-header-sync.exe" --broadcast-tx $Tx --peer 96.44.159.174:13414 --peer 66.154.127.84:13414
Write-Host "exit=$LASTEXITCODE"
Read-Host 'Finished. Press Enter to close'
