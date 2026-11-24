# GrinSight v0.2: the wallet process (host) with the real chain process, on the TEST network.
# THIS ONE USES THE NETWORK. The chain process connects DIRECTLY (not through Tor) to public Grin nodes of
# the test network, as an ordinary Grin peer: those nodes see this computer's address. It verifies headers,
# collects the state and applies the blocks; the wallet - a throw-away profile created for this run, with
# nothing in it - follows the chain block by block to the tip. No funds are involved, nothing is sent.
#
# Run from any folder:  powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\run-live-chain-host-test.ps1
# Builds the chain program first. Uses the vendored crates; downloads nothing. Writes one log next to this
# script. If target\live-headers\test holds the files of an earlier live run (headers, state, blocks), a
# copy of them is put into the chain process's own directory inside the throw-away profile: the program
# trusts none of them and checks each again, and it saves some ten minutes of downloading.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$log = Join-Path $root "live-chain-host-test-$stamp.log"
$env:CARGO_TARGET_DIR = Join-Path $root 'target'
$env:RUST_BACKTRACE = '0'
$scratch = Join-Path $env:CARGO_TARGET_DIR 'test-tmp'
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
$env:TMP = $scratch; $env:TEMP = $scratch

function Say($text) { $text | Out-File -FilePath $log -Append -Encoding utf8; Write-Host $text }

Say "started $(Get-Date -Format s)"
Say ("rustc: " + (cmd /c "rustc -V 2>&1"))
$summary = @()
Say "=== chain/fly-chain: build (release) ==="
Push-Location (Join-Path $root 'chain\fly-chain')
$started = Get-Date
cmd /c "cargo build --release 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
$code = $LASTEXITCODE
Pop-Location
$summary += ("build fly-chain exit=$code seconds=" + [int]((Get-Date) - $started).TotalSeconds)
$program = Join-Path $env:CARGO_TARGET_DIR 'release\fly-chain.exe'
if (($code -eq 0) -and (Test-Path -LiteralPath $program)) {
    Say "=== paycore/host: live test with $program ==="
    $env:FLY_CHAIN_EXE = $program
    $seed = Join-Path $env:CARGO_TARGET_DIR 'live-headers\test'
    if (Test-Path -LiteralPath (Join-Path $seed 'headers.dat')) { $env:FLY_CHAIN_SEED_DIR = $seed; Say "files of an earlier run: $seed" }
    Push-Location (Join-Path $root 'paycore\host')
    $started = Get-Date
    cmd /c "cargo test --features test-chain --test host live_the_host_follows_the_real_chain -- --ignored --nocapture 2>&1" | ForEach-Object { Say "$_" }
    $code = $LASTEXITCODE
    Pop-Location
    $summary += ("live chain host test exit=$code seconds=" + [int]((Get-Date) - $started).TotalSeconds)
} else {
    $summary += "live chain host test not run: the chain program was not built"
}
# read the log to the end first: writing into it while it is being read would never finish
$lines = @(Select-String -Path $log -Pattern '^test result:|^files of an earlier run put|^chain process at the tip|^wallet at|^chain status:|^balance:|^test .* FAILED$|panicked at|^error' | Select-Object -First 30 | ForEach-Object { $_.Line })
Say "=== summary ==="
$summary | ForEach-Object { Say $_ }
$lines | ForEach-Object { Say $_ }
Say "finished $(Get-Date -Format s)"
Write-Host ""
Write-Host "Log: $log"
