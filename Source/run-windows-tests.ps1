# GrinSight v0.2: build and test the payment core and the chain process on Windows.
# Run from any folder:  powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\run-windows-tests.ps1
# Writes one log next to this script. Changes nothing outside C:\DHW\GrinFlySight\core-v0.2; temporary files go to target\test-tmp
# (one probe file is created and removed in the shell's own TEMP).
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$log = Join-Path $root "windows-tests-$stamp.log"
$env:CARGO_TARGET_DIR = Join-Path $root 'target'
$env:RUST_BACKTRACE = '0'
# The state tests mine chains with the Grin node's own code, which takes minutes. The mined chains are kept
# in target\test-chains\<hash of the code that mines them> and reused by every crate and every later run;
# when that code changes, the hash changes and the chains are mined again.
$kit = Join-Path $root 'chain\state\src\testkit.rs'
$kitHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $kit).Hash.Substring(0, 16)
$env:FLY_STATE_TEST_CHAINS = Join-Path $env:CARGO_TARGET_DIR "test-chains\$kitHash"
New-Item -ItemType Directory -Force -Path $env:FLY_STATE_TEST_CHAINS | Out-Null

# The tests and the C compiler need a writable temporary folder. The one the
# shell hands over is recorded and probed, then replaced for this run by a
# folder inside the build output, so the run does not depend on it.
$oldTmp = $env:TMP; $oldTemp = $env:TEMP
$probe = 'no temporary folder set'
if ($oldTemp) {
    $probeFile = Join-Path $oldTemp ("fly-probe-" + [guid]::NewGuid().ToString('N') + ".tmp")
    try { [IO.File]::WriteAllText($probeFile, 'x'); Remove-Item -LiteralPath $probeFile -Force; $probe = 'writable' }
    catch { $probe = 'NOT writable: ' + $_.Exception.Message }
}
$scratch = Join-Path $env:CARGO_TARGET_DIR 'test-tmp'
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
$env:TMP = $scratch; $env:TEMP = $scratch

function Say($text) { $text | Out-File -FilePath $log -Append -Encoding utf8; Write-Host $text }

Say "started $(Get-Date -Format s)"
Say "shell TEMP: '$oldTemp' TMP: '$oldTmp' ($probe); this run uses '$scratch'"
Say ("user: " + [Environment]::UserName + "  elevated: " + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
Say "mined test chains are kept in '$env:FLY_STATE_TEST_CHAINS'"
Say ("rustc: " + (cmd /c "rustc -V 2>&1"))
Say ("cargo: " + (cmd /c "cargo -V 2>&1"))
$summary = @()
# crates whose tests start stand-in processes need a feature: "stub" is a stand-in transport or chain process,
# "test-chain" is the host with a stand-in chain and a stand-in transport
$features = @{ 'mailbox-pipe' = '--features stub'; 'chain-pipe' = '--features stub'; 'bridge' = '--features stub'; 'onion-pipe' = '--features stub'; 'host' = '--features test-chain' }
foreach ($crate in 'store', 'keys', 'mailbox', 'pipe-link', 'mailbox-pipe', 'chain-port', 'chain-pipe', 'onion-pipe', 'guard-os', 'wallet', 'bridge', 'host') {
    $dir = Join-Path $root "paycore\$crate"
    Say "=== $crate ==="
    Push-Location $dir
    $started = Get-Date
    $extra = $features[$crate]
    cmd /c "cargo test --no-fail-fast $extra 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
    $code = $LASTEXITCODE
    Pop-Location
    $secs = [int]((Get-Date) - $started).TotalSeconds
    Say "exit=$code seconds=$secs"
    $summary += "$crate exit=$code seconds=$secs"
}
# the chain process: the header chain from a starting point ("testkit" mines short test chains); the state
# collected from segments ("testkit" there mines a real chain with the Grin node's code: about two minutes,
# more the first time, when the elliptic curve code is built optimized); the program against nodes made of the
# Grin network code ("test-net"); then the product build; the public nodes' crate; Tor (only its checks: the live
# test is run-live-tor-send-test.ps1)
foreach ($run in @(@('headers', '--features testkit'), @('state', '--features testkit'), @('fly-chain', '--features test-net'), @('fly-chain', ''), @('tips', ''), @('tor', ''))) {
    $crate = $run[0]; $extra = $run[1]
    $dir = Join-Path $root "chain\$crate"
    Say "=== chain/$crate $extra ==="
    Push-Location $dir
    $started = Get-Date
    cmd /c "cargo test --no-fail-fast $extra 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
    $code = $LASTEXITCODE
    Pop-Location
    $secs = [int]((Get-Date) - $started).TotalSeconds
    Say "exit=$code seconds=$secs"
    $summary += "chain/$crate $extra exit=$code seconds=$secs"
}
# Tor for payments to and from the wallet's address (only its checks: the live test is run-live-onion-test.ps1)
Say "=== onion ==="
Push-Location (Join-Path $root 'onion')
$started = Get-Date
cmd /c "cargo test --no-fail-fast 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
$code = $LASTEXITCODE
Pop-Location
$secs = [int]((Get-Date) - $started).TotalSeconds
Say "exit=$code seconds=$secs"
$summary += "onion exit=$code seconds=$secs"
# Tor bridges: the lines the user chose, checked and put into Tor's configuration
Say "=== tor-bridges ==="
Push-Location (Join-Path $root 'tor-bridges')
$started = Get-Date
cmd /c "cargo test --no-fail-fast 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
$code = $LASTEXITCODE
Pop-Location
$secs = [int]((Get-Date) - $started).TotalSeconds
Say "exit=$code seconds=$secs"
$summary += "tor-bridges exit=$code seconds=$secs"
Say "=== web/core ==="
Push-Location (Join-Path $root 'web\core')
$started = Get-Date
cmd /c "cargo test --no-fail-fast 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
$code = $LASTEXITCODE
Pop-Location
$secs = [int]((Get-Date) - $started).TotalSeconds
Say "exit=$code seconds=$secs"
$summary += "web/core exit=$code seconds=$secs"
Say "=== web/wallet ==="
Push-Location (Join-Path $root 'web\wallet')
$started = Get-Date
cmd /c "cargo test --no-fail-fast 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
$code = $LASTEXITCODE
Pop-Location
$secs = [int]((Get-Date) - $started).TotalSeconds
Say "exit=$code seconds=$secs"
$summary += "web/wallet exit=$code seconds=$secs"
# The interface: display rules (no dependencies), the window's link to the
# wallet process, the window's own tests (offline set ui\vendor-crates)
foreach ($run in @(@('safe-display', ''), @('host-link', ''), @('app', '--lib'))) {
    $crate = $run[0]; $extra = $run[1]
    Say "=== ui/$crate $extra ==="
    Push-Location (Join-Path $root "ui\$crate")
    $started = Get-Date
    cmd /c "cargo test --no-fail-fast $extra 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
    $code = $LASTEXITCODE
    Pop-Location
    $secs = [int]((Get-Date) - $started).TotalSeconds
    Say "exit=$code seconds=$secs"
    $summary += "ui/$crate $extra exit=$code seconds=$secs"
}
$results = Select-String -Path $log -Pattern '^test result:' | Where-Object { $_.Line -notmatch ' 0 passed; 0 failed' } | ForEach-Object { $_.Line }
$failed = Select-String -Path $log -Pattern '^test .* FAILED$' | ForEach-Object { $_.Line }
$errors = Select-String -Path $log -Pattern '^error' | Select-Object -First 20 | ForEach-Object { $_.Line }
Say "=== summary ==="
$summary | ForEach-Object { Say $_ }
$results | ForEach-Object { Say $_ }
$failed | ForEach-Object { Say $_ }
$errors | ForEach-Object { Say $_ }
Say "finished $(Get-Date -Format s)"
Write-Host ""
Write-Host "Log: $log"
