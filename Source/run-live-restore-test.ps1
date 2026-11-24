# GrinSight v0.2: a wallet RESTORED FROM A RECOVERY PHRASE finds what the phrase holds, on a real network.
# The wallet process (host) starts the real chain process; the wallet follows the chain to the tip and then
# reads the old outputs - the range proofs of everything unspent - and keeps what the phrase opens.
#
# THE PHRASE. This script asks for it with the input hidden. It is handed to the test in the memory of this
# PowerShell session (an environment variable of the processes started here), and by the test to the wallet
# process over its standard input. It is not written to the log or to any file by this script or by the
# test, it is not printed, and it is taken out of the environment before this script ends. The wallet
# process seals it in a throw-away profile under target\test-tmp, with a random password nobody learns;
# that profile is deleted when the test ends. If the test is killed half-way, delete target\test-tmp.
# NOTHING IS SENT: no transaction is made, nothing is signed. The amounts found are written to the log
# (the line that begins with BALANCE, in nanogrin).
#
# THIS ONE USES THE NETWORK, AND IT DOWNLOADS A LOT: about 250 MB on Mainnet and about 2 GB on the test
# network. The chain process connects DIRECTLY (not through Tor) to public Grin nodes, as an ordinary Grin
# peer: those nodes see this computer's address, and that it reads all range proofs - not which outputs
# are yours.
#
# Run from any folder:   powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\run-live-restore-test.ps1 -Network test
#                        ... -Network main     for a phrase of the main network
# Nodes of your own:     ... -Network main -Peer 192.168.1.5:3414,10.0.0.7:3414
#                        With -Peer ONLY the named nodes are used: the seed names of the network are not asked.
# From an empty disk:    ... -Fresh    The files of earlier runs are not put in place: headers, state and
#                        blocks are fetched anew, and the time covers everything.
# As the product runs:   ... -Release  The wallet process is built optimized, as a product build is. Without
#                        it the test builds it for debugging, and the wallet's own work on every piece -
#                        trying its keys on the range proofs - is several times slower. The first build
#                        with -Release takes a few minutes.
# Builds the chain program first. Uses the vendored crates; downloads no code. Writes one log next to this
# script. If target\live-headers\<network> holds the files of an earlier live run, a copy of them is put
# into the chain process's own directory: the program checks each again, and it saves the downloading of
# headers, state and blocks.
param([Parameter(Mandatory = $true)][ValidateSet('test', 'main')][string]$Network, [string[]]$Peer = @(), [switch]$Fresh, [switch]$Release)
$ErrorActionPreference = 'Continue'
# started with -File, PowerShell hands "a,b" over as one text: take it apart
$Peer = @($Peer | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$log = Join-Path $root "live-restore-test-$stamp.log"
$env:CARGO_TARGET_DIR = Join-Path $root 'target'
$env:RUST_BACKTRACE = '0'
$scratch = Join-Path $env:CARGO_TARGET_DIR 'test-tmp'
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
$env:TMP = $scratch; $env:TEMP = $scratch

function Say($text) { $text | Out-File -FilePath $log -Append -Encoding utf8; Write-Host $text }

Say "started $(Get-Date -Format s)"
Say ("rustc: " + (cmd /c "rustc -V 2>&1"))
Say "network: $Network"
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
    Say "=== paycore/host: build of the test (nothing secret is in memory yet) ==="
    Push-Location (Join-Path $root 'paycore\host')
    $profile_flag = ''
    if ($Release) { $profile_flag = '--release '; Say "the wallet process is built optimized (-Release)" }
    cmd /c "cargo test $($profile_flag)--features test-chain --test host --no-run 2>&1" | Out-File -FilePath $log -Append -Encoding utf8
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        Write-Host ""
        Write-Host "The recovery phrase of the wallet to restore ($Network network). The input is hidden."
        Write-Host "Spaces before, after and between the words do not matter, nor do capital letters."
        # What is typed is brought to one form: words in small letters with one space between them.
        # An empty entry or a wrong number of words is asked for again and never given to the test.
        $phrase = ''
        for ($try = 0; ($try -lt 5) -and (-not $phrase); $try++) {
            $secure = Read-Host -AsSecureString "phrase"
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            try {
                $typed = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            } finally {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
            $secure = $null
            $words = @(("$typed" -replace '[\u200B\uFEFF]', '') -split '\s+' | Where-Object { $_ })
            $typed = $null
            if ($words.Count -eq 0) {
                Write-Host "Nothing was entered (a pasted text that begins with an empty line gives this). Once more."
            } elseif (@(12, 15, 18, 21, 24) -notcontains $words.Count) {
                Write-Host ("That was " + $words.Count + " words; a phrase has 12, 15, 18, 21 or 24. Once more.")
            } else {
                $phrase = ($words -join ' ').ToLowerInvariant()
            }
            $words = $null
        }
        if (-not $phrase) {
            Say "no phrase was entered: the test is not run"
            $summary += "live restore test not run: no phrase was entered"
            $code = 2
        } else {
        $env:FLY_RESTORE_PHRASE = $phrase
        $phrase = $null
        $env:FLY_RESTORE_NETWORK = $Network
        $env:FLY_CHAIN_EXE = $program
        $seed = Join-Path $env:CARGO_TARGET_DIR "live-headers\$Network"
        Remove-Item Env:FLY_CHAIN_SEED_DIR -ErrorAction SilentlyContinue
        Remove-Item Env:FLY_CHAIN_PEERS -ErrorAction SilentlyContinue
        if ($Fresh) { Say "from an empty disk: the files of earlier runs are not used" }
        elseif (Test-Path -LiteralPath (Join-Path $seed 'headers.dat')) { $env:FLY_CHAIN_SEED_DIR = $seed; Say "files of an earlier run: $seed" }
        if ($Peer.Count -gt 0) { $env:FLY_CHAIN_PEERS = ($Peer -join ','); Say ("nodes: " + ($Peer -join ', ') + " (only these)") }
        Say "=== paycore/host: live restore test with $program ==="
        $started = Get-Date
        try {
            cmd /c "cargo test $($profile_flag)--features test-chain --test host live_a_restored_wallet_finds_its_outputs -- --ignored --nocapture 2>&1" | ForEach-Object { Say "$_" }
            $code = $LASTEXITCODE
        } finally {
            Remove-Item Env:FLY_RESTORE_PHRASE -ErrorAction SilentlyContinue
        }
        $summary += ("live restore test exit=$code seconds=" + [int]((Get-Date) - $started).TotalSeconds)
        }
    } else {
        $summary += "live restore test not run: the test was not built"
    }
    Pop-Location
} else {
    $summary += "live restore test not run: the chain program was not built"
}
# read the log to the end first: writing into it while it is being read would never finish
$lines = @(Select-String -Path $log -Pattern '^test result:|^profile restored|^files of an earlier run put|^search over|^TIMING |^something was found|^BALANCE |^test .* FAILED$|panicked at|^error' | Select-Object -First 30 | ForEach-Object { $_.Line })
Say "=== summary ==="
$summary | ForEach-Object { Say $_ }
$lines | ForEach-Object { Say $_ }
Say "finished $(Get-Date -Format s)"
Write-Host ""
Write-Host "Log: $log"
