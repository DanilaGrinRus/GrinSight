# GrinSight v0.2: A PAYMENT between two wallets on a real network, until it is in a block.
# THIS ONE SENDS A PAYMENT from the wallet of the phrase you type to a wallet made for the test - a tenth of a
# grin unless you say otherwise. The wallet made for the test is deleted when the test ends, AND WHAT WAS PAID
# TO IT IS GONE WITH IT. Use a phrase of the test network.
#
# What happens: the wallet of the phrase is restored and finds its funds (as in run-live-restore-test.ps1);
# it prepares the payment; a second wallet is made and answers; the first signs. From there on nothing asks
# the wallet to send: its handler hands the transaction to the chain program, which sends it THROUGH TOR as a
# stem transaction (Dandelion): to a public node of its list by the node's API, or else to one node of the
# network; if it has not come back from the network in three minutes, once more through Tor to be announced. The test waits until the paying wallet sees its transaction in a block, then
# starts the second wallet and checks that it sees the money. Lines that begin with PAYMENT tell how it went.
#
# THE PHRASE. This script asks for it with the input hidden. It is handed to the test in the memory of this
# process and to nothing else: it is not written to the log, not printed, not put on a command line.
#
# THIS ONE USES THE NETWORK. The chain process follows the chain over DIRECT connections to Grin nodes, as an
# ordinary Grin peer: those nodes see this computer's address. The transaction itself goes through Tor: the
# node it is given to sees a Tor exit, not this computer. Tor keeps its state in the chain directory (tor\).
#
# Run from any folder:   powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\run-live-payment-test.ps1 -Network test
# Another amount:        ... -Amount 250000000     (in nanogrin; 100000000 - a tenth of a grin - by default)
# Nodes of your own:     ... -Peer 192.168.1.5:13414
# As the product runs:   ... -Release  (the wallet process built optimized; the first build takes a few minutes)
# From an empty disk:    ... -Fresh    Without it the run begins from the chain files the last run left in
#                        target\live-seed\<network> (headers, state, blocks), which saves collecting them again;
#                        the wallet's own search for its outputs is made every time.
# It takes as long as restoring the wallet does, and then some minutes for the payment to get into a block.
# Builds the chain program and the host first; uses the vendored crates; downloads no code. Writes one log
# next to this script.
param([Parameter(Mandatory = $true)][ValidateSet('test', 'main')][string]$Network, [string[]]$Peer = @(), [long]$Amount = 100000000, [switch]$Fresh, [switch]$Release)
$ErrorActionPreference = 'Continue'
# started with -File, PowerShell hands "a,b" over as one text: take it apart
$Peer = @($Peer | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$log = Join-Path $root "live-payment-test-$stamp.log"
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
        Write-Host "The recovery phrase of the wallet that PAYS ($Network network). The input is hidden."
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
            $summary += "live payment test not run: no phrase was entered"
            $code = 2
        } else {
        $env:FLY_RESTORE_PHRASE = $phrase
        $phrase = $null
        $env:FLY_RESTORE_NETWORK = $Network
        $env:FLY_CHAIN_EXE = $program
        Remove-Item Env:FLY_CHAIN_SEED_DIR -ErrorAction SilentlyContinue
        Remove-Item Env:FLY_CHAIN_PEERS -ErrorAction SilentlyContinue
        # the chain files of the last run are kept here, and the next run begins from them
        $kept = Join-Path $env:CARGO_TARGET_DIR "live-seed\$Network"
        $env:FLY_CHAIN_KEEP_DIR = $kept
        if ($Fresh) { Say "from an empty disk: the chain files of earlier runs are not used" }
        elseif (Test-Path -LiteralPath (Join-Path $kept 'headers.dat')) { $env:FLY_CHAIN_SEED_DIR = $kept; Say "chain files of an earlier run: $kept" }
        $env:FLY_PAY_AMOUNT = "$Amount"
        Say "amount: $Amount nanogrin"
        if ($Peer.Count -gt 0) { $env:FLY_CHAIN_PEERS = ($Peer -join ','); Say ("nodes: " + ($Peer -join ', ') + " (only these)") }
        Say "=== paycore/host: live payment test with $program ==="
        $started = Get-Date
        try {
            cmd /c "cargo test $($profile_flag)--features test-chain --test host live_a_payment_reaches_a_block -- --ignored --nocapture 2>&1" | ForEach-Object { Say "$_" }
            $code = $LASTEXITCODE
        } finally {
            Remove-Item Env:FLY_RESTORE_PHRASE -ErrorAction SilentlyContinue
        }
        $summary += ("live payment test exit=$code seconds=" + [int]((Get-Date) - $started).TotalSeconds)
        }
    } else {
        $summary += "live payment test not run: the test was not built"
    }
    Pop-Location
} else {
    $summary += "live payment test not run: the chain program was not built"
}
# read the log to the end first: writing into it while it is being read would never finish
$lines = @(Select-String -Path $log -Pattern '^test result:|^profile restored|^files of an earlier run put|^chain files kept| PAYMENT |^PAYMENT |^BALANCE |^test .* FAILED$|panicked at|^error' | Select-Object -First 30 | ForEach-Object { $_.Line })
Say "=== summary ==="
$summary | ForEach-Object { Say $_ }
$lines | ForEach-Object { Say $_ }
Say "finished $(Get-Date -Format s)"
Write-Host ""
Write-Host "Log: $log"
