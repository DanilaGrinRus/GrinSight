# Grin MAINNET wallet, USER SCENARIO (RESEARCH / NOT VERIFIED).
# Imitates what the product does on a user's computer:
#   * no local node, no node API, no API secrets: only public peers
#     (Grin mainnet DNS seeds + addresses the peers gossip to us);
#   * a checkpoint that ships with the release (the last cross-checked
#     mainnet-cp-run, pinned by SHA-256) - the user never builds one;
#   * the user's own data lives in evidence\user-mainnet (proven UTXO state +
#     known own outputs), separate from the developer runs.
#
# Commands (one per run):
#   .\run_user.ps1                    open the wallet. First time: install
#                                     (archive rebuild + full rangeproof scan, long).
#                                     Afterwards: only new blocks (quick).
#   .\run_user.ps1 -Send [-Wallet 4]  open + BUILD a self-transfer (fee 0.025 GRIN).
#                                     Nothing is sent.
#   .\run_user.ps1 -Broadcast         (the last -Send / -SendTo; -Folder <dir> for another one)
#                                     show the transaction, type SEND, send it.
#   .\run_user.ps1 -Confirm           (the last -Send / -SendTo; -Folder <dir> for another one)
#                                     a few blocks later: kernel in a block, input spent,
#                                     change unspent at the tip; wallet updated.
#   .\run_user.ps1 -Address [-Wallet 4]
#                                     show this wallet's slatepack address (give it to senders)
#   .\run_user.ps1 -Receive <file with the sender's slatepack> [-Wallet 4]
#   .\run_user.ps1 -Receive clipboard
#                                     someone sent a slatepack: make the answer (copied to the
#                                     clipboard + saved in the run folder); give it back to the
#                                     sender. No network needed. The coins show up at the next
#                                     open once the sender has finalized and it is mined.
#   .\run_user.ps1 -SendTo <grin1... address | wallet:N> -Amount 1.5 [-Wallet 4]
#                                     open + start a payment (S1 slatepack, copied to the
#                                     clipboard). Nothing is sent to the network.
#   .\run_user.ps1 -Finalize          (the last -SendTo; answer from the clipboard, or -Answer <file>)
#                                     take the receiver's answer (S2), finish the transaction
#                                     (offline). Then -Broadcast, later -Confirm.
#   .\run_user.ps1 -Invoice -Amount 2 -Wallet 1 [-From wallet:4 | grin1...] [-Tor]
#                                     ask for a payment: invoice slatepack (I1, clipboard). Offline.
#   .\run_user.ps1 -PayInvoice clipboard -Wallet 4      (or: -PayInvoice inbox -Wallet 4 -Tor)
#                                     open + pay an invoice (I2 answer to the clipboard).
#                                     The issuer then runs -Finalize, -Broadcast, -Confirm.
#
# Tor / messenger (automatic slatepack exchange; grinsight-tor daemon, one per wallet):
#   .\run_user.ps1 -TorStart [-Wallet 4] [-Relay http://relay:8080]
#                                     start the daemon of this wallet in its own window:
#                                     grin-wallet compatible onion (from the slatepack
#                                     address) + GrinMessenger (separate key; direct over
#                                     Tor, or the relay when Tor does not come up)
#   .\run_user.ps1 -TorStatus [-Wallet 4]   addresses, onion, policy, last events
#   .\run_user.ps1 -Contact add -Id grin1... -Name Bob [-Messenger grin1...|wallet:N] [-NoAuto]
#   .\run_user.ps1 -Contact remove -Id grin1...      /  -Contact list
#   .\run_user.ps1 -AutoAccept off|contacts|all     automatic acceptance of payments
#   .\run_user.ps1 -SendTo <grin1|wallet:N> -Amount 1 -Wallet 4 -Tor
#                                     pay automatically: after you type SEND the daemon
#                                     delivers S1, gets S2, finalizes and broadcasts.
#                                     Invoices are never paid automatically.
#   ... -Tor -ViaMessenger [-Messenger wallet:N|grin1...]
#                                     skip the foreign API: signed GrinMessenger envelope
#   -AutoBroadcast on|off            setting: send right after a successful -Finalize (default on)
#   -ExtraPeers a:3414,b:3414         add public peers (optional)
#   -Reinstall                        forget the user data and install again
#   -Probe                            look for peers again instead of using the peer store

param([switch]$Send, [int]$Wallet = 4, [switch]$Broadcast, [switch]$Confirm, [string]$Folder = '',
      [string[]]$ExtraPeers = @(), [switch]$Reinstall, [switch]$Probe,
      [switch]$Address, [string]$Receive = '',
      [string]$SendTo = '', [string]$Amount = '', [switch]$Finalize, [string]$Answer = 'clipboard',
      [switch]$Invoice, [string]$From = '', [string]$PayInvoice = '',
      [switch]$TorStart, [switch]$TorStatus, [string]$Relay = '', [string]$Contact = '', [string]$Id = '',
      [string]$Name = '', [string]$Messenger = '', [switch]$NoAuto, [string]$AutoAccept = '', [switch]$Tor, [switch]$ViaMessenger, [string]$AutoBroadcast = '', [switch]$OwnCheckpoint, [string]$CheckpointSource = '')

$ErrorActionPreference = 'Continue'
Set-Location -Path $PSScriptRoot
if ($PSScriptRoot -match '\s') { Write-Host 'GrinSight path must not contain spaces'; exit 1 }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runDir = Join-Path $PSScriptRoot "evidence\user-run-$stamp"
New-Item -ItemType Directory -Path $runDir | Out-Null
$summary = Join-Path $runDir 'summary.txt'

$env:CARGO_TARGET_DIR = "$PSScriptRoot\.build\target"
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
$env:GRINSIGHT_BIN_DIR = "$PSScriptRoot\.build\target\release"
$exe = "$env:GRINSIGHT_BIN_DIR\reverse-wtema-header-sync.exe"
# Session and policy tool (Rust; replaces grinsight.py), built with header-sync.
$grinsight = "$env:GRINSIGHT_BIN_DIR\grinsight-sync.exe"
$torExe = "$env:GRINSIGHT_BIN_DIR\grinsight-tor.exe"

$userDir = Join-Path $PSScriptRoot 'evidence\user-mainnet'
$stateDir = Join-Path $userDir 'state'
$walletState = Join-Path $userDir 'wallet-outputs.jsonl'
$cpDir = Join-Path $userDir 'checkpoint'
$seeds = Join-Path $PSScriptRoot 'TESTNET_FUNDED_SEEDS.local.txt'
# Outputs promised to senders (key ids, no secrets) until they show up on chain.
$pendingFile = Join-Path $userDir 'pending-receives.jsonl'
$probeCommitment = '0800000000000000000000000000000000000000000000000000000000000000ff'

function Note($text) {
    Write-Host $text
    Add-Content -Path $summary -Value $text -Encoding ASCII
}

# Command lines are split into an argument array here and the program is
# started DIRECTLY (no cmd.exe): characters such as & | < > ^ in an address,
# amount or path are plain text for the program, never a second command.
# Double quotes group an argument with spaces; they are not passed on.
function Split-CommandLine([string]$line) {
    $out = New-Object System.Collections.Generic.List[string]
    $cur = New-Object System.Text.StringBuilder
    $inQuote = $false; $have = $false
    foreach ($ch in $line.ToCharArray()) {
        if ($ch -eq [char]'"') { $inQuote = -not $inQuote; $have = $true; continue }
        if (-not $inQuote -and [char]::IsWhiteSpace($ch)) {
            if ($have -or $cur.Length -gt 0) { $out.Add($cur.ToString()); [void]$cur.Clear(); $have = $false }
            continue
        }
        [void]$cur.Append($ch)
    }
    if ($inQuote) { throw "unbalanced quotes in command line: $line" }
    if ($have -or $cur.Length -gt 0) { $out.Add($cur.ToString()) }
    return ,$out.ToArray()
}

function Step($name, $cmdline) {
    $log = Join-Path $runDir "$name.log"
    Write-Host ""
    Write-Host "=== $name  ($(Get-Date -Format 'HH:mm:ss')) ==="
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $argv = Split-CommandLine $cmdline
    $exeName = $argv[0]
    $rest = @($argv | Select-Object -Skip 1)
    # A .cmd/.bat would be run by cmd.exe again (and & would be live there).
    $resolved = Get-Command $exeName -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($resolved -and $resolved.Source -match '\.(cmd|bat)$') { throw "refusing to run a batch file through cmd.exe: $($resolved.Source)" }
    $ErrorActionPreference = 'Continue'
    & $exeName @rest 2>&1 | ForEach-Object { "$_" } | Set-Content -Path $log -Encoding UTF8
    $code = $LASTEXITCODE
    $sw.Stop()
    Get-Content -Path $log -Tail 25 | Write-Host
    Note ("{0}: exit={1} seconds={2:N0}" -f $name, $code, $sw.Elapsed.TotalSeconds)
    return $code
}

function Lines($name, $pattern) {
    Get-Content -Path (Join-Path $runDir "$name.log") | Where-Object { $_ -match $pattern } | ForEach-Object { Note "  $_" }
}

function Stop-Run($text) {
    Note "STOP: $text"
    Write-Host "Logs: $runDir"
    Read-Host 'Press Enter to close'
    exit 1
}

function Finish() {
    Note ("user_seconds={0:N0} (from start of the user part; build excluded)" -f ((Get-Date) - $userStart).TotalSeconds)
    Note "done=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host ""
    Write-Host "Logs: $runDir"
    Read-Host 'Finished. Press Enter to close'
    exit 0
}

$cmdName = 'open'
if ($Send) { $cmdName = 'send-build' }
if ($Broadcast) { $cmdName = 'broadcast' }
if ($Confirm) { $cmdName = 'confirm' }
if ($Address) { $cmdName = 'address' }
if ($Receive) { $cmdName = 'receive' }
if ($SendTo) { $cmdName = 'send-to' }
if ($Finalize) { $cmdName = 'finalize' }
if ($Invoice) { $cmdName = 'invoice' }
if ($PayInvoice) { $cmdName = 'pay-invoice' }
if ($TorStart) { $cmdName = 'tor-start' }
if ($TorStatus) { $cmdName = 'tor-status' }
if ($Contact) { $cmdName = "contact-$Contact" }
if ($AutoAccept) { $cmdName = 'auto-accept' }
if ($SendTo -and $Tor) { $cmdName = 'send-to-tor' }
if ($AutoBroadcast) { $cmdName = 'settings' }
Note "run=$stamp computer=$env:COMPUTERNAME network=MAINNET scenario=USER command=$cmdName"
Note '  local node: NOT USED (user scenario); peers: DNS seeds + gossip only'

# Settings (evidence\user-mainnet\settings.json). auto_broadcast: after a
# successful -Finalize the transaction goes to the network at once (default on);
# off = the old way, a separate -Broadcast with SEND typed by hand.
$settingsFile = Join-Path $userDir 'settings.json'
function Get-Settings() {
    $o = [ordered]@{ auto_broadcast = $true; checkpoint_source = 'release' }
    if (Test-Path $settingsFile) {
        try {
            $j = Get-Content $settingsFile -Raw | ConvertFrom-Json
            if ($null -ne $j.auto_broadcast) { $o.auto_broadcast = [bool]$j.auto_broadcast }
            if ($j.checkpoint_source -in 'release', 'own') { $o.checkpoint_source = $j.checkpoint_source }
        } catch { Note "  settings.json unreadable, defaults used: $_" }
    }
    return $o
}
$settings = Get-Settings
function Save-Settings() {
    New-Item -ItemType Directory -Force -Path $userDir | Out-Null
    Set-Content -Path $settingsFile -Value ($settings | ConvertTo-Json) -Encoding ASCII
}
# -OwnCheckpoint: do not rely on the shipped checkpoint at all, check every
# header from genesis (resumable). -CheckpointSource release|own switches back.
if ($OwnCheckpoint) { $settings.checkpoint_source = 'own'; Save-Settings }
if ($CheckpointSource) {
    if ($CheckpointSource -notin 'release', 'own') { Write-Host '-CheckpointSource release|own'; exit 1 }
    $settings.checkpoint_source = $CheckpointSource; Save-Settings
}
if ($AutoBroadcast) {
    if ($AutoBroadcast -notin 'on', 'off') { Write-Host '-AutoBroadcast on|off'; exit 1 }
    $settings.auto_broadcast = ($AutoBroadcast -eq 'on')
    New-Item -ItemType Directory -Force -Path $userDir | Out-Null
    Save-Settings
    Note "  auto_broadcast=$($AutoBroadcast) (saved in $settingsFile)"
    $userStart = Get-Date
    Finish
}
Note "  settings: auto_broadcast=$(if ($settings.auto_broadcast) { 'on' } else { 'off' }) checkpoint_source=$($settings.checkpoint_source)"

# 0. Program build (the user gets a ready binary; not counted) -------------------------------
# Crates added for slatepacks (grin-wallet libwallet: age, x25519, bech32, ...)
# come as one archive; unpack it into local-vendor once (builds stay offline).
$vendAdd = Join-Path $PSScriptRoot 'local-vendor-add.zip'
if ((Test-Path $vendAdd) -and -not (Test-Path (Join-Path $PSScriptRoot 'local-vendor\age-0.8.2'))) {
    Note '  unpacking local-vendor-add.zip into local-vendor (once)'
    Expand-Archive -Path $vendAdd -DestinationPath (Join-Path $PSScriptRoot 'local-vendor') -Force
}
# Some files inside vendored crates went missing on this PC (profile reset /
# cleanup): cargo then refuses to build ("failed to calculate checksum").
# Check every crate once per run; for local-vendor drop entries of missing
# files from .cargo-checksum.json (original kept as .cargo-checksum.json.orig)
# and list them in vendor-missing.txt. Other vendor dirs are only reported.
function Check-Vendor([string]$dir, [bool]$fix) {
    if (-not (Test-Path $dir)) { return }
    $missLog = Join-Path $runDir 'vendor-missing.txt'
    $nMiss = 0; $nCrates = 0
    foreach ($crate in Get-ChildItem -Path $dir -Directory) {
        $ck = Join-Path $crate.FullName '.cargo-checksum.json'
        if (-not [IO.File]::Exists($ck)) { continue }
        $j = [IO.File]::ReadAllText($ck) | ConvertFrom-Json
        $gone = @()
        foreach ($p in $j.files.PSObject.Properties) {
            $f = Join-Path $crate.FullName ($p.Name -replace '/', '\')
            if (-not [IO.File]::Exists($f)) { $gone += $p.Name }
        }
        if ($gone.Count -eq 0) { continue }
        $nCrates++; $nMiss += $gone.Count
        foreach ($g in $gone) { Add-Content -Path $missLog -Value "$($crate.Name)/$g" -Encoding ASCII }
        if ($fix) {
            $orig = "$ck.orig"
            if (-not [IO.File]::Exists($orig)) { Copy-Item -Path $ck -Destination $orig }
            foreach ($g in $gone) { $j.files.PSObject.Properties.Remove($g) }
            $txt = $j | ConvertTo-Json -Compress -Depth 5
            [IO.File]::WriteAllText($ck, $txt, (New-Object Text.UTF8Encoding $false))
        }
    }
    if ($nMiss -gt 0) {
        $what = if ($fix) { 'skipped in checksums' } else { 'NOT fixed (shared folder)' }
        Note "  vendor ${dir}: $nMiss missing files in $nCrates crates, $what; see vendor-missing.txt"
    }
    return $nMiss
}
# Real copies of files that went missing (checked against the original
# checksums); applied once, restores the original .cargo-checksum.json too.
$vendFix = Join-Path $PSScriptRoot 'local-vendor-fix.zip'
$vendFixDone = Join-Path $PSScriptRoot 'local-vendor\.fix-applied'
if ((Test-Path $vendFix) -and ((-not (Test-Path $vendFixDone)) -or ((Get-Item $vendFix).LastWriteTime -gt (Get-Item $vendFixDone).LastWriteTime))) {
    Note '  restoring missing vendor files from local-vendor-fix.zip'
    Expand-Archive -Path $vendFix -DestinationPath (Join-Path $PSScriptRoot 'local-vendor') -Force
    Set-Content -Path $vendFixDone -Value $stamp -Encoding ASCII
}
$null = Check-Vendor (Join-Path $PSScriptRoot 'local-vendor') $true
$c = Step '00-build' 'cargo build --offline --locked --release --manifest-path header-sync\Cargo.toml'
if ($c -ne 0) { Stop-Run 'build failed' }
$userStart = Get-Date

if ($Reinstall -and (Test-Path $userDir)) {
    $old = "$userDir-old-$stamp"
    Move-Item $userDir $old
    Note "  -Reinstall: previous user data moved to $old"
}
New-Item -ItemType Directory -Force -Path $userDir | Out-Null

# The folder of the last -Send / -SendTo run: -Finalize, -Broadcast and
# -Confirm use it unless -Folder says otherwise.
$lastTx = Join-Path $userDir 'last-transaction.txt'
function Get-TxFolder() {
    $f = $Folder
    if (-not $f) {
        if (-not (Test-Path $lastTx)) { Stop-Run 'no transaction started yet (run -Send or -SendTo first)' }
        $f = (Get-Content $lastTx -TotalCount 1).Trim()
    }
    $r = (Resolve-Path $f -ErrorAction SilentlyContinue).Path
    if (-not $r) { Stop-Run "no such folder: $f" }
    Note "  transaction folder: $r"
    return $r
}

function Resolve-Address($a) {
    # wallet:N = another wallet of the test bench seed file; otherwise grin1...
    if ($a -match '^wallet:(\d+)$') {
        $n = $Matches[1]
        $c = Step '05-address' "$exe --mainnet --slatepack-address --seeds $seeds"
        $line = Get-Content (Join-Path $runDir '05-address.log') | Where-Object { $_ -like "SLATEPACK_ADDRESS=wallet=$n *" } | Select-Object -First 1
        if (-not $line) { Stop-Run "no address for $a" }
        return ($line -split ' ')[1]
    }
    return $a
}
function Resolve-Messenger($a) {
    # wallet:N = messenger address of that wallet's running Tor daemon
    # (status.json); otherwise grin1... as given.
    if ($a -match '^wallet:(\d+)$') {
        $sf = Join-Path $userDir "tor-wallet-$($Matches[1])\status.json"
        if (-not (Test-Path $sf)) { Stop-Run "messenger address of $a unknown: start its daemon first (.\run_user.ps1 -TorStart -Wallet $($Matches[1]))" }
        $m = (Get-Content $sf -Raw | ConvertFrom-Json).messenger_address
        if (-not $m) { Stop-Run "the daemon of $a has no messenger address yet (wait for 'ready' in its window)" }
        return $m
    }
    return $a
}
function To-Nano($g) {
    if (-not $g) { Stop-Run '-Amount is needed (GRIN, e.g. 1.5)' }
    $n = [int64]([decimal]::Parse($g, [Globalization.CultureInfo]::InvariantCulture) * 1000000000)
    if ($n -le 0) { Stop-Run "bad -Amount $g" }
    return $n
}
function Read-Slatepack($src, $fallback, $what) {
    # 'clipboard' (falls back to a file made here on the test bench) or a file path.
    if ($src -eq 'clipboard') {
        $text = (Get-Clipboard -Raw)
        if (-not $text -or $text -notmatch 'BEGINSLATEPACK') {
            if (-not $fallback -or -not (Test-Path $fallback)) { Stop-Run "the clipboard holds no $what (BEGINSLATEPACK ... ENDSLATEPACK.)" }
            Note "  clipboard empty: using the last $what made here ($fallback)"
            $text = Get-Content $fallback -Raw
        }
        return $text
    }
    if (-not (Test-Path $src)) { Stop-Run "no such file: $src" }
    return (Get-Content $src -Raw)
}
function Give-Slatepack($file, $title) {
    $t = (Get-Content $file -Raw).Trim()
    Write-Host ""
    Write-Host "=== $title ==="
    Write-Host $t
    Write-Host ("=" * ($title.Length + 8))
    try { Set-Clipboard -Value $t; Note '  copied to the clipboard' } catch { }
}

function Show-Pending() {
    # Promised outputs: still waiting (sender has not finalized / not mined yet) or arrived.
    if (-not (Test-Path $pendingFile)) { return }
    $known = ''
    if (Test-Path $walletState) { $known = Get-Content $walletState -Raw }
    foreach ($l in Get-Content $pendingFile) {
        if ($l -notmatch '"wallet":(\d+).*"slate_id":"([^"]+)".*"amount":(\d+).*"commit":"([0-9a-f]+)".*"received_at":"([^"]+)"') { continue }
        $pw = $Matches[1]; $sid = $Matches[2]; $cm = $Matches[4]; $at = $Matches[5]
        $grin = '{0:N9}' -f ([decimal]$Matches[3] / 1000000000)
        $what = 'receive'
        if ($l.Contains('"kind":"change"') -or $l.Contains('"kind":"payment"')) { $what = 'payment change' }
        if ($l.Contains('"kind":"invoice"')) { $what = 'invoice (to be paid)' }
        if ($known.Contains($cm)) { $st = 'ARRIVED (on chain)' } else { $st = 'WAITING (sender has not finalized, or not mined yet)' }
        Note "  $what wallet=$pw amount=$grin GRIN slate=$sid at=${at}: $st"
    }
}

# Slatepack address / receive: offline, no peers --------------------------------------------------
if ($Address) {
    $c = Step '05-address' "$exe --mainnet --slatepack-address --seeds $seeds"
    $line = Get-Content (Join-Path $runDir '05-address.log') | Where-Object { $_ -like "SLATEPACK_ADDRESS=wallet=$Wallet *" } | Select-Object -First 1
    if (-not $line) { Stop-Run "no address for wallet $Wallet" }
    $addr = ($line -split ' ')[1]
    Note "slatepack_address wallet=$Wallet $addr"
    try { Set-Clipboard -Value $addr; Note '  (copied to the clipboard)' } catch { }
    Finish
}
if ($Receive) {
    if (-not (Test-Path $walletState)) { Stop-Run 'open the wallet once first (.\run_user.ps1): it records which keys are already used' }
    $inFile = Join-Path $runDir 'slatepack-in.txt'
    if ($Receive -eq 'clipboard') {
        $text = (Get-Clipboard -Raw)
        if (-not $text -or $text -notmatch 'BEGINSLATEPACK') {
            # Test bench: the payment slatepack made by the last -SendTo here.
            $lastS1 = $null
            if (Test-Path $lastTx) { $lastS1 = Join-Path (Get-Content $lastTx -TotalCount 1).Trim() 'slatepack-s1.txt' }
            if (-not $lastS1 -or -not (Test-Path $lastS1)) { Stop-Run 'the clipboard holds no slatepack (BEGINSLATEPACK ... ENDSLATEPACK.)' }
            Note "  clipboard empty: using the last payment slatepack made here ($lastS1)"
            $text = Get-Content $lastS1 -Raw
        }
        Set-Content -Path $inFile -Value $text -Encoding ASCII -NoNewline
    } else {
        if (-not (Test-Path $Receive)) { Stop-Run "no such file: $Receive" }
        Copy-Item $Receive $inFile
    }
    $tipArg = ''
    $meta = Get-Content $walletState -TotalCount 1
    if ($meta -match '"tip_height":(\d+)') { $tipArg = "--tip-height $($Matches[1])" }
    $outFile = Join-Path $runDir 'slatepack-response.txt'
    $c = Step '05-receive' "$exe --mainnet --receive-slatepack $inFile --seeds $seeds --wallet $Wallet --response-out $outFile --pending $pendingFile --known-outputs $walletState $tipArg"
    Lines '05-receive' '^RECEIVE'
    if ($c -ne 0) { Stop-Run 'receive failed (see RECEIVE=FAIL above)' }
    $resp = (Get-Content $outFile -Raw).Trim()
    Write-Host ""
    Write-Host "=== GIVE THIS ANSWER BACK TO THE SENDER ==="
    Write-Host $resp
    Write-Host "==========================================="
    try { Set-Clipboard -Value $resp; Note '  answer copied to the clipboard' } catch { }
    Note "  answer file: $outFile"
    Set-Content -Path (Join-Path $userDir 'last-answer.txt') -Value $outFile -Encoding ASCII
    Note '  the coins show up at the next .\run_user.ps1 once the sender has finalized and the block is mined'
    Note 'next (test bench, the sender is a wallet here):  .\run_user.ps1 -Finalize'
    Finish
}
# Tor daemon + address book ----------------------------------------------------------------------
function Build-Tor() {
    # Separate workspace (tor\): GrinMessenger crates + Arti from the offline
    # vendor C:\DHW\vendor (tor\.cargo\config.toml). First build takes minutes.
    if ((Check-Vendor 'C:\DHW\vendor' $false) -gt 0) { Stop-Run 'files missing in C:\DHW\vendor (see vendor-missing.txt)' }
    $c = Step '06-build-tor' 'cargo --config tor\vendor.toml build --offline --locked --release --manifest-path tor\Cargo.toml -p grinsight-tor'
    if ($c -ne 0) { Stop-Run 'grinsight-tor build failed (see 06-build-tor.log)' }
}
if ($Contact -or $AutoAccept) {
    Build-Tor
    if ($AutoAccept) {
        $c = Step '07-book' "$torExe book auto-accept $AutoAccept --user-dir $userDir"
    } elseif ($Contact -eq 'add') {
        if (-not $Id) { Stop-Run '-Contact add needs -Id grin1...' }
        $id2 = Resolve-Address $Id
        $extra = ''
        if ($Name) { $extra += " --name `"$Name`"" }
        if ($Messenger) { $extra += " --messenger $(Resolve-Messenger $Messenger)" }
        if ($NoAuto) { $extra += ' --auto no' }
        $c = Step '07-book' "$torExe book add --id $id2 $extra --user-dir $userDir"
    } elseif ($Contact -eq 'remove') {
        $c = Step '07-book' "$torExe book remove --id $(Resolve-Address $Id) --user-dir $userDir"
    } else {
        $c = Step '07-book' "$torExe book list --user-dir $userDir"
    }
    Lines '07-book' '^(CONTACT|AUTO_ACCEPT|GRINSIGHT_TOR)'
    if ($c -ne 0) { Stop-Run 'address book command failed' }
    if (-not $AutoAccept) { $c = Step '07-book-list' "$torExe book list --user-dir $userDir"; Lines '07-book-list' '^(CONTACT|AUTO_ACCEPT)' }
    Finish
}
if ($TorStart) {
    Build-Tor
    $args5 = "serve --mainnet --exe `"$exe`" --seeds `"$seeds`" --wallet $Wallet --user-dir `"$userDir`""
    if ($Relay) { $args5 += " --relay $Relay" }
    Start-Process powershell -ArgumentList '-NoExit', '-Command', "& `"$torExe`" $args5" | Out-Null
    Note "  grinsight-tor for wallet $Wallet started in its own window (keep it open; close it to stop)"
    Note '  first Tor start: 30-150 s; then  .\run_user.ps1 -TorStatus -Wallet ' + $Wallet
    Finish
}
if ($TorStatus) {
    $sf = Join-Path $userDir "tor-wallet-$Wallet\status.json"
    if (-not (Test-Path $sf)) { Stop-Run "no daemon status for wallet $Wallet (start it with -TorStart -Wallet $Wallet)" }
    Get-Content $sf | ForEach-Object { Note "  $_" }
    $lf = Join-Path $userDir "tor-wallet-$Wallet\daemon.log"
    if (Test-Path $lf) { Note '  last events:'; Get-Content $lf -Tail 12 | ForEach-Object { Note "    $_" } }
    Finish
}

if ($Invoice) {
    if (-not (Test-Path $walletState)) { Stop-Run 'open the wallet once first (.\run_user.ps1): it records which keys are already used' }
    $nano = To-Nano $Amount
    $payerArg = ''
    if ($From) { $payer = Resolve-Address $From; $payerArg = "--payer $payer"; Note "  payer: $payer (the invoice is encrypted to it)" }
    $i1 = Join-Path $runDir 'invoice-i1.txt'
    $c = Step '05-invoice' "$exe --mainnet --issue-invoice $nano --seeds $seeds --wallet $Wallet $payerArg --pending $pendingFile --known-outputs $walletState --slatepack-out $i1 --context-out $(Join-Path $runDir 'invoice-context.json')"
    Lines '05-invoice' '^INVOICE'
    if ($c -ne 0) { Stop-Run 'invoice failed (see INVOICE=FAIL above)' }
    Give-Slatepack $i1 'GIVE THIS INVOICE TO THE PAYER'
    Set-Content -Path $lastTx -Value $runDir -Encoding ASCII
    if ($Tor) {
        # The daemon sends the invoice in a signed messenger envelope; when the
        # payer's answer (I2) comes back it finalizes and broadcasts by itself.
        if (-not (Test-Path (Join-Path $userDir "tor-wallet-$Wallet\status.json"))) { Stop-Run "the Tor daemon of wallet $Wallet is not running (.\run_user.ps1 -TorStart -Wallet $Wallet); the invoice above can still be given by hand" }
        $sid = (Get-Content (Join-Path $runDir '05-invoice.log') | Where-Object { $_ -like 'INVOICE_SLATE_ID=*' } | Select-Object -First 1).Substring(17)
        $msgArg = ''
        if ($Messenger) { $msgArg = "--messenger $(Resolve-Messenger $Messenger)" }
        elseif ($From -match '^wallet:') { $msgArg = "--messenger $(Resolve-Messenger $From)" }
        $to = if ($payer) { $payer } else { 'unknown' }
        Build-Tor
        $c = Step '45-queue' "$torExe queue --user-dir `"$userDir`" --wallet $Wallet --kind invoice --slate-id $sid --to $to --armor `"$i1`" --context `"$(Join-Path $runDir 'invoice-context.json')`" --tx-folder `"$runDir`" $msgArg --messenger-only"
        if ($c -ne 0) { Stop-Run 'could not queue the invoice' }
        Note '  invoice queued for the messenger; when the payer pays, this wallet finalizes and broadcasts by itself'
        Note "  status: $runDir\AUTO_STATUS.txt  (or .\run_user.ps1 -TorStatus -Wallet $Wallet)"
        if ($From -match '^wallet:(\d+)$') { Note "next (test bench, wallet $($Matches[1]) pays):  .\run_user.ps1 -PayInvoice inbox -Wallet $($Matches[1]) -Tor" }
        Finish
    }
    if ($From -match '^wallet:(\d+)$') { Note "next (test bench, wallet $($Matches[1]) pays):  .\run_user.ps1 -PayInvoice clipboard -Wallet $($Matches[1])" }
    else { Note 'next: the payer pays it; put its answer in the clipboard' }
    Note 'then:  .\run_user.ps1 -Finalize'
    Finish
}
if ($Finalize) {
    $sendDir = Get-TxFolder
    $ctxFile = Join-Path $sendDir 'send-context.json'
    $invCtx = Join-Path $sendDir 'invoice-context.json'
    $isInvoice = Test-Path $invCtx
    if ($isInvoice) { $ctxFile = $invCtx }
    if (-not (Test-Path $ctxFile)) { Stop-Run "no send-context.json / invoice-context.json in $sendDir (already finalized?)" }
    $ansFile = Join-Path $runDir 'slatepack-answer.txt'
    if ($Answer -eq 'clipboard') {
        $text = (Get-Clipboard -Raw)
        if (-not $text -or $text -notmatch 'BEGINSLATEPACK') {
            # Test bench: the answer made by the last -Receive here.
            $la = Join-Path $userDir 'last-answer.txt'
            $lastAns = $null
            if (Test-Path $la) { $lastAns = (Get-Content $la -TotalCount 1).Trim() }
            if (-not $lastAns -or -not (Test-Path $lastAns)) { Stop-Run 'the clipboard holds no slatepack answer' }
            Note "  clipboard empty: using the last answer made here ($lastAns)"
            $text = Get-Content $lastAns -Raw
        }
        Set-Content -Path $ansFile -Value $text -Encoding ASCII -NoNewline
    } else {
        if (-not (Test-Path $Answer)) { Stop-Run "no such file: $Answer" }
        Copy-Item $Answer $ansFile
    }
    $txFile = Join-Path $sendDir 'spend-tx.hex'
    if ($isInvoice) {
        $c = Step '05-finalize' "$exe --mainnet --finalize-invoice $ansFile --seeds $seeds --invoice-context $ctxFile --tx-out $txFile"
    } else {
        $c = Step '05-finalize' "$exe --mainnet --finalize-slatepack $ansFile --seeds $seeds --send-context $ctxFile --tx-out $txFile --proof-out $(Join-Path $sendDir 'payment-proof.json')"
    }
    Lines '05-finalize' '^(GAP_SPEND_|FINALIZE|PAYMENT_PROOF)'
    if ($c -ne 0) { Stop-Run 'finalize failed (see FINALIZE=FAIL above)' }
    # -Broadcast / -Confirm read the transaction details from the send folder's log.
    Get-Content (Join-Path $runDir '05-finalize.log') | Where-Object { $_ -match '^GAP_SPEND_' } | Add-Content -Path (Join-Path $sendDir '30-wallet.log') -Encoding ASCII
    if (-not $settings.auto_broadcast) {
        Note "next (only if the transaction above is what you want):  .\run_user.ps1 -Broadcast"
        Note '  (auto_broadcast is off; .\run_user.ps1 -AutoBroadcast on  sends right after -Finalize)'
        Finish
    }
    # Finalized means both sides agreed: send it now (setting auto_broadcast).
    Note '  auto_broadcast=on: sending the finalized transaction now'
    $Broadcast = $true
    $autoSend = $true
}

# 1. Shipped checkpoint ------------------------------------------------------------------------
# The release carries a cross-checked checkpoint. Imitation: copy the last
# CROSSCHECK=PASS developer checkpoint once, pin its SHA-256, use only the copy.
$cp = Join-Path $cpDir 'checkpoint.rwm'
$hist = Join-Path $cpDir 'recent-headers.bin'
$pin = Join-Path $cpDir 'pin.txt'
# Signed release (stage 4): release\ holds checkpoint.rwm, recent-headers.bin,
# release.txt and release.sig. The wallet exe checks the signature with the
# keys compiled into it, that the files match, and that it never goes back
# from the release accepted last time (sequence, height, same-height header).
$relDir = Join-Path $PSScriptRoot 'release'
$accRel = Join-Path $cpDir 'accepted-release.txt'
if (Test-Path (Join-Path $relDir 'release.txt')) {
    $c = Step '01-release' "$exe --mainnet --verify-release `"$relDir`" --accepted `"$accRel`""
    Lines '01-release' '^RELEASE(=|_HEIGHT|_SEQUENCE|_KEY_ID|_HEADER_HASH)'
    if ($c -ne 0) { Stop-Run 'the shipped checkpoint release is not valid (see RELEASE=FAIL above); nothing was changed' }
    $relText = [IO.File]::ReadAllText((Join-Path $relDir 'release.txt'))
    $accText = if (Test-Path $accRel) { [IO.File]::ReadAllText($accRel) } else { '' }
    if ($relText -ne $accText) {
        New-Item -ItemType Directory -Force -Path $cpDir | Out-Null
        Copy-Item (Join-Path $relDir 'checkpoint.rwm'), (Join-Path $relDir 'recent-headers.bin') $cpDir -Force
        Copy-Item (Join-Path $relDir 'release.txt') $accRel -Force
        Set-Content -Path $pin -Value ($relText -split "`n" | Where-Object { $_ -match '^(checkpoint|history)_sha256=' }) -Encoding ASCII
        Note '  signed checkpoint release accepted (the wallet state is kept)'
    } else { Note '  signed checkpoint release: already accepted' }
} elseif (Test-Path $pin) { Note '  checkpoint: developer pin (no signed release in release\ yet)' }
$useShipped = $settings.checkpoint_source -ne 'own'
if ($useShipped -and -not (Test-Path $pin)) {
    $cpRun = Get-ChildItem -Directory (Join-Path $PSScriptRoot 'evidence') -Filter 'mainnet-cp-run-*' -ErrorAction SilentlyContinue |
        Sort-Object Name | Where-Object { (Test-Path (Join-Path $_.FullName 'summary.txt')) -and
            ((Get-Content (Join-Path $_.FullName 'summary.txt') -Raw) -match 'CROSSCHECK=PASS') } | Select-Object -Last 1
    if (-not $cpRun) { Stop-Run 'no cross-checked checkpoint to ship (run run_mainnet.ps1 -NewCheckpoint once)' }
    $src = Get-Content (Join-Path $cpRun.FullName 'summary.txt') -Raw
    $a = (Get-FileHash -Algorithm SHA256 (Join-Path $cpRun.FullName 'checkpoint\checkpoint.rwm')).Hash.ToLower()
    $b = (Get-FileHash -Algorithm SHA256 (Join-Path $cpRun.FullName 'checkpoint\recent-headers.bin')).Hash.ToLower()
    if ($src -notmatch "checkpoint_sha256=$a" -or $src -notmatch "history_sha256=$b") { Stop-Run "checkpoint in $($cpRun.Name) does not match its pins" }
    New-Item -ItemType Directory -Force -Path $cpDir | Out-Null
    Copy-Item (Join-Path $cpRun.FullName 'checkpoint\checkpoint.rwm'), (Join-Path $cpRun.FullName 'checkpoint\recent-headers.bin') $cpDir
    Set-Content -Path $pin -Value @("from=$($cpRun.Name)", "checkpoint_sha256=$a", "history_sha256=$b") -Encoding ASCII
    Note "  shipped checkpoint: $($cpRun.Name)"
}
if ($useShipped) {
    $pinText = Get-Content $pin -Raw
    $cpSha = (Get-FileHash -Algorithm SHA256 $cp).Hash.ToLower()
    $hiSha = (Get-FileHash -Algorithm SHA256 $hist).Hash.ToLower()
    if ($pinText -notmatch "checkpoint_sha256=$cpSha" -or $pinText -notmatch "history_sha256=$hiSha") { Stop-Run 'shipped checkpoint files changed' }
    Note "checkpoint_sha256=$cpSha history_sha256=$hiSha"
}

# 2. Public peers ------------------------------------------------------------------------------
# Everyday runs take the peers that answered last time (like a node's peer
# store) without probing them again: every extra connection to a Grin node
# makes it refuse our next one for a while (check_undesirable). A fresh probe
# (DNS seeds + gossiped addresses, all in parallel) runs on install, when the
# store is small or older than a day, or with -Probe.
$peerCache = Join-Path $userDir 'peers.txt'
$cachedOk = @()
if (Test-Path $peerCache) {
    $cachedOk = @(Get-Content $peerCache | Where-Object { $_ -match '^\S+:\d+ pibd=(yes|no)$' } | ForEach-Object {
        $f = $_ -split ' '; [pscustomobject]@{ Peer = $f[0]; Pibd = ($f[1] -eq 'pibd=yes'); Td = 0 } })
}
$installedNow = (Test-Path (Join-Path $stateDir 'state.ust')) -and (Test-Path $walletState)
$cacheFresh = (Test-Path $peerCache) -and (((Get-Date) - (Get-Item $peerCache).LastWriteTime).TotalHours -lt 24)
if ($installedNow -and $cacheFresh -and $cachedOk.Count -ge 6 -and -not $Probe) {
    $ok = $cachedOk
    Note "  peers: from the peer store ($($ok.Count)), no probe"
} else {
    $c = Step '01-dns-seeds' "$grinsight dns-seeds"
    $seedPeers = @(Get-Content (Join-Path $runDir '01-dns-seeds.log') | Where-Object { $_ -like 'KNOWN_PEER=*' } |
        ForEach-Object { ($_ -split ' ')[0].Substring(11) } | Select-Object -First 16)
    $extra = @($ExtraPeers | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $probeList = @($extra + @($cachedOk | ForEach-Object { $_.Peer }) + $seedPeers | Select-Object -Unique | Select-Object -First 32)
    Note "  cached_peers=$($cachedOk.Count) seed_peers=$($seedPeers.Count)"
    if ($probeList.Count -eq 0) { Stop-Run 'no DNS seed answered and no -ExtraPeers' }
    $c = Step '02-probe' "$exe --mainnet --discover $(($probeList | ForEach-Object { "--probe-peer $_" }) -join ' ')"
    $probeLines = @(Get-Content (Join-Path $runDir '02-probe.log') | Where-Object { $_ -match '^PROBE_PEER=\S+ OK' })
    $pibdCount = @($probeLines | Where-Object { $_ -match 'pibd=yes' }).Count
    $discovered = @(Get-Content (Join-Path $runDir '02-probe.log') | Where-Object { $_ -like 'DISCOVERED_PEER=*' } |
        ForEach-Object { $_.Substring(16) } | Where-Object { $probeList -notcontains $_ } | Select-Object -First 24)
    Note "  probed=$($probeList.Count) ok=$($probeLines.Count) pibd=$pibdCount discovered=$($discovered.Count)"
    if (($pibdCount -lt 8 -or $probeLines.Count -lt 8) -and $discovered.Count -gt 0) {
        $c = Step '03-probe-gossip' "$exe --mainnet $(($discovered | ForEach-Object { "--probe-peer $_" }) -join ' ')"
        $probeLines += @(Get-Content (Join-Path $runDir '03-probe-gossip.log') | Where-Object { $_ -match '^PROBE_PEER=\S+ OK' })
    }
    Lines '02-probe' '^PROBE_PEER=\S+ OK'
    if (Test-Path (Join-Path $runDir '03-probe-gossip.log')) { Lines '03-probe-gossip' '^PROBE_PEER=\S+ OK' }
    # Peers on the heaviest chain first (total_difficulty from the handshake).
    $ok = @($probeLines | ForEach-Object {
        $p = ($_ -split ' ')[0].Substring(11)
        $td = 0; if ($_ -match 'total_difficulty=(\d+)') { $td = [decimal]$Matches[1] }
        [pscustomobject]@{ Peer = $p; Pibd = ($_ -match 'pibd=yes'); Td = $td }
    } | Sort-Object -Property Td -Descending)
    if ($ok.Count -lt 2) { Stop-Run 'fewer than two public peers answered' }
    Set-Content -Path $peerCache -Value @($ok | ForEach-Object { "$($_.Peer) pibd=$(if ($_.Pibd) { 'yes' } else { 'no' })" }) -Encoding ASCII
    # The probe just connected to all of them: give them a moment to drop it.
    Start-Sleep -Seconds 5
}
# Header sync: four peers from different /16 networks where possible. The
# heaviest valid chain wins; it must be backed by two peers from different
# networks; a peer on another chain is reported and ignored (not fatal).
function Net16($p) { $ip = ($p -split ':')[0]; $o = $ip -split '\.'; if ($o.Count -eq 4) { "$($o[0]).$($o[1])" } else { $ip } }
$syncList = @(); $seenNets = @()
foreach ($x in $ok) { if ($syncList.Count -ge 4) { break }; $n = Net16 $x.Peer; if ($seenNets -notcontains $n) { $syncList += $x.Peer; $seenNets += $n } }
foreach ($x in $ok) { if ($syncList.Count -ge 4) { break }; if ($syncList -notcontains $x.Peer) { $syncList += $x.Peer } }
# Blocks and PIBD segments: PIBD-capable first, peers not used by the header
# sync first (a node refuses a quick reconnect from the same IP; the gap tool
# gives the last peers of the list the block download). Install: up to eight
# peers (about 670 MB to fetch); everyday runs: four (a few blocks).
$installedNow = (Test-Path (Join-Path $stateDir 'state.ust')) -and (Test-Path $walletState)
$gapMax = 4
if (-not $installedNow) { $gapMax = 8 }
$rest = @($ok | Where-Object { $syncList -notcontains $_.Peer })
$gapList = @(@($rest | Where-Object { $_.Pibd } | ForEach-Object { $_.Peer }) + @($rest | Where-Object { -not $_.Pibd } | ForEach-Object { $_.Peer }) + $syncList | Select-Object -Unique | Select-Object -First $gapMax)
$gapPeers = ($gapList | ForEach-Object { "--peer $_" }) -join ' '
$syncPeers = ($syncList | ForEach-Object { "--peer $_" }) -join ' '
Note "  sync_peers=$($syncList -join ',')"
Note "  gap_peers=$($gapList -join ',')"

# 3. -Broadcast: send an already built and inspected transaction --------------------------------
if ($Broadcast) {
    $buildDir = Get-TxFolder
    $txFile = Join-Path $buildDir 'spend-tx.hex'
    $buildLog = Join-Path $buildDir '30-wallet.log'
    if (-not (Test-Path $txFile) -or -not (Test-Path $buildLog)) { Stop-Run "no spend-tx.hex / 30-wallet.log in $buildDir (run -Send first)" }
    Write-Host ""
    Write-Host "=== MAINNET TRANSACTION TO SEND ==="
    Get-Content $buildLog | Where-Object { $_ -match '^GAP_SPEND_(WALLET|INPUT|INPUT_AMOUNT|NEW_OUTPUT|RECEIVER_OUTPUT|AMOUNT_SENT|TO|FEE|KERNEL_EXCESS|TX_VALIDATED)=' } | ForEach-Object { Write-Host "  $_"; Add-Content -Path $summary -Value "  $_" -Encoding ASCII }
    Note ("tx_file=$txFile sha256=" + (Get-FileHash -Algorithm SHA256 $txFile).Hash.ToLower())
    $toLine = Get-Content $buildLog | Where-Object { $_ -like 'GAP_SPEND_TO=*' } | Select-Object -Last 1
    if ($toLine) { Write-Host "PAYMENT to $($toLine.Substring(13)) (amount in GAP_SPEND_AMOUNT_SENT, nanogrin). Peers: $($gapList -join ', ')" }
    else { Write-Host "Self-transfer inside the same wallet; only the fee leaves it. Peers: $($gapList -join ', ')" }
    if (-not $autoSend) {
        $answer = Read-Host 'Type SEND to broadcast this transaction on MAINNET (anything else cancels)'
        if ($answer -cne 'SEND') { Stop-Run 'cancelled by user, nothing was sent' }
    }
    $c = Step '40-broadcast' "$exe --mainnet --broadcast-tx $txFile $gapPeers --allow-mainnet-spend"
    Lines '40-broadcast' '^(BROADCAST|GAP_SPEND)'
    if ($c -ne 0) { Stop-Run 'broadcast failed on every peer' }
    Note "next: after 3-10 blocks (5-20 min) run  .\run_user.ps1 -Confirm"
    Finish
}

# 3b. Own checkpoint from genesis (setting checkpoint_source=own) -------------------------------
# Every header from genesis is checked here (PoW, difficulty, header MMR),
# one peer after another (each continues where the previous stopped); a
# snapshot every 100 000 headers makes it resumable: run the same command
# again after a break. The result must be confirmed by peers from two
# different /16 networks, is compared with public explorers/APIs, and the
# signed release checkpoint (if any) is checked against this own chain.
if ($settings.checkpoint_source -eq 'own') {
    $ownDir = Join-Path $userDir 'own-checkpoint'
    $ownFinal = Join-Path $ownDir 'final'
    $ownPin = Join-Path $ownDir 'pin.txt'
    if ($OwnCheckpoint -or -not (Test-Path $ownPin)) {
        Note '  own checkpoint: checking every header from genesis (resumable; from 30 min to a few hours)'
        if (Test-Path $ownFinal) { Remove-Item -Recurse -Force $ownFinal }
        if (Test-Path $ownPin) { Remove-Item -Force $ownPin }
        $check = ''
        if (Test-Path $accRel) {
            $rt = [IO.File]::ReadAllText($accRel)
            if ($rt -match 'height=(\d+)' ) { $rh = $Matches[1] }
            if ($rt -match 'header_hash=([0-9a-f]{64})') { $check = "--check-header $($rh):$($Matches[1])" }
        }
        $all = @($ok | ForEach-Object { $_.Peer })
        $failPeers = ($all | ForEach-Object { "--peer $_" }) -join ' '
        $confPeers = ($all | ForEach-Object { "--confirm-peer $_" }) -join ' '
        $c = Step '15-own-checkpoint' "$exe --mainnet --checkpoint genesis $failPeers --failover --batches 20000 --digest-run --stop-below-tip 4320 --progress-dir `"$ownDir`" --state-dir `"$ownFinal`" $confPeers $check"
        Lines '15-own-checkpoint' '^(HEADER_SYNC_RESUMED_AT|HEADER_SYNC_STOP_AT|HEADER_SYNC_FAILOVER_ERROR|HEADER_SYNC_PEER_RESULT|HEADER_SYNC_CONFIRM|HEADER_SYNC_CHAIN_SUPPORT|HEADER_SYNC_INDEPENDENT|HEADER_SYNC_CHECK_HEADER|HEADER_SYNC_LAST_HEIGHT|HEADER_SYNC_HEADERS=|HEADER_SYNC_POW|HEADER_SYNC_NETWORK_DIFFICULTY_CHECKED|HEADER_SYNC_MMR|HEADER_SYNC=)'
        $ownLog = Get-Content (Join-Path $runDir '15-own-checkpoint.log')
        if ($c -ne 0 -or -not (Test-Path (Join-Path $ownFinal 'checkpoint.rwm'))) {
            $fail = $ownLog | Where-Object { $_ -like 'HEADER_SYNC=FAIL*' } | Select-Object -Last 1
            Stop-Run "own checkpoint not finished ($fail); run the same command again: it continues from the last snapshot"
        }
        if ($ownLog | Where-Object { $_ -like 'HEADER_SYNC_CHECK_HEADER=MISMATCH*' }) {
            Stop-Run 'WARNING: the signed release checkpoint is NOT on the chain you checked yourself. Do not trust that release; tell the developers.'
        }
        if ($check -and -not ($ownLog | Where-Object { $_ -like 'HEADER_SYNC_CHECK_HEADER=MATCH*' })) { Note '  release checkpoint: not compared (resumed past its height)' }
        elseif ($check) { Note '  release checkpoint: MATCHES your own chain' }
        $c = Step '16-own-crosscheck' "python checkpoint_crosscheck.py --mainnet --checkpoint `"$(Join-Path $ownFinal 'checkpoint.rwm')`" --api grincoin=https://grincoin.org/v2/foreign --api grinnode=https://grinnode.live/v2/foreign --explorer scan=https://scan.grin.money/block/{height} --min-full 0"
        Lines '16-own-crosscheck' '^(CHECKPOINT_|SOURCE=|CROSSCHECK=)'
        if (Select-String -Path (Join-Path $runDir '16-own-crosscheck.log') -Pattern 'MISMATCH' -Quiet) { Stop-Run 'a public source shows another header at this height: check the log before trusting anything' }
        $a1 = (Get-FileHash -Algorithm SHA256 (Join-Path $ownFinal 'checkpoint.rwm')).Hash.ToLower()
        $b1 = (Get-FileHash -Algorithm SHA256 (Join-Path $ownFinal 'recent-headers.bin')).Hash.ToLower()
        Set-Content -Path $ownPin -Value @("built=$stamp", "checkpoint_sha256=$a1", "history_sha256=$b1") -Encoding ASCII
        Note '  own checkpoint ready (the wallet state is kept)'
    }
    $cp = Join-Path $ownFinal 'checkpoint.rwm'
    $hist = Join-Path $ownFinal 'recent-headers.bin'
    $cpSha = (Get-FileHash -Algorithm SHA256 $cp).Hash.ToLower()
    $hiSha = (Get-FileHash -Algorithm SHA256 $hist).Hash.ToLower()
    $pt = Get-Content $ownPin -Raw
    if ($pt -notmatch "checkpoint_sha256=$cpSha" -or $pt -notmatch "history_sha256=$hiSha") { Stop-Run 'own checkpoint files changed since they were built' }
    Note "  checkpoint: OWN (checked from genesis, $((($pt -split "`r?`n")[0]).Substring(6))) checkpoint_sha256=$cpSha"
    # The genesis sync just talked to these peers a lot: let them forget us.
    if ($OwnCheckpoint) { Start-Sleep -Seconds 20 }
}

# 4. Headers from the checkpoint to the tip ------------------------------------------------------
# 3c. Rolling checkpoint: after each verified sync the start moves to
# tip-4320 (aligned to 720), so everyday syncs fetch a few thousand headers
# instead of everything since the shipped one. It stays tied to the base
# (signed release / own) it grew from; another base drops it.
$rollDir = Join-Path $userDir 'rolling'
$rollNew = Join-Path $userDir 'rolling-new'
$rollPin = Join-Path $rollDir 'pin.txt'
$baseSha = $cpSha
if (Test-Path $rollPin) {
    $rp = Get-Content $rollPin -Raw
    $rc = Join-Path $rollDir 'checkpoint.rwm'; $rhf = Join-Path $rollDir 'recent-headers.bin'
    $rcs = (Get-FileHash -Algorithm SHA256 $rc).Hash.ToLower(); $rhs = (Get-FileHash -Algorithm SHA256 $rhf).Hash.ToLower()
    if ($rp -match "root_base=$baseSha" -and $rp -match "checkpoint_sha256=$rcs" -and $rp -match "history_sha256=$rhs") {
        $cp = $rc; $hist = $rhf; $cpSha = $rcs; $hiSha = $rhs
        Note "  checkpoint: rolling, height $(if ($rp -match 'height=(\d+)') { $Matches[1] }) (grown from the base $($baseSha.Substring(0,12))...)"
    } else {
        Note '  rolling checkpoint dropped (other base or changed files)'
        Remove-Item -Recurse -Force $rollDir
    }
}
$cpHeight = 0
if ((Get-Content $cp -TotalCount 2) -join ' ' -match 'height (\d+)') { $cpHeight = [int64]$Matches[1] }
$snapArgs = ''
$lastTip = 0
if (Test-Path $walletState) { $first = Get-Content $walletState -TotalCount 1; if ($first -match '"tip_height":(\d+)') { $lastTip = [int64]$Matches[1] } }
if ($lastTip -gt 0) {
    $rollTarget = [math]::Floor(($lastTip - 4320) / 720) * 720
    if ($rollTarget -ge $cpHeight + 720) {
        if (Test-Path $rollNew) { Remove-Item -Recurse -Force $rollNew }
        $snapArgs = "--snapshot-at $rollTarget --snapshot-dir `"$rollNew`""
    }
}
$c = Step '20-sync' "$grinsight sync --mainnet --checkpoint $cp --checkpoint-sha256 $cpSha --history $hist --history-sha256 $hiSha $syncPeers $snapArgs"
$json = Get-Content -Path (Join-Path $runDir '20-sync.log') | Where-Object { $_.StartsWith('{') } | Select-Object -Last 1
if (-not $json) { Stop-Run 'header sync failed' }
$s = $json | ConvertFrom-Json
Note ("  sync status={0} height={1} age={2}s" -f $s.status, $s.height, $s.tip_age_seconds)
Note ("  chain: support={0} nets={1} tip={2}" -f $s.chain_support, $s.independent_nets, $s.canonical_tip)
foreach ($f in @($s.forks_rejected)) { if ($f) { Note "  fork rejected: $f" } }
if ($s.status -ne 'PASS') { Stop-Run 'header sync is not PASS' }
if ($s.work_ratio) { Note "  work since checkpoint: $($s.work_ratio) of what its difficulty implies (eclipse check)" }
if ($snapArgs -and $s.snapshot -and (Test-Path (Join-Path $rollNew 'checkpoint.rwm'))) {
    $a2 = (Get-FileHash -Algorithm SHA256 (Join-Path $rollNew 'checkpoint.rwm')).Hash.ToLower()
    $b2 = (Get-FileHash -Algorithm SHA256 (Join-Path $rollNew 'recent-headers.bin')).Hash.ToLower()
    Set-Content -Path (Join-Path $rollNew 'pin.txt') -Value @("root_base=$baseSha", "height=$($s.snapshot.height)", "hash=$($s.snapshot.hash)", "checkpoint_sha256=$a2", "history_sha256=$b2", "made=$stamp") -Encoding ASCII
    if (Test-Path $rollDir) { Remove-Item -Recurse -Force $rollDir }
    Move-Item $rollNew $rollDir
    Note "  rolling checkpoint moved to height $($s.snapshot.height) (next syncs start there)"
}
$sess = "--session $($s.session) --session-sha256 $($s.manifest_sha256)"

# 5. Wallet: install (first time) or quick open; optional send build / confirm -------------------
$st = Join-Path $stateDir 'state.ust'
$installed = (Test-Path $st) -and (Test-Path $walletState)
if ($Confirm) {
    if (-not $installed) { Stop-Run 'wallet is not installed yet' }
    $txDir = Get-TxFolder
    $buildLog = Join-Path $txDir '30-wallet.log'
    if (-not (Test-Path $buildLog)) { Stop-Run "no 30-wallet.log in $txDir" }
    $sp = @{}
    $more = @()
    Get-Content $buildLog | Where-Object { $_ -match '^GAP_SPEND_(INPUT|NEW_OUTPUT|RECEIVER_OUTPUT|EXTRA_INPUT|KERNEL_EXCESS)=' } | ForEach-Object {
        $k, $v = $_ -split '=', 2
        if ($k -in 'GAP_SPEND_RECEIVER_OUTPUT', 'GAP_SPEND_EXTRA_INPUT') { if ($more -notcontains $v) { $more += $v } } else { $sp[$k] = $v }
    }
    if (-not $sp['GAP_SPEND_INPUT'] -or -not $sp['GAP_SPEND_NEW_OUTPUT'] -or -not $sp['GAP_SPEND_KERNEL_EXCESS']) { Stop-Run 'spend details not found in the build log' }
    Note "  confirm input=$($sp['GAP_SPEND_INPUT']) new=$($sp['GAP_SPEND_NEW_OUTPUT']) kernel=$($sp['GAP_SPEND_KERNEL_EXCESS'])"
    $args3 = "--commitment $($sp['GAP_SPEND_INPUT']) --commitment $($sp['GAP_SPEND_NEW_OUTPUT']) --kernel $($sp['GAP_SPEND_KERNEL_EXCESS'])"
    foreach ($m in $more) { $args3 += " --commitment $m"; Note "  confirm also=$m" }
    # A confirmation from an earlier run counts only if its block (height AND
    # hash) is still on the chain verified in THIS run (a reorg can remove it).
    $confirmed = Join-Path $userDir 'confirmed-kernels.txt'
    $kx = $sp['GAP_SPEND_KERNEL_EXCESS']
    $prev = $null
    if (Test-Path $confirmed) { $prev = Get-Content $confirmed | Where-Object { $_ -like "$kx *" } | Select-Object -Last 1 }
    $prevBlock = $null
    if ($prev) { $pf = $prev -split ' '; if ($pf.Count -ge 4 -and $pf[2] -match '^[0-9a-f]{64}$') { $prevBlock = "$($pf[1]):$($pf[2])"; $args3 += " --check-block $prevBlock" } }
    $c = Step '30-wallet' "$grinsight gap --mainnet $sess --segment-height 13 $args3 $gapPeers --prove --state-dir $stateDir --seeds $seeds --pending $pendingFile --wallet-in $walletState --wallet-out $walletState --timeout 3600"
    Lines '30-wallet' '^(GAP_KERNEL|GAP_BLOCK_CHECK|GAP_PROVE_KERNEL_FOUND|GAP_PROVE_COMMIT|GAP_START_SOURCE|GAP_TIP_HEIGHT|GAP_BLOCKS=|GAP_WALLET|GAP_STATE_SAVED|GAP=FAIL)'
    $fail = Select-String -Path (Join-Path $runDir '30-wallet.log') -Pattern '^GAP=FAIL' -Quiet
    if (($c -notin 0, 3, 5) -or $fail) { Stop-Run 'confirm failed' }
    # A later -Confirm only scans blocks after the saved state, so a kernel
    # confirmed by an earlier run is "not in range": the earlier block (height
    # + hash) is re-checked against the chain verified now (see above).
    $log30 = Join-Path $runDir '30-wallet.log'
    $found = Get-Content $log30 | Where-Object { $_ -like "GAP_KERNEL=$kx FOUND height=*" } | Select-Object -First 1
    if ($found) {
        $h = ($found -split 'height=')[1].Split(' ')[0]
        $hh = if ($found -match 'hash=([0-9a-f]{64})') { $Matches[1] } else { '-' }
        Add-Content -Path $confirmed -Value "$kx $h $hh $stamp" -Encoding ASCII
        Note "CONFIRMED: kernel in block $h ($hh)"
    } elseif ($prevBlock) {
        $chk = Get-Content $log30 | Where-Object { $_ -like "GAP_BLOCK_CHECK=$prevBlock *" } | Select-Object -First 1
        $ph = ($prevBlock -split ':')[0]
        if ($chk -match 'ON_VERIFIED_CHAIN depth=(\d+)' -and $chk -notmatch 'NOT_ON') { Note "CONFIRMED earlier: kernel in block $ph, still on the verified chain (depth $($Matches[1]))" }
        elseif ($chk -match 'NOT_ON_VERIFIED_CHAIN') { Note "NOT CONFIRMED: block $ph of the earlier confirmation is no longer on the verified chain (reorg); the transaction may be back in the pool or dropped - check again later" }
        elseif ($chk -match 'BELOW_VERIFIED_RANGE') { Note "CONFIRMED earlier: kernel in block $ph, deeper than the verified session (not re-checked; a reorg that deep is not expected)" }
        else { Note "NOT CONFIRMED: the earlier confirmation (block $ph) could not be re-checked ($chk)" }
    } elseif ($prev) {
        Note "NOT RE-VERIFIED: the earlier confirmation (block $(($prev -split ' ')[1])) has no block hash (old record), so a reorg cannot be ruled out; not counted as confirmed"
    } else { Note 'NOT CONFIRMED yet: kernel not in the scanned blocks (try again in a few minutes)' }
    Show-Pending
    Finish
}

$spendArgs = ''
if ($SendTo) {
    $nano = To-Nano $Amount
    $toWallet = $null
    if ($SendTo -match '^wallet:(\d+)$') { $toWallet = $Matches[1] }
    $dest = Resolve-Address $SendTo
    $spendArgs = "--spend auto:$Wallet --send-to $dest --send-amount $nano --slatepack-out $(Join-Path $runDir 'slatepack-s1.txt') --context-out $(Join-Path $runDir 'send-context.json') --allow-mainnet-spend"
    Note "  PAYMENT START: wallet $Wallet pays $Amount GRIN ($nano nanogrin) to $dest; nothing will be sent to the network"
}
if ($PayInvoice) {
    # An inbox invoice moves to inbox\paid only AFTER the daemon reports the
    # answer DELIVERED (status DONE...). Until then it stays in the inbox, so
    # a repeated  -PayInvoice inbox  finds it and resends the SAME answer.
    function Wait-Reply($folder) {
        $st = Join-Path $folder 'AUTO_STATUS.txt'
        $t0 = Get-Date
        $line = ''
        while (((Get-Date) - $t0).TotalSeconds -lt 180) {
            if (Test-Path $st) {
                $line = (Get-Content $st -Raw).Trim()
                if ($line -and $line -ne 'DISPATCHED') { break }
            }
            Start-Sleep -Seconds 3
        }
        return $line
    }
    function Move-InvoicePaid($file, $peerFile) {
        $paidDir = Join-Path $userDir "tor-wallet-$Wallet\inbox\paid"
        New-Item -ItemType Directory -Force -Path $paidDir | Out-Null
        Move-Item -Force $file $paidDir
        if (Test-Path $peerFile) { Move-Item -Force $peerFile $paidDir }
    }
    function Finish-Reply($folder, $file, $peerFile) {
        $line = Wait-Reply $folder
        if ($line -like 'DONE*') {
            Note "  daemon: $line"
            if ($file) { Move-InvoicePaid $file $peerFile; Note '  invoice moved to inbox\paid' }
        } else {
            if ($line) { Note "  daemon: $line" } else { Note '  daemon: no result yet (see -TorStatus)' }
            if ($file) { Note '  the invoice STAYS in the inbox (answer not confirmed as delivered): run  -PayInvoice inbox -Tor  again to resend the same answer' }
        }
    }
    $fb = $null
    if (Test-Path $lastTx) { $fb = Join-Path (Get-Content $lastTx -TotalCount 1).Trim() 'invoice-i1.txt' }
    $inv = Join-Path $runDir 'invoice-in.txt'
    $invPeer = $null
    if ($PayInvoice -eq 'inbox') {
        # Invoices that came over the messenger (the daemon never pays them).
        $ib = Join-Path $userDir "tor-wallet-$Wallet\inbox"
        $invFile = Get-ChildItem -Path $ib -Filter 'invoice-*.txt' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
        if (-not $invFile) { Stop-Run "no invoice in $ib" }
        Note "  invoice from the inbox: $($invFile.FullName)"
        $pf = [IO.Path]::ChangeExtension($invFile.FullName, '.peer')
        if (Test-Path $pf) { $invPeer = (Get-Content $pf -TotalCount 1).Trim(); Note "  sent by (signed envelope): $invPeer" }
        Copy-Item $invFile.FullName $inv
        # Already paid by this wallet (answer built, not sent yet): send that
        # answer again instead of paying twice.
        $invSid = $invFile.BaseName.Substring(8)
        $paidBefore = (Test-Path $pendingFile) -and (
            (Select-String -Path $pendingFile -SimpleMatch "`"kind`":`"change`",`"wallet`":$Wallet,`"slate_id`":`"$invSid`"" -Quiet) -or
            (Select-String -Path $pendingFile -SimpleMatch "`"kind`":`"payment`",`"what`":`"invoice`",`"wallet`":$Wallet,`"slate_id`":`"$invSid`"" -Quiet))
        if ($paidBefore) {
            $prevRun = Get-ChildItem -Directory (Join-Path $PSScriptRoot 'evidence') -Filter 'user-run-*' | Sort-Object Name -Descending |
                Where-Object { (Test-Path (Join-Path $_.FullName 'invoice-i2.txt')) -and (Select-String -Path (Join-Path $_.FullName '30-wallet.log') -SimpleMatch "PAY_INVOICE_SLATE_ID=$invSid" -Quiet) } | Select-Object -First 1
            if (-not $prevRun) { Stop-Run "invoice $invSid is already paid by wallet $Wallet, but its answer was not found" }
            Note "  already paid in $($prevRun.Name): sending that answer (paying twice would spend the same coins)"
            $resend = Join-Path $prevRun.FullName 'invoice-i2.txt'
            if (-not $Tor) { Give-Slatepack $resend 'GIVE THIS ANSWER BACK TO THE ISSUER'; Finish }
            $target = if ($Messenger) { Resolve-Messenger $Messenger } else { $invPeer }
            if (-not $target) { Stop-Run 'no messenger address of the issuer (-Messenger grin1...|wallet:N)' }
            $w30 = Get-Content (Join-Path $prevRun.FullName '30-wallet.log')
            $amt = ($w30 | Where-Object { $_ -like 'PAY_INVOICE_AMOUNT=*' } | Select-Object -First 1).Substring(19)
            Write-Host ""
            Write-Host "PAYMENT on MAINNET: $([decimal]$amt / 1000000000) GRIN to the issuer of invoice $invSid ($target)."
            Write-Host 'Sending this answer lets the issuer finalize and broadcast: the money leaves this wallet.'
            $answer = Read-Host 'Type PAY to send the answer over the messenger (anything else: keep it for manual use)'
            if ($answer -cne 'PAY') { Note '  answer not sent; the invoice stays in the inbox'; Finish }
            Build-Tor
            $c = Step '45-queue' "$torExe queue --user-dir `"$userDir`" --wallet $Wallet --kind reply --slate-id $invSid --to $target --armor `"$resend`" --context - --tx-folder `"$runDir`" --messenger $target --messenger-only"
            if ($c -ne 0) { Stop-Run 'could not queue the answer' }
            Finish-Reply $runDir $invFile.FullName $pf
            Note 'next: the issuer finalizes and broadcasts; then  .\run_user.ps1 -Confirm'
            Finish
        }
    } else {
        Set-Content -Path $inv -Value (Read-Slatepack $PayInvoice $fb 'invoice') -Encoding ASCII -NoNewline
    }
    $spendArgs = "--spend auto:$Wallet --pay-invoice $inv --slatepack-out $(Join-Path $runDir 'invoice-i2.txt') --allow-mainnet-spend"
    Note "  PAY INVOICE: wallet $Wallet; nothing will be sent to the network (the issuer broadcasts)"
}
if ($Send) {
    $spendArgs = "--spend auto:$Wallet --tx-out $(Join-Path $runDir 'spend-tx.hex') --allow-mainnet-spend"
    Note "  SEND BUILD ONLY: wallet $Wallet, largest own output, nothing will be sent"
}
if ($installed) {
    $mode = 'QUICK'
    $walletArgs = "--wallet-in $walletState --wallet-out $walletState"
} else {
    $mode = 'INSTALL'
    $walletArgs = "--wallet-out $walletState"
    Note '  first run on this computer: install (archive rebuild + full rangeproof scan)'
}
Note "  wallet_mode=$mode"
$c = Step '30-wallet' "$grinsight gap --mainnet $sess --segment-height 13 --commitment $probeCommitment $gapPeers --prove --state-dir $stateDir --seeds $seeds --pending $pendingFile $walletArgs --timeout 7200 $spendArgs"
if ($mode -eq 'QUICK' -and (Select-String -Path (Join-Path $runDir '30-wallet.log') -Pattern '^GAP_WALLET_STALE=' -Quiet)) {
    Note '  saved wallet is older than the saved state: full scan once'
    $mode = 'INSTALL'
    Move-Item (Join-Path $runDir '30-wallet.log') (Join-Path $runDir '30-wallet-stale.log')
    $c = Step '30-wallet' "$grinsight gap --mainnet $sess --segment-height 13 --commitment $probeCommitment $gapPeers --prove --state-dir $stateDir --seeds $seeds --pending $pendingFile --wallet-out $walletState --timeout 7200 $spendArgs"
}
Lines '30-wallet' '^(GAP_INSTALL|GAP_WALLET_EARLY|GAP_PROVE_SEGMENTS_SECONDS|GAP_SCAN_RPROOF_SECONDS|GAP_WALLET_SOURCE|GAP_WALLET_NEW_BLOCKS_SCANNED|GAP_START_SOURCE|GAP_ARCHIVE_HEIGHT|GAP_TIP_HEIGHT|GAP_BLOCKS=|GAP_BLOCKS_SECONDS|GAP_PEER_BLOCKS|GAP_PROVE_SEGMENT_PEER|GAP_PROVE_DOWNLOAD_BYTES|GAP_SCAN_RPROOF_(BYTES|SECONDS|CHECKED)|GAP_WALLET|GAP_STATE_SAVED|GAP=FAIL)'
$fail = Select-String -Path (Join-Path $runDir '30-wallet.log') -Pattern '^GAP=FAIL' -Quiet
if (($c -notin 0, 3, 5) -or $fail) { Stop-Run 'wallet update failed' }
Copy-Item $walletState (Join-Path $runDir 'wallet-outputs.jsonl') -Force
Note "  wallet_mode_done=$mode"
Show-Pending
if ($SendTo) {
    Lines '30-wallet' '^(SEND|GAP_SPENDABLE)'
    $s1File = Join-Path $runDir 'slatepack-s1.txt'
    if (-not (Test-Path $s1File)) { Stop-Run 'payment slatepack was not built' }
    $s1 = (Get-Content $s1File -Raw).Trim()
    Write-Host ""
    Write-Host "=== GIVE THIS SLATEPACK TO THE RECEIVER ==="
    Write-Host $s1
    Write-Host "==========================================="
    try { Set-Clipboard -Value $s1; Note '  slatepack copied to the clipboard' } catch { }
    Set-Content -Path $lastTx -Value $runDir -Encoding ASCII
    if ($Tor) {
        $sid = (Get-Content (Join-Path $runDir '30-wallet.log') | Where-Object { $_ -like 'SEND_SLATE_ID=*' } | Select-Object -First 1).Substring(14)
        $sf = Join-Path $userDir "tor-wallet-$Wallet\status.json"
        if (-not (Test-Path $sf)) { Stop-Run "the Tor daemon of wallet $Wallet is not running (.\run_user.ps1 -TorStart -Wallet $Wallet); the slatepack above can still be given by hand" }
        Write-Host ""
        Write-Host "AUTOMATIC PAYMENT on MAINNET: $Amount GRIN to $dest."
        Write-Host 'The daemon delivers it, receives the answer, finalizes and broadcasts without asking again.'
        $answer = Read-Host 'Type SEND to let it go (anything else: keep the slatepack for manual use)'
        if ($answer -cne 'SEND') { Note '  not sent automatically; the slatepack above can be given by hand'; Finish }
        $msgArg = ''
        if ($Messenger) { $msgArg = "--messenger $(Resolve-Messenger $Messenger)" }
        elseif ($ViaMessenger -and $SendTo -match '^wallet:') { $msgArg = "--messenger $(Resolve-Messenger $SendTo)" }
        if ($ViaMessenger) { $msgArg += ' --messenger-only'; Note "  route: GrinMessenger envelope only ($msgArg)" }
        $c = Step '45-queue' "$torExe queue --user-dir `"$userDir`" --wallet $Wallet --kind send --slate-id $sid --to $dest --slate-json `"$(Join-Path $runDir 'slatepack-s1.json')`" --armor `"$(Join-Path $runDir 'slatepack-s1.txt')`" --context `"$(Join-Path $runDir 'send-context.json')`" --tx-folder `"$runDir`" $msgArg"
        if ($c -ne 0) { Stop-Run 'could not queue the payment' }
        Note '  queued; waiting for the daemon (up to 5 min)...'
        $st = Join-Path $runDir 'AUTO_STATUS.txt'
        $t0 = Get-Date
        while (((Get-Date) - $t0).TotalSeconds -lt 300) {
            Start-Sleep -Seconds 5
            if (Test-Path $st) {
                $line = (Get-Content $st -Raw).Trim()
                if ($line -notlike 'SENT via messenger*') { break }
            }
        }
        if (Test-Path $st) { Note "  daemon: $((Get-Content $st -Raw).Trim())" } else { Note '  daemon: no answer yet (see -TorStatus); the run folder gets AUTO_STATUS.txt when done' }
        if (Test-Path (Join-Path $runDir 'AUTO_RESULT.txt')) { Get-Content (Join-Path $runDir 'AUTO_RESULT.txt') | ForEach-Object { Note "  $_" } }
        Note 'next: after 3-10 blocks (5-20 min)  .\run_user.ps1 -Confirm'
        Finish
    }
    if ($toWallet) { Note "next (test bench, wallet $toWallet receives):  .\run_user.ps1 -Receive clipboard -Wallet $toWallet" }
    else { Note 'next: give the slatepack to the receiver; put its answer in the clipboard' }
    Note 'then:  .\run_user.ps1 -Finalize'
}
if ($PayInvoice) {
    Lines '30-wallet' '^(PAY_INVOICE|GAP_SPENDABLE)'
    $i2 = Join-Path $runDir 'invoice-i2.txt'
    if (-not (Test-Path $i2)) { Stop-Run 'invoice was not paid (see the log)' }
    Give-Slatepack $i2 'GIVE THIS ANSWER BACK TO THE ISSUER'
    Set-Content -Path (Join-Path $userDir 'last-answer.txt') -Value $i2 -Encoding ASCII
    # By hand: the answer is shown above (the user delivers it).
    if (-not $Tor -and $PayInvoice -eq 'inbox') { Move-InvoicePaid $invFile.FullName $pf }
    if ($Tor) {
        $target = if ($Messenger) { Resolve-Messenger $Messenger } else { $invPeer }
        if (-not $target) { Stop-Run 'no messenger address of the issuer (-Messenger grin1...|wallet:N); the answer above can still be given by hand' }
        $w30 = Get-Content (Join-Path $runDir '30-wallet.log')
        $sid = ($w30 | Where-Object { $_ -like 'PAY_INVOICE_SLATE_ID=*' } | Select-Object -First 1).Substring(21)
        $amt = ($w30 | Where-Object { $_ -like 'PAY_INVOICE_AMOUNT=*' } | Select-Object -First 1).Substring(19)
        Write-Host ""
        Write-Host "PAYMENT on MAINNET: $([decimal]$amt / 1000000000) GRIN to the issuer of invoice $sid ($target)."
        Write-Host 'Sending this answer lets the issuer finalize and broadcast: the money leaves this wallet.'
        $answer = Read-Host 'Type PAY to send the answer over the messenger (anything else: keep it for manual use)'
        if ($answer -cne 'PAY') { Note '  answer not sent; it can be given by hand'; Finish }
        Build-Tor
        $c = Step '45-queue' "$torExe queue --user-dir `"$userDir`" --wallet $Wallet --kind reply --slate-id $sid --to $target --armor `"$i2`" --context - --tx-folder `"$runDir`" --messenger $target --messenger-only"
        if ($c -ne 0) { Stop-Run 'could not queue the answer' }
        $invPath = if ($PayInvoice -eq 'inbox') { $invFile.FullName } else { $null }
        Finish-Reply $runDir $invPath $pf
        Note 'next: the issuer finalizes and broadcasts; then  .\run_user.ps1 -Confirm  on the issuer side'
        Finish
    }
    Note 'next (test bench, the issuer is a wallet here):  .\run_user.ps1 -Finalize'
}
if ($Send) {
    Lines '30-wallet' '^GAP_SPEND_'
    if (-not (Test-Path (Join-Path $runDir 'spend-tx.hex'))) { Stop-Run 'spend transaction was not built' }
    Set-Content -Path $lastTx -Value $runDir -Encoding ASCII
    Note "next (only if the transaction above is what you want):  .\run_user.ps1 -Broadcast"
}
Finish
