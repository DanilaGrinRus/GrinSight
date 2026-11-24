# GrinSight: fetches the official Tor Expert Bundle (the programs for Tor bridges: lyrebird and
# its kin, and Tor Browser's list of built-in bridges) and checks it before anything is used.
# THIS ONE DOWNLOADS: one archive and its list of checksums from https://dist.torproject.org,
# and, when gpg is on this computer, the Tor Browser developers' signing key from keys.openpgp.org.
#   powershell -ExecutionPolicy Bypass -File C:\DHW\GrinFlySight\core-v0.2\get-tor-bridge-programs.ps1
# Nothing is run from the archive here. Result: C:\DHW\dist\tor-expert-bundle\<version>\<platform>\
param(
    [string]$Version = '16.0.1',
    [string]$Platform = 'windows-x86_64',
    [string]$Store = 'C:\DHW\dist\tor-expert-bundle'
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# SHA-256 of the archives this project was built with. An archive that differs is refused.
$pinned = @{
    'windows-x86_64-16.0.1'  = '9eed3c3ff1fe43df034ce360196c9ec95472560d77ff55614d0cd5120edea27b'
    'linux-x86_64-16.0.1'    = '7039cb16060ab22e669852e55774d894b55f25ea8bd0ab7194d3478429a58725'
    'linux-aarch64-16.0.1'   = '67040520d44c87ccaaf5aa7df0dc1ff122eb938dbb600ae7722e8b6b75282a4b'
    'macos-aarch64-16.0.1'   = '0b7d022017c31e3f972d06465bcd7ac50feb66ac825547419a934914fe4bb156'
    'macos-x86_64-16.0.1'    = '15464d99adc3bb4de1308260d79878336b04a1ac1aeff83e10f192de7d235946'
    'android-aarch64-16.0.1' = '0091927b9fd72992a88021d55416b23a8380dc39a70c4b73a2cca9ee6a3dbcec'
    'android-armv7-16.0.1'   = 'dc41baf7fcd23eca898085fa1833c9cb7fd3c4ce0018972d509e17f588de998f'
    'android-x86_64-16.0.1'  = 'cdb1b567ffe8f93ed21b5a8ca3cc72571387e8cf16055ce76084bb81ddc56674'
}
# The key Tor Browser releases are signed with (torbrowser@torproject.org).
$signer = 'EF6E286DDA85EA2A4BA7DE684E2C6E8793298290'

$name = "tor-expert-bundle-$Platform-$Version.tar.gz"
$base = "https://dist.torproject.org/torbrowser/$Version"
$dir = Join-Path (Join-Path $Store $Version) $Platform
$archive = Join-Path $dir $name
$sums = Join-Path $dir 'sha256sums-signed-build.txt'
$out = Join-Path $dir 'files'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
function Say($text) { Write-Host $text }
function Fetch($url, $to) {
    if (Test-Path -LiteralPath $to) { Say "already here: $to"; return }
    Say "downloading $url"
    $part = "$to.part"
    Invoke-WebRequest -Uri $url -OutFile $part -UseBasicParsing
    Move-Item -LiteralPath $part -Destination $to -Force
}
Fetch "$base/$name" $archive
Fetch "$base/sha256sums-signed-build.txt" $sums
$size = (Get-Item -LiteralPath $archive).Length
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLower()
Say "archive: $name  bytes: $size"
Say "sha256:  $hash"

# 1. the list of checksums published next to the archive names this very file
$line = Select-String -LiteralPath $sums -Pattern ([regex]::Escape($name) + '$') | Select-Object -First 1
if (-not $line) { Say "REFUSED: $name is not in the published list of checksums"; exit 2 }
$listed = ($line.Line -split '\s+')[0].ToLower()
if ($listed -ne $hash) { Say "REFUSED: the checksum differs from the published one ($listed)"; exit 2 }
Say "checksum: the same as in the published list"

# 2. the checksum this project pinned, once there is one
$key = "$Platform-$Version"
if ($pinned.ContainsKey($key)) {
    if ($pinned[$key] -ne $hash) { Say "REFUSED: the checksum differs from the pinned one"; exit 2 }
    Say "pinned:   the same as pinned in this script"
} else {
    Say "pinned:   nothing pinned yet for $key"
}

# 3. the signature on the list, when gpg is here. Not having gpg is said, not hidden.
$gpg = $null
foreach ($c in @('gpg.exe', 'C:\Program Files\Git\usr\bin\gpg.exe', 'C:\Program Files (x86)\GnuPG\bin\gpg.exe')) {
    $found = Get-Command $c -ErrorAction SilentlyContinue
    if ($found) { $gpg = $found.Source; break }
}
$signature = 'not checked: no gpg on this computer'
if ($gpg) {
    try {
        $asc = "$sums.asc"
        Fetch "$base/sha256sums-signed-build.txt.asc" $asc
        $keyFile = Join-Path $dir 'tor-browser-developers.asc'
        Fetch "https://keys.openpgp.org/vks/v1/by-fingerprint/$signer" $keyFile
        $home2 = Join-Path $dir 'gnupg'
        New-Item -ItemType Directory -Force -Path $home2 | Out-Null
        # the gpg that comes with Git reads a folder only in its own spelling (/c/...)
        if ($gpg -like '*\Git\*' -and $home2 -match '^[A-Za-z]:\\') {
            $home2 = '/' + $home2.Substring(0, 1).ToLower() + $home2.Substring(2).Replace('\', '/')
        }
        # gpg writes its remarks to the error stream: they are not failures of this script
        $ErrorActionPreference = 'Continue'
        # --no-autostart: gpg starts no helper of its own (a helper left running keeps
        # this script's output open and whoever waits for it never sees it end)
        & $gpg --batch --quiet --no-autostart --homedir $home2 --import $keyFile 2>$null | Out-Null
        $status = & $gpg --batch --no-autostart --homedir $home2 --status-fd 1 --verify $asc $sums 2>$null
        $conf = Join-Path (Split-Path -Parent $gpg) 'gpgconf.exe'
        if (Test-Path -LiteralPath $conf) { & $conf --homedir $home2 --kill all 2>$null | Out-Null }
        $ErrorActionPreference = 'Stop'
        Say "gpg: $gpg"
        $valid = $status | Where-Object { $_ -match '^\[GNUPG:\] VALIDSIG ' } | Select-Object -First 1
        if ($valid -and ($valid -split ' ')[-1] -eq $signer) { $signature = "good, made with a key of $signer" }
        elseif ($valid) { $signature = 'NOT ACCEPTED: signed by another key' }
        elseif ($status | Where-Object { $_ -match '^\[GNUPG:\] BADSIG ' }) { $signature = 'NOT ACCEPTED: gpg says the signature is bad' }
        elseif ($status | Where-Object { $_ -match '^\[GNUPG:\] NO_PUBKEY ' }) { $signature = 'not checked: gpg did not take the key' }
        else { $signature = 'not checked: gpg gave no verdict (' + (@($status).Count) + ' lines)' }
    } catch {
        $signature = 'not checked: ' + $_.Exception.Message
    }
}
Say "signature of the list: $signature"
if ($signature -like 'NOT ACCEPTED*') { exit 2 }

# unpack (Windows' own tar), into a fresh folder
if (Test-Path -LiteralPath $out) {
    Say "already unpacked: $out"
} else {
    $fresh = "$out.part"
    if (Test-Path -LiteralPath $fresh) { Remove-Item -LiteralPath $fresh -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $fresh | Out-Null
    & "$env:SystemRoot\System32\tar.exe" -xzf $archive -C $fresh
    if ($LASTEXITCODE -ne 0) { Say "REFUSED: the archive did not unpack"; exit 2 }
    Move-Item -LiteralPath $fresh -Destination $out
}
Say "files:"
Get-ChildItem -LiteralPath $out -Recurse -File | ForEach-Object { Say ("  {0,10}  {1}" -f $_.Length, $_.FullName.Substring($out.Length + 1)) }
Say "done: $out"
exit 0
