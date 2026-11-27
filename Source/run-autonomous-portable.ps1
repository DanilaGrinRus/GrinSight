# Run on Windows with Windows PowerShell 5.1 after the three release builds.
param(
    [Parameter(Mandatory)][string]$BaseExe,
    [Parameter(Mandatory)][string]$WindowExe,
    [Parameter(Mandatory)][string]$ChainExe,
    [Parameter(Mandatory)][string]$HostExe,
    [Parameter(Mandatory)][string]$OutputDir,
    [string]$MailboxExe,
    [string]$OnionExe
)
$ErrorActionPreference = 'Stop'
$version = '0.4.7A'
$name = "GrinSight-$version-windows-x64-portable"
$expected = '49ccfde95da8d5199761cbd0f48949cc6a05cb9d2cf4d3bfbb72028a10d7d7f8'
$baseline = (Resolve-Path -LiteralPath $BaseExe).Path
$baseBytes = [IO.File]::ReadAllBytes($baseline)
$sha = [Security.Cryptography.SHA256]::Create()
try { $baseHash = [BitConverter]::ToString($sha.ComputeHash($baseBytes)).Replace('-','') }
finally { $sha.Dispose() }
if ($baseHash -ne $expected) { throw 'Unexpected 0.4.6 executable.' }
$workName = 'build-047A-' + [guid]::NewGuid().ToString('N').Substring(0,20)
$work = Join-Path (Split-Path $PSScriptRoot -Parent) $workName
$tree = Join-Path $work 'GrinSight'
[void][IO.Directory]::CreateDirectory((Join-Path $tree 'bin'))
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$allowed = @('GrinSight.exe','README.txt','LICENSE-GPL-3.0.txt','SHA256SUMS.txt','bin\fly-chain.exe',
    'bin\fly-mailbox.exe','bin\fly-paycore-host.exe','bin\fly-onion.exe','bin\lyrebird.exe','LICENSE-lyrebird.txt')
$found = @{}
if ([bool]$MailboxExe -ne [bool]$OnionExe) { throw 'Supply both transport programs together.' }
$source = [Reflection.Assembly]::Load([byte[]]$baseBytes).GetManifestResourceStream('runtime.zip')
$old = [IO.Compression.ZipArchive]::new($source,[IO.Compression.ZipArchiveMode]::Read)
try {
    foreach ($entry in $old.Entries) {
        $pieces = $entry.FullName.Replace('/','\').Split(@([char]92),2)
        if ($pieces.Count -ne 2) {throw 'Missing ZIP root'}
        $rel = $pieces[1]
        if ($rel -cnotin $allowed -or $found.ContainsKey($rel)) {throw 'Unexpected or duplicate component'}
        $found[$rel] = $true
        if ($rel -in @('GrinSight.exe','bin\fly-chain.exe','bin\fly-paycore-host.exe','SHA256SUMS.txt')) {continue}
        if ($MailboxExe -and $rel -in @('bin\fly-mailbox.exe','bin\fly-onion.exe')) {continue}
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry,(Join-Path $tree $rel))
    }
} finally { $old.Dispose(); $source.Dispose() }
foreach ($rel in $allowed) { if (!$found.ContainsKey($rel)) { throw "Missing $rel" } }
$licenses = foreach ($font in 'Inter','DejaVu','WalletCJK') {
    $font + [Environment]::NewLine + [IO.File]::ReadAllText((Join-Path $PSScriptRoot "ui\app\fonts\LICENSE-$font.txt"))
}
[IO.File]::WriteAllText((Join-Path $tree 'FONT-LICENSES.txt'), ($licenses -join ([Environment]::NewLine * 2)))
$allowed += 'FONT-LICENSES.txt'
Copy-Item -LiteralPath $WindowExe -Destination (Join-Path $tree 'GrinSight.exe')
Copy-Item -LiteralPath $ChainExe -Destination (Join-Path $tree 'bin\fly-chain.exe')
Copy-Item -LiteralPath $HostExe -Destination (Join-Path $tree 'bin\fly-paycore-host.exe')
if ($MailboxExe) {
    Copy-Item -LiteralPath $MailboxExe -Destination (Join-Path $tree 'bin\fly-mailbox.exe')
    Copy-Item -LiteralPath $OnionExe -Destination (Join-Path $tree 'bin\fly-onion.exe')
}
# README is specific to this candidate. Keep inherited notices and licenses in the package.
$readme = Join-Path $tree 'README.txt'
$legacyReadme = [IO.File]::ReadAllText($readme)
[IO.File]::WriteAllText($readme,("GrinSight 0.4.7A - Windows x64 portable wallet." + [Environment]::NewLine +
    "A new Mainnet profile starts from the built-in checkpoint and checks the bundled history sample." + [Environment]::NewLine +
    "You can also check the headers from network genesis. After a successful check the wallet can resume from its local checkpoint." + [Environment]::NewLine +
    "Wallet Settings contains checkpoint import, export, verification from the first block, and the wallet output scan. Each action has a help button." + [Environment]::NewLine +
    "To move a checkpoint, save one .gshp file in Settings, then select it on the receiving wallet. For an older two-file export, select checkpoint.json with history.proof alongside it. Unlock after import to continue from the verified checkpoint." + [Environment]::NewLine +
    "Chain freshness and payment confirmation are checked separately." + [Environment]::NewLine +
    "When sending a payment or issuing an invoice, keep the wallet open and unlocked until the exchange finishes. After a restart, check unfinished payments before starting a new exchange. A saved final transaction can be sent again." + [Environment]::NewLine +
    "Inherited 0.4.6 distribution notes:" + [Environment]::NewLine + $legacyReadme))
$catalog = foreach ($rel in ($allowed | Sort-Object)) {
    if ($rel -ne 'SHA256SUMS.txt') {
        (Get-FileHash -LiteralPath (Join-Path $tree $rel)).Hash.ToLowerInvariant() + '  ' + $rel.Replace('\','/')
    }
}
[IO.File]::WriteAllLines((Join-Path $tree 'SHA256SUMS.txt'),[string[]]$catalog)
$zipFile = Join-Path $work "$name.zip"
$archive = [IO.Compression.ZipFile]::Open($zipFile,[IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($rel in ($allowed | Sort-Object)) {
        [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,(Join-Path $tree $rel),('GrinSight/'+$rel.Replace('\','/')))
    }
} finally { $archive.Dispose() }
[IO.File]::WriteAllText((Join-Path $work 'SHA256SUMS.txt'),((Get-FileHash -LiteralPath $zipFile).Hash.ToLowerInvariant() + "  $name.zip"))
$lines = @(& (Join-Path $PSScriptRoot 'run-onefile.ps1') -Version $version -Release $workName)
$result = @($lines | Where-Object { $_ -like 'ONEFILE=*' })
if ($result.Count -ne 1) { throw 'No unambiguous portable executable produced.' }
[void][IO.Directory]::CreateDirectory($OutputDir)
$exe = Join-Path $OutputDir "$name.exe"
[IO.File]::Copy($result[0].Substring(8),$exe,$false)
Write-Output ("PACKAGED=" + $exe)
