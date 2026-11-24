# Wrap the published Windows portable ZIP without rebuilding the wallet.
param([ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version = '0.4.3')
$ErrorActionPreference = 'Stop'
$project = Split-Path $PSScriptRoot -Parent
$release = Join-Path $project 'releases'
$baseName = "GrinSight-$Version-windows-x64-portable"
$source = Join-Path $release "$baseName.zip"
$zipHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
$pin = @(Get-Content -LiteralPath (Join-Path $release 'SHA256SUMS.txt') |
    Where-Object { $_ -match ('^[0-9a-fA-F]{64}\s+\*?' + [regex]::Escape("$baseName.zip") + '$') })
if ($pin.Count -ne 1 -or $pin[0].Substring(0,64) -ne $zipHash) { throw 'Published ZIP checksum mismatch.' }
$dist = Join-Path (Split-Path $project -Parent) 'dist'
$out = Join-Path $dist ('onefile-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($out)
$catalog = Join-Path $out 'runtime.catalog'
$lines = [Collections.Generic.List[string]]::new()
$lines.Add($zipHash)
$required = @('GrinSight.exe','README.txt','LICENSE-GPL-3.0.txt','SHA256SUMS.txt',
    'bin\fly-chain.exe','bin\fly-mailbox.exe','bin\fly-paycore-host.exe')
$allowed = $required + @('bin\fly-onion.exe','bin\lyrebird.exe','LICENSE-lyrebird.txt')
$seen = @{}
$root = $null
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($source)
try {
    foreach ($entry in $archive.Entries) {
        $path = $entry.FullName.Replace('/','\')
        if ($path -notmatch '^([\w.-]+)\\(.+)$') { throw 'Invalid path in portable ZIP.' }
        $prefix = $Matches[1]
        $relative = $Matches[2]
        if (-not $root) { $root = $prefix }
        if ($prefix -cne $root -or $relative -cnotin $allowed -or $seen.ContainsKey($relative)) {
            throw 'Unexpected or duplicate file in portable ZIP.'
        }
        $seen[$relative] = $true
        $stream = $entry.Open()
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLowerInvariant() }
        finally { $stream.Dispose(); $sha.Dispose() }
        $lines.Add((@($relative,$hash,$entry.Length,$entry.FullName) -join [char]9))
    }
} finally { $archive.Dispose() }
foreach ($file in $required) { if (-not $seen.ContainsKey($file)) { throw "Missing package file: $file" } }
[IO.File]::WriteAllLines($catalog,$lines,[Text.UTF8Encoding]::new($false))
$info = Join-Path $out 'AssemblyInfo.cs'
[IO.File]::WriteAllLines($info,@('using System.Reflection;',
    '[assembly: AssemblyTitle("GrinSight Portable")]','[assembly: AssemblyProduct("GrinSight")]',
    "[assembly: AssemblyFileVersion(`"$Version.0`")]","[assembly: AssemblyVersion(`"$Version.0`")]"))
$exe = Join-Path $out "$baseName.exe"
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$icon = Join-Path $PSScriptRoot 'installer\grinsight.ico'
$launcher = Join-Path $PSScriptRoot 'installer\PortableLauncher.cs'
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /reference:System.IO.Compression.dll /reference:System.Windows.Forms.dll "/win32icon:$icon" "/resource:$source,runtime.zip" "/resource:$catalog,runtime.catalog" "/out:$exe" $launcher $info
if ($LASTEXITCODE -ne 0) { throw 'Portable launcher compilation failed.' }
Write-Output "ONEFILE=$exe"
