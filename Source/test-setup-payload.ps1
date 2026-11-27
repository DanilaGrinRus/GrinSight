# Read-only acceptance of an extracted setup when the current Windows account has an installation.
param([Parameter(Mandatory)][string]$ExtractedApp, [Parameter(Mandatory)][string]$Runtime,
      [Parameter(Mandatory)][string]$SetupExtra)
$ErrorActionPreference='Stop'
$app=(Get-Item -LiteralPath $ExtractedApp).FullName
$files=@{}
foreach ($name in 'GrinSight.exe','bin\fly-paycore-host.exe','bin\fly-chain.exe','bin\fly-mailbox.exe','bin\fly-onion.exe','bin\lyrebird.exe','FONT-LICENSES.txt','LICENSE-lyrebird.txt','LICENSE-GPL-3.0.txt') {
    $files[$name] = Join-Path $Runtime $name
}
foreach ($name in 'README.txt','installed.txt','SHA256SUMS.txt') { $files[$name]=Join-Path $SetupExtra $name }
foreach ($name in 'stop-own.ps1','grinsight.ico') { $files[$name]=Join-Path "$PSScriptRoot\installer" $name }
$actual=@(Get-ChildItem -LiteralPath $app -File -Recurse | ForEach-Object { $_.FullName.Substring($app.Length+1) })
if (Compare-Object @($files.Keys | Sort-Object) @($actual | Sort-Object)) {throw 'The extracted setup has an unexpected set of files.'}
foreach ($name in $files.Keys) {
    $sha=(Get-FileHash -LiteralPath $files[$name]).Hash
    if ((Get-FileHash -LiteralPath (Join-Path $app $name)).Hash -ne $sha) {throw "Setup differs for $name"}
}
Write-Output "PASS SHA-256 equality for all $($files.Count) setup files"
