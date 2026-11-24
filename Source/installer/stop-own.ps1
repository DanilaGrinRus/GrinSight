# Stop only binaries from this installation. PSScriptRoot is a path value.
$images = @('GrinSight.exe','bin\fly-paycore-host.exe','bin\fly-chain.exe','bin\fly-mailbox.exe','bin\fly-onion.exe','bin\lyrebird.exe') |
    ForEach-Object { Join-Path $PSScriptRoot $_ }
foreach ($process in (Get-Process -Name GrinSight,fly-paycore-host,fly-chain,fly-mailbox,fly-onion,lyrebird -ErrorAction SilentlyContinue)) {
    if ($process.Path -and $images -contains $process.Path) {
        Stop-Process -InputObject $process -Force -ErrorAction SilentlyContinue
    }
}
