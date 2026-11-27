# Builds the Linux packages (.deb, .rpm, .tar.gz + PKGBUILD) for a wide range of
# distributions inside the GrinSightBuild WSL distribution: see build-linux.sh.
# Run: powershell -ExecutionPolicy Bypass -File C:\DHW\ui-probe\scripts\build-linux.ps1
param([ValidateSet('core','all')][string]$Phase='all')
$ErrorActionPreference = 'Continue'
$log = 'C:\DHW\ui-probe\out\build-linux-' + (Get-Date -Format 'yyyyMMdd-HHmm') + '.log'
$path = (& wsl.exe -d GrinSightBuild -- wslpath -a (Join-Path $PSScriptRoot 'build-linux.sh')).Trim()
if ($LASTEXITCODE -ne 0 -or !$path) { throw 'Cannot locate the selected checkout in WSL.' }
& wsl.exe -d GrinSightBuild -u root -- bash $path $Phase 2>&1 | ForEach-Object { $l = "$_"; if ($l -ne 'System.Management.Automation.RemoteException') { Write-Host $l; Add-Content -Path $log -Value $l -Encoding utf8 } }
$code = $LASTEXITCODE
Write-Host "exit=$code"
Add-Content -Path $log -Value "exit=$code" -Encoding utf8
Write-Host "Log: $log"
exit $code
