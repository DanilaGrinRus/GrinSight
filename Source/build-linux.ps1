# Builds the Linux packages (.deb, .rpm, .tar.gz + PKGBUILD) for a wide range of
# distributions inside the GrinSightBuild WSL distribution: see build-linux.sh.
# Run: powershell -ExecutionPolicy Bypass -File C:\DHW\ui-probe\scripts\build-linux.ps1
$ErrorActionPreference = 'Continue'
$log = 'C:\DHW\ui-probe\out\build-linux-' + (Get-Date -Format 'yyyyMMdd-HHmm') + '.log'
& wsl.exe -d GrinSightBuild -u root -- bash /mnt/c/DHW/ui-probe/scripts/build-linux.sh 2>&1 | ForEach-Object { $l = "$_"; if ($l -ne 'System.Management.Automation.RemoteException') { Write-Host $l; Add-Content -Path $log -Value $l -Encoding utf8 } }
Write-Host "exit=$LASTEXITCODE"
Add-Content -Path $log -Value "exit=$LASTEXITCODE" -Encoding utf8
Write-Host "Log: $log"
