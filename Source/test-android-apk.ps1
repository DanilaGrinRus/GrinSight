# Check the packaged Java activity and x86_64 native code on a new, disposable AVD.
param([Parameter(Mandatory)][string]$Apk, [Parameter(Mandatory)][string]$Evidence,
      [string]$Sdk='C:\DHW\.toolchain\android-sdk', [string]$VersionName='0.4.7A', [int]$VersionCode=407,
      [ValidateSet('x86_64','arm64-v8a')][string]$ExpectedAbi='x86_64')
$ErrorActionPreference = 'Stop'
$apkPath = (Resolve-Path -LiteralPath $Apk).Path
$out = (Get-Item -LiteralPath $Evidence).FullName
$testRoot = [IO.Path]::GetTempPath()
$name = 'GrinSightCheck' + [Guid]::NewGuid().ToString('N')
$dir = (New-Item -Type Directory -Path (Join-Path $testRoot $name)).FullName
$env:ANDROID_AVD_HOME = $dir
$env:ANDROID_SDK_ROOT = $Sdk
$adb = Join-Path $Sdk 'platform-tools\adb.exe'
$emulator = Join-Path $Sdk 'emulator\emulator.exe'
$manager = Join-Path $Sdk 'cmdline-tools\latest\bin\avdmanager.bat'
$systemImage = Get-ChildItem -LiteralPath "$Sdk\system-images" -Directory | Sort-Object Name -Descending |
    Where-Object { Test-Path "$($_.FullName)\google_apis\x86_64\system.img" } | Select-Object -First 1
if (!$systemImage) { throw 'Install a Google APIs x86_64 emulator system image.' }
$port = $null
$listeners = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners().Port
foreach ($n in 5554..5584) {
    if (($n % 2 -eq 0) -and $n -notin $listeners -and ($n+1) -notin $listeners) { $port=$n; break }
}
if (!$port) { throw 'No free port for an isolated Android emulator.' }
$serial = "emulator-$port"
$ours = $false
function Adb([string[]]$Commands) {
    $ErrorActionPreference = 'Continue'
    $reply = @(& $adb -s $serial @Commands 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "adb failed ($LASTEXITCODE) for $($Commands -join ' '): $($reply -join ' ')" }
    return $reply
}
function WalletHostPid([string]$serviceId) {
    if ($serviceId -notmatch '^[1-9]\d*$') { throw 'Expected a single wallet service PID.' }
    $pattern = '^\s*(\d+)\s+' + [regex]::Escape($serviceId) + '\s+(?:(?:\S*/)?ndk_translation_program_runner_binfmt_misc_arm64\s+)?(?:\S*/)?libfly_paycore_host\.so(?:\s|$)'
    $matching = @(Adb @('shell','ps','-A','-o','PID,PPID,ARGS') | ForEach-Object {
        if ($_ -match $pattern) { $Matches[1] }
    })
    if ($matching.Count -ne 1) { throw 'Expected one native wallet process belonging to this service.' }
    return $matching[0]
}
function Assert-WalletWindowSecure {
    $windows = (Adb @('shell','dumpsys','window','windows')) -join "`n"
    $wallet = [regex]::Match($windows, '(?ms)^\s*Window #\d+ Window\{[^}\n]*org\.grinsight\.fly/[^}\n]*\}:\s*\n(.*?)(?=^\s*Window #\d+ Window\{|\z)')
    if (!$wallet.Success) { throw 'Unable to inspect the wallet activity window.' }
    $flags = [regex]::Match($wallet.Groups[1].Value, '(?m)^\s*fl=([^\r\n]+)')
    if (!$flags.Success) { throw 'Wallet window flags unavailable.' }
    $names = $flags.Groups[1].Value
    if ($names -match '\bSECURE\b') { return }
    if ($names -match '^0x([0-9a-f]+)\b' -and (([Convert]::ToUInt32($Matches[1],16) -band 0x2000) -ne 0)) { return }
    throw 'Secure display flag missing from wallet activity.'
}
try {
    $image = 'system-images;' + $systemImage.Name + ';google_apis;x86_64'
    & {
        $ErrorActionPreference='Continue'
        'no' | & $manager create avd -n $name -k $image --device 'pixel_6' --path "$dir\disk.avd" *> "$out\avd-create.log"
        if ($LASTEXITCODE -ne 0) { throw 'Unable to create the isolated Android device.' }
    }
    $process = Start-Process -FilePath $emulator -ArgumentList @('-avd',$name,'-port',$port,'-no-window','-no-snapshot','-no-audio','-no-boot-anim','-gpu','software') -WindowStyle Hidden -PassThru -RedirectStandardOutput "$out\emulator.stdout" -RedirectStandardError "$out\emulator.stderr"
    $null = $process.Handle
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        Start-Sleep -Seconds 2
        if ($process.HasExited) { throw 'Isolated emulator exited before boot.' }
        $reported = @(& { $ErrorActionPreference='Continue'; & $adb -s $serial emu avd name 2>$null })
        if ($reported -contains $name) { $ours=$true }
        if ($ours) {
            $booted = & { $ErrorActionPreference='Continue'; & $adb -s $serial shell getprop sys.boot_completed 2>$null }
            if ($booted -eq '1') { break }
        }
        if ($clock.Elapsed.TotalSeconds -gt 240) { throw 'Isolated emulator did not finish booting.' }
    } while ($true)
    $installer = Start-Process -FilePath $adb -ArgumentList @('-s',$serial,'install','--no-streaming',"`"$apkPath`"") -PassThru -WindowStyle Hidden -RedirectStandardOutput "$out\adb-install.log" -RedirectStandardError "$out\adb-install.err"
    $null = $installer.Handle
    if (!$installer.WaitForExit(300000)) { $installer.Kill(); throw 'APK installation timed out.' }
    if ($installer.ExitCode -ne 0 -or (Get-Content "$out\adb-install.log" -Raw) -notmatch 'Success') { throw 'APK installation failed.' }
    Write-Output 'PASS Android isolated APK installation'
    $meta = Adb @('shell','dumpsys','package','org.grinsight.fly')
    if (!($meta -match ('primaryCpuAbi=' + [regex]::Escape($ExpectedAbi) + '$'))) { throw "Android did not select the expected ABI: $ExpectedAbi" }
    Write-Output "PASS selected ABI $ExpectedAbi"
    if (!($meta -match ('versionName=' + [regex]::Escape($VersionName) + '$')) -or !($meta -match "versionCode=$VersionCode\b")) { throw 'Wrong installed application version.' }
    if ([int](Adb @('shell','getprop','ro.build.version.sdk')) -ge 33) {
        $null = Adb @('shell','pm','grant','org.grinsight.fly','android.permission.POST_NOTIFICATIONS')
    }
    foreach ($attempt in 1,2,3) {
        $launch = Adb @('shell','am','start','-W','-n','org.grinsight.fly/.FlyActivity')
        $launch | Set-Content -LiteralPath "$out\launch-$attempt.txt"
        if (!($launch -match '^Activity: org\.grinsight\.fly/')) { throw 'Wallet did not open in the foreground.' }
        Start-Sleep -Seconds 7
        if (!(Adb @('shell','pidof','org.grinsight.fly'))) { throw 'Activity did not stay running.' }
        $servicePid = (Adb @('shell','pidof','org.grinsight.fly:core')).Trim()
        if (!$servicePid) { throw 'Wallet service did not stay running.' }
        $hostPid = WalletHostPid $servicePid
        Assert-WalletWindowSecure
        $crashes = Adb @('logcat','-b','crash','-d')
        if ($crashes -match 'org\.grinsight\.fly|libfly_ui|fly-paycore-host') { throw 'Android reported an application crash.' }
        Write-Output "PASS Android app and core service, start $attempt"
        if ($attempt -eq 1) {
            $firstService = $servicePid
            $firstHost = $hostPid
            $windowPid = (Adb @('shell','pidof','org.grinsight.fly')).Trim()
            if (!$ours -or $windowPid -notmatch '^[1-9]\d*$' -or $windowPid -eq $servicePid) { throw 'Unexpected test window PID.' }
            # Only the two processes of this empty, disposable AVD. The Java service stays up.
            $null = Adb @('shell','input','keyevent','KEYCODE_HOME')
            $null = Adb @('shell','su','0','kill','-TERM',$hostPid)
            $null = Adb @('shell','su','0','kill','-KILL',$windowPid)
            Start-Sleep -Seconds 2
        }
        if ($attempt -eq 2) {
            if ($servicePid -ne $firstService -or $hostPid -eq $firstHost) { throw 'A new native host must start under the original service.' }
            Write-Output 'PASS exited child replaced on reattachment with the same Android service; secure activity window'
            $null = Adb @('shell','am','force-stop','org.grinsight.fly')
        }
    }
} catch {
    if ($ours) {
        & { $ErrorActionPreference='Continue'; & $adb -s $serial logcat -b crash -d 2>$null } | Set-Content -LiteralPath "$out\crash.txt"
    }
    Write-Error -Message ("Android check: " + $_.Exception.Message) -ErrorAction Continue
    throw
} finally {
    if ($ours) { & $adb -s $serial emu kill 2>$null | Out-Null }
    if ($process -and !$process.WaitForExit(55000)) { throw 'Isolated emulator has not exited; its test directory is retained.' }
    $base=(Get-Item -LiteralPath $testRoot).FullName.TrimEnd('\')
    $folder=Get-Item -LiteralPath $dir
    if ($folder.Parent.FullName.TrimEnd('\') -ne $base -or $folder.Name -ne $name -or ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected AVD cleanup path.' }
    if (Get-ChildItem -LiteralPath $dir -Force -Recurse -Attributes ReparsePoint) { throw 'Linked file in the isolated AVD.' }
    Remove-Item -LiteralPath $dir -Force -Recurse
}
