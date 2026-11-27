# GrinSight for Android (arm64 phones and the x86_64 emulator, one APK): builds the wallet's programs and
# the interface, packs them into one APK, installs it on the emulator, starts it
# and saves a screenshot, the process list and the error log into
# C:\DHW\ui-probe\out\android-fly-<time>\.
# The programs are packed as lib*.so: the app's native library folder is the
# one place Android lets an app start programs from.
# Run: powershell -ExecutionPolicy Bypass -File C:\DHW\ui-probe\scripts\build-android.ps1
param([switch]$NoBuild, [switch]$CoreOnly, [switch]$PackageOnly,
      [string]$SigningPasswordFile)
# Preserve callers using environment credentials, without passing them to the build tools.
$inheritedStorePass = $env:GRINSIGHT_ANDROID_STORE_PASS
$inheritedKeyPass = $env:GRINSIGHT_ANDROID_KEY_PASS
try {
$env:GRINSIGHT_ANDROID_STORE_PASS = $null
$env:GRINSIGHT_ANDROID_KEY_PASS = $null
$ErrorActionPreference = 'Continue'
$core = $PSScriptRoot
$root = 'C:\DHW\ui-probe'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = Join-Path $root "out\android-fly-$stamp"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$log = Join-Path $out 'build.log'
function Say($s) { $line = "$(Get-Date -Format 'HH:mm:ss') $s"; Write-Host $line; Add-Content -Path $log -Value $line -Encoding utf8 }
function Tool($exe, [string[]]$argv) {
    $text = & $exe @argv 2>&1 | ForEach-Object { "$_" } | Out-String
    Add-Content -Path $log -Value $text -Encoding utf8
    return $LASTEXITCODE
}

$sdk = 'C:\DHW\.toolchain\android-sdk'
$ndk = Get-ChildItem (Join-Path $sdk 'ndk') -Directory | Sort-Object { [version]$_.Name } | Select-Object -Last 1 | ForEach-Object FullName
$bt = Join-Path $sdk 'build-tools\36.0.0'
$jar = Join-Path $sdk 'platforms\android-36\android.jar'
$adb = Join-Path $sdk 'platform-tools\adb.exe'
$emu = Join-Path $sdk 'emulator\emulator.exe'
$llvm = Join-Path $ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin'
$api = 26
# Both: arm64 for phones, x86_64 for the emulator; one APK carries both.
$targets = @(
    @{ triple = 'aarch64-linux-android'; abi = 'arm64-v8a' },
    @{ triple = 'x86_64-linux-android'; abi = 'x86_64' })
# See android-core-build.ps1: lmdb-master-sys asks for advapi32 when built on Windows.
$stub = Join-Path $root 'android-link-stub'
New-Item -ItemType Directory -Force -Path $stub | Out-Null
if (-not (Test-Path "$stub\libadvapi32.a")) { & (Join-Path $llvm 'llvm-ar.exe') rc "$stub\libadvapi32.a" | Out-Null }
foreach ($t in $targets) {
    $triple = $t.triple
    $upper = $triple.Replace('-', '_').ToUpper()
    $lower = $triple.Replace('-', '_')
    $clang = Join-Path $llvm "$triple$api-clang.cmd"
    Set-Item "env:CARGO_TARGET_${upper}_LINKER" $clang
    Set-Item "env:CC_$lower" $clang
    Set-Item "env:CXX_$lower" (Join-Path $llvm "$triple$api-clang++.cmd")
    Set-Item "env:AR_$lower" (Join-Path $llvm 'llvm-ar.exe')
    Set-Item "env:RANLIB_$lower" (Join-Path $llvm 'llvm-ranlib.exe')
    Set-Item "env:CARGO_TARGET_${upper}_RUSTFLAGS" "-L native=$stub"
}
$env:ANDROID_NDK_HOME = $ndk; $env:ANDROID_NDK_ROOT = $ndk; $env:ANDROID_NDK = $ndk
Say "NDK $ndk"

$coreTarget = Join-Path $root 'target-android-core'
$uiTarget = Join-Path $root 'target-android-ui'
if (-not $NoBuild) {
    foreach ($t in $targets) {
        $triple = $t.triple
        foreach ($job in @(
                @('host', "$core\paycore\host", '--bin fly-paycore-host'),
                @('chain', "$core\chain\fly-chain", ''),
                @('mailbox', "$core\transport\mailbox-nostr", '--bin fly-mailbox'),
                @('onion', "$core\onion", '--bin fly-onion'))) {
            $name, $dir, $extra = $job
            $env:CARGO_TARGET_DIR = $coreTarget
            $started = Get-Date
            $part = Join-Path $out "build-$name-$triple.log"
            Push-Location $dir
            cmd /c "cargo build --release --locked --offline --target $triple $extra 2>&1" | Out-File -FilePath $part -Encoding utf8
            $code = $LASTEXITCODE
            Pop-Location
            Say "$name $triple build exit=$code seconds=$([int]((Get-Date) - $started).TotalSeconds)"
            if ($code -ne 0) { Select-String -Path $part -Pattern 'error' | Select-Object -First 15 | ForEach-Object { Say ("   " + $_.Line) }; exit 1 }
        }
        if ($CoreOnly) { continue }
        # The interface: offline from ui\vendor-crates when that set is there,
        # otherwise from the drive root with crates.io.
        $env:CARGO_TARGET_DIR = $uiTarget
        $started = Get-Date
        $part = Join-Path $out "build-ui-$triple.log"
        if (Test-Path "$core\ui\vendor-crates") {
            Push-Location "$core\ui\app"
            cmd /c "cargo build --release --locked --offline --lib --target $triple 2>&1" | Out-File -FilePath $part -Encoding utf8
        } else {
            Push-Location 'C:\'
            cmd /c "cargo build --release --locked --lib --target $triple --manifest-path `"$core\ui\app\Cargo.toml`" 2>&1" | Out-File -FilePath $part -Encoding utf8
        }
        $code = $LASTEXITCODE
        Pop-Location
        Say "ui $triple build exit=$code seconds=$([int]((Get-Date) - $started).TotalSeconds)"
        if ($code -ne 0) { Select-String -Path $part -Pattern 'error' | Select-Object -First 15 | ForEach-Object { Say ("   " + $_.Line) }; exit 1 }
    }
}

# ---- APK
if ($CoreOnly) { Say 'core phase complete'; exit 0 }
$libs = @()
foreach ($t in $targets) {
    $triple = $t.triple; $abi = $t.abi
    $libs += @{ name = 'libfly_ui.so'; abi = $abi; path = Join-Path $uiTarget "$triple\release\libfly_ui.so" }
    $libs += @{ name = 'libfly_paycore_host.so'; abi = $abi; path = Join-Path $coreTarget "$triple\release\fly-paycore-host" }
    $libs += @{ name = 'libfly_chain.so'; abi = $abi; path = Join-Path $coreTarget "$triple\release\fly-chain" }
    $libs += @{ name = 'libfly_mailbox.so'; abi = $abi; path = Join-Path $coreTarget "$triple\release\fly-mailbox" }
    $libs += @{ name = 'libfly_onion.so'; abi = $abi; path = Join-Path $coreTarget "$triple\release\fly-onion" }
    # The program for Tor bridges is not built here: it is the lyrebird of the official Tor
    # Expert Bundle for this ABI, fetched and checked by get-tor-bridge-programs.ps1.
    $ptPlatform = if ($abi -eq 'arm64-v8a') { 'android-aarch64' } else { 'android-x86_64' }
    powershell -NoProfile -ExecutionPolicy Bypass -File "$core\get-tor-bridge-programs.ps1" -Platform $ptPlatform 2>&1 | ForEach-Object { Say "$_" }
    if ($LASTEXITCODE -ne 0) { Say "the Tor Expert Bundle for $ptPlatform was not accepted"; exit 1 }
    $pt = Get-ChildItem -LiteralPath "C:\DHW\dist\tor-expert-bundle\16.0.1\$ptPlatform\files" -Recurse -File | Where-Object { $_.Name -match '^(lib)?lyrebird(\.so)?$' } | Select-Object -First 1
    if (-not $pt) { Say "no lyrebird in the bundle for $ptPlatform"; exit 1 }
    $libs += @{ name = 'liblyrebird.so'; abi = $abi; path = $pt.FullName }
}
foreach ($l in $libs) {
    if (-not (Test-Path $l.path)) { Say "missing $($l.path)"; exit 1 }
    Say ("{0,-12} {1,-24} {2,12:N0} bytes" -f $l.abi, $l.name, (Get-Item $l.path).Length)
}
$res = Join-Path $out 'res'
New-Item -ItemType Directory -Force -Path "$res\mipmap-xxhdpi" | Out-Null
Copy-Item "$core\ui\app\images\icon.png" "$res\mipmap-xxhdpi\ic_launcher.png"
# ---- Java: the window's activity and the core service (core-v0.2\android\java)
$bt36 = $bt
$obj = Join-Path $out 'obj'; $dex = Join-Path $out 'dex'
foreach ($d in $obj, $dex) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
$java = Get-ChildItem "$core\android\java" -Recurse -Filter *.java | ForEach-Object FullName
$c = Tool 'javac' (@('-source', '11', '-target', '11', '-encoding', 'UTF-8', '-nowarn', '-classpath', $jar, '-d', $obj) + $java)
if ($c -ne 0) { Say "javac failed"; exit 1 }
# the plain-Java checks of the service's parts (core-v0.2\android\tests), on this computer
$tobj = Join-Path $out 'test-obj'
New-Item -ItemType Directory -Force -Path $tobj | Out-Null
$tests = Get-ChildItem "$core\android\tests" -Recurse -Filter *.java
$c = Tool 'javac' (@('-encoding', 'UTF-8', '-nowarn', '-classpath', "$obj;$jar", '-d', $tobj) + ($tests | ForEach-Object FullName))
if ($c -ne 0) { Say "javac of the tests failed"; exit 1 }
foreach ($t in $tests) {
    $c = Tool 'java' @('-ea', '-classpath', "$tobj;$obj", ('org.grinsight.fly.' + $t.BaseName))
    Say "java test $($t.BaseName) exit=$c"
    if ($c -ne 0) { exit 1 }
}
$classes = Get-ChildItem $obj -Recurse -Filter *.class | ForEach-Object FullName
$c = Tool (Join-Path $bt36 'd8.bat') (@('--release', '--min-api', "$api", '--lib', $jar, '--output', $dex) + $classes)
if ($c -ne 0) { Say "d8 failed"; exit 1 }
$manifest = Join-Path $out 'AndroidManifest.xml'
# the version is the window's own: one line of ui\app\src\lib.rs
$vm = [regex]::Match((Get-Content -LiteralPath (Join-Path $core 'ui\app\src\lib.rs') -Raw), '(?m)^pub const APP_VERSION: &str = "((\d+)\.(\d+)\.(\d+)A?)";')
if (-not $vm.Success) { Say "no APP_VERSION in ui\app\src\lib.rs"; exit 1 }
$version = $vm.Groups[1].Value
$versionCode = [int]$vm.Groups[2].Value * 10000 + [int]$vm.Groups[3].Value * 100 + [int]$vm.Groups[4].Value
Say "version: $version (code $versionCode)"
@'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.grinsight.fly"
    android:versionCode="@CODE@"
    android:versionName="@NAME@">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
    <application
        android:label="GrinSight"
        android:icon="@mipmap/ic_launcher"
        android:hasCode="true"
        android:extractNativeLibs="true"
        android:allowBackup="false">
        <service
            android:name=".CoreService"
            android:process=":core"
            android:exported="false"
            android:foregroundServiceType="specialUse">
            <property
                android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
                android:value="A wallet keeps its process running to receive payments and messages while its window is closed." />
        </service>
        <activity
            android:name=".FlyActivity"
            android:exported="true"
            android:configChanges="orientation|screenSize|screenLayout|keyboardHidden|uiMode|density"
            android:windowSoftInputMode="adjustResize">
            <meta-data android:name="android.app.lib_name" android:value="fly_ui" />
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
'@.Replace('@CODE@', "$versionCode").Replace('@NAME@', $version) | Out-File -FilePath $manifest -Encoding utf8
$flat = Join-Path $out 'res.zip'
$c = Tool (Join-Path $bt 'aapt2.exe') @('compile', '--dir', $res, '-o', $flat)
$base = Join-Path $out 'base.apk'; $aligned = Join-Path $out 'aligned.apk'; $apk = Join-Path $out 'grinsight-light.apk'
$c = Tool (Join-Path $bt 'aapt2.exe') @('link', '-o', $base, '--manifest', $manifest, '-I', $jar, '--min-sdk-version', "$api", '--target-sdk-version', '36', $flat)
if ($c -ne 0) { Say "aapt2 link failed"; exit 1 }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$noticeZip = [System.IO.Compression.ZipFile]::Open($base, 'Update')
try {
    [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($noticeZip, "$core\dist-files\LICENSE-GPL-3.0.txt", 'assets/licenses/LICENSE-GPL-3.0.txt')
    foreach ($font in 'Inter','DejaVu','WalletCJK') {
        [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($noticeZip, "$core\ui\app\fonts\LICENSE-$font.txt", "assets/licenses/LICENSE-$font.txt")
    }
} finally { $noticeZip.Dispose() }
$bare = Join-Path $out 'bare.apk'
Copy-Item $base $bare -Force
$zip = [System.IO.Compression.ZipFile]::Open($base, 'Update')
try {
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, (Join-Path $dex 'classes.dex'), 'classes.dex') | Out-Null
    foreach ($l in $libs) {
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $l.path, "lib/$($l.abi)/$($l.name)") | Out-Null
    }
} finally { $zip.Dispose() }
$c = Tool (Join-Path $bt 'zipalign.exe') @('-P', '16', '-f', '4', $base, $aligned)
$ks = Join-Path $root 'probe-debug.keystore'
if (-not (Test-Path -LiteralPath $ks -PathType Leaf)) { throw 'Missing existing signing key; a replacement cannot update the prior APK.' }
function Sign-ReleaseApk([string]$unsigned, [string]$signedPath) {
    $signer = Join-Path $bt 'apksigner.bat'
    $secure = $null
    $bstr = [IntPtr]::Zero
    try {
        if ($SigningPasswordFile) {
            # DPAPI CurrentUser, written by ConvertFrom-SecureString with no explicit key.
            try {
                $encrypted = (Get-Content -LiteralPath $SigningPasswordFile -Raw -ErrorAction Stop).Trim()
                $secure = ConvertTo-SecureString -String $encrypted -ErrorAction Stop
                $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
                $env:GRINSIGHT_ANDROID_STORE_PASS = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                $env:GRINSIGHT_ANDROID_KEY_PASS = $env:GRINSIGHT_ANDROID_STORE_PASS
            } catch { throw 'Could not unlock the APK signing password with the current Windows account.' }
        } else {
            $env:GRINSIGHT_ANDROID_STORE_PASS = $inheritedStorePass
            $env:GRINSIGHT_ANDROID_KEY_PASS = $inheritedKeyPass
        }
        foreach ($name in 'GRINSIGHT_ANDROID_STORE_PASS', 'GRINSIGHT_ANDROID_KEY_PASS') {
            if (!(Test-Path "Env:$name")) { throw "Missing protected signing environment variable $name." }
        }
        $result = Tool $signer @('sign', '--ks', $ks, '--ks-pass', 'env:GRINSIGHT_ANDROID_STORE_PASS',
            '--ks-key-alias', 'probe', '--key-pass', 'env:GRINSIGHT_ANDROID_KEY_PASS', '--out', $signedPath, $unsigned)
    } finally {
        $env:GRINSIGHT_ANDROID_STORE_PASS = $null
        $env:GRINSIGHT_ANDROID_KEY_PASS = $null
        if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        if ($secure) { $secure.Dispose() }
    }
    if ($result -ne 0 -or !(Test-Path -LiteralPath $signedPath -PathType Leaf)) { throw 'APK signing failed.' }
    $certificate = & $signer verify --print-certs $signedPath
    if ($LASTEXITCODE -ne 0 -or $certificate -notcontains 'Signer #1 certificate SHA-256 digest: 891600203fa03bc1d3f5e2a8e2c3b6bd60d73bd1246b368984d003d54f54ba0a') {
        throw 'Android signing certificate differs from the published 0.4.6 APK.'
    }
}
if ($c -ne 0) { throw 'APK alignment failed.' }
Sign-ReleaseApk $aligned $apk
Say ("apk: {0} ({1:N0} KB)" -f $apk, ((Get-Item $apk).Length / 1KB))
New-Item -ItemType Directory -Force -Path 'C:\DHW\dist' | Out-Null
$distApk = "C:\DHW\dist\GrinSight-$stamp.apk"
Copy-Item $apk $distApk
Say ("dist: {0}  sha256 {1}" -f $distApk, (Get-FileHash $distApk -Algorithm SHA256).Hash.ToLower())

# ---- the phone's own package: the same programs for arm64 only (the one that is published;
# the package above also carries x86_64, for the emulator that checks it)
$armBase = Join-Path $out 'base-arm64.apk'; $armAligned = Join-Path $out 'aligned-arm64.apk'; $armApk = Join-Path $out 'grinsight-light-arm64.apk'
Copy-Item $bare $armBase -Force
$zip = [System.IO.Compression.ZipFile]::Open($armBase, 'Update')
try {
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, (Join-Path $dex 'classes.dex'), 'classes.dex') | Out-Null
    foreach ($l in ($libs | Where-Object { $_.abi -eq 'arm64-v8a' })) {
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $l.path, "lib/$($l.abi)/$($l.name)") | Out-Null
    }
} finally { $zip.Dispose() }
$c = Tool (Join-Path $bt 'zipalign.exe') @('-P', '16', '-f', '4', $armBase, $armAligned)
if ($c -ne 0) { throw 'Arm64 APK alignment failed.' }
Sign-ReleaseApk $armAligned $armApk
$packed = [IO.Compression.ZipFile]::OpenRead($armApk)
try {
    $expected = @($libs | Where-Object { $_.abi -eq 'arm64-v8a' } | ForEach-Object { 'lib/arm64-v8a/' + $_.name })
    $actual = @($packed.Entries | Where-Object { $_.FullName.StartsWith('lib/') } | ForEach-Object FullName)
    if (Compare-Object $expected $actual) { throw 'Unexpected native programs in arm64 APK.' }
    foreach ($notice in 'GPL-3.0','Inter','DejaVu','WalletCJK') {
        $entry = $packed.GetEntry("assets/licenses/LICENSE-$notice.txt")
        if (!$entry -or !$entry.Length) { throw "Missing license: $notice" }
    }
} finally { $packed.Dispose() }
$distArm = "C:\DHW\dist\GrinSight-$stamp-arm64.apk"
Copy-Item $armApk $distArm
Say ("dist: {0}  {1:N0} bytes  sha256 {2}" -f $distArm, (Get-Item $distArm).Length, (Get-FileHash $distArm -Algorithm SHA256).Hash.ToLower())

# ---- emulator
if ($PackageOnly) { exit 0 }
& "$PSScriptRoot\test-android-apk.ps1" -Apk $apk -Sdk $sdk -Evidence $out
} finally {
    $env:GRINSIGHT_ANDROID_STORE_PASS = $inheritedStorePass
    $env:GRINSIGHT_ANDROID_KEY_PASS = $inheritedKeyPass
}
