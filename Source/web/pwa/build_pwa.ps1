# Rebuild the diagnostic PWA assets from the tested browser module.
# Usage: .\build_pwa.ps1
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Resolve-Path (Join-Path $here '..\..')
$browser = Join-Path $root 'web-core\browser'
$icons = Join-Path $root 'UI\flutter_app\web\icons'
New-Item -ItemType Directory -Force (Join-Path $here 'core'), (Join-Path $here 'icons') | Out-Null
Copy-Item (Join-Path $browser 'grinsight_api.mjs') (Join-Path $here 'core\grinsight_api.mjs') -Force
Copy-Item (Join-Path $browser 'grinsight_core.js') (Join-Path $here 'core\grinsight_core.js') -Force
Copy-Item (Join-Path $browser 'grinsight_core.wasm') (Join-Path $here 'core\grinsight_core.wasm') -Force
Set-Content (Join-Path $here 'core\package.json') '{"type":"module"}' -Encoding ASCII
foreach ($name in 'Icon-192.png','Icon-512.png','Icon-maskable-192.png','Icon-maskable-512.png') {
    Copy-Item (Join-Path $icons $name) (Join-Path $here "icons\$name") -Force
}
# Version the offline cache by the content of everything it holds (UI + core):
# a changed byte gives a new sw.js, the browser installs it, and the old cache
# is dropped on activate. Wallet data lives in localStorage, not in this cache.
$assets = @('index.html', 'manifest.webmanifest', 'worker.mjs', 'transport.mjs', 'core\grinsight_api.mjs', 'core\grinsight_core.js', 'core\grinsight_core.wasm')
$sha = [Security.Cryptography.SHA256]::Create()
$buf = New-Object IO.MemoryStream
foreach ($a in $assets) {
    $f = Join-Path $here $a
    if (Test-Path $f) { $b = [IO.File]::ReadAllBytes($f); $buf.Write($b, 0, $b.Length) }
}
$ver = (-join ($sha.ComputeHash($buf.ToArray()) | ForEach-Object { $_.ToString('x2') })).Substring(0, 12)
$sw = Join-Path $here 'sw.js'
$text = [IO.File]::ReadAllText($sw)
$new = [regex]::Replace($text, "const CACHE = 'grinsight-pwa-[^']*';", "const CACHE = 'grinsight-pwa-$ver';")
if ($new -eq $text -and $text -notmatch "grinsight-pwa-$ver") { throw 'sw.js: CACHE line not found' }
[IO.File]::WriteAllText($sw, $new, (New-Object Text.UTF8Encoding $false))
Write-Output "PWA cache version: grinsight-pwa-$ver"
Write-Output 'PWA assets copied'
Get-ChildItem $here -Recurse -File | Select-Object FullName, Length
