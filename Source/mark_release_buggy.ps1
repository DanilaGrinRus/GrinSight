# mark_release_buggy.ps1 - marks a published release as BUGGY / DO NOT USE.
#   GitHub (gh, your account): title "... - BUGGY, DO NOT USE", pre-release (so it is never
#     "Latest"), a warning on top of the notes (EN + RU) pointing to the fixed version,
#     every asset renamed DO-NOT-USE-<name>; the fixed version is made "Latest" if it exists.
#     The tag and the files themselves stay (hashes are the same, only names change).
#   Local: dist\release\<v>  ->  dist\release\<v>-BUGGY-DO-NOT-USE  + a НЕ_ИСПОЛЬЗОВАТЬ.txt note.
#
#   .\mark_release_buggy.ps1                         (0.4.0, fixed in 0.4.1-ThxWiesche)
#   .\mark_release_buggy.ps1 -Version 0.4.0 -Fixed 0.4.1-ThxWiesche -LocalOnly
param(
    [string]$Version = '0.4.0',
    [string]$Fixed = '0.4.1-ThxWiesche',
    [string]$Repo = 'GrinSight',
    [switch]$LocalOnly
)
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot
function Run([string]$what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" } }
$utf8 = New-Object Text.UTF8Encoding $false
$tag = "v$Version"
$fixedTag = "v$Fixed"

$warnEn = @"
> [!CAUTION]
> **DO NOT USE GrinSight $Version.** Its normal wallet sync has consensus gaps found in an external review:
> coinbase maturity was not checked, the emission / kernel sums were not verified, UTXO rangeproofs and
> kernel signatures were verified only on the helper path, and kernel_root was skipped when no kernel
> segment was served. **Fixed in [$Fixed](../$fixedTag) - install that version instead.**
> Updating keeps your wallet files; the saved chain state is re-verified once.
"@
$warnRu = @"
> [!CAUTION]
> **НЕ ИСПОЛЬЗУЙТЕ GrinSight $Version.** В обычной синхронизации кошелька найдены (внешнее ревью) пробелы
> в проверке консенсуса: не проверялось созревание coinbase, не сверялись эмиссия и суммы ядер, rangeproof
> выходов и подписи ядер проверялись только в режиме helper, kernel_root пропускался без сегмента ядер.
> **Исправлено в [$Fixed](../$fixedTag) - ставьте её.** Файлы кошельков при обновлении сохраняются;
> сохранённое состояние цепочки один раз проверяется заново.
"@
$marker = "DO NOT USE GrinSight $Version"

if (-not $LocalOnly) {
    $user = gh api user | ConvertFrom-Json; Run 'gh api user'
    $full = "$($user.login)/$Repo"
    $rel = gh api "repos/$full/releases/tags/$tag" | ConvertFrom-Json; Run "release $tag not found on $full"
    Write-Host "release: $($rel.html_url)"
    Write-Host "  title now: $($rel.name)"
    $rel.assets | ForEach-Object { Write-Host "  asset: $($_.name)" }
    if ((Read-Host "Mark $tag on $full as BUGGY / DO NOT USE? (y/n)") -ne 'y') { Write-Host 'cancelled'; exit 1 }

    # Notes: warning on top (once).
    $body = [string]$rel.body
    if (-not $body.Contains($marker)) { $body = "$warnEn`n`n$warnRu`n`n---`n`n$body" }
    $notes = Join-Path $env:TEMP "grinsight-$Version-buggy-notes.md"
    [IO.File]::WriteAllText($notes, $body, $utf8)
    gh release edit $tag --repo $full --title "GrinSight $Version - BUGGY, DO NOT USE (use $Fixed)" --prerelease --notes-file $notes; Run 'gh release edit'
    Remove-Item $notes -ErrorAction SilentlyContinue

    # Assets: DO-NOT-USE-<name> (once).
    foreach ($a in $rel.assets) {
        if ($a.name.StartsWith('DO-NOT-USE-')) { continue }
        gh api -X PATCH "repos/$full/releases/assets/$($a.id)" -f "name=DO-NOT-USE-$($a.name)" | Out-Null; Run "rename $($a.name)"
        Write-Host "  renamed: DO-NOT-USE-$($a.name)"
    }

    # The fixed version becomes "Latest", if it is published already.
    $ErrorActionPreference = 'Continue'
    gh release view $fixedTag --repo $full 2>&1 | Out-Null
    $fixedExists = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = 'Stop'
    if ($fixedExists) {
        gh release edit $fixedTag --repo $full --prerelease=false --latest; Run "gh release edit $fixedTag --latest"
        Write-Host "latest: $fixedTag"
    } else {
        Write-Host "$fixedTag is not published yet: after .\publish_github.ps1 -Version $Fixed run this script again (it only sets Latest then)."
    }
}

# Local copy.
$dir = Join-Path $PSScriptRoot "dist\release\$Version"
$bad = "$dir-BUGGY-DO-NOT-USE"
if (Test-Path $dir) {
    if (Test-Path $bad) { throw "$bad already exists" }
    Rename-Item $dir $bad
}
if (Test-Path $bad) {
    $note = "GrinSight $Version - BUGGY, DO NOT USE / НЕ ИСПОЛЬЗОВАТЬ`r`n`r`n" +
        "Consensus gaps in the normal wallet sync (coinbase maturity, emission / kernel sums,`r`n" +
        "rangeproofs and kernel signatures, kernel_root fail-open). Fixed in $Fixed.`r`n`r`n" +
        "Пробелы в проверке консенсуса в обычной синхронизации (созревание coinbase, эмиссия и суммы`r`n" +
        "ядер, rangeproof и подписи ядер, kernel_root без сегмента). Исправлено в $Fixed.`r`n"
    [IO.File]::WriteAllText((Join-Path $bad 'НЕ_ИСПОЛЬЗОВАТЬ.txt'), $note, $utf8)
    Write-Host "local: $bad"
} else {
    Write-Host "local: no dist\release\$Version here (nothing to rename)"
}
