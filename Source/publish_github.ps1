# Publishes a release built by make_github_release.ps1 to GitHub:
#   repository <your account>/GrinSight, branch GrinSight = dist\release\<v>\repo
#   (README, licenses, Documents\, Source\), tag v<v>, release v<v> with dist\release\<v>\assets.
#
#   .\publish_github.ps1 -Version 0.1.0
#
# Needs the GitHub CLI signed in (gh auth login). The branch is REPLACED by the release
# tree (force push) and an existing release of the same version is recreated; asks first.
# Commits are signed as the author from GrinSight\release-docs\AUTHOR.txt with GitHub's
# private noreply address (your real email is never published).
param([Parameter(Mandatory = $true)][string]$Version, [string]$Repo = 'GrinSight', [string]$Branch = 'GrinSight')
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

function Run([string]$what) {
    if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" }
}

$rel = Join-Path $PSScriptRoot "dist\release\$Version"
$tree = Join-Path $rel 'repo'
$assets = Join-Path $rel 'assets'
if (-not (Test-Path (Join-Path $tree 'README.md'))) { throw "no release ${Version}: .\make_github_release.ps1 -Version $Version" }
if (-not (Test-Path (Join-Path $tree 'Source'))) { throw "release ${Version} has the old layout: .\make_github_release.ps1 -Version $Version" }

$ErrorActionPreference = 'Continue'
gh auth status 2>&1 | Out-Null
$signedIn = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = 'Stop'
if (-not $signedIn) { throw 'GitHub CLI is not signed in: gh auth login --hostname github.com --git-protocol https --web' }
$user = gh api user | ConvertFrom-Json; Run 'gh api user'
$full = "$($user.login)/$Repo"
$author = (Get-Content (Join-Path $PSScriptRoot 'GrinSight\release-docs\AUTHOR.txt') -TotalCount 1).Trim()
$email = "$($user.id)+$($user.login)@users.noreply.github.com"
$tag = "v$Version"

Write-Host "repository: https://github.com/$full  (branch $Branch, tag $tag)"
Write-Host "author:     $author <$email>"
Write-Host 'assets:'
Get-ChildItem $assets -File | ForEach-Object { Write-Host ("    {0,14:N0}  {1}" -f $_.Length, $_.Name) }
if ((Read-Host "Branch $Branch will be replaced by this release. Publish? (y/n)") -ne 'y') { Write-Host 'cancelled'; exit 1 }

# A fresh git tree each time: exactly the release, nothing else.
$git = Join-Path $rel 'git'
if (Test-Path $git) { Remove-Item -Recurse -Force $git }
Copy-Item $tree $git -Recurse
Push-Location $git
try {
    git init -q -b $Branch; Run 'git init'
    git config user.name $author
    git config user.email $email
    git config core.autocrlf false
    git add -A; Run 'git add'
    git commit -q -m "GrinSight $Version"; Run 'git commit'
    git tag -a $tag -m "GrinSight $Version"; Run 'git tag'

    $ErrorActionPreference = 'Continue'
    gh repo view $full 2>&1 | Out-Null
    $repoExists = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = 'Stop'
    if (-not $repoExists) {
        gh repo create $full --public --description 'GrinSight - Revelio for your coins. Grin light wallet that proves its balance.'; Run 'gh repo create'
    }
    git remote add origin "https://github.com/$full.git"
    git push -f origin $Branch; Run 'git push (branch)'
    gh repo edit $full --default-branch $Branch | Out-Null; Run 'gh repo edit'

    # "release not found" on stderr is the normal answer for a new version:
    # Windows PowerShell would turn it into a terminating error under Stop.
    $ErrorActionPreference = 'Continue'
    gh release view $tag --repo $full 2>&1 | Out-Null
    $exists = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = 'Stop'
    if ($exists) { gh release delete $tag --repo $full --yes; Run 'gh release delete' }
    git push -f origin "refs/tags/$tag"; Run 'git push (tag)'

    # Release text: English, then Russian.
    $notes = Join-Path $rel 'release-notes.md'
    $en = Get-Content (Join-Path $tree 'Documents\RELEASE_NOTES_EN.md') -Raw -Encoding UTF8
    $ru = Get-Content (Join-Path $tree 'Documents\RELEASE_NOTES_RU.md') -Raw -Encoding UTF8
    [IO.File]::WriteAllText($notes, "$en`n`n---`n`n$ru", (New-Object Text.UTF8Encoding $false))
    $files = (Get-ChildItem $assets -File).FullName
    gh release create $tag $files --repo $full --verify-tag --title "GrinSight $Version" --notes-file $notes; Run 'gh release create'
} finally { Pop-Location }

Write-Host ""
Write-Host "published: https://github.com/$full/releases/tag/$tag"
gh release view $tag --repo $full --web
