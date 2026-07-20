#Requires -Version 5.1
<#
.SYNOPSIS
    Installs hightower and puts it on your PATH.

.DESCRIPTION
    Downloads the released hightower binary into %LOCALAPPDATA%\Programs\hightower
    and adds that folder to your *user* PATH. No administrator rights are needed
    and nothing outside your user profile is touched.

    Re-running is safe: the binary is replaced and the PATH entry is never
    duplicated.

.PARAMETER Version
    Release tag to install, e.g. v1.1.0. Defaults to the latest release.

.PARAMETER InstallDir
    Where to put the binary. Defaults to %LOCALAPPDATA%\Programs\hightower.

.EXAMPLE
    .\install.ps1
    Installs the latest release and updates your PATH.

.EXAMPLE
    .\install.ps1 -Version v1.0.0
    Installs a specific release.
#>
[CmdletBinding()]
param(
    [string] $Version = 'latest',
    [string] $InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\hightower')
)

$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 can still default to TLS 1.0, which GitHub refuses.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# The download progress bar makes Invoke-WebRequest crawl on 5.1.
$ProgressPreference = 'SilentlyContinue'

$repo = 'gsjonio/hightower'
$assetPattern = 'hightower-*-x86_64-pc-windows-msvc.exe'
$headers = @{ 'User-Agent' = 'hightower-install' }

$releaseUrl = if ($Version -eq 'latest') {
    "https://api.github.com/repos/$repo/releases/latest"
} else {
    "https://api.github.com/repos/$repo/releases/tags/$Version"
}

Write-Host "Looking up the $Version release of $repo..."
$release = Invoke-RestMethod -Uri $releaseUrl -Headers $headers
$asset = $release.assets | Where-Object { $_.name -like $assetPattern } | Select-Object -First 1
if (-not $asset) {
    throw "No Windows binary matching '$assetPattern' in release $($release.tag_name)."
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$target = Join-Path $InstallDir 'hightower.exe'

Write-Host "Downloading $($asset.name)"
# ponytail: the download is trusted on HTTPS + the official repo alone -- there is
# no checksum or signature check, because the release binary is unsigned today.
# Upgrade path: publish checksums (or sign the binary) and verify them here.
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $target -Headers $headers
Write-Host "Installed to $target"

# Put the install folder on the *user* PATH, exactly once.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$entries = if ([string]::IsNullOrEmpty($userPath)) { @() } else { $userPath.Split(';') }
if ($entries -contains $InstallDir) {
    Write-Host "$InstallDir is already on your user PATH."
} else {
    # Deliberately not `setx`: it truncates PATH at 1024 characters.
    $newPath = if ([string]::IsNullOrEmpty($userPath)) { $InstallDir } else { "$userPath;$InstallDir" }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Write-Host "Added $InstallDir to your user PATH."
}

Write-Host ''
Write-Host "hightower $($release.tag_name) installed."
Write-Host 'Open a NEW terminal, then run:  hightower scan'
Write-Host 'The binary is unsigned, so SmartScreen may warn on first run.'
