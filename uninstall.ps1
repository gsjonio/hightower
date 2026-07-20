#Requires -Version 5.1
<#
.SYNOPSIS
    Removes hightower and takes it back off your PATH.

.DESCRIPTION
    Deletes the install folder created by install.ps1 and removes it from your
    *user* PATH. No administrator rights are needed. Safe to run when hightower
    is not installed -- it simply reports what was already absent.

.PARAMETER InstallDir
    The folder to remove. Defaults to %LOCALAPPDATA%\Programs\hightower.

.EXAMPLE
    .\uninstall.ps1
#>
[CmdletBinding()]
param(
    [string] $InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\hightower')
)

$ErrorActionPreference = 'Stop'

if (Test-Path -LiteralPath $InstallDir) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
    Write-Host "Removed $InstallDir"
} else {
    Write-Host "$InstallDir does not exist -- nothing to remove."
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$entries = if ([string]::IsNullOrEmpty($userPath)) { @() } else { $userPath.Split(';') }
if ($entries -contains $InstallDir) {
    # Drop only our entry, keep everything else in order.
    $kept = $entries | Where-Object { $_ -ne $InstallDir }
    [Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'User')
    Write-Host "Removed $InstallDir from your user PATH."
} else {
    Write-Host "$InstallDir was not on your user PATH."
}

Write-Host ''
Write-Host 'hightower uninstalled. Open a new terminal for the PATH change to apply.'
