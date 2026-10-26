#Requires -RunAsAdministrator
<#
Removes the Ark startup task, firewall rules and program files.
Data in C:\ProgramData\Ark is kept unless -Purge is given.

    powershell -ExecutionPolicy Bypass -File deploy\windows\uninstall.ps1 [-Purge]
#>
param([switch]$Purge)
$ErrorActionPreference = 'Stop'
$InstallDir = Join-Path $env:ProgramFiles 'Ark'
$DataDir = Join-Path $env:ProgramData 'Ark'
$Exe = Join-Path $InstallDir 'ark.exe'

Stop-ScheduledTask -TaskName 'Ark' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'Ark' -Confirm:$false -ErrorAction SilentlyContinue
Get-Process -Name 'ark' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Exe } | Stop-Process -Force
Get-NetFirewallRule -Group 'Ark' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
if ($Purge) {
    Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
    Write-Host 'Ark removed, including all data.'
} else {
    Write-Host "Ark removed. Data kept in $DataDir (use -Purge to delete)."
}
