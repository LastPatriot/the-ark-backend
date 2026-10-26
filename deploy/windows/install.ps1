#Requires -RunAsAdministrator
<#
Installs Ark to start at boot on Windows: a Scheduled Task running as SYSTEM at
startup, restarted on failure, plus private-network firewall rules.

    powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1 [-Dns] [-DnsUpstream 192.168.1.1]

Program: C:\Program Files\Ark\ark.exe
Config:  C:\ProgramData\Ark\ark.toml (written once; edit and rerun to restart)
Data:    C:\ProgramData\Ark\data
Log:     C:\ProgramData\Ark\ark.log (the first-run admin setup code is printed here)
#>
param(
    [string]$Binary = "$PSScriptRoot\..\..\target\release\the-ark.exe",
    [switch]$Dns,
    [string]$DnsUpstream = ""
)
$ErrorActionPreference = 'Stop'
$InstallDir = Join-Path $env:ProgramFiles 'Ark'
$DataDir = Join-Path $env:ProgramData 'Ark'
$Exe = Join-Path $InstallDir 'ark.exe'
$Log = Join-Path $DataDir 'ark.log'
$Config = Join-Path $DataDir 'ark.toml'

if (-not (Test-Path $Binary)) { throw "Binary not found: $Binary (build with: cargo build --release)" }

# Stop a running copy so the binary can be replaced.
Stop-ScheduledTask -TaskName 'Ark' -ErrorAction SilentlyContinue
Get-Process -Name 'ark' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Exe } | Stop-Process -Force
Start-Sleep -Seconds 1

New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir | Out-Null
Copy-Item -Force $Binary $Exe

if (-not (Test-Path $Config)) {
    $dnsLine = if ($Dns) { 'true' } else { 'false' }
    $upstreamLine = if ($DnsUpstream) { "dns_upstream = `"$DnsUpstream`"" } else { '# dns_upstream = "192.168.1.1"  # the router' }
    $toml = @"
# Ark configuration. Same keys as the ARK_* variables, lowercased (ARK_BACKEND.md section 3).
bind = "0.0.0.0:80"
data_dir = '$DataDir\data'
hostname = "ark"
session_hours = 12
docs = true
dns = $dnsLine
dns_bind = "0.0.0.0:53"
$upstreamLine
"@
    # UTF-8 without BOM.
    [System.IO.File]::WriteAllText($Config, $toml)
}

# Firewall: private/domain networks only.
Get-NetFirewallRule -Group 'Ark' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$common = @{ Group = 'Ark'; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Private,Domain'; Program = $Exe }
New-NetFirewallRule @common -DisplayName 'Ark HTTP' -Protocol TCP -LocalPort 80 | Out-Null
New-NetFirewallRule @common -DisplayName 'Ark mDNS' -Protocol UDP -LocalPort 5353 | Out-Null
if ($Dns -or (Select-String -Path $Config -Pattern '^\s*dns\s*=\s*true' -Quiet)) {
    New-NetFirewallRule @common -DisplayName 'Ark DNS (UDP)' -Protocol UDP -LocalPort 53 | Out-Null
    New-NetFirewallRule @common -DisplayName 'Ark DNS (TCP)' -Protocol TCP -LocalPort 53 | Out-Null
}

# cmd.exe redirects output to the log; the task's working directory holds ark.toml.
$action = New-ScheduledTaskAction -Execute 'cmd.exe' `
    -Argument "/c `"`"$Exe`" >> `"$Log`" 2>&1`"" -WorkingDirectory $DataDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'Ark' -Description 'Ark shared media drive' `
    -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'Ark'

$ok = $false
foreach ($i in 1..15) {
    Start-Sleep -Seconds 1
    try { if ((Invoke-WebRequest -UseBasicParsing 'http://127.0.0.1/healthz' -TimeoutSec 2).Content -eq 'ok') { $ok = $true; break } } catch {}
}
if ($ok) { Write-Host 'Ark is running: http://ark.local  (docs: http://ark.local/docs)' -ForegroundColor Green }
else { Write-Warning "Ark did not answer on port 80 yet; check $Log (is another program using port 80?)" }

$code = Select-String -Path $Log -Pattern 'setup code: (\d+)' -ErrorAction SilentlyContinue | Select-Object -Last 1
if ($code) { Write-Host "First-run admin setup code: $($code.Matches[0].Groups[1].Value)" -ForegroundColor Yellow }

$public = Get-NetConnectionProfile | Where-Object NetworkCategory -eq 'Public'
foreach ($p in $public) {
    Write-Warning "Network '$($p.Name)' is Public; phones cannot reach Ark. Fix: Set-NetConnectionProfile -InterfaceAlias '$($p.InterfaceAlias)' -NetworkCategory Private"
}
