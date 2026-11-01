#Requires -RunAsAdministrator
# Installs (or updates) the DNSFilter service and its watchdog task.
#
#   powershell -ExecutionPolicy Bypass -File deploy\install.ps1
#
# Build first (cd src; make main). Re-run this script after rebuilding or after
# editing blocked.txt to push the new versions.

param(
    [string]$Exe       = (Join-Path $PSScriptRoot '..\src\main.exe'),
    [string]$Blocklist = (Join-Path $PSScriptRoot '..\blocked.txt')
)

$ErrorActionPreference = 'Stop'

$Name       = 'DNSFilter'
$TaskName   = 'DNSFilter Watchdog'
$InstallDir = Join-Path $env:ProgramFiles 'DNSFilter'
$BackupDir  = Join-Path $env:ProgramData 'DNSFilter'
$Watchdog   = Join-Path $PSScriptRoot 'watchdog.ps1'

foreach ($f in $Exe, $Blocklist, $Watchdog) {
    if (-not (Test-Path $f)) { throw "Missing file: $f" }
}

# Stop the current version so its exe can be overwritten.
if (Get-Service $Name -ErrorAction SilentlyContinue) {
    Stop-Service $Name -Force -ErrorAction SilentlyContinue
}

# Install copy (what the service runs) + backup copy (what the watchdog restores from).
New-Item -ItemType Directory -Force $InstallDir, $BackupDir | Out-Null
foreach ($dir in $InstallDir, $BackupDir) {
    Copy-Item $Exe       (Join-Path $dir 'main.exe')    -Force
    Copy-Item $Blocklist (Join-Path $dir 'blocked.txt') -Force
}
Copy-Item $Watchdog (Join-Path $BackupDir 'watchdog.ps1') -Force

# The watchdog runs as SYSTEM from this folder, so only SYSTEM and Administrators
# may write to it. ProgramData normally lets regular users create files, which
# would let any program on the PC run code as SYSTEM.
icacls $BackupDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

# Watchdog: at startup and every 5 minutes, as SYSTEM.
$action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
             -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$BackupDir\watchdog.ps1`""
$triggers  = @(
    (New-ScheduledTaskTrigger -AtStartup),
    (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5))
)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
             -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers `
    -Principal $principal -Settings $settings -Force | Out-Null

# Run the watchdog now: it creates/configures the service, starts it, and sets DNS.
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 8

$svc = Get-Service $Name -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host "DNSFilter is running. DNS on connected adapters now points at 127.0.0.1." -ForegroundColor Green
    Write-Host "Restart Chrome (or clear chrome://net-internals/#dns) so it drops cached lookups."
} else {
    Write-Warning "DNSFilter is not running yet. Check: sc.exe query $Name  /  Event Viewer > Windows Logs > System"
}
