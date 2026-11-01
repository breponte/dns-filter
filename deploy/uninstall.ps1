#Requires -RunAsAdministrator
# Removes the DNSFilter service and watchdog and restores normal DNS.
#
#   powershell -ExecutionPolicy Bypass -File deploy\uninstall.ps1

$ErrorActionPreference = 'Continue'

$Name       = 'DNSFilter'
$TaskName   = 'DNSFilter Watchdog'
$InstallDir = Join-Path $env:ProgramFiles 'DNSFilter'
$BackupDir  = Join-Path $env:ProgramData 'DNSFilter'

# Remove the watchdog first, or it would put everything back within 5 minutes.
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

if (Get-Service $Name -ErrorAction SilentlyContinue) {
    sc.exe failure $Name reset= 0 actions= '""' | Out-Null      # no auto-restart while stopping
    Stop-Service $Name -Force -ErrorAction SilentlyContinue
    sc.exe delete $Name | Out-Null
}

# Back to DHCP-provided DNS, IPv6 on (same as the reset block in README.md).
Get-NetAdapter | ForEach-Object {
    Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses
    Enable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
}
Clear-DnsClientCache

foreach ($key in 'HKLM:\SOFTWARE\Policies\Google\Chrome', 'HKLM:\SOFTWARE\Policies\Microsoft\Edge') {
    Remove-ItemProperty -Path $key -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue
}

Remove-Item $InstallDir, $BackupDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "DNSFilter removed; DNS reset to automatic." -ForegroundColor Green
