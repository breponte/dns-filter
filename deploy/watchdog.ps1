# DNSFilter watchdog. Runs as SYSTEM at startup and every 5 minutes (scheduled task
# "DNSFilter Watchdog", registered by install.ps1). It is idempotent: each run puts
# back whatever is missing or changed.
#
# Lives in C:\ProgramData\DNSFilter next to backup copies of main.exe and blocked.txt.

$ErrorActionPreference = 'Continue'

$Name       = 'DNSFilter'
$InstallDir = Join-Path $env:ProgramFiles 'DNSFilter'
$BackupDir  = $PSScriptRoot
$Exe        = Join-Path $InstallDir 'main.exe'

# 1. Restore the installed files from the backup copies if they were deleted.
New-Item -ItemType Directory -Force $InstallDir | Out-Null
foreach ($f in 'main.exe', 'blocked.txt') {
    $dst = Join-Path $InstallDir $f
    if (-not (Test-Path $dst)) { Copy-Item (Join-Path $BackupDir $f) $dst -Force }
}

# 2. Recreate the service if it was deleted.
if (-not (Get-Service $Name -ErrorAction SilentlyContinue)) {
    sc.exe create $Name binPath= "`"$Exe`"" start= auto DisplayName= "DNS Filter" depend= Tcpip | Out-Null
    sc.exe description $Name "Blocks DNS lookups for domains listed in blocked.txt" | Out-Null
}

# 3. Re-apply the service settings every run, in case someone changed them.
sc.exe config  $Name binPath= "`"$Exe`"" start= auto | Out-Null
#    Restart 1s after the 1st and 2nd failure, 5s after later ones; reset the count daily.
sc.exe failure $Name reset= 86400 actions= restart/1000/restart/1000/restart/5000 | Out-Null
#    Also treat "stopped with an error code" as a failure, not only crashes/kills.
sc.exe failureflag $Name 1 | Out-Null

# 4. Start it if it isn't running.
if ((Get-Service $Name).Status -ne 'Running') {
    Start-Service $Name -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# 5. Only point DNS at 127.0.0.1 while the filter is actually running; otherwise
#    every lookup would fail and the PC would have no internet.
if ((Get-Service $Name).Status -eq 'Running') {
    $changed = $false
    Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
        $current = (Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4).ServerAddresses
        if (($current -join ',') -ne '127.0.0.1') {
            Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses 127.0.0.1
            $changed = $true
        }
        # IPv6 DNS servers (e.g. from the router) would bypass the IPv4-only filter.
        $v6 = Get-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
        if ($v6 -and $v6.Enabled) {
            Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6
            $changed = $true
        }
    }
    if ($changed) { Clear-DnsClientCache }
}

# 6. Stop Chrome and Edge from using secure DNS (DoH), which skips the filter entirely.
foreach ($key in 'HKLM:\SOFTWARE\Policies\Google\Chrome', 'HKLM:\SOFTWARE\Policies\Microsoft\Edge') {
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    Set-ItemProperty -Path $key -Name 'DnsOverHttpsMode' -Value 'off' -Type String
}
