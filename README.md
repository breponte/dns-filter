# DNS Filter

Hello world!

```
Get-NetAdapter | ForEach-Object {
    Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses
    Enable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6
}
Clear-DnsClientCache
```

```
Get-NetAdapter | Where Status -eq Up | ForEach-Object {
    Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses 127.0.0.1
    Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6
}
Clear-DnsClientCache
```

```
Resolve-DnsName youtube.com
Resolve-DnsName youtube.com -Server 127.0.0.1
```