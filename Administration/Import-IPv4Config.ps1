






Set-DnsClient -InterfaceIndex 1 -ConnectionSpecificSuffix $DNSsuffix



# Configure the DNS client server IP addresses
Write-Progress -Activity "Configuring IP..." -Status "Working..." -CurrentOperation "Setting DNS to $DNS1 and $DNS2"
Set-DnsClientServerAddress -InterfaceAlias $Adapter -ServerAddresses ($DNS1,$DNS2)

# Disables IPv6
Write-Progress -Activity "Configuring IP..." -Status "Working..." -CurrentOperation "Disabling IPv6"
Disable-NetAdapterBinding -InterfaceAlias $Adapter -ComponentID ms_tcpip6

# Removes any previous IP settings.  This eliminates errors during script execution.
Write-Progress -Activity "Configuring IP..." -Status "Working..." -CurrentOperation "Removing previous IP settings"
Get-NetAdapter -InterfaceAlias $Adapter | Get-NetIPAddress | Remove-NetIPAddress -Confirm:$false
Remove-NetRoute -InterfaceAlias $Adapter -DestinationPrefix 0.0.0.0/0 -Confirm:$false
   
# Configure the IP address and default gateway
Write-Progress -Activity "Configuring IP..." -Status "Trying Initial IP:" -CurrentOperation "$subnet.$newIP"
New-NetIPAddress `
-InterfaceAlias $Adapter `
-IPAddress "$subnet.$newIP" `
-AddressFamily $IPType `
-PrefixLength $MaskBits `
-DefaultGateway $Gateway



    Write-Progress -Activity "IP Configuration" -Status "Trying IP $subnet.$newIP" -CurrentOperation "Reconfiguring..."
    Get-NetAdapter -InterfaceAlias $Adapter | Get-NetIPAddress | Remove-NetIPAddress -Confirm:$false
   
    # Configure the IP address and default gateway
    New-NetIPAddress -InterfaceAlias $Adapter -IPAddress "$subnet.$newIP" -AddressFamily $IPType -PrefixLength $MaskBits
    Start-Sleep -Seconds 4

