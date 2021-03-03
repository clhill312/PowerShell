function Get-IPv4Configuration {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [string[]]
        $ComputerName = $env:COMPUTERNAME
    )
    
    process {

        foreach ($Computer in $ComputerName) {

            # use cim sessions to gather info from remote computer
            $cimsession = New-CimSession -ComputerName $Computer 
        
            $adapters = Get-NetAdapter -CimSession $cimsession
            
            foreach ($adapter in $adapters) {

                $ifIndex = $adapter.ifIndex

                $ip = Get-NetIPAddress -CimSession $cimsession -InterfaceIndex $ifIndex -AddressFamily IPv4

                $NetIPconfig = Get-NetIPConfiguration -CimSession $cimsession -InterfaceIndex $ifIndex

                $DNSServerAddress = $NetIPconfig.DNSServer.ServerAddresses
                if ($DNSServerAddress -is [array]) {
                    $PrimaryDNS = $DNSServerAddress[0]
                    $AlternateDNS = $DNSServerAddress[1]
                }
                else {
                    $PrimaryDNS = $DNSServerAddress
                    $AlternateDNS = $null
                }


                $DNSsuffix = (Get-DnsClient -CimSession $cimsession -InterfaceIndex $ifIndex).Suffix
                
                
                # final output of psobject
                [PSCustomObject]@{
                    ComputerName = $Computer
                    Status = $adapter.Status
                    Name = $adapter.Name
                    InterfaceDescription = $adapter.InterfaceDescription
                    MAC = $adapter.MacAddress
                    InterfaceIndex = $ifIndex
                    IPv4Address = $ip.IPv4Address
                    SubnetMask = $ip.PrefixLength
                    DefaultGateway = $NetIPconfig.IPv4DefaultGateway.NextHop
                    PrimaryDNS = $PrimaryDNS
                    AlternateDNS = $AlternateDNS
                    DNSsuffix = $DNSsuffix
                }

            }

        }

    }
    
    
}
