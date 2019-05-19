function Export-IPv4Configuration {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory)]
        [string]$ExportFile,

        [Parameter(Mandatory)]
        [ValidateSet('CSV','JSON')]
        [string]$ExportFormat
    )
    
    begin {
        # use cim sessions to gather info from remote computer
        $cimsession = New-CimSession -ComputerName $ComputerName  
    }
    
    process {

        # exclusions
        $AdapterExclusions = @(
            "Hyper-V Virtual Ethernet Adapter"
            "Npcap Loopback Adapter"
        )

        $adapter = Get-NetAdapter -CimSession $cimsession | Where-Object {($_.Status -eq "Up") -and ($_.InterfaceDescription -notin $AdapterExclusions)}

        $MAC = $adapter.MacAddress
        $ifIndex = $adapter.ifIndex

        $ip = Get-NetIPAddress -CimSession $cimsession -InterfaceIndex $ifIndex -AddressFamily IPv4
        $IPv4Address = $ip.IPv4Address
        $SubnetMask = $ip.PrefixLength

        $NetIPconfig = Get-NetIPConfiguration -CimSession $cimsession -InterfaceIndex $ifIndex
        $DefaultGateway = $NetIPconfig.IPv4DefaultGateway

        $DNSServerAddress = $NetIPconfig.DNSServer.ServerAddresses
        $PrimaryDNS = $DNSServerAddress[0]
        $AlternateDNS = $DNSServerAddress[1]

        $DNSsuffix = (Get-DnsClient -CimSession $cimsession -InterfaceIndex $ifIndex).Suffix

    }
    
    end {

        $PSObject = [PSCustomObject]@{
            MacAddress = $MAC
            InterfaceIndex = $ifIndex
            IPv4Address = $IPv4Address
            SubnetMask = $SubnetMask
            DefaultGateway = $DefaultGateway
            PrimaryDNS = $PrimaryDNS
            AlternateDNS = $AlternateDNS
            DNSsuffix = $DNSsuffix
        }

        switch ($ExportFormat) {
            CSV { $PSObject | Export-Csv -Path $ExportFile -NoTypeInformation }
            JSON { $PSObject | ConvertTo-Json | Set-Content $ExportFile }
            Default {}
        } 
        
    }
}
