#initial server config
Rename-Computer -NewName DC -Restart:$false

# add new disk
Get-Disk | Where-Object PartitionStyle -eq "RAW" | 
         Initialize-Disk -PartitionStyle GPT -PassThru |
            New-Volume -FileSystem NTFS -DriveLetter E -FriendlyName 'data'


            Set-Disk -Number 1 -IsOffline $false

# set ip address, netmask, gateway, dns server
New-NetIPAddress -InterfaceIndex 2 -IPAddress 10.10.10.10 -PrefixLength 24 -DefaultGateway 10.10.10.1
Set-DnsClientServerAddress -InterfaceIndex 2 -ServerAddresses 10.10.10.10


Restart-Computer


# install AD domain services
Add-WindowsFeature AD-Domain-Services


# add forest and make domain controller
$DomainName = "karl.lab"
$adminpass =  -AsSecureString

Install-ADDSForest -InstallDns -DomainName $DomainName -CreateDNSDelegation -DatabasePath "E:\NTDS" -SysvolPath "F:\SYSVOL" -LogPath "F:\Logs" -SafeModeAdministratorPassword $adminpass
