function Get-DhcpV4ReservationIPAddress {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$MacAddress,

        [Parameter(Mandatory=$true)]
        [string]$DhcpServer
        
    )
    

    # convert macaddress to XX-XX-XX-XX-XX-XX format
    Write-Verbose "Validating MAC Address" -Verbose
    switch ($MacAddress) {
        {$_ -match '\w\w-\w\w-\w\w-\w\w-\w\w-\w\w'} {}
        {$_ -match '\w\w \w\w \w\w \w\w \w\w \w\w'} {$macAddress = $MacAddress -replace ' ','-'}
        {$_ -match '\w\w:\w\w:\w\w:\w\w:\w\w:\w\w'} {$MacAddress = $MacAddress -replace ':','-'}
        {$_ -match '\w\w\w\w\w\w\w\w\w\w\w\w'} {
            $MacSplit = [regex]::Matches($MacAddress,'\w\w') | ForEach-Object {$_.Value}
            $MacAddress = $MacSplit -join '-'
        }
        Default {
            Write-Error "MAC Address is not in the proper format. MAC Address must be in XX-XX-XX-XX-XX-XX, XX:XX:XX:XX:XX:XX, XXXXXXXXXXXX, or XX XX XX XX XX XX format!"
            break
        }
    }

        # Get the DHCP reservation of the MAC address from the print server
        Write-Verbose "Finding the DHCP leases on $DhcpServer from the MAC address $MacAddress" -Verbose
        $DhcpScopes = Get-DhcpServerv4Scope -ComputerName $DhcpServer
        $DhcpReservation = foreach ($scope in $DhcpScopes) {
            Get-DhcpServerv4Lease -ComputerName $DhcpServer $scope.ScopeId | Where-Object {$_.ClientId -eq $MacAddress}
        }
    

    # is dhcp reservation active?
    switch ($DhcpReservation.AddressState) {
        ActiveReservation {
            Write-Output "$MacAddress has an Active Reservation for:"
            Write-Output $DhcpReservation.IPAddress
        }
        InactiveReservation {
            Write-Output "MAC Address $MacAddress has an Inactive DHCP reservation for:"
            $res = ($DhcpReservation | Where-Object {$_.AddressState -eq "InactiveReservation"}).IPAddress
            Write-Output $res.IPAddressToString
        }
        Active {
            Write-Host -BackgroundColor DarkYellow -ForegroundColor Black "$MacAddress is active with the IP Address:"
            $ActiveIPAddress = ($DhcpReservation | Where-Object {$_.AddressState -eq "Active"}).IPAddress
            Write-Host -BackgroundColor DarkYellow -ForegroundColor Black $ActiveIPAddress.IPAddressToString
            Write-Host -BackgroundColor DarkYellow -ForegroundColor Black "in the scope: $($DhcpReservation.ScopeId)"
            Write-Host -BackgroundColor DarkYellow -ForegroundColor Black "but has no reservation."

        }
        Default {
            Write-Error "DHCP state for $MacAddress is $($DhcpReservation.AddressState)"
            break
        }
    }

    $DhcpReservation = $DhcpReservation.IPAddress
 
}
