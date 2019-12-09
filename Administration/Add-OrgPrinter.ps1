function Add-OrgPrinter {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$PrintServer,

        [Parameter()]
        [string]$DhcpReservationIPAddress,

        [Parameter(Mandatory=$true)]
        [string]$MacAddress,

        [Parameter(Mandatory=$true)]
        [ValidatePattern('[A-Z]')]
        [ValidateLength(4,4)]
        [string]$Location,

        [Parameter(Mandatory=$true)]
        [ValidateLength(6,6)]
        [string]$UID,

        [Parameter(Mandatory=$true)]
        [ValidateSet("MC","PL")]
        [string]$FunctionalCode,

        [Parameter()]
        [string]$Description
    )
    
    begin {
        # concatinate the $Location+$UID+$FunctionalCode
        $PrinterName = $Location+$UID+$FunctionalCode
        
        # get list of all devices on $PrintServer like the concatination
        $CurrentPrinterNames = Get-Printer -ComputerName $PrintServer | Where-Object {$_.Name -like "$PrinterName*"}

        #generate array of all possible names
        Write-Verbose "Determining the new printer name from list of available names..." -Verbose
        $PossiblePrinterNames = [System.Collections.ArrayList]::new()

        [int]$n = 0
        while ($n -le 998) {
            $n++
            [string]$fn = $n
            $fn = $fn.PadLeft(3,'0')
            $PossiblePrinterNames.Add($PrinterName+$fn) | Out-Null
        }

        # get list of available printer names
        $UntakenPrinterNames = Compare-Object -ReferenceObject $CurrentPrinterNames.Name -DifferenceObject $PossiblePrinterNames | Where-Object {$_.SideIndicator -eq '=>'}
        
        # 1st untaken name becomes the new printer name
        $NewPrinterName = $UntakenPrinterNames.InputObject[0]
        Write-Verbose "New printer name will be $NewPrinterName" -Verbose

        # create list of drivers from driver names on print server
        Write-Verbose "Gathering list of print drivers..." -Verbose
        $PrinterList = Get-Printer -ComputerName $PrintServer
        $PrinterDriverList = [System.Collections.ArrayList]::new()
        foreach ($PrintDriverName in $PrinterList.DriverName) {
            if (-not($PrinterDriverList -contains $PrintDriverName)) {
                $PrinterDriverList.Add($PrintDriverName) | Out-Null
            }
        }

        # choose from list of drivers
        $SelectedPrinterDriver = $PrinterDriverList | Sort-Object | Out-GridView -Title "Select the Printer Driver" -PassThru
        
        # printer comment 
        $PrinterComment =  "$FunctionalCode - $PrinterDhcpReservation - $Description"
        
    
        # compile arguments
        $PrinterArgs = @{
            ComputerName = $PrintServer
            Comment = $PrinterComment
            DriverName = $SelectedPrinterDriver
            Name = $NewPrinterName
            Shared = $true
        }

        $PrinterPortArgs = @{
            ComputerName = $PrintServer
            Name = $PrinterIPAddress
            PrinterHostAddress = $PrinterIPAddress
        }

        $SetPrinterArgs = @{
            Name = $NewPrinterName
            ComputerName = $PrintServer
            PortName = $PrinterIPAddress
        }
    }
    
    process {
        # add printer with, generated printer name, driver name, comments
        Write-Verbose "adding the printer:" -Verbose
        $PrinterArgs
        #Add-Printer @PrinterArgs

        # printer port
        Write-Verbose "adding printer port:" -Verbose
        $PrinterPortArgs
        #Add-PrinterPort @PrinterPortArgs
        Write-Verbose "setting printer" -Verbose
        $SetPrinterArgs
        #Set-Printer @SetPrinterArgs
    }
    
    end {}

}
