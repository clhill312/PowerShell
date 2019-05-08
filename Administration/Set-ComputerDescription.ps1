function Set-ComputerDescription {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [Parameter()]
        [string]$Description,

        [Parameter()]
        [switch]$ADDescription

    )
    
    BEGIN {}
    
    PROCESS {

        foreach ($Computer in $ComputerName) {

            if ($ADDescription) {
                $Description = (Get-ADComputer -Identity $Computer -Properties Description).Description
            }
            
            Get-CimInstance -ComputerName $Computer -ClassName Win32_OperatingSystem | Set-CimInstance -Property @{Description = $Description}
            Get-CimInstance -ComputerName $Computer -ClassName Win32_OperatingSystem | Select-Object Description
        }
    }
    
    END {}

}

