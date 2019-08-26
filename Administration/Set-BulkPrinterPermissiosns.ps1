function Set-BulkPrinterPermissions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$PrintServer,

        [Parameter(
            Mandatory,
            HelpMessage = "Printer with the correct permissions set that all others will use as a model."
        )]
        [string]$ModelPrinter
    )
    
    $security = Get-Printer -Name $ModelPrinter -ComputerName $PrintServer -Full

    Get-Printer * -ComputerName $PrintServer | Foreach-Object {Set-Printer $_.Name -ComputerName $PrintServer -PermissionSDDL $security.PermissionSDDL}
}

