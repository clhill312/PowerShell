function Export-BitlockerRecoveryKey {
    
    <#
   .SYNOPSIS
       Exports BitLocker recovery keys to a CSV.
   
   .DESCRIPTION
       Used when BitLocker recovery keys need to be saved in a file for later reference.
       Commom scenario is when a computer object has been deleted from Active Directory and object restoration is not possible.
       Requires Domain Admin privileges
        
   .PARAMETER ExportPath
       The location where the CSV file is to be saved.
   
   .EXAMPLE
       Export-BitlockerRecoveryKey -ExportPath \\server\share\folder

   .NOTES
       Contact: carl.l.hill@outlook.com
   
   #>
    
   [CmdletBinding()]
   Param(
       [Parameter(Mandatory=$True)]
       [ValidateNotNullOrEmpty()]
       [string]$ExportPath
    )
 
    $date = Get-Date -Format yyyy-MM-dd_HHmmss

    $computer = Get-ADComputer -Filter * -SearchBase 'OU=Computers,DC=karl,DC=lab'

    Get-ADObject -Filter { objectclass -eq "msFVE-RecoveryInformation"} -Properties "msFVE-RecoveryPassword" |


        ForEach-Object {
            New-Object psobject -Property @{
            ComputerName = (($_.DistinguishedName -split ',')[1] -join ',') -replace "(CN=)"
            RecoveryKey = $_.'msFVE-RecoveryPassword'
            DateTime = $($_.Name).Remove(19)
            PasswordID = ($_.Name -split '{')[1] -replace '}'
            }
        } | Select-Object ComputerName,DateTime,PasswordID,RecoveryKey |
        Export-Csv -Path $ExportPath\blkeys-$date.csv -NoTypeInformation
     
}
