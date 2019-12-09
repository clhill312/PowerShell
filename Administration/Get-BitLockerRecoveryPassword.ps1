function Get-BitLockerRecoveryPassword {
    
    
   [CmdletBinding()]
   Param(
       [Parameter(Mandatory=$True)]
       [ValidateNotNullOrEmpty()]
       [string] $ComputerName,

       [Parameter(Mandatory=$true)]
       [ValidateNotNullOrEmpty]
       [string] $ComputersOU
    )
 
    
    $Computer = Get-ADComputer -Identity $ComputerName

    Get-ADObject -Filter { (objectclass -eq "msFVE-RecoveryInformation")} -Properties "msFVE-RecoveryPassword" -SearchBase $ComputersOU |
        Where-Object {$_.DistinguishedName -like "*$($Computer.Name)*"} |
            ForEach-Object {
                New-Object psobject -Property @{
                ComputerName = (($_.DistinguishedName -split ',')[1] -join ',') -replace "(CN=)"
                RecoveryKey = $_.'msFVE-RecoveryPassword'
                DateTime = $($_.Name).Remove(19)
                PasswordID = ($_.Name -split '{')[1] -replace '}'
                }
            } | Select-Object ComputerName,DateTime,PasswordID,RecoveryKey | Sort-Object DateTime -Descending
     
}
