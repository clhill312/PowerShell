function Get-BitLockerRecoveryPassword {
    <#
    .SYNOPSIS
        Gets the 48-digit Bitlocker recovery password from one or more computers

    .EXAMPLE
        Get-BitLockerRecoveryPassword -ComputerName Win101

        Get-BitLockerRecoveryPassword -ComputerName 'Win101','Win102','Win103'

    #>
    
    [CmdletBinding()]
    Param(

        # can accept one computername or a list of computernames or output from Get-ADComputer
        [Parameter(ValueFromPipeline)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]      
        [string[]]
        $ComputerName
     )
  
    process{
        foreach ($Computer in $ComputerName) {
            $ComputerDN = (Get-ADComputer -Identity $Computer).DistinguishedName
            Get-ADObject -Filter {ObjectClass -eq 'msFVE-RecoveryInformation'} -Properties 'msFVE-RecoveryPassword' -SearchBase $ComputerDN |
                ForEach-Object {
                    [PSCustomObject]@{
                        ComputerName = (($_.DistinguishedName -split ',')[1] -join ',') -replace '(CN=)'
                        RecoveryPassword = $_.'msFVE-RecoveryPassword'
                        DateTime = $($_.Name).Remove(19)
                        PasswordID = ($_.Name -split '{')[1] -replace '}'
                    }
                }

        }
    }
      
 }
