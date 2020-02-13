function Disable-InactiveNauComputers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [int]$DaysInactive,
        
        [Parameter(Mandatory=$true)]
        [string]$SearchOU,
        
        [Parameter(Mandatory=$true)]
        [string]$DisabledComputersOU
    )
    
    begin {}
    
    process {
        # get all computer accounts that have not been logged into with X days
        $InactiveComputers = Search-ADAccount -AccountInactive -ComputersOnly -DateTime (Get-Date).AddDays(-$DaysInactive) -SearchBase $SearchOU |
            Where-Object { $_.DistinguishedName -notlike "*$DisabledComputersOU*" }

        # disable accounts
        $InactiveComputers | Disable-ADAccount

        # Move to disabled computers OU
        $InactiveComputers | Move-ADObject -TargetPath $DisabledComputersOU -Confirm:$false
        
    }
    
    end {}
}
