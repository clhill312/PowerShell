 function Add-BulkGroupMembership {
 
 <#
.SYNOPSIS
    Add users to security groups in bulk.

.DESCRIPTION
    Imports a CSV with the 1st column containing users' ID number to the 2nd column (Group) which is the name
    of the AD security group to which the users are to be added. If users are to be added to multiple security groups,
    than their ID number will appear more than once in the CSV:

    IdNumber,Group
    1234567890,LAB-GENERALUSERS
    098765321,LAB-GENERALUSERS
    1234567890,LAB-SPECIALUSERS
    0987654321,LAB-SPECIALUSERS


.PARAMETER CSV
    A Comma Seperated Value (.csv) file that contains ID and Group headers.
    IDNumber column contains ID numbers for the users.
    Group column contains the name of the securiy group for them to be added to.

.PARAMETER LogPath
    The file path that the transcript will be saved to.  Can be a local folder or a network share.

.EXAMPLE
    Add-BulkGroupMembership -CSV "C:\Temp\massaddgroups.csv" -LogPath "\\server\share\logs"

.NOTES
    Contact: carl.l.hill@outlook.com

#>

　
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string]$CSV,

    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string]$LogPath
)

    BEGIN {
        $date = Get-Date -Format yyyy-MM-dd_HHmmss
        [string]$logfile = "Add-BulkGroupMembership-$($date).txt"

        Start-Transcript -Path "$LogPath\$logfile" -Append
    }

    PROCESS {　
        $userlist = Import-Csv $CSV

        foreach ($user in $userlist) {
        
            $AccountDN = (Get-ADUser -Filter {UserPrincipalName -eq "$($user.IdNumber)@mail.com"}).DistinguishedName

            Write-Output "Adding $($user.IdNumber) to $($user.Group)"
            
            $GroupCN = (Get-ADGroup -Filter {CN -eq "$($user.Group)"}).DistinguishedName
            
            Add-ADGroupMember -Identity $GroupCN -Members $AccountDN -Confirm 
        }
    }

    END {
        Stop-Transcript 
    }

}
