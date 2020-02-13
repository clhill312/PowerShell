function Copy-SecurityGroupMemebership {

    Param(
        [CmdletBinding()]
    
        [Parameter(
            Mandatory=$true,
            HelpMessage = 'SAM Account Name (Pre-Windows 2000 Logon) of the new user'
        )]
        [ValidateNotNullOrEmpty()]
        [string] $NewUserSam,
    
        [Parameter(
            Mandatory=$true,
            HelpMessage = 'SAM Account Name (Pre-Windows 2000 Logon) of the user to mirror permissions from'
        )]
        [ValidateNotNullOrEmpty()]
        [string] $MirrorFromSam,

        [Parameter(
            HelpMessage = 'Use Out-ViewGrid to select groups which to copy membership'
        )]
        [switch] $Gui

    )
    
    

    if ($Gui) {
    # Gathers all of the security groups that the source account is a member of
        $groups = Get-ADUser $MirrorFromSam -Properties memberof | Select-Object -ExpandProperty memberof | Out-GridView -Title "Select Security Groups to add to $NewUserSam" -PassThru
    }
    else {
        $groups = Get-ADUser $MirrorFromSam -Properties memberof | Select-Object -ExpandProperty memberof
    }


    # Adds MirrorFromSam groups to NewUserSam
    Write-Verbose "Copying Security Groups..."
    $groups | Add-ADGroupMember -Members $NewUserSam -Confirm:$false -ErrorAction Ignore -Verbose

    Write-Host "Security Group Copy complete."
}
