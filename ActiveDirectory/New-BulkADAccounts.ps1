function New-BulkADAccounts {

<#
.SYNOPSIS
Creates AD user accounts in bulk

.DESCRIPTION
Describe the function in more detail

.EXAMPLE
Create-Account -Spreadsheet C:\Temp\accounts.csv -AccountType test

.PARAMETER AccountType
Specify TEST or PRODUCTION account. TEST account will be created into the TEST OU and PRODUCTION account will go into the production OU.

.PARAMETER SpreadSheet
The CSV files used to import the user information.
The CSV file will need the following columns:

FirstName,MI,LastName,EmployeeID,Expiration,EnterpriseName,Team,MirrorAccount

.NOTES

EnterpriseName is the user's enterprise email address without the Persona Type or the @company.com
The format to identify the MirrorAccount is the user's EnterpiseName WITH the Persona Type included, but not the @company.com


#>

　

[CmdletBinding()]
Param(
[Parameter(Mandatory=$True,Position=1)]
[alias("CSV")]
[string]$SpreadSheet,

[Parameter(Mandatory=$True)]
[alias("type")]
[string]$AccountType

)

BEGIN {
   

    $date = Get-Date -Format yyyy-MM-dd_HHmmss
    $logpath = "\\server\share\logs"
    $logfile = "AccountCreation-$($date).txt"
    $i = 0 # interval set at 0 for use with the progress bar
    $pass = ConvertTo-SecureString "!QAZ@WSX3edc4rfv" -AsPlainText -Force # password is required for account creation but is changed by SCRIL
    $successes = 0 # sets the success counter at 0
    $fails = 0 # sets the fail counter at 0

    if ($AccountType -eq "production") {$OU = "OU=production,DC=KARL,DC=LAB"}
    elseif ($AccountType -eq "test") {$OU = "OU=production,DC=KARL,DC=LAB"}

    $sam = "$($user.EmployeeID).$($user.Persona)"
    $UPN = "$($user.EmployeeID)@company.com"
    $Team = "$($user.Team)"
    $MirrorAccount = $user.MirrorAccount


    $userlist = Import-Csv $spreadsheet
    $totalusers = $userlist | Measure-Object

    $NewUser = @{
        
            UserPrincipalName = $UPN
            SamAccountName = $sam
            Name = "$($user.EnterpriseName).$($user.Persona)"
            GivenName = $user.FirstName
            Initials = $user.MI
            Surname = $user.LastName
            EmailAddress = "$($user.EnterpriseName).$($user.Persona)@company.com"
            DisplayName = "$($user.LastName), $($user.FirstName) $($user.Persona) COMPANY"
            AccountExpirationDate = $user.Expiration
            AccountPassword = $pass
            ChangePasswordAtLogon = $false
            CannotChangePassword = $false
            SmartCardLogonRequired = $true
            Enabled = $true
            Description = $user.Team
            Path = $OU
            ScriptPath = "Scripts\logonscript.vbs"
            OtherAttributes = @{'extensionAttribute5'="$($user.EnterpriseName).$($user.Persona)@company.com"}
            employeeID = $user.EmployeeID
        
        }


    Start-Transcript -Path $logpath\$logfile -Append -Force

}

　

PROCESS {

    foreach ($user in $userlist) {


        $i++ # Adds +1 to the interval
        Write-Progress -Activity "Creating User $i of $($totalusers.Count)" -CurrentOperation "Creating User: $sam" -PercentComplete (($i/$totalusers.Count) *100)

    　

        # If user does not already have AD account in the domain, create the account.

        if (-Not (Get-ADUser -Filter {UserPrincipalName -eq $UPN})) {

            Try {

                New-ADUser @NewUser -Verbose

                # Adds user to their team's GeneralUser group if no mirror account is specified.
                if ($MirrorAccount -eq "No"){

                    switch ($Team) {
                        "GROUP1" {$GenUserGroup = 'GRP1-GENERALUSERS'; break}
                        "GROUP2" {$GenUserGroup = 'GRP2-GENERALUSERS'; break}
                        "Other" {"Manually Add SGs"; break}
                        default {"No Group Identified"; break}
                        }

                Add-ADGroupMember -Identity $GenUserGroup -Members $sam

                }

                # Mirrors Group membership if a MirrorAccount is specified
                else {
                    $MirrorAccountSAM = (Get-ADUser -Filter {Name -eq $MirrorAccount}).SamAccountName

                    Get-ADUser $MirrorAccountSAM -Properties memberof | Select-Object -ExpandProperty memberof |
                    Add-ADGroupMember -Members $sam -ErrorAction SilentlyContinue

                    Write-Verbose "Mirroring $MirrorAccount group membership to $sam"
                }

                    Write-Output "Created user $($UPN)"
                    $successes++
            }

            Catch {
                Write-Error "There was a problem creating $($user.EmployeeID)!"
                $fails++
            }

        }

    　

        # Check for and rename the Visitor account if it already exists
        elseif (Get-ADuser -Filter {UserPrincipalName -eq $UPN} -SearchBase "OU=Visitors,DC=karl,DC=lab") {

            Write-Warning "User has an active Visitor account..."

            # Replaces the last 8 characters of the UPN to XXXX@company.com
            $DisabledUPN = "$($UPN -replace ".{8}$")XXXX@company.com"

            Write-Output "Renaming Visitor account to $DisabledUPN"

            Get-ADUser -Filter {UserPrincipalName -eq $UPN} | Set-ADUser -UserPrincipalName $DisabledUPN -Confirm

            Try {
                New-ADUser @NewUser -Verbose
        
                # Adds user to their team's GeneralUser group if no mirror account is specified.
                if ($MirrorAccount -eq "No"){
        
                    switch ($Team) {
                        "GROUP1" {$GenUserGroup = 'GRP1-GENERALUSERS'; break}
                        "GROUP2" {$GenUserGroup = 'GRP2-GENERALUSERS'; break}
                        "Other" {"Manually Add SGs"; break}
                        default {"No Group Identified"; break}
                    }
        
                Add-ADGroupMember -Identity $GenUserGroup -Members $sam
        
                }
        
                # Mirrors Group membership if a MirrorAccount is specified
                else {
                    $MirrorAccountSAM = (Get-ADUser -Filter {Name -eq $MirrorAccount}).SamAccountName
            
                    Get-ADUser $MirrorAccountSAM -Properties memberof | Select-Object -ExpandProperty memberof |
                    Add-ADGroupMember -Members $sam -ErrorAction SilentlyContinue
            
                    Write-Verbose "Mirroring $MirrorAccount group membership to $sam"
                }
        

        
            Write-Output "Created user $($UPN)"
            $successes++
            }
        
            Catch {
                Write-Error "There was a problem creating $($user.EmployeeID)!"
                $fails++
            }
        
        }
        

        # Displays the existing user
        else {
            Write-Error "A user with ID number $($user.EmployeeID) already exists!" -Category ResourceExists
            $fails++
        }

    }
}


END {
    Write-Host -BackgroundColor Green "Created $($successes) accounts successfully."
    Write-Host -BackgroundColor Red "Failed to create $($fails) accounts."

    Stop-Transcript
}

}
