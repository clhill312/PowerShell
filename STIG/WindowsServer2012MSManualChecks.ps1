<#
    V-1121
    V-1120
    V-7002
    V-6840
    V-14225
    V-32274
    V-40200
    V-40202
    V-40237
    V-57653
    V-80473
    V-1112
    V-3472
    V-73085
    V-80477
    V-1168
    V-3289
    V-1074
    V-3481
    V-14268
    V-14269
    V-14270
    V-15727
    V-16021
    V-16048
    V-36656
    V-36657
    V-36657
    V-36667
    V-36668
    V-36722
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$ComputerName
)

BEGIN {

    # check for NTFSSecurity Module
    try {
        Get-Module -Name NTFSSecurity
    }
    catch {
        throw "NTFSSecurity Module not installed! Install the modules with `n
        Install-Module -Name NTFSSecurity -Repository PSGallery -Force"
    }

$report = [System.Collections.ArrayList]::new() # create results array

#region functions
function Add-ObjectToReport {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $VulnNo,

        [Parameter()]
        [string]
        $RuleName,

        [Parameter()]
        [string]
        $Finding,

        [Parameter()]
        [string]
        $FindingComment
    )

    $obj = New-Object -TypeName PSObject # create new object
    $obj | Add-Member -MemberType NoteProperty -Name Vulnerability -Value $VulnNo
    $obj | Add-Member -MemberType NoteProperty -Name RuleTitle -Value $RuleName
    $obj | Add-Member -MemberType NoteProperty -Name IsFinding -Value $Finding
    $obj | Add-Member -MemberType NoteProperty -Name Comment -Value $FindingComment
    $report.Add($obj) | Out-Null # add object to array
    
}
function Get-SecurityAuditPolicy {
    <#
        borrowed code from https://github.com/claudiospizzi/SecurityFever
    #>

    [CmdletBinding()]
    param ()

    # Use the helper functions to execute the auditpol.exe queries.
    $csvAuditCategories = (auditpol.exe /list /subcategory:* /r) | Where-Object { -not [String]::IsNullOrEmpty($_) } | ConvertFrom-Csv
    $csvAuditSettings   = (auditpol.exe /get /category:* /r) | Where-Object { -not [String]::IsNullOrEmpty($_) } | ConvertFrom-Csv

    foreach ($csvAuditCategory in $csvAuditCategories) {
        # If the Category/Subcategory field starts with two blanks, it is a
        # subcategory entry - else a category entry.
        if ($csvAuditCategory.'GUID' -like '{*-797A-11D9-BED3-505054503030}') {
            $lastCategory     = $csvAuditCategory.'Category/Subcategory'
            $lastCategoryGuid = $csvAuditCategory.GUID
        }
        else {
            $csvAuditSetting = $csvAuditSettings | Where-Object { $_.'Subcategory GUID' -eq $csvAuditCategory.GUID }

            # Return the result object
            [PSCustomObject] @{
                PSTypeName      = 'SecurityFever.AuditPolicy'
                ComputerName    = $csvAuditSetting.'Machine Name'
                Category        = $lastCategory
                CategoryGuid    = $lastCategoryGuid
                Subcategory     = $csvAuditSetting.'Subcategory'
                SubcategoryGuid = $csvAuditSetting.'Subcategory GUID'
                AuditSuccess    = $csvAuditSetting.'Inclusion Setting' -like '*Success*'
                AuditFailure    = $csvAuditSetting.'Inclusion Setting' -like '*Failure*'
            }
        }
    }
}
function Get-SWLocalPasswordLastSet {
    <#
        Borrowed code from unknown origin
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]$UserName,

        [Parameter(Mandatory=$true)]
        [String]$ComputerName
    )

    Try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement 
        $PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $ComputerName)
        $User = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($PrincipalContext, $UserName)
        $User.LastPasswordSet
    }

    Catch {
        Write-Warning -Message "$($_.Exception.Message)"
    }

}
function Get-LocalGroupMember {

    <#
        Borrowed code from unknown origin
    #>

    [CmdletBinding()]
    
    param(
    
        [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$true)]
        [string]$GroupName
    
    )

    
    BEGIN {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement

        $ctype = [System.DirectoryServices.AccountManagement.ContextType]::Machine
    }
    
    PROCESS {
    
        foreach ($computer in $computername) {
        
            $context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $ctype, $computer
            
            $idtype = [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName
            
            $group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($context,$idtype,$GroupName)
            
            $group.Members | Select-Object @{N='Server'; E={$computer}}, @{N='Domain'; E={$_.Context.Name}}, SamAccountName
        
        }
    
    }
    
}
function Get-Software {
    <#
        Borrowed code from unknown origin; shares similarities to http://powershellpr0mpt.com
    #>

    [OutputType('System.Software.Inventory')]
    
    [Cmdletbinding()] 
    
    Param( 
    
        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)] 
        
        [String]$Computername
    
    )         
    
    BEGIN {}
    
    PROCESS {
    
        foreach  ($Computer in  $Computername){ 
        
            if (Test-Connection -ComputerName  $Computer -Count  1 -Quiet) {
            
                $Paths  = @("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall","SOFTWARE\\Wow6432node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")         
                
                foreach ($Path in $Paths) {
                
                    Write-Verbose "Checking Path: $Path"
                    
                    # Create an instance of the Registry Object and open the HKLM base key 
                    try  { 
                        $reg=[microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$Computer,'Registry64') 
                    }
                    
                    catch {
                        Write-Error $_ 
                        Continue 
                    } 
                    
                    # Drill down into the Uninstall key using the OpenSubKey Method 
                    
                    try  {
                        $regkey=$reg.OpenSubKey($Path)  
                    
                        # Retrieve an array of string that contain all the subkey names 
                        $subkeys=$regkey.GetSubKeyNames()      
                    
                        # Open each Subkey and use GetValue Method to return the required  values for each 
                        foreach ($key in $subkeys) {
                        
                            Write-Verbose "Key: $Key"
                            
                            $thisKey=$Path+"\\"+$key 
                            
                            try {
                            
                                $thisSubKey = $reg.OpenSubKey($thisKey)   
                                
                                # Prevent Objects with empty DisplayName
                                $DisplayName =  $thisSubKey.getValue("DisplayName")
                                
                                if ($DisplayName -and $DisplayName  -notmatch '^Update  for|rollup|^Security Update|^Service Pack|^HotFix') {
                                
                                $Date = $thisSubKey.GetValue('InstallDate')
                                
                                if ($Date) {
                                    try { 
                                        $Date = [datetime]::ParseExact($Date, 'yyyyMMdd', $Null)
                                    }
                                    catch {  
                                        Write-Warning "$($Computer): $_ <$($Date)>"
                                        $Date = $Null
                                    }
                                } 
                                
                                # Create New Object with empty Properties
                                $Publisher =  try {
                                    $thisSubKey.GetValue('Publisher').Trim()
                                } 
                                
                                catch {
                                    $thisSubKey.GetValue('Publisher')
                                }
                                
                                $Version = try {
                                    #Some weirdness with trailing [char]0 on some strings
                                    $thisSubKey.GetValue('DisplayVersion').TrimEnd(([char[]](32,0)))
                                } 
                                
                                catch {
                                    $thisSubKey.GetValue('DisplayVersion')
                                }
                                
                                $UninstallString = try {
                                    $thisSubKey.GetValue('UninstallString').Trim()
                                } 
                                
                                catch {
                                    $thisSubKey.GetValue('UninstallString') 
                                }
                                
                                $InstallLocation = try {
                                    $thisSubKey.GetValue('InstallLocation').Trim()
                                } 
                                
                                catch {
                                    $thisSubKey.GetValue('InstallLocation')
                                }
                                
                                $InstallSource = try {
                                    $thisSubKey.GetValue('InstallSource').Trim()
                                } 
                                
                                catch {
                                    $thisSubKey.GetValue('InstallSource')
                                }
                                
                                $HelpLink = try { 
                                    $thisSubKey.GetValue('HelpLink').Trim()
                                } 
                                
                                catch {
                                    $thisSubKey.GetValue('HelpLink')
                                }
                                
                                $Object = [pscustomobject]@{
                                    Computername = $Computer
                                    DisplayName = $DisplayName
                                    Version  = $Version
                                    InstallDate = $Date
                                    Publisher = $Publisher
                                    UninstallString = $UninstallString
                                    InstallLocation = $InstallLocation
                                    InstallSource  = $InstallSource
                                    HelpLink = $thisSubKey.GetValue('HelpLink')
                                    EstimatedSizeMB = [decimal]([math]::Round(($thisSubKey.GetValue('EstimatedSize')*1024)/1MB,2))
                                }
                                
                                $Object.pstypenames.insert(0,'System.Software.Inventory')
                                
                                Write-Output $Object
                                
                                }
                            
                            }
                            
                            catch {
                                Write-Warning "$Key : $_"
                            }   
                        
                        }
                    
                    }
                    
                    catch {}
                    
                    $reg.Close() 
                
                }
            
            }

            else {
                Write-Error  "$($Computer): unable to reach remote system!"
            }
        
        }
    
    }

    END {}

}

#endregion

#Get local security policy
$AuditPolicy = Invoke-Command -ComputerName $ComputerName -ScriptBlock ${function:Get-SecurityAuditPolicy}

}
    

PROCESS {

    #region 1121
    $VulnNo = "1121"
    $RuleName = "FTP System File Access"
    $Check = Get-WindowsFeature -ComputerName $ComputerName -Name Web-Ftp-Server

    switch ($Check.InstallState) {
        Available {
            $Finding = "N/A"
            $FindingComment = "FTP is not installed"
        }
        Removed {
            $Finding = "N/A"
            $FindingComment = "FTP is not installed"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "FTP role is installed; Manual Check must be performed"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 1120
    $VulnNo = "1120"
    $RuleName = "Prohibited FTP Logins"

    $Check = Get-WindowsFeature -ComputerName $ComputerName -Name Web-Ftp-Server

    switch ($Check.InstallState) {
        Available {
            $Finding = "N/A"
            $FindingComment = "FTP is not installed"
        }
        Removed {
            $Finding = "N/A"
            $FindingComment = "FTP is not installed"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "FTP role is installed; Manual Check must be performed"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 7002
    $VulnNo = "7002"
    $RuleName = "Password Requirement"

    $Check = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True and Disabled=False" -ComputerName $ComputerName
    switch ($Check.PasswordRequired) {
        $null {
            $Finding = $false
            $FindingComment = "No accounts without a password were found"
        }
        $true {
            $Finding = $false
            $FindingComment = "No accounts without a password were found"
        }
        $false {
            $Finding = $true
            $FindingComment = $Check.Name
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "Unable to determine, manual check required"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 6840
    $VulnNo = "6840"
    $RuleName = "Password Expiration"

    $Check = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True and Disabled=False" -ComputerName $ComputerName
    switch ($Check.PasswordExpires) {
        $null {
            $Finding = $false
            $FindingComment = "No accounts without a password expriation were found"
        }
        $true {
            $Finding = $false
            $FindingComment = "No accounts without a password expriation were found"
        }
        $false {
            $Finding = $true
            $FindingComment = "$($Check.Name) - $($Check.PasswordExpires)"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "Unable to determine, manual check required"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 14225
    $VulnNo = "14225"
    $RuleName = "Administrator Account Password Changes"

    $BuiltInAdminAccount = Get-CimInstance -Class Win32_Useraccount -Filter "LocalAccount=True" -ComputerName $ComputerName | Where-Object {$_.SID -like "*-500"}

    $BuiltInAdminAccountPwLastSetDate = Get-SWLocalPasswordLastSet -UserName $BuiltInAdminAccount.Name -ComputerName $ComputerName
        
    $YearAgo = (Get-Date).AddYears(-1)
    $Check = $BuiltInAdminAccountPwLastSetDate -le $YearAgo

    switch ($Check) {
        $true {
            $Finding = $true
            $FindingComment = "PW last set $BuiltInAdminAccountPwLastSetDate"
        }
        $false {
            $Finding = $false
            $FindingComment = "PW last set $BuiltInAdminAccountPwLastSetDate is after $YearAgo"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "Unable to determine, manual check required"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 32274
    $VulnNo = "32274"
    $RuleName = "WINPK-000003"

    $DoDCerts = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-ChildItem -Path Cert:Localmachine\disallowed | Where-Object {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | Select-Object Subject,Issuer,Thumbprint,NotAfter
        }

    $Check = ($DoDCerts.Thumbprint -contains "22BBE981F0694D246CC1472ED2B021DC8540A22F") -and ($DoDCerts.Thumbprint -contains "AC06108CA348CC03B53795C64BF84403C1DBD341")

    switch ($Check) {
        $true {
            $Finding = $false
            $FindingComment = "DoD Cross Certs 22BBE981F0694D246CC1472ED2B021DC8540A22F and AC06108CA348CC03B53795C64BF84403C1DBD341 were found in the Untrusted Certificates Store"
        }
        $false {
            $Finding = $true
            $FindingComment = "DoD Cross Certs 22BBE981F0694D246CC1472ED2B021DC8540A22F or AC06108CA348CC03B53795C64BF84403C1DBD341 were not found in the Untrusted Certificates Store"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "Unable to determine, manual check required"
        }
    }  

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 40200
    $VulnNo = "40200"
    $RuleName = "WNAU-000060"

    $Check = $AuditPolicy | Where-Object {($_.Category -eq "Object Access") -and ($_.SubCategory -eq "Central Policy Staging")}

    switch ($Check.AuditFailure) {
        $true {
            $Finding = $false
            $FindingComment = "Object Access -> Central Policy Staging is configured to Failure"
        }
        $false {
            $Finding = $true
            $FindingComment = "Object Access -> Central Policy Staging is not configured to Failure"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "Unable to determine, manual check required"
        }
    }  

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 40202
    $VulnNo = "40202"
    $RuleName = "WNAU-000059"

    $AuditPolicy = Invoke-Command -ComputerName $ComputerName -ScriptBlock ${function:Get-SecurityAuditPolicy}

    $Check = $AuditPolicy | Where-Object {($_.Category -eq "Object Access") -and ($_.SubCategory -eq "Central Policy Staging")}

    switch ($Check.AuditSuccess) {
        $true {
            $Finding = $false
            $FindingComment = "Object Access -> Central Policy Staging is configured to Success"
        }
        $false {
            $Finding = $true
            $FindingComment = "Object Access -> Central Policy Staging is not configured to Success"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "Unable to determine, manual check required"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 40237
    $VulnNo = "40237"
    $RuleName = "WINPK-000004"
    $DoDCerts = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-ChildItem -Path Cert:Localmachine\disallowed | Where-Object {$_.Issuer -Like "*DoD CCEB Interoperability*" -and $_.Subject -Like "*DoD*"} | Select-Object Subject,Issuer,Thumbprint,NotAfter
        }

    $Check = $DoDCerts.Thumbprint -contains "929BF3196896994C0A201DF4A5B71F603FEFBF2E"

    switch ($Check) {
        $true {
            $Finding = $false
            $FindingComment = "DoD CCEB Interoperability Root CA 2 cross-certificate (929BF3196896994C0A201DF4A5B71F603FEFBF2E) was found in the Untrusted Certificates Store"
        }
        $false {
            $Finding = $true
            $FindingComment = "DoD CCEB Interoperability Root CA 2 cross-certificate (929BF3196896994C0A201DF4A5B71F603FEFBF2E) was not found in the Untrusted Certificates Store"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "Unable to determine, manual check required"
        }
    } 

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 57653
    $VulnNo = "57653"
    $RuleName = "WINGE-000056" # temporary user accounts

    $Check = Get-CimInstance -Class Win32_Useraccount -Filter "LocalAccount=True and Disabled=False" -ComputerName $ComputerName
    switch ($Check.AccountExpires) {
        $null {
            $Finding = "N/A"
            $FindingComment = "No temporary local accounts were found"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "Unable to determine, manual check required"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 80473
    $VulnNo = "80473"
    $RuleName = "WIN00-000200" # PowerShell version must support script block logging

    $Check = Invoke-Command -ComputerName $ComputerName -ScriptBlock {$PSVersionTable}
    $FullPsVersion = "$($Check.PSVersion.Major)"+"."+"$($Check.PSVersion.Minor)"

    switch ($Check.PSVersion.Major -ge 4) {
        $true {
            $Finding = $false
            $FindingComment = "PowerShell version is $FullPsVersion"
        }
        $false {
            $Finding = $true
            $FindingComment = "PowerShell version is $FullPsVersion"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "Unable to determine, manual check required"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 1112
    $VulnNo = "1112"
    $RuleName = "Dormant Accounts" # Outdated or unused accounts must be removed from the system or disabled.

    $Check = Invoke-Command -ComputerName $ComputerName -ScriptBlock {

        $LocalUsers = @()
        ([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where-Object { $_.SchemaClassName -eq 'user' } | ForEach-Object {
                $user = ([ADSI]$_.Path)
                $lastLogin = $user.Properties.LastLogin.Value
                $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2

                if ($null -eq $lastLogin) {
                    $lastLogin = 'Never'
                }
                if ($enabled -eq $true) {
                [string]$username = $user.Name
                    if ($username -ne '$Administrator') {
                        $obj = New-Object -TypeName PSObject # create new object
                        $obj | Add-Member -MemberType NoteProperty -Name UserName -Value $username
                        $obj | Add-Member -MemberType NoteProperty -Name LastLogin -Value $lastLogin
                        $obj | Add-Member -MemberType NoteProperty -Name Enabled -Value $enabled
                        $LocalUsers += $obj
                    }
                }
                
            }
            $LocalUsers
            
        }

    switch ($Check.UserName) {
        $null {
            $Finding = $false
            $FindingComment = "No dormant accounts found"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "Unable to determine, manual check required"
        }
    }
        
    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 3472
    $VulnNo = "3472"

    $RuleName = "Windows Time Service - Configure NTP Client"
    $Check = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        ((W32tm /query /configuration | select-string "Type:") -match "NT5DS")
    }


    switch ($Check) {
        $true {
            $Finding = $false
            $FindingComment = "Server is configured to use NTP"
        }
        $false {
            $Finding = $true
            $FindingComment = "Server is not configure to use NTP"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "Unable to determine, manual check required"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 73085
    $VulnNo = "73805"
    $RuleName = "WIN00-000160" #The Server Message Block (SMB) v1 protocol must be disabled on Windows 2012 R2.

    $Check = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Get-WindowsOptionalFeature -Online | Where-Object FeatureName -eq SMB1Protocol
    }


    switch ($Check.State) {
        Disabled {
            $Finding = $false
            $FindingComment = "SMBv1 is disabled"
        }
        Enabled {
            $Finding = $true
            $FindingComment = "SMBv1 is enabled"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "Unable to determine, manual check required"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 80477
    $VulnNo = "80477"
    $RuleName = "WIN00-000220" #Windows PowerShell 2.0 must not be installed on Windows 2012/2012 R2.

    $Check = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Get-WindowsFeature -Name PowerShell-v2
    }


    switch ($Check.InstallState) {
        Removed {
            $Finding = $false
            $FindingComment = "PowerShell v2 is not installed"
        }
        Available {
            $Finding = $false
            $FindingComment = "PowerShell v2 is not installed"
        }
        Installed {
            $Finding = $true
            $FindingComment = "PowerShell v2 is installed"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "Unable to determine, manual check required"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 1168
    $VulnNo = "1168"
    $RuleName = "Members of the Backup Operators"

    $Check = Get-LocalGroupMember -ComputerName $ComputerName -GroupName "Backup Operators"

    switch ($Check.SamAccountName) {
        $null {
            $Finding = "N/A"
            $FindingComment = "No users found in the Backup Operators group"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "$($Check.SamAccountName) are members of the Backup Operators group"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 3289
    $VulnNo = "3289"
    $RuleName = "Intrusion Detection System"

    $Check = Get-Software -Computername $ComputerName | Where-Object {$_.DisplayName -like "McAfee Host Intrusion Prevention"}

    switch ($Check.SamAccountName) {
        $null {
            $Finding = $true
            $FindingComment = "McAfee HIPS is not installed"
        }
        $true {
            $Finding = $false
            $FindingComment = "McAfee HIPS is installed"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "$($Check.SamAccountName) are members of the Backup Operators group"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 1074
    $VulnNo = "1074"
    $RuleName = "WIN00-000100" #The Windows 2012 / 2012 R2 system must use an anti-virus program.

    $Check = Get-Software -Computername $ComputerName | Where-Object {$_.DisplayName -like "McAfee VirusScan Enterprise"}

    switch ($Check.SamAccountName) {
        $null {
            $Finding = $true
            $FindingComment = "McAfee VSE is not installed"
        }
        $true {
            $Finding = $false
            $FindingComment = "McAfee VSE is installed"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "$($Check.SamAccountName) are members of the Backup Operators group"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 3481
    $VulnNo = "3481"
    $RuleName = "Media Player - Prevent Codec Download"#Media Player must be configured to prevent automatic Codec downloads

    $Check = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer\" -Name PreventCodecDownload
    }


    switch ($Check.PreventCodecDownload) {
        1 {
            $Finding = $false
            $FindingComment = "PreventCodecDownload is enabled"
        }
        default {
            $Finding = $true
            $FindingComment = "PreventCodecDownload is configured: $($Check.PreventCodecDownload)"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 14268
    $VulnNo = "14268"
    $RuleName = "Attachment Mgr - Preserve Zone Info"#Zone information must be preserved when saving attachments.

    $Check = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name SaveZoneInformation
    }

    switch ($Check.SaveZoneInformation) {
        2 {
            $Finding = $false
            $FindingComment = "SaveZoneInformation is disabled"
        }
        default {
            $Finding = $true
            $FindingComment = "SaveZoneInformation is configured: $($Check.SaveZoneInformation)"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 14269
    $VulnNo = "14269"
    $RuleName = "Attachment Mgr - Hide Mech to Remove Zone Info"#Mechanisms for removing zone information from file attachments must be hidden.

    $Check = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name HideZoneInfoOnProperties
    }

    switch ($Check.HideZoneInfoOnProperties) {
        1 {
            $Finding = $false
            $FindingComment = "HideZoneInfoOnProperties is enabled"
        }
        default {
            $Finding = $true
            $FindingComment = "HideZoneInfoOnProperties is configured: $($Check.HideZoneInfoOnProperties)"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 14270
    $VulnNo = "14270"
    $RuleName = "Attachment Mgr - Scan with Antivirus"#Mechanisms for removing zone information from file attachments must be hidden

    $Check = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name ScanWithAntiVirus
    }

    switch ($Check.ScanWithAntiVirus) {
        3 {
            $Finding = $false
            $FindingComment = "ScanWithAntiVirus is enabled"
        }
        default {
            $Finding = $true
            $FindingComment = "ScanWithAntiVirus is configured: $($Check.ScanWithAntiVirus)"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 15727
    $VulnNo = "15727"
    $RuleName = "User Network Sharing"#Users must be prevented from sharing files in their profiles.

    $Check = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoInPlaceSharing
    }

    switch ($Check.NoInPlaceSharing) {
        1 {
            $Finding = $false
            $FindingComment = "NoInPlaceSharing is enabled"
        }
        default {
            $Finding = $true
            $FindingComment = "NoInPlaceSharing is configured: $($Check.NoInPlaceSharing)"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 16021
    $VulnNo = "16021"
    $RuleName = "Help Experience Improvement Program"#The Windows Help Experience Improvement Program must be disabled.

    $Check = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0\" -Name NoImplicitFeedback
    }

    switch ($Check.NoImplicitFeedback) {
        1 {
            $Finding = $false
            $FindingComment = "NoImplicitFeedback is enabled"
        }
        default {
            $Finding = $true
            $FindingComment = "NoImplicitFeedback is configured: $($Check.NoImplicitFeedback)"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 16048
    $VulnNo = "16048"
    $RuleName = "Help Ratings"#Windows Help Ratings feedback must be turned off.

    $Check = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0\" -Name NoExplicitFeedback
    }

    switch ($Check.NoExplicitFeedback) {
        1 {
            $Finding = $false
            $FindingComment = "NoExplicitFeedback is enabled"
        }
        default {
            $Finding = $true
            $FindingComment = "NoExplicitFeedback is configured: $($Check.NoExplicitFeedback)"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 36656
    $VulnNo = "36656"
    $RuleName = "WINUC-000001"#A screen saver must be enabled on the system.

    $Check = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\" -Name ScreenSaveActive
    }

    switch ($Check.ScreenSaveActive) {
        1 {
            $Finding = $false
            $FindingComment = "ScreenSaveActive is enabled"
        }
        default {
            $Finding = $true
            $FindingComment = "ScreenSaveActive is configured: $($Check.ScreenSaveActive)"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 36657
    $VulnNo = "36657"
    $RuleName = "WINUC-000003" #The screen saver must be password protected.

    $Check = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\" -Name ScreenSaverIsSecure
    }

    switch ($Check.ScreenSaverIsSecure) {
        1 {
            $Finding = $false
            $FindingComment = "ScreenSaverIsSecure is enabled"
        }
        default {
            $Finding = $true
            $FindingComment = "ScreenSaverIsSecure is configured: $($Check.ScreenSaverIsSecure)"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 36657
    $VulnNo = "36657"
    $RuleName = "WINUC-000003" #The screen saver must be password protected.

    $Check = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\" -Name ScreenSaverIsSecure
    }

    switch ($Check.ScreenSaverIsSecure) {
        1 {
            $Finding = $false
            $FindingComment = "ScreenSaverIsSecure is enabled"
        }
        default {
            $Finding = $true
            $FindingComment = "ScreenSaverIsSecure is configured: $($Check.ScreenSaverIsSecure)"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 36667
    $VulnNo = "36667"
    $RuleName = "WINAU-000016" # The system must be configured to audit Object Access - Removable Storage failures.

    $Check = $AuditPolicy | Where-Object {($_.Category -eq "Object Access") -and ($_.SubCategory -eq "Removable Storage")}

    switch ($Check.AuditFailure) {
        $true {
            $Finding = $false
            $FindingComment = "Object Access >> Audit Removable Storage configured to audit failures"
        }
        $false {
            $Finding = $true
            $FindingComment = "Object Access >> Audit Removable Storage is not configured to audit failures"
        }
        default {
            $Finding = $true
            $FindingComment = "Object Access >> Audit Removable Storage is configured: $($Check.AuditFailure)"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 36668
    $VulnNo = "36668"
    $RuleName = "WINAU-000017" # The system must be configured to audit Object Access - Removable Storage successes.

    $Check = $AuditPolicy | Where-Object {($_.Category -eq "Object Access") -and ($_.SubCategory -eq "Removable Storage")}

    switch ($Check.AuditSuccess) {
        $true {
            $Finding = $false
            $FindingComment = "Object Access >> Audit Removable Storage configured to audit success"
        }
        $false {
            $Finding = $true
            $FindingComment = "Object Access >> Audit Removable Storage is not configured to audit success"
        }
        default {
            $Finding = $true
            $FindingComment = "Object Access >> Audit Removable Storage is configured: $($Check.AuditSuccess)"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

    #region 36722
    $VulnNo = "36722"
    $RuleName = "WINAU-000204" # Permissions for the Application event log must prevent access by nonprivileged accounts.

    $ACL = Get-NTFSAccess \\$ComputerName\C$\Windows\SYSTEM32\WINEVT\LOGS

    switch ($ACL) {
        {$_.Account.Accountname -eq "NT SERVICE\EventLog"} {$EventLogRights = $_.AccessRights }
        {$_.Account.Accountname -eq "NT AUTHORITY\SYSTEM"} {$SystemRights = $_.AccessRights}
        {$_.Account.Accountname -eq "BUILTIN\Administrators"} {$AdminRights = $_.AccessRights}
        {$_.Account.Accountname -eq "NT AUTHORITY\Authenticated Users"} {$UserRights = $_.AccessRights}
        Default {}
    }

    $Check = ($EventLogRights -eq "FullControl") -and ($SystemRights -eq "FullControl") -and ($AdminRights -eq "FullControl") -and ($UserRights -eq "Read, Synchronize")


    switch ($Check) {
        $true {
            $Finding = $false
            $FindingComment = "Eventlog, SYSTEM, and Administrators set to Full Control; Users set to Read"
        }
        $false {
            $Finding = $true
            $FindingComment = "Eventlog set to $EventLogRights, SYSTEM set to $SystemRights, Administrators set to $AdminRights, Users set to $UserRights"
        }
        default {
            $Finding = "UNKN"
            $FindingComment = "Unable to determine, must perform manual check"
        }
    }

    Add-ObjectToReport -VulnNo $VulnNo -RuleName $RuleName -Finding $Finding -FindingComment $FindingComment
    #endregion

}


END {
    $report | Sort-Object Vulnerability
}
