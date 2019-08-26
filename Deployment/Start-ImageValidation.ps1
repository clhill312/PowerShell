function Start-ImageValidation {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $report = [System.Collections.ArrayList]::new() # generate empty array for the report
    

    ### Software ###
    Write-Verbose "Getting list of installed software on $ComputerName..." -Verbose
    $SoftwareList = Get-Software -ComputerName $ComputerName

        # Application List
        $Applications = @(
            "Adobe Acrobat DC"
            "Java 8 Update 211"
            "Configuration Manager Client"
            "Mozilla Firefox 68.0 (x64 en-US)"
        )

        # find apps that are on the list that are not installed
        $AppListResults = Compare-Object -ReferenceObject $Softwarelist.DisplayName -DifferenceObject $Applications -IncludeEqual

        $InstalledAppList = $AppListResults | Where-Object {$_.SideIndicator -eq "=="}

        
        foreach ($app in $InstalledAppList) {
            $obj = New-Object -TypeName PSObject # create new object
			   $obj | Add-Member -MemberType NoteProperty -Name Category -Value "Application Installation"
			   $obj | Add-Member -MemberType NoteProperty -Name Check -Value $app.InputObject
			   $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Pass"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value "Installed"
            $report.Add($obj) | Out-Null # add object to array
        }

    
        $MissingAppList = $AppListResults | Where-Object {$_.SideIndicator -eq "=>"}

        # add the missing apps to the errors array and increase the error count
        foreach ($MissingApp in $MissingAppList) {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "Application Installation"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value $MissingApp.InputObject
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Fail"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value "Not Installed"
            $report.Add($obj) | Out-Null # add object to array
        }

        # desktop files
        if (Test-Path -Path "\\$ComputerName\C$\Users\Public\Desktop\DesktopProgram.exe") {
            $obj = New-Object -TypeName PSObject # create new object
			   $obj | Add-Member -MemberType NoteProperty -Name Category -Value "Application Installation"
			   $obj | Add-Member -MemberType NoteProperty -Name Check -Value "DesktopProgram"
			   $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Pass"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value "Installed"
            $report.Add($obj) | Out-Null # add object to array

        }
        else {
            $obj = New-Object -TypeName PSObject # create new object
			   $obj | Add-Member -MemberType NoteProperty -Name Category -Value "Application Installation"
			   $obj | Add-Member -MemberType NoteProperty -Name Check -Value "DesktopProgram"
			   $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Fail"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value "Not Installed"
            $report.Add($obj) | Out-Null # add object to array
        }


        
        ### BitLocker ###
        Write-Verbose "Getting BitLocker info..." -Verbose
        
        $bl = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-BitLockerVolume -MountPoint C:
        }


        if ($bl.VolumeStatus -eq "FullyEncrypted") {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "BitLocker"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "Volume Status"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Pass"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $bl.VolumeStatus
            $report.Add($obj) | Out-Null # add object to array
        }
        else {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "BitLocker"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "Volume Status"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Fail"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $bl.VolumeStatus
            $report.Add($obj) | Out-Null # add object to array
        }

        if ($bl.KeyProtector -contains "TpmPin" -and "RecoveryPassword") {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "BitLocker"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "Key Protector"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Pass"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $bl.KeyProtector
            $report.Add($obj) | Out-Null # add object to array
        }
        else {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "BitLocker"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "Key Protector"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Fail"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $bl.KeyProtector
            $report.Add($obj) | Out-Null # add object to array
        }

        if ($bl.ProtectionStatus -eq "On") {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "BitLocker"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "Protection Status"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Pass"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $bl.ProtectionStatus
            $report.Add($obj) | Out-Null # add object to array
        }
        else {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "BitLocker"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "Key Protector"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Fail"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $bl.ProtectionStatus
            $report.Add($obj) | Out-Null # add object to array
        }


        ### TPM and Security Info ###
        Write-Verbose "Gathering TPM and Security info..." -Verbose

        # secure boot uefi
        $SecureBoot = Invoke-Command -ComputerName $ComputerName -ScriptBlock {Confirm-SecureBootUEFI}
        if ($SecureBoot) {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "SecureBoot-UEFI"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "SecureBoot-UEFI"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Pass"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $SecureBoot
            $report.Add($obj) | Out-Null # add object to array
        }
        else {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "SecureBoot-UEFI"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "SecureBoot-UEFI"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Fail"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $SecureBoot
            $report.Add($obj) | Out-Null # add object to array
        }


        # credential guard
        $DevGuard = Get-CimInstance -ComputerName $ComputerName -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
        if ($DevGuard.SecurityServicesConfigured -contains 1) {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "Credential Guard"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "Credential Guard"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Pass"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $DevGuard.SecurityServicesConfigured
            $report.Add($obj) | Out-Null # add object to array
        }
        else {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "Credential Guard"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "Credential Guard"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Fail"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $DevGuard.SecurityServicesConfigured
            $report.Add($obj) | Out-Null # add object to array
        }


        # TPM 
        $TPM = Get-WMIObject -ComputerName $ComputerName -Class Win32_Tpm -Namespace root\cimv2\Security\MicrosoftTpm

        # TPM version 2.0
        if ($TPM.SpecVersion -match "2.0") {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "TPM"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "Spec Version"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Pass"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $TPM.SpecVersion
            $report.Add($obj) | Out-Null # add object to array
        }
        else {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "TPM"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "Spec Version"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Fail"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $TPM.SpecVersion
            $report.Add($obj) | Out-Null # add object to array
        }

        # TPM Activated
        if ($TPM.IsActivated_InitialValue) {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "TPM"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "Activation"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Pass"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $TPM.IsActivated_InitialValue
            $report.Add($obj) | Out-Null # add object to array
        }
        else {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "TPM"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "Activation"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Fail"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $TPM.IsActivated_InitialValue
            $report.Add($obj) | Out-Null # add object to array
        }

        # TPM Enabled
        if ($TPM.IsEnabled_InitialValue) {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "TPM"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "Enabled"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Pass"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $TPM.IsEnabled_InitialValue
            $report.Add($obj) | Out-Null # add object to array
        }
        else {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "TPM"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "Enabled"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Faild"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $TPM.IsEnabled_InitialValue
            $report.Add($obj) | Out-Null # add object to array
        }

        # TPM SHA 256
        $TPMKeyInfo = Invoke-Command -ComputerName $ComputerName -ScriptBlock {Get-TpmEndorsementKeyInfo}
        if ($TPMKeyInfo.IsPresent -eq $true) {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "TPM"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "Key Info (SHA 256)"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Pass"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $TPMKeyInfo.IsPresent
            $report.Add($obj) | Out-Null # add object to array
        }
        else {
            $obj = New-Object -TypeName PSObject # create new object
            $obj | Add-Member -MemberType NoteProperty -Name Category -Value "TPM"
            $obj | Add-Member -MemberType NoteProperty -Name Check -Value "Key Info (SHA 256)"
            $obj | Add-Member -MemberType NoteProperty -Name Pass-Fail -Value "Fail"
            $obj | Add-Member -MemberType NoteProperty -Name Output -Value $TPMKeyInfo.IsPresent
            $report.Add($obj) | Out-Null # add object to array
        }

        # show report
        $report
    

}
