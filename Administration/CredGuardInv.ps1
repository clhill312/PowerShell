$date = Get-Date -Format yyyyMMdd_HHmm
$ExportPath = "\\server\share\folder"
$ExportFile = "CredGuardInventory-$date.csv"

# get the latest report and filter out the ones who already have cred guard enabled
if (Test-Path $ExportPath\*) {
    $LatestReport = (Get-ChildItem -Path $ExportPath).FullName | Select-Object -Last 1
    $Csv = Import-Csv $LatestReport
    $CredGuardEnabledComputers = $Csv | Where-Object CredGuardEnabled -ne "Enabled"
    $Computers = $CredGuardEnabledComputers.ComputerName    
}

# if no report exists, gather all the computer names in the computers OU
else {
    $Computers = Get-ADComputer -Filter * -SearchBase "OU=Computers,DC=karl,DC=lab"
    $Computers = $Computers.Name
}


$i = 0 # set counter to zero

    foreach ($ComputerName in $Computers) {
        
        $i++  # increase counter one
        Write-Output "Working on $ComputerName - $i of $($Computers.Count)"
        Write-Progress -Activity "Checking Credential Guard" -Status $ComputerName -PercentComplete (($i/$($Computers.Count))*100)

        #re-write variables as blank to avoid false positives
        $Online = ""
        $CredGuardEnabled = ""


        if (Test-Connection -ComputerName $ComputerName -Count 2 -ErrorAction SilentlyContinue) {

            $Online = "YES"

            try {
                $DevGuard = Get-CimInstance -ComputerName $ComputerName -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop

                if ($DevGuard.SecurityServicesConfigured -contains 1) {
                    $CredGuardEnabled = "Enabled"
                    Write-Host -ForegroundColor Green "Credential Guard Enabled!"
                }
            }
            catch {
                Write-Host -BackgroundColor DarkRed "CimError"
                $CredGuardEnabled = "CimError"
            }

        }

        else {
            Write-Host -ForegroundColor DarkGray "$ComputerName offline..."
            $Online = "NO"
            $CredGuardEnabled = "NotOnline"
        }


        $OutputObj  = New-Object -Type PSObject

        $OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $ComputerName -ErrorAction Ignore
        $OutputObj | Add-Member -MemberType NoteProperty -Name CredGuardEnabled -Value $CredGuardEnabled -ErrorAction Ignore
        $OutputObj | Add-Member -MemberType NoteProperty -Name Online -Value $Online -ErrorAction Ignore

        $OutputObj | Export-Csv $ExportPath\$ExportFile -Append -NoTypeInformation -ErrorAction Ignore -Force


    }
