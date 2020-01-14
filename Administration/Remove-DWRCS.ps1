function Remove-DWRCS {
    <#
    .DESCRIPTION
        Removes the DameWare Remote Client Service from remote computers
    #>
    
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ComputerName
    )
    
    Write-Verbose "Attemping to remove DWRCS on $ComputerName" -Verbose

    if (Test-Path \\$ComputerName\C$\Windows\DWRCS\dwrcs.exe) {

        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Stop-Service -Name dwmrcs

            # remove drivers
            regsvr32 /u /s C:\Windows\DWRCS\DWRCSh.dll
            regsvr32 /u /s C:\Windows\DWRCS\DWRCSE.dll
            regsvr32 /u /s C:\Windows\DWRCS\DWRCSET.dll
            regsvr32 /u /s C:\Windows\DWRCS\DWRCSI.dll
            regsvr32 /u /s C:\Windows\DWRCSDWRCRSS.dll
            regsvr32 /u /s C:\Windows\DWRCS\DWRCK.dll
            regsvr32 /u /s C:\Windows\DWRCS\DWRCWXL.dll

            # uninstall
            Start-Process "C:\Windows\DWRCS\dwrcs.exe" -ArgumentList "-remove" -Wait

            #remove DWRCS folder
            Remove-Item "C:\Windows\DWRCS\" -Recurse -Force
        }
    }

    else {
        Write-Output "Unable to find DWRCS on $ComputerName"
    }

}
