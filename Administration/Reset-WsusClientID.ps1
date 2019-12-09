function Reset-WsusClientID {

    <#
        .SYNOPSIS
        Resets the WSUS Client ID.
        
        .DESCRIPTION
        Resets the WSUS Client ID to a unique ID number.

        .NOTES
        Useful for VM templates or anytime a Windows OS is "cloned", the WSUS client ID needs to be regenerated or else the client will not seem to appear in the WSUS console.
        If each WSUS client ID is the same, the client will "clobber" the entry in WSUS and it will show a rotating view of a single computer.
        
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string] $ComputerName
    )


foreach ($Computer in $ComputerName) {
    $Computer = $Computer.Name
    Invoke-Command -ComputerName $Computer -ScriptBlock {

        Stop-Service wuauserv
        
        Push-Location
        Set-Location -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate"
        Remove-ItemProperty . -Name SUSclientid
        Remove-ItemProperty . -Name SusClientIdValidation
        Pop-Location
        
        Remove-Item -Path "C:\Windows\SoftwareDistribution" -Force -Recurse
        Remove-Item -Path "C:\Windows\SoftwareDistributionOLD" -Force -Recurse
        
        Start-Service wuauserv
        
        wuauclt.exe /resetauthorization /detectnow
    }
    
}
