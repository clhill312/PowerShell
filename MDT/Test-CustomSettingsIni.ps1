function Test-CustomSettingsIni {
    [CmdletBinding()]
    param (
        [CmdletBinding()]
    
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $DeploymentShare
    )
    
     Remove-Item C:\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT -Force
     cscript.exe $DeploymentShare\Scripts\ZTIGather.wsf /Debug:True /inifile:$DeploymentShare\Control\CustomSettings.ini
     CMTrace.exe C:\MININT\SMSOSD\OSDLOGS\BDD.log

}
