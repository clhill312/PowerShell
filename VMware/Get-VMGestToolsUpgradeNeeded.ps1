$vCenter = Read-Host "vCenter Hostname"

$creds = Get-Credential

Connect-VIServer -Server $vCenter -Credential $creds

$VMsNeedingupgrade = Get-VM | Where-Object {$_.Extensiondata.Summary.Guest.ToolsVersionStatus -like 'guestToolsNeedUpgrade'}

$VMsNeedingupgrade | Select-Object name,folder,@{N='tools vers';E={$_.ExtensionData.Config.Tools.ToolsVersion}},@{N='Tools Status';E={$_.Extensiondata.Summary.Guest.ToolsVersionStatus}}
