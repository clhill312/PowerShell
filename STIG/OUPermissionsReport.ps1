# Generates report with Active Directory OU ACLs

# Finding ID: V-39333
# Rule ID: SV-56720r1_rule


$OrgOU = Read-Host "Distinguished Name of the Org OU?"

$ExportPath = Read-Host "Path to export report to"

$schemaIDGUID = @{}
$ErrorActionPreference = 'SilentlyContinue'
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID |
 ForEach-Object {$schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID |
 ForEach-Object {$schemaIDGUID.add([System.GUID]$_.rightsGUID,$_.name)}
$ErrorActionPreference = 'Continue'

$OUs =  Get-ChildItem AD:\$OrgOU -Recurse | Where-Object {$_.ObjectClass -eq "organizationalUnit"}

$report = @()


ForEach ($OU in $OUs) {
    $report += Get-Acl -Path "AD:\$OU" |
     Select-Object -ExpandProperty Access | 
     Select-Object @{name='organizationalUnit';expression={$OU}}, `
                   @{name='objectTypeName';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'All'} Else {$schemaIDGUID.Item($_.objectType)}}}, `
                   @{name='inheritedObjectTypeName';expression={$schemaIDGUID.Item($_.inheritedObjectType)}}, `
                   *
}

# Dump the raw report out to a CSV file for analysis in Excel.
#$report | Export-Excel -Path "$ExportPath\OU_Permissions.xslx" -AutoSize -FreezeTopRow -AutoFilter -BoldTopRow -TableStyle Medium8
$report | Export-Csv -Path "$ExportPath\OU_Permissions.csv" -NoTypeInformation
