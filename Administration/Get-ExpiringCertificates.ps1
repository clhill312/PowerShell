function Get-ExpiringCertificates {
    [CmdletBinding()]
    param (
        [CmdletBinding()]
    
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $Days = 30,

        
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $OU = $ServersOU
    )
    
    begin {
        $Computers = Get-ADComputer -Filter {OperatingSystem -like "Windows Server *"} -SearchBase $OU
        $deadline = (Get-Date).AddDays($Days)
    } 
        
    
    process {
        
        $Computer = $Computer.Name

        $i = 0

        foreach ($Computer in $Computers ) {
            $i++

            try {
                Write-Verbose "Checking $Computer ($i of $($Computers.Count))" -Verbose
                if (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {

                    Invoke-Command -ComputerName $Computer { Get-ChildItem Cert:\LocalMachine\My } | ForEach-Object { 
                        if ($_.NotAfter -le $deadline) { $_ | Select-Object PSComputerName,FriendlyName,Issuer,Subject,NotAfter, @{Label="Expires In (Days)";Expression={($_.NotAfter - (Get-Date)).Days}} } 
                    } 
                }
                else {
                    Write-Error "$Computer is offline"
                }
                
            }
            catch {
                Write-Error "$Computer has error"
            }
         
        }

    }
    
    end {}
}
