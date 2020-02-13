function Install-HBSSComponent {

    Param(
        [CmdletBinding()]
    
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $ComputerName,

        [Parameter()]
        [switch] $HIPS,

        [Parameter()]
        [switch] $VSE,

        [Parameter()]
        [switch] $ACCM,
        
        #[Parameter()]
        #[switch] $DLP,
        
        [Parameter()]
        [switch] $PAA,

        [Parameter()]
        [switch] $RSD,

        [Parameter()]
        [switch] $MA,

        [Parameter()]
        # SADR McAfeeHttp folder shared
        [string] $HBSSshare

    )


try {   
        Write-Verbose "Using HBSS Share $HBSSshare" -Verbose
        Test-Connection -ComputerName $ComputerName -Count 1 -ErrorAction SilentlyContinue -Quiet
    
        # Host Intrusion Prevention System
        if ($HIPS) {
            Write-Verbose "Copying HIPS files to $ComputerName" -Verbose
            Copy-Item -Path "$HBSSshare\Current\HOSTIPS_8000\Install\0000" -Destination "\\$ComputerName\C$\Temp\HIPS" -Recurse
            
            Write-Output "Installing HIPS..."
            
            Invoke-Command -ComputerName $ComputerName -AsJob -ScriptBlock {
                Start-Process "C:\Temp\HIPS\McAfeeHIP_ClientSetup.exe" -Wait
            }

        }


        # VirusScan Enterprise
        if ($VSE) {
            Write-Verbose "Copying VSE files to $ComputerName" -Verbose
            Copy-Item -Path "$HBSSshare\Current\VIRUSCAN8800\Install\0000" -Destination "\\$ComputerName\C$\Temp\VSE" -Recurse
                Write-Output "Installing VirusScan Enterprise..."

                Invoke-Command -ComputerName $ComputerName -AsJob -ScriptBlock {
                    Start-Process "C:\Temp\VSE\setupvse.exe" -ArgumentList "ADDLOCAL=ALL","RUNAUTOUPDATE=TRUE","/qn","/l*v","C:\Windows\Temp\McAfeeLogs\VSElog.txt" -Wait
                }
                
        }



        # Asset Compliance Configuration Manager
        if ($ACCM) {
            Write-Verbose "Copying ACCM files to $ComputerName" -Verbose
            Copy-Item -Path "$HBSSshare\Current\S_USAF021001\Install\0000" -Destination "\\$ComputerName\C$\Temp\ACCM" -Recurse
            Write-Output "Installing ACCM..."

            Invoke-Command -ComputerName $ComputerName -AsJob -ScriptBlock {
                Start-Process "msiexec.exe" -ArgumentList "/i", "C:\Temp\ACCM\ACCM_MSI.msi", "/qn" -Wait
            }
        }
        

        <# Data Loss Prevention
        if ($DLP) {

            Copy-Item "$HBSSshare\Current\DLPAGENT11200\Install\0409" -Destination "\\$ComputerName\C$\Temp\DLP" -Recurse -Force
            

            Write-Output "Installing vcredist KeyView..."
            Start-Process psexec -ArgumentList {-s \\$ComputerName "C:\Temp\DLP\vcredist_KeyView_x64.exe" /Q} -NoNewWindow -Wait

            Write-Output "Installing vcpp..."
            Start-Process psexec -ArgumentList {-s \\$ComputerName "C:\Temp\DLP\en_visual_c_pp_2010_sp1_redistributable_package_x64_651767.exe" /passive /norestart} -NoNewWindow -Wait

            Write-Output "Installing DLP..."
            Start-Process psexec -ArgumentList {-s \\$ComputerName "msiexec /i C:\Temp\DLP\DLPAgentInstaller.msi" /qn} -NoNewWindow -Wait

            Start-Process psexec -ArgumentList {-s \\$ComputerName "C:\Program Files\McAfee\Agent\cmdagent.exe" -p} -NoNewWindow -Wait

            Remove-Item -Path "\\$ComputerName\C$\Temp\DLP" -Recurse -Force -Confirm:$false
        }
        #>

        # Policy Auditor Agent
        if ($PAA) {
            Write-Verbose "Copying PAA files to $ComputerName" -Verbose
            Copy-Item -Path "$HBSSshare\Current\POLICYAU6000\Install\0000" -Destination "\\$ComputerName\C$\Temp\PAA" -Recurse

            Write-Output "Installing PAA..."

            Invoke-Command -ComputerName $ComputerName -AsJob -ScriptBlock {
                Start-Process "C:\Temp\PAA\Setup.exe" -ArgumentList "/s" -Wait
            }
        }

        
        # Rogue System Detector
        if ($RSD) {
            Write-Verbose "Copying RSD files to $ComputerName" -Verbose
            Copy-Item -Path "$HBSSshare\Current\RSD_____4700\Install\0000" -Destination "\\$ComputerName\C$\Temp\RSD" -Recurse

            Write-Output "Installing RSD..."

            Invoke-Command -ComputerName $ComputerName -AsJob -ScriptBlock {
                Start-Process "C:\Temp\RSD\RSDInstaller.exe" -ArgumentList "/VERYSILENT" -Wait
            }

        }

        # Rogue System Detector
        if ($RSD) {
            Write-Verbose "Copying MA files to $ComputerName" -Verbose
            Copy-Item -Path "$HBSSshare\Current\EPOAGENT3000\Install\0409" -Destination "\\$ComputerName\C$\Temp\MA" -Recurse

            Write-Output "Installing McAfee Agent..."

            Invoke-Command -ComputerName $ComputerName -AsJob -ScriptBlock {
                Start-Process "C:\Temp\MA\FramePkg.exe" -ArgumentList "/install=agent","/silent" -Wait
            }

        }

    }

    catch {
        Write-Error "$ComputerName is unreachable."
    }


}
