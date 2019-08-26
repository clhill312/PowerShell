function Backup-EpoServer {

    <#
        .SYNOPSIS
        Perform backup of ePolicy Orchestrator
        
        .DESCRIPTION
        Zips the ePO configs and software folders as well as the ePO database onto a local backup location. The local backup is then copied to a network location.

        .NOTES
        KB article on backup procedures: https://kc.mcafee.com/corporate/index?page=content&id=kb66616
    #>
    
    [CmdletBinding()]
    PARAM ()


    BEGIN {
        $date = Get-Date -Format yyyy-MM-dd_HHmmss
        $LocalBackupLocation = C:\Backups
        $NetworkBackupLocation = "\\server\share\folder"
    }

    PROCESS {

        mkdir $LocalBackupLocation\$date

        $EpoServices = @(
            "MCAFEEEVENTPARSERSRV"
            "MCAFEETOMCATSRV530"
            "MCAFEEAPACHESRV"
        )

        # Stop Services
        foreach ($service in $EpoServices) {
            Stop-Service -Name $service -Verbose
        }

        # archive ePO folders
        $ePOfolders = @(
            "C:\Program Files (x86)\McAfee\ePolicy Orchestrator\Server\extensions"
            "C:\Program Files (x86)\McAfee\ePolicy Orchestrator\Server\conf"
            "C:\Program Files (x86)\McAfee\ePolicy Orchestrator\Server\keystore"
            "C:\Program Files (x86)\McAfee\ePolicy Orchestrator\DB\Software"
            "C:\Program Files (x86)\McAfee\ePolicy Orchestrator\DB\Keystore"
            "C:\Program Files (x86)\McAfee\ePolicy Orchestrator\Apache2\conf"
        )

        Compress-Archive -Path $ePOfolders -CompressionLevel Optimal -DestinationPath "$BackupLocation\$($date)-ePOFoldersBackup.zip"


        # backup sql database
        $user = "SQLUSERNAME"
        $pw = Get-Content C:\cred.txt | ConvertTo-SecureString 

        $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$pw
        Backup-SqlDatabase -ServerInstance SERVER\INSTANCE -Database db_name -Credential $creds -BackupFile "$LocalBackupLocation\$date\epodb.bak"
    }

    END {
        # Start Services
        foreach ($service in $EpoServices) {
            Start-Service -Name $service -Verbose
        }

        mkdir $NetworkBackupLocation\$date
        Copy-Item -Path $LocalBackupLocation\$date -Destination $NetworkBackupLocation\$date -Recurse -Verbose
    }


}
