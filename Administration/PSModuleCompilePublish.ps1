    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ScriptsFolder,

        [Parameter(Mandatory)]
        [string]$ModuleName,

        [Parameter()]
        [string]$ModuleVersion,

        [Parameter()]
        [string]$RequiredModules,

        [Parameter()]
        [string]$PSRepo
    )
    
    begin {
        # create temp folder
        $OutputPath = "C:\temp\$ModuleName"
        mkdir $OutputPath
    }
    
    process {
        # generate new psm1 file
        $Scripts = Get-ChildItem $ScriptsFolder -Filter *.ps1

        foreach ($Script in $Scripts) {
            Get-Content $Script.FullName | Out-File -FilePath "$OutputPath\$ModuleName.psm1" -Append
        }
       
        # generate new module manifest parameters
       $ManifestParams = @{
            RootModule = "$ModuleName.psm1"
            Author = "Carl Hill"
            Company = "Company or Organization Name"
            PowerShellVersion = "5.0"
            Path = "$OutputPath\$ModuleName.psd1"
            Description = "Helps Automate tasks"
            ModuleVersion = $ModuleVersion
        }

    
        # actions if there are required modules
        if ($RequiredModules -ne "") {

            # add required modules to manifest params
            $ManifestParams += @{
                RequiredModules = $RequiredModules
            }

             # publish required modules to PSRepo
            foreach ($RequiredModule in $RequiredModules) {
                Write-Output "Publsihing $RequiredModule to from the PSGallery to internal PS repo.."
                Import-Module $RequiredModule
                $Module = Get-Module $RequiredModule
                Publish-Module -Name $Module.Name -RequiredVersion $Module.Version -Repository $PSRepo -Verbose
            }
            
        }

        # generate module manifest
        New-ModuleManifest @ManifestParams

        # publish module
        Write-Output "Publsihing $ModuleName to internal PS repo.."
        Publish-Module -Path $OutputPath -Repository $PSRepo -Verbose
    }
    
    end {
        $title = "Confirm Temp folder Removal"
        $message = Write-Host "Confirm Temp folder Removal"
    
            $quit = New-Object System.Management.Automation.Host.ChoiceDescription "&Quit","Exits the script."
            $delhd = New-Object System.Management.Automation.Host.ChoiceDescription "&Delete","Removes temp folder"
    
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($quit, $delhd)
    
        $result = $host.ui.PromptForChoice($title, $message, $options, 0) 
    
        switch ($result) {
    
            0 {exit} 
            1 { Remove-Item -Path $OutputPath -Recurse -Force -Verbose }
    
        }
        
    }
