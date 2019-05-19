
[CmdletBinding()]
Param(
    [Parameter()]
    [string]$NasPath = "Z:",

    [Parameter(Mandatory=$true)]
    [string]$SpreadSheet,

    [Parameter(Mandatory=$true)]
    [string]$DestinationDrive
)


#
$MoviesLocation = "$NasPath\Movies"
$TvShowsLocation = "$NasPath\TV Shows"
$DocsLocation = "$NasPath\Documentaries\Films"
$DocuSeriesLocation = "$NasPath\Documentaries\Shows"
$MusicLocation = "$NasPath\Music"


##############################
##### Import Spreadsheet #####
##############################

Write-Output "Importing Spreadsheet..."

$TransferMovies = Import-Excel $SpreadSheet -WorksheetName "Movies" | Where-Object Transfer -like x
Write-Output "Imported $($TransferMovies.Count) Movies"

$TransferShows = Import-Excel $SpreadSheet -WorksheetName "TVshows" | Where-Object Transfer -like x
Write-Output "Imported $($TransferShows.Count) TV Shows"

$TransferDocs = Import-Excel $SpreadSheet -WorksheetName "Docs" | Where-Object Transfer -like x
Write-Output "Imported $($TransferDocs.Count) Docmentaries"

$TransferDocuSeries = Import-Excel $SpreadSheet -WorksheetName "DocuSeries" | Where-Object Transfer -like x
Write-Output "Imported $($TransferDocuSeries.Count) DocuSeries"

$TransferMusic = Import-Excel $SpreadSheet -WorksheetName "Music" | Where-Object Transfer -like x
Write-Output "Imported $($TransferMusic.Count) Music Albums"



############################
##### Gather File List #####
############################

#### Gather Movies from NAS

if ($TransferMovies) {

    $xMovieList = foreach ($TransferMovie in $TransferMovies) {
        New-Object psobject -Property @{
            Title = $TransferMovie.Title
            Year = $TransferMovie.Year
            Collection = $TransferMovie.Collection
        }
    }

    Write-Output "Gathering Movie List from NAS..."

    $NasMovies = Get-ChildItem -Path $MoviesLocation -File -Recurse

    $NasMovieList = foreach ($NasMovie in $NasMovies) {
        New-Object psobject -Property @{
            Title = (($NasMovie.Name -split '\(\d\d\d\d\).*')[0]).Trim()
            Year = ($NasMovie.Name -split '(\d\d\d\d)')[1]
            Collection = (($NasMovie.Directory).Name | Where-Object {$_ -ne "Movies"})
            FilePath = $NasMovie.FullName
        }
    }

    Write-Output "Found $($NasMovieList.Count) Movies on NAS."

}


#### Gather TV Shows from NAS

if ($TransferShows) {

    $xShowList = foreach ($TransferShow in $TransferShows) {
        New-Object psobject -Property @{
            Title = $TransferShow.Title
            Year = $TransferShow.Year
        }
    }

    Write-Output "Gathering TV Shows List from NAS..."
    $NasShows = Get-ChildItem -Path $TvShowsLocation -Directory

    $NasShowsList = foreach ($NasShow in $NasShows) {
        New-Object psobject -Property @{
            Title = $NasShow.Name 
            FilePath = $NasShow.FullName
        }
    }

    Write-Output "Found $($NasShowsList.Count) TV Shows on NAS."

}

#### Gather Documentaries from NAS

if ($TransferDocs) {

    $xDocList = foreach ($TransferDoc in $TransferDocs) {
        New-Object psobject -Property @{
            Title = $TransferDoc.Title
            Year = $TransferDoc.Year
        }
    }

    Write-Output "Gathering Documentaries List from NAS..."

    $NasDocs = Get-ChildItem -Path $DocsLocation -File 

    $NasDocList = foreach ($NasDoc in $NasDocs) {
        New-Object psobject -Property @{
            Title = (($NasDoc.Name -split '\(\d\d\d\d\).*')[0]).Trim()
            Year = ($NasDoc.Name -split '(\d\d\d\d)')[1]
            FilePath = $NasDoc.FullName
        }
    }

    Write-Output "Found $($NasDocList.Count) Documentaries on NAS."

}

#### Gather Documentary Series from NAS

if ($TransferDocuSeries) {

    $xDocSeriesList = foreach ($TransferDocuShow in $TransferDocuSeries) {
        New-Object psobject -Property @{
            Title = $TransferDocuShow.Title
            Year = $TransferDocuShow.Year
        }
    }

    Write-Output "Gathering Documentary Series List from NAS..."

    $NasDocuSeries = Get-ChildItem -Path $DocuSeriesLocation -Directory

    $NasDocSeriesList = foreach ($NasDocuShow in $NasDocuSeries) {
        New-Object psobject -Property @{
            Title = $NasDocuShow.Name 
            FilePath = $NasDocuShow.FullName
        }
    }

    Write-Output "Found $($NasDocSeriesList.Count) Documentary Series on NAS."

}

<#### Gather Music from NAS

if ($TransferMusic) {

       
    $xMusicList = foreach ($TransferAlbum in $TransferMusic) {
        New-Object psobject -Property @{
            Artist = $TransferAlbum.Artist
            Title = $TransferAlbum.Album
            Year = $TransferAlbum.Year
        }
    }

    Write-Output "Gathering Music List from NAS..."
    $NasMusics = Get-ChildItem -Path $MusicLocation -Directory -Depth 1

    $NasMusicList = foreach ($NasMusic in $NasMusics) {
        New-Object psobject -Property @{
            Title = $NasMusic.Name
            FilePath = $NasMusic.FullName
        }
    }

    Write-Output "Found $($NasMusicList.Count) Music Albums on NAS."
    
}

#>

##########################
##### Create Folders #####
##########################

if (-Not(Test-Path "$DestinationDrive\FromKarl")) {
    New-Item -Path "$DestinationDrive" -Name "FromKarl" -ItemType Directory
}

if ($TransferMovies) {
    New-Item -Path "$DestinationDrive\FromKarl" -Name "Movies" -ItemType Directory
}

if ($TransferShows) {
    New-Item -Path "$DestinationDrive\FromKarl" -Name "TV Shows" -ItemType Directory
}

foreach ($TransferMovie in $TransferMovies) {

    if (-Not(Test-Path "$DestinationDrive\FromKarl\Movies\$($TransferMovie.Collection)")) {
        New-Item -Path "$DestinationDrive\FromKarl\Movies" -Name $TransferMovie.Collection -ItemType Directory
    }
}


if ($TransferDocs) {
    New-Item -Path "$DestinationDrive\FromKarl" -Name "Documentaries" -ItemType Directory -ErrorAction Ignore
}

if ($TransferDocuSeries) {
    New-Item -Path "$DestinationDrive\FromKarl" -Name "Documentary Series" -ItemType Directory -ErrorAction Ignore
}

if ($TransferMusic) {
    New-Item -Path "$DestinationDrive\FromKarl" -Name "Music" -ItemType Directory -ErrorAction Ignore
}


##########################
####### Copy Files #######
##########################

if ($TransferDocuSeries) {

    Write-Output "Copying Documentary Series..."

    foreach ($xDocShow in $NasDocSeriesList) {

    $FileToCopy = Compare-Object -ReferenceObject $xDocSeriesList -DifferenceObject $xDocShow -IncludeEqual -Property Title
    if ($FileToCopy.SideIndicator -eq "==") {
        Write-Progress -Activity "Copying DocuSeries"
        Copy-Item -Path $xDocShow.FilePath -Destination "$DestinationDrive\FromKarl\Documentary Series" -Recurse  -Verbose
        }
    }

}

if ($TransferDocs) {

    Write-Output "Copying Documentaries..."

    foreach ($xDoc in $NasDocList) {

    $FileToCopy = Compare-Object -ReferenceObject $xDocList -DifferenceObject $xDoc -IncludeEqual -Property Title
    if ($FileToCopy.SideIndicator -eq "==") {
        Copy-Item -Path $xDoc.FilePath -Destination "$DestinationDrive\FromKarl\Documentaries" -Verbose
        }
    }

}

if ($TransferShows) {

    Write-Output "Copying TV Shows..."

    foreach ($xShow in $NasShowsList) {

    $FileToCopy = Compare-Object -ReferenceObject $xShowList -DifferenceObject $xShow -IncludeEqual -Property Title
    if ($FileToCopy.SideIndicator -eq "==") {
        Copy-Item -Path $xShow.FilePath -Destination "$DestinationDrive\FromKarl\TV Shows" -Recurse  -Verbose
        }
    }

}


if ($TransferMovies) {
    Write-Output "Copying Movies..."

    foreach ($xMovie in $NasMovieList) {

    $FileToCopy = Compare-Object -ReferenceObject $xMovieList -DifferenceObject $xMovie -IncludeEqual -Property Title
    if ($FileToCopy.SideIndicator -eq "==") {
        Copy-Item -Path $xMovie.FilePath -Destination "$DestinationDrive\FromKarl\Movies\$($xMovie.Collection)" -Verbose
        }
    }
        
}

if ($TransferMusic) {

    Write-Output "Copying Music..."

    foreach ($xMusic in $TransferMusic) {

        Copy-Item -Path "$NasPath\Music\$($xMusic.Artist)\$($xMusic.Year) - $($xMusic.Album)" -Destination "$DestinationDrive\FromKarl\Music\$($xMusic.Artist)\$($xMusic.Year) - $($xMusic.Album)" -Recurse -Verbose
        
    }
    

}





