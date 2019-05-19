[CmdletBinding()]
Param(

    [Parameter()]
    [string]$NasPath = "Z:\",

    [Parameter(Mandatory=$true)]
    [string]$ExportPath,

    [Parameter()]
    [string]$ExportFile = "KarlsNASmedia.xlsx",
    
    [Parameter()]
    [switch]$GatherAll,

    [Parameter()]
    [switch]$GatherDocFilms,

    [Parameter()]
    [switch]$GatherDocSeries,

    [Parameter()]
    [switch]$GatherMovies,
    
    [Parameter()]
    [switch]$GatherTvShows,
    
    [Parameter()]
    [switch]$GatherMusic
)


#### Documentaries

if ($GatherAll -or $GatherDocFilms) {

    Write-Output "Gathering Documentaries..."

    $Docs = Get-ChildItem "$NasPath\Documentaries\Films" -Exclude *.srt
    $DocsOutput = foreach ($doc in $Docs) {
        New-Object -Type PSObject -Property @{
            Transfer = ""
            Title = (($doc.Name -split '\(\d\d\d\d\).*')[0]).Trim()
            Year = ($doc.Name -split '(\d\d\d\d)')[1]
        } 
    }

}
#### Documentary Series

if ($GatherAll -or $GatherDocSeries) {

    Write-Output "Gathering DocuSeries..."

    $DocuSeries = Get-ChildItem "$NasPath\Documentaries\Shows" -Directory
    $DocuSeriesOutput = foreach ($series in $DocuSeries) {
        New-Object -Type PSObject -Property @{
        Transfer = ""
        Title = $series.Name
        }
    }

}

#### TV Shows

if ($GatherAll -or $GatherTvShows) {

    Write-Output "Gathering TV Shows..."

    $TvShows = Get-ChildItem "$NasPath\TV Shows" -Directory -Exclude "syslog"
    $TvShowsOutput = foreach ($show in $TvShows) {
        New-Object -Type PSObject -Property @{
        Transfer = ""
        Title = $show.Name
        Seasons = ((Get-ChildItem $show.FullName -Recurse -Directory | Where-Object {$_.Name -ne "Specials"} | Measure-Object).Count | Where-Object {$_ -ne 0})
        }
    } 

}

#### Movies

if ($GatherAll -or $GatherMovies) {

    Write-Output "Gathering Movies..."

    $Movies = Get-ChildItem $NasPath\Movies\ -Recurse -File -Exclude *.srt
    $MoviesOutput = foreach ($movie in $Movies) {
        New-Object -Type PSObject -Property @{
            Transfer = ""
            Title = (($movie.Name -split '\(\d\d\d\d\).*')[0]).Trim()
            Year = ($movie.Name -split '(\d\d\d\d)')[-2]
            Collection = (($movie.Directory).Name | Where-Object {$_ -ne "Movies"})
        }
    }

}

#### Music

if ($GatherAll -or $GatherMusic) {

    Write-Output "Gathering Music..."

    $ExcludedDirs = @(
        "_Remixes"
        "_Soundtracks"
        "Artwork"
        "Remixes"
        "Others"
        "Other"
        "Extras"
        "Bonus*"
        "Singles"
        "Rarities and B-Sides"
    )

    $Music = Get-ChildItem "$NasPath\Music\*\" -Directory -Exclude $ExcludedDirs
    $MusicOutput = foreach ($album in $Music) {
        New-Object -Type PSObject -Property @{
        Transfer = ""
        Artist = ($album.FullName).Split('\')[2]
        Album = (($album.Name -split '\(\d\d\d\d\).*') -split '-')[1].Trim()
        Year = ($album.Name -split '(\d\d\d\d)')[1]
        }
    } 

}

#### Formatting
Write-Output "Formatting Spreadsheet..."

if ($GatherAll -or $GatherDocFilms) {
    $DocsSheet = $DocsOutput | Select-Object Transfer,Title,Year |
    Export-Excel -Path $ExportPath\$ExportFile -WorkSheetname "Docs" -FreezeTopRow -BoldTopRow -TableName DocsTable -TableStyle Medium8 -AutoSize -PassThru
    $DocsSheetObj = $DocsSheet.Workbook.Worksheets["Docs"]
    foreach ($c in 1..3) {$DocsSheetObj.Column($c) | Set-Format -HorizontalAlignment Left}
    Export-Excel -ExcelPackage $DocsSheet -WorkSheetname "Docs"
}

if ($GatherAll -or $GatherDocSeries) {
    $DocuSeriesSheet = $DocuSeriesOutput | Select-Object Transfer,Title |
    Export-Excel -Path $ExportPath\$ExportFile -WorkSheetname "DocuSeries" -FreezeTopRow -BoldTopRow -TableName DocuSeriesTable -TableStyle Medium8 -AutoSize -PassThru
    $DocuSeriesSheetObj = $DocuSeriesSheet.Workbook.Worksheets["DocuSeries"]
    foreach ($c in 1..2) {$DocuSeriesSheetObj.Column($c) | Set-Format -HorizontalAlignment Left}
    Export-Excel -ExcelPackage $DocuSeriesSheet -WorkSheetname "DocuSeries"
}

if ($GatherAll -or $GatherTvShows) {
    $TvShowsSheet = $TvShowsOutput| Select-Object Transfer,Title,Seasons |
    Export-Excel -Path $ExportPath\$ExportFile -WorkSheetname "TVshows" -FreezeTopRow -BoldTopRow -TableName TvShowsTable -TableStyle Medium8 -AutoSize -PassThru
    $TvShowsSheetObj = $TvShowsSheet.Workbook.Worksheets["TVshows"]
    foreach ($c in 1..3) {$TvShowsSheetObj.Column($c) | Set-Format -HorizontalAlignment Left}
    Export-Excel -ExcelPackage $TvShowsSheet -WorkSheetname "TVshows"
}

if ($GatherAll -or $GatherMovies) {
    $MoviesSheet = $MoviesOutput | Select-Object Transfer,Title,Year,Collection |
    Export-Excel -Path $ExportPath\$ExportFile -WorkSheetname "Movies" -FreezeTopRow -BoldTopRow -TableName MoviesTable -TableStyle Medium8 -AutoSize -PassThru
    $MoviesSheetObj = $MoviesSheet.Workbook.Worksheets["Movies"]
    foreach ($c in 1..4) {$MoviesSheetObj.Column($c) | Set-Format -HorizontalAlignment Left}
    Export-Excel -ExcelPackage $MoviesSheet -WorkSheetname "Movies"
}

if ($GatherAll -or $GatherMusic) {
    $MusicSheet = $MusicOutput | Select-Object Transfer,Artist,Album,Year |
    Export-Excel -Path $ExportPath\$ExportFile -WorkSheetname "Music" -FreezeTopRow -BoldTopRow -TableName MusicTable -TableStyle Medium8 -AutoSize -PassThru
    $MusicSheetObj = $MusicSheet.Workbook.Worksheets["Music"]
    foreach ($c in 1..4) {$MusicSheetObj.Column($c) | Set-Format -HorizontalAlignment Left}
    Export-Excel -ExcelPackage $MusicSheet -WorkSheetname "Music"
}




Write-Output "Complete!"





