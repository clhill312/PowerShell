# Requires that mkvmerge is installed.
# https://www.bunkus.org/videotools/mkvtoolnix/doc/mkvmerge.html

$no = 0 # set initial variable for counter

$InputPath = "Z:\TV Shows\Show\Season 1"

# Create an "automated" folder if it does not exist
if (-Not(Test-Path "$InputPath\automated")) {
    New-Item -Path $InputPath -Name "automated" -ItemType Directory
}

$InputFiles = Get-ChildItem $InputPath -File

foreach ($file in $InputFiles) {


$OutputFilename = $file.Name

# Parses the episode title from the filename. Assumes that filename is in "Show Name - S00E00 - Episode Name" format
$Title = $file.Name
$Title = $Title.Split('-')
$Title = $Title.Split('.')
$Title = $Title[2]
$Title = $Title.Trim()


# audio track ID to keep
$AudioTracks = "1"

#subtitle track ID to keep
$SubtitleTracks = "5"

$no++
Write-Output "Processing file $no of $($InputFiles.Count)"

mkvmerge.exe --output "$InputPath\automated\$OutputFilename" --title $Title --audio-tracks $AudioTracks --subtitle-tracks $SubtitleTracks $file.FullName

}
