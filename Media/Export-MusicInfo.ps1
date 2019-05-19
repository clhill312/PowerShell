#Requires -RunAsAdministrator

$path = "D:\Music"
$ExportPath = "D:\"
$ExportFile = "MusicInfo.csv"


$objShell = New-Object -ComObject Shell.Application
function getMP3MetaData($path)
{
	# Get the file name, and the folder it exists in
	$file = split-path $path -leaf
	$path = split-path $path
	$objFolder = $objShell.namespace($path)
	$objFile = $objFolder.parsename($file)
	$result = @{}
	0..266 | ForEach-Object {
		if ($objFolder.getDetailsOf($objFile, $_))
		{
			$result[$($objFolder.getDetailsOf($objFolder.items, $_))] = $objFolder.getDetailsOf($objFile, $_)
		}
	}
	return $result
}


# music file types to include
$MusicFileTypes = "*.m4a", "*.m4b", "*.mp3", "*.mp4", "*.wma", "*.flc", "*.flac"


$MusicFiles = Get-ChildItem -Force -Path $path -Recurse -Include $MusicFileTypes | Where-Object {! $_.PSIsContainer}

foreach ($file in $MusicFiles) {
# Get the metadata for the file
$fileData = getMP3MetaData($file.FullName)

Write-Output "Exporting info for $($file.FullName)"

$OutputObj  = New-Object -Type PSObject

$OutputObj | Add-Member -MemberType NoteProperty -Name Path -Value $fileData.Path -ErrorAction Continue
$OutputObj | Add-Member -MemberType NoteProperty -Name Size -Value $fileData.Size -ErrorAction Continue
$OutputObj | Add-Member -MemberType NoteProperty -Name Artist -Value $fileData.Authors -ErrorAction Continue
$OutputObj | Add-Member -MemberType NoteProperty -Name TrackNo -Value $fileData.'#' -ErrorAction Continue
$OutputObj | Add-Member -MemberType NoteProperty -Name Title -Value $fileData.Title -ErrorAction Continue
$OutputObj | Add-Member -MemberType NoteProperty -Name Album -Value $fileData.Album -ErrorAction Continue
$OutputObj | Add-Member -MemberType NoteProperty -Name Year -Value $fileData.Year -ErrorAction Continue

$OutputObj | Export-Csv "$ExportPath\$ExportFile" -Append -NoTypeInformation -ErrorAction Continue -Force

}

Write-Output "Complete!"
