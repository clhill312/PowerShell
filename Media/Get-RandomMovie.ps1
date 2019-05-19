function Get-RandomMovie {   
    [CmdletBinding()]

    $ExcludedFiletypes = @(
        '*.sub'
        '*.srt'
        '*.jpg'
        '*.png'
    )
    
    $MoviePaths = @(
        'C:\Movies'
        'C:\Documentaries'
        'C:\AnimatedFilms'
    )

    $AllMovies = Get-ChildItem -Path $MoviePaths -File -Exclude $ExcludedFiletypes -Recurse
    $AllMovies.FullName |
    Get-Random |
    ForEach-Object {mpv $_}

}