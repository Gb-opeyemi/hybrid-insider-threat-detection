param(
    [Parameter(Mandatory)]
    [ValidateRange(1, 150)]
    [int]$FileCount
)

$ErrorActionPreference = "Stop"

$root = "C:\UniversityData\ResearchData"

if (-not (Test-Path $root -PathType Container)) {
    throw "ResearchData repository not found."
}

# Discover documents in root and departmental subfolders.
# Exclude pilot artefacts and reserved reference material.
$eligible = @(
    Get-ChildItem -LiteralPath $root -File -Recurse |
        Where-Object {
            $_.Extension -eq ".txt" -and
            $_.FullName -notlike "*\M04-Pilot\*" -and
            $_.Name -ne "confidential-research.txt"
        }
)

if ($eligible.Count -lt $FileCount) {
    throw "Only $($eligible.Count) eligible files available."
}

$selected = @(
    $eligible | Get-Random -Count $FileCount
)

foreach ($file in $selected) {
    $relativePath = $file.FullName.Substring(
        $root.Length
    ).TrimStart("\")

    [PSCustomObject]@{
        RelativePath = $relativePath
        FullPath = $file.FullName
        FileName = $file.Name
        SizeBytes = $file.Length
    }
}
