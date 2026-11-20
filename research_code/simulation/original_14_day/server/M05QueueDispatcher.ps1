param(
    [Parameter(Mandatory)]
    [string]$SessionID,

    [Parameter(Mandatory)]
    [string]$Username,

    [ValidateRange(1,150)]
    [int]$FileCount = 3
)

$ErrorActionPreference = "Stop"

$base = "C:\UniversityData\Simulation"
$researchRoot = "C:\UniversityData\ResearchData"
$queueDir = Join-Path $base "M05Queue\Pending"
$resultDir = Join-Path $base "M05Results"

# The existing Windows 11 worker runs as the configured example account.
# Never label another user's session as the configured example account's activity.
if ($Username -ine "example.user") {
    throw "M05 worker is configured only for example.user. Requested: $Username"
}

if ($SessionID -notmatch '^[a-zA-Z0-9_-]+$') {
    throw "Invalid SessionID."
}

if (-not (Test-Path $researchRoot -PathType Container)) {
    throw "Research repository not found."
}

New-Item -ItemType Directory -Path $queueDir -Force | Out-Null

$jobPath = Join-Path $queueDir "$SessionID.json"
$resultPath = Join-Path $resultDir "$SessionID-result.json"

if ((Test-Path $jobPath) -or (Test-Path $resultPath)) {
    throw "M05 session already queued or executed: $SessionID"
}

# Select from the original shared research repository.
$files = @(
    Get-ChildItem -LiteralPath $researchRoot -File -Recurse |
    Where-Object {
        $_.Extension -eq ".txt" -and
        $_.FullName -notlike "*\M04-Pilot\*" -and
        $_.Name -ne "confidential-research.txt"
    }
)

if ($files.Count -lt $FileCount) {
    throw "Insufficient research documents for M05."
}

$selected = @($files | Get-Random -Count $FileCount)

$sourceFiles = @(
    foreach ($file in $selected) {
        # Preserve relative paths for departmental subfolders.
        $file.FullName.Substring(
            $researchRoot.TrimEnd('\').Length + 1
        )
    }
)

$job = [ordered]@{
    SessionID = $SessionID
    Scenario = "M05"
    Username = $Username
    SourceFiles = $sourceFiles
    Destination = "198.51.100.20"
    Status = "Pending"
}

# Write a temporary file first, then publish it to the queue.
$tempPath = Join-Path $queueDir (
    ".staging-" + [guid]::NewGuid().ToString("N") + ".tmp"
)

try {
    $json = $job | ConvertTo-Json -Depth 5
    $encoding = New-Object System.Text.UTF8Encoding($false)

    [System.IO.File]::WriteAllText(
        $tempPath,
        $json,
        $encoding
    )

    Move-Item -LiteralPath $tempPath `
        -Destination $jobPath `
        -ErrorAction Stop
}
finally {
    if (Test-Path $tempPath) {
        Remove-Item -LiteralPath $tempPath -Force
    }
}

Write-Host ""
Write-Host "M05 JOB QUEUED" -ForegroundColor Green
Write-Host "Session: $SessionID"
Write-Host "User: $Username"
Write-Host "Files selected: $($sourceFiles.Count)"
Write-Host "Destination: 198.51.100.20"
Write-Host "Queue file: $jobPath"
Write-Host "Execution: Awaiting Windows 11 worker"
