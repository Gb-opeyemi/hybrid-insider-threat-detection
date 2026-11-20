param(
    [Parameter(Mandatory)]
    [string]$SessionID,

    [Parameter(Mandatory)]
    [string]$Username,

    [ValidateRange(1, 20)]
    [int]$FileCount = 10
)

$ErrorActionPreference = "Stop"

$base = "C:\UniversityData\Simulation"
$share = "\\198.51.100.10\M04ResearchWorkspace"
$credentialPath = "$base\Credentials\$Username.xml"
$resultDir = "$base\Dataset2026\ExecutionResults"

if ($SessionID -notmatch '^[A-Za-z0-9-]{1,80}$') {
    throw "Invalid SessionID."
}

Import-Module ActiveDirectory

$user = Get-ADUser -Identity $Username
$groups = @(
    Get-ADPrincipalGroupMembership $user |
    Select-Object -ExpandProperty Name
)

if ("Researchers-Group" -notin $groups) {
    throw "M04 requires a researcher account."
}

if (-not (Test-Path $credentialPath)) {
    throw "Credential file missing: $credentialPath"
}

New-Item -ItemType Directory -Path $resultDir -Force |
    Out-Null

$resultPath = Join-Path $resultDir "$SessionID.json"

if (Test-Path $resultPath) {
    throw "Existing result found. Duplicate execution blocked."
}

$credential = Import-Clixml $credentialPath

if ($credential -isnot [PSCredential]) {
    throw "Invalid credential file."
}

$drive = "M04DATA"
$driveCreated = $false
$started = [DateTime]::UtcNow
$deleted = 0
$activities = @()
$errorMessage = ""
$status = "Failed"

try {
    New-PSDrive `
        -Name $drive `
        -PSProvider FileSystem `
        -Root $share `
        -Credential $credential `
        -ErrorAction Stop | Out-Null

    $driveCreated = $true

    # Select existing research documents only
    # Search the authenticated research share and all its subfolders.
    $files = @(
        Get-ChildItem "${drive}:\" -File -Recurse -ErrorAction Stop |
        Where-Object {
            $_.Extension -eq ".txt" -and
            $_.FullName -notlike "*\M04-Pilot\*" -and
            $_.Name -ne "confidential-research.txt"
        }
    )

    if ($files.Count -lt $FileCount) {
        throw "Not enough documents remain in M04 repository."
    }

    $selected = @($files | Get-Random -Count $FileCount)

    # Delete selected existing files in a burst
    foreach ($file in $selected) {
        $timestamp = [DateTime]::UtcNow
        $outcome = "Failed"
        $activityError = ""

        try {
            Remove-Item -LiteralPath $file.FullName `
                -Force -ErrorAction Stop

            $outcome = "Success"
            $deleted++
        }
        catch {
            $activityError = $_.Exception.Message
        }

        $activities += [PSCustomObject]@{
            SessionID    = $SessionID
            TimestampUTC = $timestamp.ToString("o")
            ActionType   = "Delete"
            TargetPath   = $file.FullName
            Outcome      = $outcome
            ErrorMessage = $activityError
        }

        Start-Sleep -Milliseconds (
            Get-Random -Minimum 200 -Maximum 1200
        )
    }

    if ($deleted -eq $FileCount) {
        $status = "Completed"
    }
    else {
        $status = "Partial"
    }
}
catch {
    $errorMessage = $_.Exception.Message
}
finally {
    if ($driveCreated) {
        Remove-PSDrive -Name $drive -Force `
            -ErrorAction SilentlyContinue
    }

    $ended = [DateTime]::UtcNow

    $result = [PSCustomObject]@{
        SessionID         = $SessionID
        ScenarioID        = "M04"
        Username          = $Username
        IntendedLabel     = 1
        StartedUTC        = $started.ToString("o")
        EndedUTC          = $ended.ToString("o")
        FilesRequested    = $FileCount
        FilesDeleted      = $deleted
        ExecutionStatus   = $status
        ValidationStatus  = "PendingWazuhVerification"
        Activities        = $activities
        ErrorMessage      = $errorMessage
    }

    $result |
        ConvertTo-Json -Depth 6 |
        Set-Content $resultPath -Encoding UTF8

    Write-Host "M04 session: $SessionID"
    Write-Host "Researcher: $Username"
    Write-Host "Files deleted: $deleted / $FileCount"
    Write-Host "Status: $status"
}

if ($status -ne "Completed") {
    throw "M04 incomplete. See execution result for details."
}

