param(
    [string]$SessionID = "",
    [string]$Username = "grace.student",
    [string]$Role = "Student",
    [ValidateSet("NORMAL_READ", "M03")]
    [string]$ScenarioID = "NORMAL_READ",
    [ValidateRange(1, 300)]
    [int]$FileCount = 6,
    [ValidateRange(0, 300)]
    [double]$MinDelaySeconds = 20,
    [ValidateRange(0, 300)]
    [double]$MaxDelaySeconds = 120
)

$ErrorActionPreference = "Stop"

$base = "C:\UniversityData\Simulation"
$credentialPath = "$base\Credentials\$Username.xml"
$sessionFile = "$base\simulation_sessions.csv"
$activityFile = "$base\simulation_activities.csv"

# Prevent inconsistent timing parameters
if ($MaxDelaySeconds -lt $MinDelaySeconds) {
    throw "MaxDelaySeconds must be greater than or equal to MinDelaySeconds."
}

# Match the supplied account to its actual AD role
$roleGroups = @{
    Student        = "Students-Group"
    Researcher     = "Researchers-Group"
    Lecturer       = "Lecturers-Group"
    Administrative = "Administrative-Group"
    IT             = "IT-Group"
}

Import-Module ActiveDirectory

if (-not $roleGroups.ContainsKey($Role)) {
    throw "Invalid role: $Role"
}

$user = Get-ADUser -Identity $Username
$members = @(Get-ADPrincipalGroupMembership $user |
    Select-Object -ExpandProperty Name)

if ($roleGroups[$Role] -notin $members) {
    throw "$Username is not a member of $($roleGroups[$Role])."
}

if ($ScenarioID -eq "M03" -and $Role -notin @("Researcher", "Lecturer")) {
    throw "M03 is restricted to researcher and lecturer accounts."
}

$resources = @{
    Student = @{
        Share = "\\198.51.100.10\RestrictedAcademicDocuments"
        Resource = "AcademicDocuments"
    }
    Researcher = @{
        Share = "\\198.51.100.10\RestrictedResearch"
        Resource = "ResearchData"
    }
    Lecturer = @{
        Share = "\\198.51.100.10\RestrictedAcademicDocuments"
        Resource = "AcademicDocuments"
    }
    Administrative = @{
        Share = "\\198.51.100.10\RestrictedStudentRecords"
        Resource = "StudentRecords"
    }
    IT = @{
        Share = "\\198.51.100.10\RestrictedITResources"
        Resource = "IT-Resources"
    }
}

if (-not (Test-Path $credentialPath)) {
    throw "Credential file not found: $credentialPath"
}

# Don't allow an existing SMB connection to contaminate attribution
$existingConnections = @(net use 2>&1 |
    Select-String -SimpleMatch "198.51.100.10")

if ($existingConnections.Count -gt 0) {
    throw "Existing SMB connection detected. Run 'net use' and disconnect it first."
}

if ([string]::IsNullOrWhiteSpace($SessionID)) {
    $sessionID = [guid]::NewGuid().ToString()
}
else {
    $sessionID = $SessionID
}
$start = [DateTime]::UtcNow
$activities = @()
$driveName = "SIMDRIVE"
$driveCreated = $false
$status = "Failed"
$resource = $resources[$Role]
$failureMessage = ""

$intendedLabel = if ($ScenarioID -eq "M03") { 1 } else { 0 }
$scenarioType = if ($ScenarioID -eq "M03") {
    "ExcessiveFileAccessPilot"
} else {
    "NormalDocumentAccess"
}

try {
    $credential = Import-Clixml $credentialPath

    New-PSDrive `
        -Name $driveName `
        -PSProvider FileSystem `
        -Root $resource.Share `
        -Credential $credential `
        -ErrorAction Stop | Out-Null

    $driveCreated = $true

    $files = @(
    Get-ChildItem "${driveName}:\" -File -Recurse -ErrorAction Stop |
    Where-Object {
        $_.Extension -eq ".txt" -and
        $_.FullName -notlike "*\M04-Pilot\*" -and
        $_.Name -ne "confidential-research.txt"
    }
)

    if ($files.Count -lt $FileCount) {
        throw "Requested $FileCount files but only $($files.Count) are available."
    }

    # Random selection also randomizes the order
    $selectedFiles = @($files | Get-Random -Count $FileCount)

    foreach ($file in $selectedFiles) {
        $timestamp = [DateTime]::UtcNow
        $outcome = "Failed"
        $errorMessage = ""

        try {
            Get-Content -LiteralPath $file.FullName `
                -ErrorAction Stop | Out-Null
            $outcome = "Success"
        }
        catch {
            $errorMessage = $_.Exception.Message
            if ($_.Exception -is [System.UnauthorizedAccessException]) {
                $outcome = "Denied"
            }
        }

        $activities += [PSCustomObject]@{
            SessionID    = $sessionID
            ActivityID   = [guid]::NewGuid().ToString()
            Username     = $Username
            ActionType   = "Read"
            ResourceType = $resource.Resource
            TargetPath   = $file.FullName
            TimestampUTC = $timestamp.ToString("o")
            Outcome      = $outcome
            ErrorMessage = $errorMessage
        }

        $delayMs = [int]((
            $MinDelaySeconds +
            (Get-Random -Minimum 0.0 -Maximum 1.0) *
            ($MaxDelaySeconds - $MinDelaySeconds)
        ) * 1000)

        if ($delayMs -gt 0) {
            Start-Sleep -Milliseconds $delayMs
        }
    }

    if (@($activities | Where-Object Outcome -eq "Success").Count -eq $FileCount) {
        $status = "Completed"
    }
    else {
        $status = "Partial"
    }
}
catch {
    $failureMessage = $_.Exception.Message
    Write-Warning "Simulation error: $failureMessage"
}
finally {
    if ($driveCreated) {
        Remove-PSDrive -Name $driveName `
            -Force -ErrorAction SilentlyContinue
    }

    $end = [DateTime]::UtcNow

    $session = [PSCustomObject]@{
        SessionID         = $sessionID
        Username          = $Username
        Role              = $Role
        ScenarioID        = $ScenarioID
        ScenarioType      = $scenarioType
        IntendedLabel     = $intendedLabel
        StartTimeUTC      = $start.ToString("o")
        EndTimeUTC        = $end.ToString("o")
        DurationSeconds   = [Math]::Round(($end - $start).TotalSeconds, 2)
        ActionsAttempted  = $activities.Count
        ActionsSucceeded  = @($activities | Where-Object Outcome -eq "Success").Count
        ActionsDenied     = @($activities | Where-Object Outcome -eq "Denied").Count
        ExecutionStatus   = $status
        ValidationStatus  = "PendingWazuhVerification"
    }

    # Existing fixed-schema CSV files
    foreach ($activity in $activities) {
        $activity | Export-Csv -Path $activityFile `
            -Append -NoTypeInformation -Encoding UTF8
    }

    $session | Export-Csv -Path $sessionFile `
        -Append -NoTypeInformation -Encoding UTF8

    Write-Host "`nSimulation results:" -ForegroundColor Cyan
    $session | Format-List

    if ($failureMessage) {
        Write-Host "Error: $failureMessage" -ForegroundColor Red
    }
}


