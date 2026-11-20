param(
    [Parameter(Mandatory=$true)]
    [string]$SessionID,

    [Parameter(Mandatory=$true)]
    [string]$Username,

    [ValidateRange(1,20)]
    [int]$FileCount = 3
)

$ErrorActionPreference = "Stop"

$base = "C:\UniversityData\Simulation"
$credentialPath = "$base\Credentials\$Username.xml"
$resultDir = "$base\Dataset2026\ExecutionResults"

$restrictedShare = "\\198.51.100.10\RestrictedResearch"

New-Item -ItemType Directory -Path $resultDir -Force |
    Out-Null

if ($SessionID -notmatch '^[a-zA-Z0-9-]{1,80}$') {
    throw "Invalid SessionID."
}

Import-Module ActiveDirectory

$user = Get-ADUser -Identity $Username

$groups = @(
    Get-ADPrincipalGroupMembership $user |
    Select-Object -ExpandProperty Name
)

if ("Students-Group" -notin $groups) {
    throw "M01 requires a student account."
}

if (-not (Test-Path $credentialPath)) {
    throw "Credential file missing: $credentialPath"
}

$resultPath = Join-Path $resultDir "$SessionID.json"

if (Test-Path $resultPath) {
    throw "Session result already exists. Refusing duplicate execution."
}

$credential = Import-Clixml $credentialPath

$started = [DateTime]::UtcNow

$denied = 0
$allowed = 0
$attempts = @()

# Known synthetic research files.
# File enumeration itself may be denied to students.
$fileNumbers = @(1..300 | Get-Random -Count $FileCount)

foreach ($number in $fileNumbers) {

    $fileName = "ResearchData_Document_{0:D4}.txt" -f $number
    $target = "$restrictedShare\$fileName"
    $drive = "M01$([guid]::NewGuid().ToString('N').Substring(0,8))"

    $outcome = "Unknown"
    $errorMessage = ""

    try {
        New-PSDrive `
            -Name $drive `
            -PSProvider FileSystem `
            -Root $restrictedShare `
            -Credential $credential `
            -ErrorAction Stop | Out-Null

        Get-Content -LiteralPath "${drive}:\$fileName" `
            -ErrorAction Stop | Out-Null

        $outcome = "Allowed"
        $allowed++
    }
    catch {
        $errorMessage = $_.Exception.Message

        if (
            $_.Exception -is [System.UnauthorizedAccessException] -or
            $errorMessage -match 'access is denied|access denied|permission denied'
        ) {
            $outcome = "Denied"
            $denied++
        }
        else {
            $outcome = "Error"
        }
    }
    finally {
        Remove-PSDrive -Name $drive `
            -Force -ErrorAction SilentlyContinue
    }

    $attempts += [PSCustomObject]@{
        TargetPath = $target
        TimestampUTC = [DateTime]::UtcNow.ToString("o")
        Outcome = $outcome
        ErrorMessage = $errorMessage
    }

    Start-Sleep -Milliseconds (Get-Random -Minimum 300 -Maximum 1500)
}

$ended = [DateTime]::UtcNow

$executionStatus = if ($denied -eq $FileCount) {
    "Completed"
}
elseif ($allowed -gt 0) {
    "UnexpectedAccessAllowed"
}
else {
    "Failed"
}

$result = [PSCustomObject]@{
    SessionID = $SessionID
    ScenarioID = "M01"
    Username = $Username
    IntendedLabel = 1
    StartedUTC = $started.ToString("o")
    EndedUTC = $ended.ToString("o")
    Attempts = $FileCount
    AccessDenied = $denied
    AccessAllowed = $allowed
    ExecutionStatus = $executionStatus
    ValidationStatus = "PendingWazuhVerification"
    Activities = $attempts
}

$result |
    ConvertTo-Json -Depth 5 |
    Set-Content $resultPath -Encoding UTF8

Write-Host "M01 session: $SessionID"
Write-Host "User: $Username"
Write-Host "Access denied: $denied"
Write-Host "Unexpectedly allowed: $allowed"
Write-Host "Status: $executionStatus"

if ($executionStatus -ne "Completed") {
    throw "M01 did not produce the expected access-denial outcomes."
}
