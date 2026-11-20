param(
    [Parameter(Mandatory)]
    [string]$SessionID,

    [Parameter(Mandatory)]
    [string]$Username,

    [ValidateRange(1, 8)]
    [int]$FailedLogins = 3
)

$ErrorActionPreference = "Stop"

$base = "C:\UniversityData\Simulation"
$credentialPath = "$base\Credentials\$Username.xml"
$resultDir = "$base\Dataset2026\ExecutionResults"
$share = "\\198.51.100.10\RestrictedAcademicDocuments"

Import-Module ActiveDirectory

if ($SessionID -notmatch '^[a-zA-Z0-9-]{1,80}$') {
    throw "Invalid SessionID"
}

$user = Get-ADUser -Identity $Username

$groups = @(
    Get-ADPrincipalGroupMembership $user |
    Select-Object -ExpandProperty Name
)

if ("Students-Group" -notin $groups) {
    throw "M02 requires a student account."
}

# Respect effective account lockout policy
$finePolicy = Get-ADUserResultantPasswordPolicy -Identity $Username

$threshold = if ($null -ne $finePolicy) {
    [int]$finePolicy.LockoutThreshold
}
else {
    [int](Get-ADDefaultDomainPasswordPolicy).LockoutThreshold
}

if ($threshold -gt 0 -and $FailedLogins -ge $threshold) {
    throw "Planned failures could lock the account. Session blocked."
}

if (-not (Test-Path $credentialPath)) {
    throw "Credential file missing."
}

New-Item -ItemType Directory -Path $resultDir -Force |
    Out-Null

$resultPath = Join-Path $resultDir "$SessionID.json"

if (Test-Path $resultPath) {
    throw "Session already has a result. Duplicate execution blocked."
}

$correctCredential = Import-Clixml $credentialPath

if ($correctCredential -isnot [PSCredential]) {
    throw "Invalid saved credential."
}

$started = [DateTime]::UtcNow
$activities = @()
$failuresObserved = 0
$successObserved = $false

try {
    for ($i = 1; $i -le $FailedLogins; $i++) {

        $badPassword = (
            [guid]::NewGuid().ToString("N") + "!Incorrect"
        ) | ConvertTo-SecureString -AsPlainText -Force

        $badCredential = New-Object System.Management.Automation.PSCredential(
            $correctCredential.UserName,
            $badPassword
        )

        $drive = "AUTHBAD"
        $outcome = "FailedAuthentication"

        try {
            New-PSDrive -Name $drive `
                -PSProvider FileSystem `
                -Root $share `
                -Credential $badCredential `
                -ErrorAction Stop | Out-Null

            $outcome = "UnexpectedSuccess"
        }
        catch {
            $outcome = "FailedAuthentication"
            $failuresObserved++
        }
        finally {
            Remove-PSDrive -Name $drive -Force `
                -ErrorAction SilentlyContinue
        }

        $activities += [PSCustomObject]@{
            TimestampUTC = [DateTime]::UtcNow.ToString("o")
            Attempt = $i
            Outcome = $outcome
        }

        if ($outcome -eq "UnexpectedSuccess") {
            throw "Incorrect credentials were unexpectedly accepted."
        }

        Start-Sleep -Seconds (Get-Random -Minimum 2 -Maximum 6)
    }

    # Attempt successful authentication
    $drive = "AUTHGOOD"

    try {
        New-PSDrive -Name $drive `
            -PSProvider FileSystem `
            -Root $share `
            -Credential $correctCredential `
            -ErrorAction Stop | Out-Null

        Get-ChildItem "${drive}:\" -ErrorAction Stop |
            Select-Object -First 1 | Out-Null

        $successObserved = $true
    }
    finally {
        Remove-PSDrive -Name $drive -Force `
            -ErrorAction SilentlyContinue
    }

    $activities += [PSCustomObject]@{
        TimestampUTC = [DateTime]::UtcNow.ToString("o")
        Attempt = $FailedLogins + 1
        Outcome = if ($successObserved) {
            "SuccessfulAuthentication"
        } else {
            "FailedAuthentication"
        }
    }
}
catch {
    $errorMessage = $_.Exception.Message
}
finally {
    $ended = [DateTime]::UtcNow

    $status = if (
        $failuresObserved -eq $FailedLogins -and
        $successObserved
    ) {
        "Completed"
    }
    else {
        "Failed"
    }

    $result = [PSCustomObject]@{
        SessionID = $SessionID
        ScenarioID = "M02"
        Username = $Username
        IntendedLabel = 1
        StartedUTC = $started.ToString("o")
        EndedUTC = $ended.ToString("o")
        FailedLoginsRequested = $FailedLogins
        FailedLoginsObserved = $failuresObserved
        SuccessfulAuthentication = $successObserved
        ExecutionStatus = $status
        ValidationStatus = "PendingWazuhVerification"
        Activities = $activities
        ErrorMessage = $errorMessage
    }

    $result |
        ConvertTo-Json -Depth 5 |
        Set-Content $resultPath -Encoding UTF8

    Write-Host "M02 Session: $SessionID"
    Write-Host "User: $Username"
    Write-Host "Failed attempts: $failuresObserved"
    Write-Host "Successful authentication: $successObserved"
    Write-Host "Status: $status"
}

if ($status -ne "Completed") {
    throw "M02 session failed. Check execution result."
}
