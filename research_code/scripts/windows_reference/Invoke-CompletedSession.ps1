
#requires -Version 5.1
<#
Completed-session SMB simulation for a configured university lab.
Uses existing saved credentials and audited SMB shares.
Does not modify the original 14-day dataset.

Example:
.\Invoke-CompletedSession.ps1 -User example.user -Mode Benign
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')]
    [string]$User,

    [ValidateSet('Benign', 'Suspicious')]
    [string]$Mode = 'Benign',

    [string]$CredentialsDir = 'C:\UniversityData\Simulation\Credentials',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')]
    [string]$AccountDomain = 'EXAMPLE',
    [string]$LabServer = '198.51.100.10',
    [string]$SourceShare = '',
    [string]$RestrictedShare = '',
    [string]$OutputDir = 'C:\ThesisScripts\SessionResults',

    [ValidateRange(1, 100)]
    [int]$BenignFileCount = 8,

    [ValidateRange(10, 200)]
    [int]$SuspiciousFileCount = 40,

    [ValidateRange(0, 120)]
    [int]$SettleSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Override LabServer and/or shares for the target lab; defaults are documentation-only.
if (-not $SourceShare) { $SourceShare = '\\' + $LabServer + '\M04ResearchWorkspace' }
if (-not $RestrictedShare) { $RestrictedShare = '\\' + $LabServer + '\RestrictedAcademicDocuments' }

function Format-Utc([datetime]$Time) {
    return $Time.ToUniversalTime().ToString(
        "yyyy-MM-ddTHH:mm:ss.fffffff'Z'",
        [Globalization.CultureInfo]::InvariantCulture
    )
}

function Mount-LabShare(
    [string]$Unc,
    [pscredential]$Credential
) {
    if (-not $Unc.StartsWith(
        ('\\' + $LabServer + '\'),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Share is not on the configured lab server: $Unc"
    }

    $name = 'LAB' + [guid]::NewGuid().ToString('N').Substring(0, 7)

    New-PSDrive -Name $name `
        -PSProvider FileSystem `
        -Root $Unc `
        -Credential $Credential `
        -Scope Script `
        -ErrorAction Stop | Out-Null

    return $name
}

function Get-AccountSecurityEvents(
    [datetime]$FromUtc,
    [datetime]$ToUtc,
    [string]$Account
) {
    $matches = New-Object 'System.Collections.Generic.List[object]'
    $parts = $Account -split '\\', 2
    $domain = $parts[0]
    $name = $parts[1]

    try {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = @(5145, 4663, 5140)
            StartTime = $FromUtc.ToLocalTime().AddSeconds(-2)
            EndTime = $ToUtc.ToLocalTime().AddSeconds(2)
        } -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound' -or
            $_.Exception.Message -match 'No events were found') {
            return @{ Events = @(); LogError = $null }
        }

        return @{
            Events = @()
            LogError = $_.Exception.Message
        }
    }

    foreach ($event in $events) {
        try {
            [xml]$xml = $event.ToXml()
            $values = @{}

            foreach ($item in $xml.Event.EventData.Data) {
                $key = $item.GetAttribute('Name')
                if ($key) {
                    $values[$key] = [string]$item.InnerText
                }
            }

            if ($values['SubjectUserName'] -ieq $name -and
                $values['SubjectDomainName'] -ieq $domain) {

                $matches.Add([pscustomobject]@{
                    id = $event.Id
                    time_utc = Format-Utc (
                        $event.TimeCreated.ToUniversalTime()
                    )
                    share = $values['ShareName']
                    relative_path = $values['RelativeTargetName']
                })
            }
        }
        catch {
            # Do not attribute unreadable events by guessing.
        }
    }

    return @{
        Events = @($matches.ToArray())
        LogError = $null
    }
}

# Load existing university account credentials.

$credentialPath = Join-Path $CredentialsDir ($User + '.xml')

if (-not (Test-Path -LiteralPath $credentialPath -PathType Leaf)) {
    throw "Credential file not found: $credentialPath"
}

$credential = Import-Clixml -LiteralPath $credentialPath

if ($credential -isnot [pscredential]) {
    throw "Imported XML is not a PSCredential"
}

$expectedUsername = $AccountDomain + '\' + $User

if ($credential.UserName -ine $expectedUsername) {
    throw "Credential account mismatch: expected $expectedUsername"
}

# Prepare separate output location.

New-Item -ItemType Directory -Path $OutputDir -Force |
    Out-Null

$sessionId = [guid]::NewGuid().ToString('D')
$mounted = New-Object 'System.Collections.Generic.List[string]'

$counts = [ordered]@{
    source_files_read = 0
    restricted_access_attempts = 0
    restricted_files_read = 0
    restricted_access_denied = 0
    other_restricted_errors = 0
}

$notes = New-Object 'System.Collections.Generic.List[string]'

$failure = $null
$started = $null
$ended = $null

$securityResult = @{
    Events = @()
    LogError = $null
}

try {
    # Connect using the selected university account.

    $sourceDrive = Mount-LabShare `
        -Unc $SourceShare `
        -Credential $credential

    $mounted.Add($sourceDrive)
    $sourceRoot = $sourceDrive + ':\'

    $needed = if ($Mode -eq 'Benign') {
        $BenignFileCount
    }
    else {
        $SuspiciousFileCount
    }

    # Find existing synthetic lab documents.

    $files = @(Get-ChildItem `
        -LiteralPath $sourceRoot `
        -File `
        -Recurse `
        -ErrorAction Stop |
        Where-Object {
            $_.Length -gt 0 -and
            $_.Length -le 1048576 -and
            $_.FullName -notmatch '\\CompletedSessionRuns\\'
        } |
        Select-Object -First $needed)

    if ($files.Count -eq 0) {
        throw "No readable files found on $SourceShare"
    }

    if ($files.Count -lt $needed) {
        $notes.Add(
            "Only $($files.Count) files available; requested $needed."
        )
    }

    # Keep preparation outside the recorded session.

    Start-Sleep -Seconds 4

    $started = [datetime]::UtcNow

    # Perform file activity using authenticated SMB access.

    foreach ($file in $files) {
        try {
            Get-Content `
                -LiteralPath $file.FullName `
                -Encoding Byte `
                -TotalCount 1024 `
                -ErrorAction Stop | Out-Null

            $counts['source_files_read']++
        }
        catch {
            $notes.Add(
                "Read failed: $($file.Name)"
            )
        }

        if ($Mode -eq 'Benign') {
            Start-Sleep -Milliseconds 900
        }
        else {
            Start-Sleep -Milliseconds 150
        }
    }

    # Additional controlled activity for suspicious mode.

    if ($Mode -eq 'Suspicious') {
        $counts['restricted_access_attempts']++

        try {
            $restrictedDrive = Mount-LabShare `
                -Unc $RestrictedShare `
                -Credential $credential

            $mounted.Add($restrictedDrive)

            $restrictedRoot = $restrictedDrive + ':\'

            $restrictedItem = Get-ChildItem `
                -LiteralPath $restrictedRoot `
                -File `
                -Recurse `
                -ErrorAction Stop |
                Select-Object -First 1

            if ($null -ne $restrictedItem) {
                Get-Content `
                    -LiteralPath $restrictedItem.FullName `
                    -Encoding Byte `
                    -TotalCount 1024 `
                    -ErrorAction Stop | Out-Null

                $counts['restricted_files_read']++
            }
            else {
                $notes.Add(
                    'Restricted share accessible but contains no files.'
                )
            }
        }
        catch {
            if (
                $_.Exception -is [UnauthorizedAccessException] -or
                $_.CategoryInfo.Category -eq
                    [Management.Automation.ErrorCategory]::PermissionDenied -or
                $_.Exception.Message -match
                    'Access is denied|permission|logon failure'
            ) {
                $counts['restricted_access_denied']++
            }
            else {
                $counts['other_restricted_errors']++
            }

            $notes.Add(
                "Restricted attempt: $($_.CategoryInfo.Category)"
            )
        }
    }

    # Allow a settling period inside the recorded window.

    if ($SettleSeconds -gt 0) {
        Start-Sleep -Seconds $SettleSeconds
    }
}
catch {
    $failure = $_.Exception.Message
}
finally {
    if ($null -ne $started) {
        $ended = [datetime]::UtcNow

        # Verify local events for the selected account.

        $securityResult = Get-AccountSecurityEvents `
            -FromUtc $started `
            -ToUtc $ended `
            -Account $expectedUsername
    }

    Start-Sleep -Seconds 3

    # Disconnect temporary SMB drives.

    foreach ($name in $mounted) {
        Remove-PSDrive `
            -Name $name `
            -Scope Script `
            -Force `
            -ErrorAction SilentlyContinue
    }
}

# Summarize verified Security events.

$auditEvents = @($securityResult.Events)

$auditCounts = [ordered]@{
    event_5145 = @(
        $auditEvents | Where-Object { $_.id -eq 5145 }
    ).Count

    event_4663 = @(
        $auditEvents | Where-Object { $_.id -eq 4663 }
    ).Count

    event_5140 = @(
        $auditEvents | Where-Object { $_.id -eq 5140 }
    ).Count
}

$status = if ($null -ne $failure) {
    'failed'
}
elseif ($auditEvents.Count -eq 0) {
    'audit_not_verified'
}
else {
    'completed'
}

# Save ground-truth session metadata.

$record = [ordered]@{
    mode = 'completed_session_lab_simulation_smb'
    session_id = $sessionId
    status = $status
    scenario_ground_truth = $Mode
    simulated_username = $expectedUsername

    controlling_process_user = (
        [Security.Principal.WindowsIdentity]::GetCurrent().Name
    )

    host = $env:COMPUTERNAME

    activity_start = if ($null -ne $started) {
        Format-Utc $started
    }
    else {
        $null
    }

    activity_end = if ($null -ne $ended) {
        Format-Utc $ended
    }
    else {
        $null
    }

    end_includes_settle_seconds = $SettleSeconds

    source_share = $SourceShare

    restricted_share = if ($Mode -eq 'Suspicious') {
        $RestrictedShare
    }
    else {
        $null
    }

    counts = $counts
    local_security_event_counts = $auditCounts
    local_security_log_error = $securityResult.LogError
    local_security_sample = @(
        $auditEvents | Select-Object -First 8
    )
    notes = @($notes.ToArray())
    error = $failure
    alerts_published = $false
    models_retrained = $false
    original_dataset_modified = $false

    limitations = @(
        'SMB operations use the selected credentials.',
        'Local PowerShell and Sysmon processes may belong to Administrator.',
        'Indexer ingestion and model features require separate verification.'
    )
}

$jsonPath = Join-Path $OutputDir (
    'session_' + $sessionId + '.json'
)

$record |
    ConvertTo-Json -Depth 7 |
    Set-Content -LiteralPath $jsonPath -Encoding UTF8

# Display results.

Write-Host ''
Write-Host ('Status:          {0}' -f $status)
Write-Host ('Simulated user:  {0}' -f $expectedUsername)
Write-Host ('Controlling OS: {0}' -f $record.controlling_process_user)
Write-Host ('Start UTC:      {0}' -f $record.activity_start)
Write-Host ('End UTC:        {0}' -f $record.activity_end)
Write-Host ('Files read:     {0}' -f $counts['source_files_read'])

Write-Host ('Security 5145:  {0}' -f $auditCounts.event_5145)
Write-Host ('Security 4663:  {0}' -f $auditCounts.event_4663)
Write-Host ('Security 5140:  {0}' -f $auditCounts.event_5140)

Write-Host ('Session ID:     {0}' -f $sessionId)
Write-Host ('Saved JSON:     {0}' -f $jsonPath)

if ($securityResult.LogError) {
    Write-Warning $securityResult.LogError
}

foreach ($note in $notes) {
    Write-Warning $note
}

if ($status -eq 'completed') {
    Write-Host ''
    Write-Host 'Run this on your authenticated Mac terminal:'

    Write-Host '/opt/miniconda3/bin/python3 -m src.controlled_replay.new_session \'

    Write-Host ("  --username '{0}' \" -f $expectedUsername)
    Write-Host ("  --start '{0}' \" -f $record.activity_start)
    Write-Host ("  --end '{0}' \" -f $record.activity_end)

    Write-Host (
        "  --output-dir 'data/experiments/new_completed_sessions/{0}'" -f $sessionId
    )
}
elseif ($status -eq 'audit_not_verified') {
    Write-Warning 'No matching local Security events found.'
    Write-Warning 'Check auditing before running model inference.'
}
else {
    throw "Session failed. Inspect $jsonPath. Error: $failure"
}
