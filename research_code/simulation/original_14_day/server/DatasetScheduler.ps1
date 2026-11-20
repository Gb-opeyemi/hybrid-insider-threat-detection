param(
    [switch]$ShowPlan,
    [switch]$RunDue,
    [ValidateRange(1,20)]
    [int]$MaxSessions = 3
)

$ErrorActionPreference = "Stop"

$base = "C:\UniversityData\Simulation"
$schedulePath = Join-Path $base "Dataset2026\dataset_schedule_v3.csv"
$normalController = Join-Path $base "Scripts\NormalActivityController.ps1"
$maliciousDispatcher = Join-Path $base "Scripts\MaliciousDispatcher.ps1"
$m05Dispatcher = Join-Path $base "Scripts\M05QueueDispatcher.ps1"
$stateDir = Join-Path $base "Dataset2026\SchedulerState"
$ledgerPath = Join-Path $stateDir "execution_ledger.csv"
$lockPath = Join-Path $stateDir "scheduler.lock"

# Simulation Day 1: 26 October 2026, UTC
$startUTC = [datetime]::SpecifyKind(
    [datetime]"2026-10-26",
    [System.DateTimeKind]::Utc
)

New-Item -ItemType Directory -Path $stateDir -Force | Out-Null

if (-not (Test-Path $schedulePath)) {
    throw "Dataset schedule not found."
}

if (-not (Test-Path $normalController)) {
    throw "Normal activity controller not found."
}

$rows = @(Import-Csv -LiteralPath $schedulePath)

if ($rows.Count -ne 1200) {
    throw "Expected 1200 sessions. Found $($rows.Count)."
}

$seenIDs = @{}

$sessions = foreach ($row in $rows) {

    if ($seenIDs.ContainsKey($row.SessionID)) {
        throw "Duplicate SessionID: $($row.SessionID)"
    }

    $seenIDs[$row.SessionID] = $true

    $day = [int]$row.SimulationDay

    if ($day -lt 1 -or $day -gt 14) {
        throw "Invalid simulation day for $($row.SessionID)"
    }

    $time = [timespan]::Parse(
        $row.TimeOfDayUTC,
        [System.Globalization.CultureInfo]::InvariantCulture
    )

    if ($time.TotalDays -ge 1 -or $time.TotalSeconds -lt 0) {
        throw "Invalid time for $($row.SessionID)"
    }

    $scheduledUTC = $startUTC.AddDays($day - 1).Add($time)

    [PSCustomObject]@{
        SessionID = $row.SessionID
        ScheduledUTC = $scheduledUTC
        SimulationDay = $day
        ScenarioID = $row.ScenarioID
        IntendedLabel = $row.IntendedLabel
        Username = $row.Username
        Role = $row.Role
        FileCount = [int]$row.FileCount
        FailedLogins = [int]$row.FailedLogins
        MinDelaySeconds = [int]$row.MinDelaySeconds
        MaxDelaySeconds = [int]$row.MaxDelaySeconds
    }
}

$sessions = @($sessions | Sort-Object ScheduledUTC, SessionID)

function Get-Ledger {
    if (Test-Path $ledgerPath) {
        return @(Import-Csv -LiteralPath $ledgerPath)
    }

    return @()
}

function Write-Ledger {
    param(
        [object]$Session,
        [string]$Status,
        [string]$Detail
    )

    $entry = [PSCustomObject]@{
        SessionID = $Session.SessionID
        ScheduledUTC = $Session.ScheduledUTC.ToString("o")
        ScenarioID = $Session.ScenarioID
        Username = $Session.Username
        ExecutionUTC = [datetime]::UtcNow.ToString("o")
        Status = $Status
        Detail = $Detail
    }

    $entry | Export-Csv `
        -LiteralPath $ledgerPath `
        -NoTypeInformation `
        -Append `
        -Encoding UTF8
}

if ($ShowPlan) {

    Write-Host ""
    Write-Host "UNIVERSITY DATASET EXECUTION PLAN" -ForegroundColor Cyan
    Write-Host "Start (UTC): $($startUTC.ToString('yyyy-MM-dd'))"
    Write-Host "End (UTC): $($startUTC.AddDays(13).ToString('yyyy-MM-dd'))"
    Write-Host "Total sessions: $($sessions.Count)"
    Write-Host "Normal sessions: $(@($sessions | Where-Object { $_.ScenarioID -match '^N0[1-7]$' }).Count)"
    Write-Host "Malicious sessions: $(@($sessions | Where-Object { $_.ScenarioID -match '^M0[1-5]$' }).Count)"

    Write-Host ""
    Write-Host "SCENARIO DISTRIBUTION" -ForegroundColor Cyan

    $sessions |
        Group-Object ScenarioID |
        Sort-Object Name |
        Select-Object Name, Count |
        Format-Table -AutoSize

    Write-Host "FIRST 10 SCHEDULED SESSIONS" -ForegroundColor Cyan

    $sessions |
        Select-Object -First 10 `
            SessionID, ScheduledUTC, ScenarioID, Username |
        Format-Table -AutoSize

    Write-Host "LAST 5 SCHEDULED SESSIONS" -ForegroundColor Cyan

    $sessions |
        Select-Object -Last 5 `
            SessionID, ScheduledUTC, ScenarioID |
        Format-Table -AutoSize

    Write-Host "Completed/attempted records: $((Get-Ledger).Count)"
    Write-Host ""
    Write-Host "M01-M05 dispatch: Not yet connected" -ForegroundColor Yellow
    Write-Host "No simulation activities executed."

    return
}

if (-not $RunDue) {
    Write-Host "Use -ShowPlan or -RunDue."
    return
}

# Only one scheduler instance may execute at a time.
$lock = $null

try {
    $lock = [System.IO.File]::Open(
        $lockPath,
        [System.IO.FileMode]::OpenOrCreate,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None
    )
}
catch {
    Write-Host "Another scheduler instance is active. Exiting."
    return
}

try {
    $processed = @{}

    foreach ($entry in (Get-Ledger)) {
        $processed[$entry.SessionID] = $true
    }

    $nowUTC = [datetime]::UtcNow

    $due = @(
        $sessions | Where-Object {
            $_.ScheduledUTC -le $nowUTC -and
            -not $processed.ContainsKey($_.SessionID)
        }
    )

    $executed = 0
    $waitingForIntegration = 0

    foreach ($session in $due) {

        if ($executed -ge $MaxSessions) {
            break
        }

        if ($session.ScenarioID -eq "M05") {

            # The current Windows 11 worker executes as the configured example account.
            # Preserve real user attribution.
            if ($session.Username -ine "example.user") {
                $waitingForIntegration++
                continue
            }


            $executed++
        Write-Ledger $session "Started" "Session execution initiated"

            Write-Host ""
            Write-Host "Queueing M05: $($session.SessionID)" `
                -ForegroundColor Yellow

            try {
                & $m05Dispatcher `
                    -SessionID $session.SessionID `
                    -Username $session.Username `
                    -FileCount $session.FileCount

                $jobPath = Join-Path $base (
                    "M05Queue\Pending\" + $session.SessionID + ".json"
                )

                $resultPath = Join-Path $base (
                    "M05Results\" + $session.SessionID + "-result.json"
                )

                if ((Test-Path -LiteralPath $jobPath) -or
                    (Test-Path -LiteralPath $resultPath)) {

                    Write-Ledger $session "Queued" `
                        "Awaiting Windows 11 worker completion"

                    Write-Host "M05 job accepted by queue." `
                        -ForegroundColor Green
                }
                else {
                    throw "M05 job not found after dispatch."
                }
            }
            catch {
                Write-Ledger $session "Failed" $_.Exception.Message

                Write-Warning (
                    "M05 queue dispatch failed: " +
                    $_.Exception.Message
                )
            }

            $nowUTC = [datetime]::UtcNow
            continue
        }

        if ($session.ScenarioID -notmatch '^(N0[1-7]|M0[1-5])$') {
            Write-Ledger $session "InvalidScenario" "Unrecognised scenario"
            continue
        }


        $executed++
        Write-Ledger $session "Started" "Session execution initiated"

        if ($session.ScenarioID -match '^M0[1-4]$') {

            Write-Host ""
            Write-Host "Invoking malicious handler: $($session.ScenarioID)" `
                -ForegroundColor Yellow

            try {
                & $maliciousDispatcher `
                    -ScenarioID $session.ScenarioID `
                    -SessionID $session.SessionID `
                    -Username $session.Username `
                    -Role $session.Role `
                    -FileCount $session.FileCount `
                    -FailedLogins $session.FailedLogins `
                    -MinDelaySeconds $session.MinDelaySeconds `
                    -MaxDelaySeconds $session.MaxDelaySeconds

                # DIRECT MALICIOUS OUTCOME REPORTING
                # Read the execution result for this exact SessionID.
                if ($session.ScenarioID -eq "M03") {

                    $m03Path = Join-Path $base "simulation_sessions.csv"

                    if (-not (Test-Path -LiteralPath $m03Path)) {
                        throw "M03 result CSV not found."
                    }

                    $matches = @(
                        Import-Csv -LiteralPath $m03Path |
                        Where-Object {
                            $_.SessionID -eq $session.SessionID -and
                            $_.ScenarioID -eq "M03"
                        }
                    )

                    if ($matches.Count -ne 1) {
                        throw "Expected one M03 result; found $($matches.Count)."
                    }

                    $result = $matches[0]
                }
                else {

                    $resultPath = Join-Path $base (
                        "Dataset2026\ExecutionResults\" +
                        $session.SessionID + ".json"
                    )

                    if (-not (Test-Path -LiteralPath $resultPath)) {
                        throw "Malicious handler result not found."
                    }

                    $result = Get-Content -LiteralPath $resultPath -Raw |
                        ConvertFrom-Json -ErrorAction Stop
                }

                if ($result.SessionID -ne $session.SessionID -or
                    $result.ScenarioID -ne $session.ScenarioID -or
                    $result.Username -ine $session.Username) {

                    throw "Handler result identity mismatch."
                }

                if ($result.ExecutionStatus -ne "Completed") {
                    throw "Handler outcome: $($result.ExecutionStatus)"
                }

                Write-Ledger $session "Completed" `
                    "Handler confirmed successful execution."
            }
            catch {
                Write-Ledger $session "Failed" $_.Exception.Message
                Write-Warning "Malicious dispatch failed: $($_.Exception.Message)"
            }

            $nowUTC = [datetime]::UtcNow
            continue
        }

        Write-Host ""
        Write-Host "Executing $($session.SessionID)" -ForegroundColor Cyan
        Write-Host "$($session.ScenarioID) / $($session.Username)"

        try {
            $arguments = @{
                ScenarioID = $session.ScenarioID
                SessionID = $session.SessionID
                Username = $session.Username
                Role = $session.Role
                FileCount = $session.FileCount
                FailedLogins = $session.FailedLogins
                MinDelaySeconds = $session.MinDelaySeconds
                MaxDelaySeconds = $session.MaxDelaySeconds
            }

            & $normalController @arguments

            $resultPath = Join-Path $base (
                "NormalResults\" + $session.SessionID + "-result.json"
            )

            if (-not (Test-Path -LiteralPath $resultPath)) {
                throw "Controller returned without a result file."
            }

            $result = Get-Content -LiteralPath $resultPath -Raw |
                ConvertFrom-Json

            if ($result.ExecutionStatus -ne "Completed") {
                throw "Controller result was not Completed."
            }

            Write-Ledger $session "Completed" (
                "Actions: " + $result.CompletedActions
            )
        }
        catch {
            Write-Ledger $session "Failed" $_.Exception.Message

            Write-Warning (
                "Session " + $session.SessionID +
                " failed: " + $_.Exception.Message
            )
        }

        $nowUTC = [datetime]::UtcNow
    }

    # M05 INTERNAL WORKER OUTCOME REPORTING
    # Check only dispatched M05 sessions awaiting a final outcome.
    # No worker jobs are created or rerun here.

    $m05Ledger = @(Get-Ledger)
    $latestM05 = @{}

    foreach ($entry in $m05Ledger) {
        if ($entry.ScenarioID -eq "M05") {
            $latestM05[$entry.SessionID] = $entry
        }
    }

    foreach ($m05Session in @(
        $sessions | Where-Object { $_.ScenarioID -eq "M05" }
    )) {

        $id = $m05Session.SessionID

        if (-not $latestM05.ContainsKey($id)) {
            continue
        }

        if ($latestM05[$id].Status -ne "Queued") {
            continue
        }

        $resultPath = Join-Path $base (
            "M05Results\" + $id + "-result.json"
        )

        if (-not (Test-Path -LiteralPath $resultPath)) {
            continue
        }

        try {
            $result = Get-Content -LiteralPath $resultPath -Raw |
                ConvertFrom-Json -ErrorAction Stop

            if ($result.SessionID -and
                $result.SessionID -ne $id) {

                throw "M05 SessionID mismatch."
            }

            if ($result.Username -and
                $result.Username -ine $m05Session.Username) {

                throw "M05 username mismatch."
            }

            $workerStatus = if ($result.ExecutionStatus) {
                [string]$result.ExecutionStatus
            }
            else {
                [string]$result.Status
            }

            if ($workerStatus -match '^(Completed|Success|Succeeded)$') {

                $requested = 0
                $transferred = 0

                $requestedValid = [int]::TryParse(
                    [string]$result.FilesRequested,
                    [ref]$requested
                )

                $transferredValid = [int]::TryParse(
                    [string]$result.FilesTransferred,
                    [ref]$transferred
                )

                if (-not $requestedValid -or
                    -not $transferredValid -or
                    $requested -le 0 -or
                    $requested -ne $m05Session.FileCount -or
                    $transferred -ne $requested) {

                    throw "M05 transfer counts do not match the plan."
                }

                Write-Ledger $m05Session "Completed" (
                    "Worker transferred $transferred/$requested files."
                )

                Write-Host "M05 completed: $id" -ForegroundColor Green
            }
            elseif ($workerStatus -match '^(Failed|Error)$') {

                Write-Ledger $m05Session "Failed" `
                    "Windows 11 worker reported failure."

                Write-Warning "M05 failed: $id"
            }
            else {
                Write-Warning (
                    "M05 has no final worker status: $id / $workerStatus"
                )
            }
        }
        catch {
            # Preserve Queued for invalid or ambiguous worker results.
            Write-Warning (
                "M05 result requires review: $id / " +
                $_.Exception.Message
            )
        }
    }

    Write-Host ""
    Write-Host "SCHEDULER RUN FINISHED" -ForegroundColor Green
    Write-Host "Normal sessions attempted: $executed"
    Write-Host "Malicious sessions encountered and deferred: $waitingForIntegration"
    Write-Host "Ledger: $ledgerPath"
}
finally {
    if ($lock) {
        $lock.Dispose()
    }
}





