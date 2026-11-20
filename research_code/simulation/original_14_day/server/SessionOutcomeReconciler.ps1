param(
    [switch]$Apply
)

$ErrorActionPreference = "Stop"

$base = "C:\UniversityData\Simulation"
$planPath = "$base\Dataset2026\dataset_schedule_v3.csv"
$ledgerPath = "$base\Dataset2026\SchedulerState\execution_ledger.csv"
$jsonDir = "$base\Dataset2026\ExecutionResults"
$m03Path = "$base\simulation_sessions.csv"
$m05Dir = "$base\M05Results"

$plan = @(Import-Csv -LiteralPath $planPath)
$ledger = @(Import-Csv -LiteralPath $ledgerPath)

$m03Rows = @()
if (Test-Path -LiteralPath $m03Path) {
    $m03Rows = @(
        Import-Csv -LiteralPath $m03Path |
        Where-Object { $_.ScenarioID -eq "M03" }
    )
}

$latestById = @{}
foreach ($entry in $ledger) {
    $latestById[$entry.SessionID] = $entry
}

$report = foreach ($session in $plan) {

    $scenario = $session.ScenarioID
    if ($scenario -notmatch '^M0[1-5]$') {
        continue
    }

    $id = $session.SessionID
    $latest = $latestById[$id]

    if (-not $latest) {
        continue
    }

    $originalStatus = [string]$latest.Status
    $newStatus = ""
    $reason = ""

    if ($scenario -in @("M01", "M02", "M04")) {

        $path = Join-Path $jsonDir "$id.json"

        if (Test-Path -LiteralPath $path) {

            try {
                $result = Get-Content -LiteralPath $path -Raw |
                    ConvertFrom-Json

                if (
                    $result.SessionID -ne $id -or
                    $result.ScenarioID -ne $scenario -or
                    $result.Username -ine $session.Username
                ) {
                    throw "Result identity mismatch"
                }

                $newStatus = if (
                    $result.ExecutionStatus -eq "Completed"
                ) {
                    "Completed"
                }
                else {
                    "Failed"
                }

                $reason = "Handler result: $($result.ExecutionStatus)"
            }
            catch {
                $reason = "Invalid result: $($_.Exception.Message)"
            }
        }
        else {
            $reason = "Handler result not found"
        }
    }

    elseif ($scenario -eq "M03") {

        $matches = @(
            $m03Rows |
            Where-Object { $_.SessionID -eq $id }
        )

        if ($matches.Count -eq 1) {

            $result = $matches[0]

            if ($result.Username -ine $session.Username) {
                $reason = "M03 username mismatch"
            }
            else {
                $newStatus = if (
                    $result.ExecutionStatus -eq "Completed"
                ) {
                    "Completed"
                }
                else {
                    "Failed"
                }

                $reason = "M03 executor: $($result.ExecutionStatus)"
            }
        }
        elseif ($matches.Count -gt 1) {
            $reason = "Multiple M03 results; review required"
        }
        else {
            $reason = "M03 CSV result not found"
        }
    }

    elseif ($scenario -eq "M05") {

        $names = @("$id-result.json")

        if ($id -notlike "M05-*") {
            $names += "M05-$id-result.json"
        }

        $paths = @(
            $names |
            ForEach-Object { Join-Path $m05Dir $_ } |
            Where-Object { Test-Path -LiteralPath $_ }
        )

        if ($paths.Count -eq 1) {

            try {
                $result = Get-Content -LiteralPath $paths[0] -Raw |
                    ConvertFrom-Json

                $validIds = @($id, "M05-$id") |
                    Select-Object -Unique

                if (
                    $result.SessionID -and
                    $result.SessionID -notin $validIds
                ) {
                    throw "M05 result SessionID mismatch"
                }

                if (
                    $result.Username -and
                    $result.Username -ine $session.Username
                ) {
                    throw "M05 username mismatch"
                }

                $workerStatus = if ($result.ExecutionStatus) {
                    [string]$result.ExecutionStatus
                }
                else {
                    [string]$result.Status
                }

                if ($workerStatus -match '^(Completed|Success|Succeeded)$') {

                    $requested = [int]$result.FilesRequested
                    $transferred = [int]$result.FilesTransferred

                    if (
                        $requested -gt 0 -and
                        $requested -eq [int]$session.FileCount -and
                        $transferred -eq $requested
                    ) {
                        $newStatus = "Completed"
                        $reason = "Worker transferred $transferred/$requested files"
                    }
                    else {
                        $reason = "Worker completed but file counts need review"
                    }
                }
                elseif ($workerStatus -match '^(Failed|Error)$') {
                    $newStatus = "Failed"
                    $reason = "Worker reported failure"
                }
                else {
                    $reason = "Worker status not final: $workerStatus"
                }
            }
            catch {
                $reason = "Invalid worker result: $($_.Exception.Message)"
            }
        }
        elseif ($paths.Count -gt 1) {
            $reason = "Multiple M05 results; review required"
        }
        else {
            $reason = "Awaiting M05 worker result"
        }
    }

    if (-not $newStatus) {
        $newStatus = "NeedsReview"
    }

    [PSCustomObject]@{
        SessionID = $id
        ScenarioID = $scenario
        Username = $session.Username
        OriginalStatus = $originalStatus
        ReconciledStatus = $newStatus
        Reason = $reason
    }
}

Write-Host "`nMALICIOUS SESSION OUTCOMES" -ForegroundColor Cyan

$report |
    Group-Object ScenarioID, ReconciledStatus |
    Sort-Object Name |
    Select-Object Name, Count |
    Format-Table -AutoSize

Write-Host "`nSESSIONS REQUIRING REVIEW" -ForegroundColor Yellow

$report |
    Where-Object ReconciledStatus -eq "NeedsReview" |
    Select-Object ScenarioID, SessionID, Reason |
    Format-Table -AutoSize

$changes = @(
    $report |
    Where-Object {
        $_.ReconciledStatus -in @("Completed", "Failed") -and
        $_.OriginalStatus -ne $_.ReconciledStatus
    }
)

Write-Host "`nPROPOSED LEDGER UPDATES: $($changes.Count)" -ForegroundColor Cyan

$changes |
    Select-Object ScenarioID, OriginalStatus, ReconciledStatus, Reason |
    Format-Table -AutoSize

if ($Apply -and $changes.Count -gt 0) {

    # Preserve the original ledger before appending corrections.
    $backupPath = "$ledgerPath.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Copy-Item -LiteralPath $ledgerPath -Destination $backupPath

    foreach ($change in $changes) {

        $original = $latestById[$change.SessionID]

        [PSCustomObject]@{
            SessionID = $change.SessionID
            ScheduledUTC = $original.ScheduledUTC
            ScenarioID = $change.ScenarioID
            Username = $change.Username
            ExecutionUTC = [DateTime]::UtcNow.ToString("o")
            Status = $change.ReconciledStatus
            Detail = "Reconciled: $($change.Reason)"
        } |
            Export-Csv -LiteralPath $ledgerPath `
                -NoTypeInformation -Append -Encoding UTF8
    }

    Write-Host "`nLedger updated. Backup: $backupPath" -ForegroundColor Green
}
else {
    Write-Host "`nPreview only. No ledger entries changed." -ForegroundColor Green
}
