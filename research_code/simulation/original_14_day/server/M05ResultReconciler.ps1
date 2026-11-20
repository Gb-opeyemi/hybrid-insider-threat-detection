$ErrorActionPreference = "Stop"

$base = "C:\UniversityData\Simulation"

$planPath = Join-Path $base "Dataset2026\dataset_schedule_v3.csv"
$ledgerPath = Join-Path $base "Dataset2026\SchedulerState\execution_ledger.csv"
$resultDir = Join-Path $base "M05Results"
$queueDir = Join-Path $base "M05Queue\Pending"
$reportPath = Join-Path $base "Dataset2026\SchedulerState\m05_reconciliation.csv"

$plan = @(
    Import-Csv -LiteralPath $planPath |
    Where-Object { $_.ScenarioID -eq "M05" }
)

if ($plan.Count -ne 45) {
    throw "Expected 45 M05 sessions. Found $($plan.Count)."
}

$ledger = @()

if (Test-Path $ledgerPath) {
    $ledger = @(Import-Csv -LiteralPath $ledgerPath)
}

$report = foreach ($session in $plan) {

    $id = $session.SessionID

    $entries = @(
        $ledger |
        Where-Object { $_.SessionID -eq $id }
    )

    $latest = $null

    if ($entries.Count -gt 0) {
        $latest = $entries[-1]
    }

    $jobPath = Join-Path $queueDir "$id.json"
    $resultPath = Join-Path $resultDir "$id-result.json"

    $state = "NotDispatched"
    $workerStatus = ""
    $detail = ""

    if ($latest) {
        $state = $latest.Status
    }

    if (Test-Path -LiteralPath $jobPath) {
        $state = "PendingWorker"
    }

    if (Test-Path -LiteralPath $resultPath) {

        try {
            $result = Get-Content -LiteralPath $resultPath -Raw |
                ConvertFrom-Json -ErrorAction Stop

            if ($result.SessionID -and
                $result.SessionID -ne $id) {
                throw "Result SessionID does not match schedule."
            }

            if ($result.Username -and
                $result.Username -ine $session.Username) {
                throw "Result username does not match schedule."
            }

            $statusFields = @(
                "ExecutionStatus",
                "Status",
                "Result"
            )

            foreach ($field in $statusFields) {
                $property = $result.PSObject.Properties[$field]

                if ($property -and $null -ne $property.Value) {
                    $workerStatus = [string]$property.Value
                    break
                }
            }

            if ($workerStatus -match '^(Completed|Success|Succeeded)$') {
                $state = "WorkerReportedCompleted"
            }
            elseif ($workerStatus -match '^(Failed|Error)$') {
                $state = "WorkerReportedFailed"
            }
            else {
                $state = "ResultNeedsReview"
            }

            $detail = "Worker result file found"
        }
        catch {
            $state = "InvalidResult"
            $detail = $_.Exception.Message
        }
    }

    [PSCustomObject]@{
        SessionID = $id
        Username = $session.Username
        ScheduledDay = $session.SimulationDay
        SchedulerStatus = if ($latest) { $latest.Status } else { "" }
        QueueFilePresent = Test-Path -LiteralPath $jobPath
        ResultFilePresent = Test-Path -LiteralPath $resultPath
        WorkerStatus = $workerStatus
        ReconciledStatus = $state
        Detail = $detail
    }
}

$directory = Split-Path $reportPath -Parent
New-Item -ItemType Directory -Path $directory -Force | Out-Null

$tempPath = "$reportPath.tmp"

try {
    $report | Export-Csv `
        -LiteralPath $tempPath `
        -NoTypeInformation `
        -Encoding UTF8

    Move-Item -LiteralPath $tempPath `
        -Destination $reportPath `
        -Force `
        -ErrorAction Stop
}
finally {
    if (Test-Path $tempPath) {
        Remove-Item $tempPath -Force
    }
}

Write-Host ""
Write-Host "M05 RECONCILIATION REPORT" -ForegroundColor Cyan

$report |
    Group-Object ReconciledStatus |
    Select-Object Name, Count |
    Format-Table -AutoSize

Write-Host "Total M05 sessions: $($report.Count)"
Write-Host "Report: $reportPath"
Write-Host "No simulation activities executed."
