[CmdletBinding()]
param([string]$DatasetRoot = 'C:\UniversityData\Simulation\Dataset2026')
$ErrorActionPreference = 'Stop'
$plan = @(Import-Csv -LiteralPath (Join-Path $DatasetRoot 'dataset_schedule_v3.csv'))
$ledger = @(Import-Csv -LiteralPath (Join-Path $DatasetRoot 'SchedulerState\execution_ledger.csv'))
if ($plan.Count -eq 0) { throw 'Schedule is empty' }
# Last row per SessionID wins, following the append order of the execution ledger.
$latest = @{}
foreach ($entry in $ledger) {
    if ($entry.SessionID) { $latest[$entry.SessionID] = $entry }
}
$results = @(
    foreach ($s in $plan) {
        $entry = $latest[$s.SessionID]
        [pscustomobject]@{
            Day = $s.SimulationDay
            SessionID = $s.SessionID
            Scenario = $s.ScenarioID
            Username = $s.Username
            Status = if ($null -ne $entry -and $entry.Status) { $entry.Status } else { 'Not Executed' }
        }
    }
)
Write-Host "Total scheduled: $($results.Count)"
$results | Group-Object Status | Sort-Object Name |
    Select-Object Name,Count | Format-Table -AutoSize
$results | Group-Object Day | Sort-Object { [int]$_.Name } | ForEach-Object {
    [pscustomobject]@{
        Day=$_.Name
        Scheduled=$_.Count
        Completed=@($_.Group | Where-Object Status -eq 'Completed').Count
        Failed=@($_.Group | Where-Object Status -eq 'Failed').Count
        Queued=@($_.Group | Where-Object Status -eq 'Queued').Count
        NotExecuted=@($_.Group | Where-Object Status -eq 'Not Executed').Count
    }
} | Format-Table -AutoSize
Write-Host 'Non-completed sessions:'
$results | Where-Object Status -ne 'Completed' |
    Format-Table Day,SessionID,Scenario,Username,Status -AutoSize
