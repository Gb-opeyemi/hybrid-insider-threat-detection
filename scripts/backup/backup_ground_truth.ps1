[CmdletBinding()]
param(
    [string]$SimulationRoot = 'C:\UniversityData\Simulation',
    [string]$BackupRoot = 'C:\UniversityData\ThesisDatasetBackup'
)
$ErrorActionPreference = 'Stop'
$dataset = Join-Path $SimulationRoot 'Dataset2026'
$schedule = Join-Path $dataset 'dataset_schedule_v3.csv'
$ledger = Join-Path $dataset 'SchedulerState\execution_ledger.csv'
$m05 = Join-Path $SimulationRoot 'M05Results'
foreach ($p in @($schedule,$ledger,$m05)) {
    if (-not (Test-Path -LiteralPath $p)) { throw "Missing source: $p" }
}
New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
$resultDir = Join-Path $BackupRoot 'M05Results'
New-Item -ItemType Directory -Path $resultDir -Force | Out-Null
Copy-Item -LiteralPath $schedule -Destination $BackupRoot -Force
Copy-Item -LiteralPath $ledger -Destination $BackupRoot -Force
# Remove stale JSON copies only from the dedicated backup M05 folder.
Get-ChildItem -LiteralPath $resultDir -Filter '*.json' -File | Remove-Item -Force
Get-ChildItem -LiteralPath $m05 -Filter '*.json' -File |
    Copy-Item -Destination $resultDir -Force
Write-Host "Copied schedule, ledger and $(@(Get-ChildItem -LiteralPath $resultDir -Filter '*.json' -File).Count) M05 JSON files."
