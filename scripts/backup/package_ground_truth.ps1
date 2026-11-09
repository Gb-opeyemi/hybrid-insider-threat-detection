[CmdletBinding()]
param([string]$BackupRoot = 'C:\UniversityData\ThesisDatasetBackup')
$ErrorActionPreference = 'Stop'
$items = @(
    (Join-Path $BackupRoot 'dataset_schedule_v3.csv'),
    (Join-Path $BackupRoot 'execution_ledger.csv'),
    (Join-Path $BackupRoot 'M05Results')
)
foreach ($item in $items) {
    if (-not (Test-Path -LiteralPath $item)) { throw "Missing input: $item" }
}
$zipPath = Join-Path $BackupRoot 'thesis_ground_truth.zip'
Compress-Archive -LiteralPath $items -DestinationPath $zipPath -Force
$hash = Get-FileHash -LiteralPath $zipPath -Algorithm SHA256
"$($hash.Hash.ToLowerInvariant())  thesis_ground_truth.zip" |
    Set-Content -LiteralPath "$zipPath.sha256" -Encoding Ascii
Get-Item -LiteralPath $zipPath | Select-Object FullName,Length,LastWriteTime
Write-Host "SHA256: $($hash.Hash)"
