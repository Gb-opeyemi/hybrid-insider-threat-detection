$ErrorActionPreference = "Stop"
$base = "C:\UniversityData\Simulation"
$stamp = [DateTime]::UtcNow.ToString("yyyyMMdd-HHmmss")
$log = "$base\Dataset2026\SchedulerLogs\scheduler-$stamp.log"

try {
    & "$base\Scripts\DatasetScheduler.ps1" -RunDue -MaxSessions 20 *>&1 |
        Out-File -LiteralPath $log -Encoding UTF8
}
catch {
    $_ | Out-File -LiteralPath $log -Append
    throw
}
