param(
    [Parameter(Mandatory)]
    [ValidateSet("M01","M02","M03","M04","M05")]
    [string]$ScenarioID,

    [Parameter(Mandatory)]
    [string]$SessionID,

    [Parameter(Mandatory)]
    [string]$Username,

    [string]$Role = "",

    [int]$FileCount = 1,

    [int]$FailedLogins = 0,

    [double]$MinDelaySeconds = 0,

    [double]$MaxDelaySeconds = 0
)

$ErrorActionPreference = "Stop"

$scripts = "C:\UniversityData\Simulation\Scripts"

$handlers = @{
    M01 = Join-Path $scripts "M01Handler.ps1"
    M02 = Join-Path $scripts "M02Handler.ps1"
    M03 = Join-Path $scripts "DatasetExecutor.ps1"
    M04 = Join-Path $scripts "M04Handler.ps1"
}

if ($ScenarioID -eq "M05") {
    throw "M05 requires Windows 11 queue dispatch. Not integrated yet."
}

$handler = $handlers[$ScenarioID]

if (-not (Test-Path -LiteralPath $handler)) {
    throw "Handler not found: $handler"
}

Write-Host ""
Write-Host "MALICIOUS SESSION DISPATCH" -ForegroundColor Cyan
Write-Host "Session: $SessionID"
Write-Host "Scenario: $ScenarioID"
Write-Host "User: $Username"

switch ($ScenarioID) {

    "M01" {
        if ($FileCount -lt 1 -or $FileCount -gt 20) {
            throw "M01 FileCount outside handler range 1-20."
        }

        & $handler `
            -SessionID $SessionID `
            -Username $Username `
            -FileCount $FileCount

        break
    }

    "M02" {
        if ($FailedLogins -lt 1 -or $FailedLogins -gt 8) {
            throw "M02 FailedLogins outside handler range 1-8."
        }

        & $handler `
            -SessionID $SessionID `
            -Username $Username `
            -FailedLogins $FailedLogins

        break
    }

    "M03" {
        if ([string]::IsNullOrWhiteSpace($Role)) {
            throw "M03 requires a university role."
        }

        if ($FileCount -lt 1 -or $FileCount -gt 300) {
            throw "M03 FileCount outside handler range 1-300."
        }

        if ($MinDelaySeconds -gt $MaxDelaySeconds) {
            throw "Invalid M03 delay range."
        }

        & $handler `
            -SessionID $SessionID `
            -Username $Username `
            -Role $Role `
            -ScenarioID "M03" `
            -FileCount $FileCount `
            -MinDelaySeconds $MinDelaySeconds `
            -MaxDelaySeconds $MaxDelaySeconds

        break
    }

    "M04" {
        if ($FileCount -lt 1 -or $FileCount -gt 20) {
            throw "M04 FileCount outside handler range 1-20."
        }

        & $handler `
            -SessionID $SessionID `
            -Username $Username `
            -FileCount $FileCount

        break
    }
}

if (-not $?) {
    throw "Handler $ScenarioID reported an execution error."
}

Write-Host "Handler invocation finished: $ScenarioID" -ForegroundColor Green
Write-Host "Telemetry and scenario outcome still require result validation."
