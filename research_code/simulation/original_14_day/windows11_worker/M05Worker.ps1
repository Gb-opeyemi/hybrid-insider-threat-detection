$ErrorActionPreference = "Stop"

$queue = "\\198.51.100.10\M05Queue\Pending"
$serverResults = "\\198.51.100.10\M05Results"
$sourceRoot = "\\198.51.100.10\RestrictedResearch"
$localResults = "C:\Users\Public\UniversityM05"
$key = Join-Path $env:USERPROFILE ".ssh\m05_sftp_ed25519"

if ((whoami) -ne "EXAMPLE\example.user") {
    throw "M05 worker must run as the configured example account."
}

if (-not (Test-Path $key)) {
    throw "SSH key not found."
}

foreach ($jobFile in @(Get-ChildItem $queue -Filter "*.json")) {

    $job = $null
    $resultPath = $null
    $batchPath = $null
    $started = [DateTime]::UtcNow
    $status = "Failed"
    $errorMessage = ""
    $fileCount = 0
    $sourceBytes = [long]0
    $names = @()
    $skipExistingResult = $false

    try {
        $job = Get-Content $jobFile.FullName -Raw |
            ConvertFrom-Json

        if ($job.SessionID -notmatch '^M05-[A-Za-z0-9-]{1,80}$') {
            throw "Invalid M05 SessionID."
        }

        $resultPath = Join-Path $localResults `
            "$($job.SessionID)-result.json"

        # Never automatically repeat an attempted transfer.
        if (Test-Path $resultPath) {
            $skipExistingResult = $true
            Write-Host "Already processed: $($job.SessionID)"
            continue
        }

        if ($job.Scenario -ne "M05" -or
            $job.Username -ne "example.user" -or
            $job.Destination -ne "198.51.100.20") {
            throw "Invalid job instructions."
        }

        # Accept both the new and old job formats.
        if ($null -ne $job.SourceFiles) {
            $names = @($job.SourceFiles)
        }
        elseif ($job.SourceFile) {
            $names = @($job.SourceFile)
        }
        else {
            throw "No source documents specified."
        }

        if ($names.Count -lt 1 -or $names.Count -gt 8) {
            throw "M05 requires between 1 and 8 documents."
        }

        if (@($names | Select-Object -Unique).Count -ne $names.Count) {
            throw "Duplicate source documents detected."
        }

        $batchCommands = @("cd /received")

        foreach ($name in $names) {

            # Permit root documents and the three known research departments.
            # Reject traversal, absolute paths and unexpected filenames.
            $rootPattern = '^ResearchData_Document_\d{4}\.txt$'
            $departmentPattern = '^(ComputerScience|Engineering|HealthSciences)\\\1_Research_\d{4}\.txt$'

            if (
                $name -notmatch $rootPattern -and
                $name -notmatch $departmentPattern
            ) {
                throw "Invalid research document path: $name"
            }

            $source = Join-Path $sourceRoot $name

            if (-not (Test-Path $source -PathType Leaf)) {
                throw "Source document missing: $name"
            }

            $sourceBytes += (Get-Item $source).Length

                        $remoteName = "$($job.SessionID)-$($name.Replace('\','_'))"

            $batchCommands += "put `"$source`" `"$remoteName`""
            $batchCommands += "ls `"$remoteName`""
        }

        $batchCommands += "bye"

        $batchPath = Join-Path $localResults `
            "$($job.SessionID)-batch.txt"

        $batchCommands |
            Set-Content $batchPath -Encoding ASCII

        $output = & sftp.exe `
            -i $key `
            -o BatchMode=yes `
            -o ConnectTimeout=15 `
            -b $batchPath `
            m05receiver@198.51.100.20 2>&1 |
            Out-String

        if ($LASTEXITCODE -ne 0) {
            throw "SFTP transfer failed: $output"
        }

        $fileCount = $names.Count
        $status = "Completed"

        Write-Host "Completed $($job.SessionID): $fileCount files" `
            -ForegroundColor Green
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Warning $errorMessage
    }
    finally {
        if ($batchPath -and (Test-Path $batchPath)) {
            Remove-Item $batchPath -Force
        }

        if ($resultPath -and -not $skipExistingResult) {
            $result = [ordered]@{
                SessionID = $job.SessionID
                Scenario = "M05"
                ExecutedBy = (whoami)
                SourceFiles = @($names)
                Destination = $job.Destination
                StartedUTC = $started.ToString("o")
                EndedUTC = [DateTime]::UtcNow.ToString("o")
                Status = $status
                FilesRequested = $names.Count
                FilesTransferred = $fileCount
                SourceBytes = $sourceBytes
                TransferPerformed = ($status -eq "Completed")
                ValidationStatus = "PendingWazuhVerification"
                ErrorMessage = $errorMessage
            }

            $tempResult = "$resultPath.tmp"

            $result | ConvertTo-Json -Depth 5 |
                Set-Content $tempResult -Encoding UTF8

            Move-Item $tempResult $resultPath -Force

            # Report results to Windows Server.
            # A reporting failure must not repeat the transfer.
            try {
                Copy-Item $resultPath `
                    (Join-Path $serverResults `
                    "$($job.SessionID)-result.json") `
                    -Force -ErrorAction Stop
            }
            catch {
                Write-Warning "Transfer result saved locally, but server reporting failed."
            }
        }
    }
}


