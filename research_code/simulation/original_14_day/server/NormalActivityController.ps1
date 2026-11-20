param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("N01","N02","N03","N04","N05","N06","N07")]
    [string]$ScenarioID,

    [Parameter(Mandatory=$true)]
    [string]$SessionID,

    [Parameter(Mandatory=$true)]
    [string]$Username,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Student","Lecturer","Researcher","Administrative","IT")]
    [string]$Role,

    [ValidateRange(1,150)]
    [int]$FileCount = 1,

    [ValidateRange(0,2)]
    [int]$FailedLogins = 0,

    [ValidateRange(0,60)]
    [int]$MinDelaySeconds = 0,

    [ValidateRange(0,60)]
    [int]$MaxDelaySeconds = 2
)

$ErrorActionPreference = "Stop"

$base = "C:\UniversityData\Simulation"
$resultDir = Join-Path $base "NormalResults"
$credentialPath = Join-Path $base "Credentials\$Username.xml"

$server = "198.51.100.10"

$roleGroups = @{
    Student        = "Students-Group"
    Lecturer       = "Lecturers-Group"
    Researcher     = "Researchers-Group"
    Administrative = "Administrative-Group"
    IT             = "IT-Group"
}

$allowedRoles = @{
    N01 = @("Student","Lecturer","Researcher","Administrative","IT")
    N02 = @("Lecturer","Researcher","Administrative","IT")
    N03 = @("Lecturer","Researcher","Administrative","IT")
    N04 = @("Researcher")
    N05 = @("Student","Lecturer","Researcher","Administrative","IT")
    N06 = @("Lecturer","Researcher")
    N07 = @("Lecturer","Researcher","IT")
}

$approvedFolders = @{
    Researcher = "Research"
    Lecturer   = "Academic"
    IT         = "IT"
}

$activities = New-Object System.Collections.ArrayList
$startedUTC = [DateTime]::UtcNow
$status = "Failed"
$errorMessage = ""
$resource = ""
$sourceDrive = $null
$destinationDrive = $null

function Get-Resource {
    param(
        [string]$UserRole,
        [string]$Scenario
    )

    switch ($UserRole) {
        "Student"        { return "AcademicDocuments" }
        "Researcher"     { return "ResearchData" }
        "Administrative" { return "StudentRecords" }
        "IT"             { return "IT-Resources" }

        "Lecturer" {
            if ($Scenario -in @("N01","N05","N06")) {
                return @(
                    "AcademicDocuments",
                    "ResearchData",
                    "StudentRecords"
                ) | Get-Random
            }

            return "AcademicDocuments"
        }
    }

    throw "Unsupported university role."
}

function Get-ResourceShare {
    param([string]$Resource)

    $localPath = "C:\UniversityData\$Resource"

    $matches = @(
        Get-SmbShare | Where-Object {
            $_.Path -and
            $_.Path.TrimEnd('\') -ieq $localPath.TrimEnd('\') -and
            -not $_.Special
        }
    )

    if ($matches.Count -ne 1) {
        throw "Expected one SMB share for $Resource. Found $($matches.Count)."
    }

    return "\\$server\$($matches[0].Name)"
}

function Connect-UserShare {
    param(
        [string]$Share,
        [pscredential]$Credential
    )

    $drive = "U" + [guid]::NewGuid().ToString("N").Substring(0,7)

    New-PSDrive `
        -Name $drive `
        -PSProvider FileSystem `
        -Root $Share `
        -Credential $Credential `
        -Scope Script `
        -ErrorAction Stop | Out-Null

    return $drive
}

function Get-EligibleFiles {
    param([string]$Root)

    return @(
        Get-ChildItem -LiteralPath $Root -File -Recurse -ErrorAction Stop |
        Where-Object {
            $_.Extension -eq ".txt" -and
            $_.FullName -notlike "*\M04-Pilot\*" -and
            $_.Name -ne "confidential-research.txt"
        }
    )
}

function Add-Activity {
    param(
        [string]$Action,
        [string]$File,
        [string]$Outcome = "Success",
        [string]$Detail = ""
    )

    [void]$activities.Add([PSCustomObject]@{
        Action = $Action
        File = $File
        Outcome = $Outcome
        Detail = $Detail
        TimeUTC = [DateTime]::UtcNow.ToString("o")
    })
}

function Pause-BetweenActions {
    if ($MaxDelaySeconds -le 0) {
        return
    }

    if ($MinDelaySeconds -gt $MaxDelaySeconds) {
        throw "Minimum delay exceeds maximum delay."
    }

    $milliseconds = Get-Random `
        -Minimum ($MinDelaySeconds * 1000) `
        -Maximum (($MaxDelaySeconds * 1000) + 1)

    Start-Sleep -Milliseconds $milliseconds
}

function Read-UniversityFile {
    param([string]$Path)

    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite
    )

    try {
        $buffer = New-Object byte[] 8192

        while ($stream.Read($buffer,0,$buffer.Length) -gt 0) {
            # Read the complete document.
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Attempt-FailedAuthentication {
    param(
        [string]$Share,
        [string]$UserIdentity
    )

    $wrongPassword = ConvertTo-SecureString `
        ("WrongPassword-" + [guid]::NewGuid().ToString("N")) `
        -AsPlainText -Force

    $wrongCredential = New-Object System.Management.Automation.PSCredential(
        $UserIdentity,
        $wrongPassword
    )

    $badDrive = "B" + [guid]::NewGuid().ToString("N").Substring(0,7)
    $rejected = $false
    $detail = ""

    try {
        New-PSDrive `
            -Name $badDrive `
            -PSProvider FileSystem `
            -Root $Share `
            -Credential $wrongCredential `
            -Scope Script `
            -ErrorAction Stop | Out-Null

        # Force a network operation so authentication is attempted.
        Get-ChildItem "${badDrive}:\" -ErrorAction Stop |
            Select-Object -First 1 | Out-Null
    }
    catch {
        $rejected = $true
        $detail = $_.Exception.Message
    }
    finally {
        Remove-PSDrive -Name $badDrive -Force `
            -ErrorAction SilentlyContinue
    }

    if (-not $rejected) {
        throw "Incorrect credentials were unexpectedly accepted."
    }

    # Rejection alone does not prove an AD 4625 event was generated.
    Add-Activity `
        -Action "FailedLoginAttempt" `
        -File "" `
        -Outcome "RejectedByClient" `
        -Detail $detail
}

New-Item -ItemType Directory -Path $resultDir -Force | Out-Null

$resultPath = Join-Path $resultDir "$SessionID-result.json"

if (Test-Path -LiteralPath $resultPath) {
    throw "Session $SessionID already has a result file. Refusing to rerun."
}

try {
    if ($MinDelaySeconds -gt $MaxDelaySeconds) {
        throw "Invalid delay range."
    }

    if ($Role -notin $allowedRoles[$ScenarioID]) {
        throw "$Role is not authorised for $ScenarioID."
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    $adUser = Get-ADUser -Identity $Username -ErrorAction Stop

    $membership = @(
        Get-ADPrincipalGroupMembership -Identity $adUser |
        Select-Object -ExpandProperty Name
    )

    if ($roleGroups[$Role] -notin $membership) {
        throw "$Username is not in the expected AD role group."
    }

    if (-not (Test-Path -LiteralPath $credentialPath)) {
        throw "Credential file not found for $Username."
    }

    $credential = Import-Clixml -LiteralPath $credentialPath

    if ($credential -isnot [pscredential]) {
        throw "Credential file is invalid."
    }

    $credentialIdentity = $credential.UserName
    $credentialSam = ($credentialIdentity -split '\\')[-1]
    $credentialSam = ($credentialSam -split '@')[0]

    if ($credentialSam -ine $Username) {
        throw "Stored credential identity does not match $Username."
    }

    if ($ScenarioID -eq "N04" -and $FileCount -gt 3) {
        throw "N04 is restricted to a maximum of 3 deletions."
    }

    if ($ScenarioID -eq "N05" -and
        ($FailedLogins -lt 1 -or $FailedLogins -gt 2)) {
        throw "N05 requires 1 or 2 failed login attempts."
    }

    if ($ScenarioID -eq "N06") {
        if ($Role -eq "Lecturer" -and
            ($FileCount -lt 10 -or $FileCount -gt 18)) {
            throw "N06 lecturer file count must be 10 to 18."
        }

        if ($Role -eq "Researcher" -and
            ($FileCount -lt 15 -or $FileCount -gt 30)) {
            throw "N06 researcher file count must be 15 to 30."
        }
    }

    $resource = Get-Resource -UserRole $Role -Scenario $ScenarioID
    $sourceShare = Get-ResourceShare -Resource $resource

    if ($ScenarioID -eq "N05") {
        for ($attempt = 1; $attempt -le $FailedLogins; $attempt++) {
            Attempt-FailedAuthentication `
                -Share $sourceShare `
                -UserIdentity $credential.UserName

            Start-Sleep -Seconds 2
        }
    }

    $sourceDrive = Connect-UserShare `
        -Share $sourceShare `
        -Credential $credential

    $sourceRoot = "${sourceDrive}:\"

    # This is an actual authenticated SMB read, not a local admin read.
    $files = @(Get-EligibleFiles -Root $sourceRoot)

    switch ($ScenarioID) {

        { $_ -in @("N01","N05","N06") } {

            if ($files.Count -lt $FileCount) {
                throw "Not enough readable documents in $resource."
            }

            $selected = @($files | Get-Random -Count $FileCount)

            foreach ($file in $selected) {
                Read-UniversityFile -Path $file.FullName

                Add-Activity `
                    -Action "Read" `
                    -File $file.FullName.Substring($sourceRoot.Length)

                Pause-BetweenActions
            }

            break
        }

        "N02" {

            for ($i = 1; $i -le $FileCount; $i++) {

                $filename = "UniversityDocument_$([guid]::NewGuid().ToString('N')).txt"
                $target = "${sourceDrive}:\$filename"

                $content = @"
University working document
Department: $Role
Last updated: $([DateTime]::UtcNow.ToString("o"))
Content: Routine university documentation and working notes.
"@

                Write-Host "N02 DRIVE NAME: $sourceDrive"
                Write-Host "N02 DRIVE ROOT: $((Get-PSDrive -Name $sourceDrive).Root)"
                Write-Host "N02 TARGET: $target"

                New-Item `
                    -ItemType File `
                    -Path $target `
                    -Value $content `
                    -ErrorAction Stop | Out-Null

                Add-Activity -Action "Create" -File $filename

                Pause-BetweenActions
            }

            break
        }

        "N03" {

            if ($files.Count -lt $FileCount) {
                throw "Not enough documents for modification."
            }

            $selected = @($files | Get-Random -Count $FileCount)

            foreach ($file in $selected) {

                Add-Content `
                    -LiteralPath $file.FullName `
                    -Value "Routine update: $([DateTime]::UtcNow.ToString('o'))" `
                    -ErrorAction Stop

                Add-Activity `
                    -Action "Modify" `
                    -File $file.FullName.Substring($sourceRoot.Length)

                Pause-BetweenActions
            }

            break
        }

        "N04" {

            if ($Role -ne "Researcher" -or
                $resource -ne "ResearchData") {
                throw "N04 deletion is permitted for researchers only."
            }

            # Keep a minimum research-document inventory available.
            if ($files.Count -lt (500 + $FileCount)) {
                throw "Research-document preservation threshold reached."
            }

            $selected = @($files | Get-Random -Count $FileCount)

            foreach ($file in $selected) {

                Remove-Item `
                    -LiteralPath $file.FullName `
                    -ErrorAction Stop

                Add-Activity `
                    -Action "Delete" `
                    -File $file.FullName.Substring($sourceRoot.Length)

                Pause-BetweenActions
            }

            break
        }

        "N07" {

            if (-not $approvedFolders.ContainsKey($Role)) {
                throw "This role cannot perform approved transfers."
            }

            $destinationShare = "\\$server\ApprovedTransferWorkspace"
            $approvedSubfolder = $approvedFolders[$Role]

            $destinationDrive = Connect-UserShare `
                -Share $destinationShare `
                -Credential $credential

            $destinationRoot = "${destinationDrive}:\$approvedSubfolder"

            if (-not (Test-Path -LiteralPath $destinationRoot -PathType Container)) {
                throw "Approved destination is inaccessible: $approvedSubfolder"
            }

            if ($files.Count -lt $FileCount) {
                throw "Not enough source documents for N07."
            }

            $selected = @($files | Get-Random -Count $FileCount)

            foreach ($file in $selected) {

                $destinationName = $file.Name
                $counter = 1

                while (Test-Path -LiteralPath (Join-Path $destinationRoot $destinationName)) {
                    $destinationName = "{0}_copy_{1}{2}" -f `
                        $file.BaseName, $counter, $file.Extension
                    $counter++
                }
                $destinationPath = Join-Path $destinationRoot $destinationName

                Copy-Item `
                    -LiteralPath $file.FullName `
                    -Destination $destinationPath `
                    -ErrorAction Stop

                Add-Activity `
                    -Action "ApprovedSMBTransfer" `
                    -File $file.FullName.Substring($sourceRoot.Length) `
                    -Detail "$approvedSubfolder\$destinationName"

                Pause-BetweenActions
            }

            break
        }
    }

    $status = "Completed"
}
catch {
    $errorMessage = $_.Exception.Message
}
finally {

    if ($destinationDrive) {
        Remove-PSDrive -Name $destinationDrive `
            -Force -ErrorAction SilentlyContinue
    }

    if ($sourceDrive) {
        Remove-PSDrive -Name $sourceDrive `
            -Force -ErrorAction SilentlyContinue
    }

    $completedActions = @(
        $activities | Where-Object {
            $_.Outcome -eq "Success"
        }
    ).Count

    $result = [PSCustomObject]@{
        SessionID = $SessionID
        ScenarioID = $ScenarioID
        IntendedLabel = 0
        Username = $Username
        Role = $Role
        Resource = $resource
        RequestedFileCount = $FileCount
        CompletedActions = $completedActions
        FailedLoginsRequested = $FailedLogins
        StartedUTC = $startedUTC.ToString("o")
        EndedUTC = [DateTime]::UtcNow.ToString("o")
        ExecutionStatus = $status
        ErrorMessage = $errorMessage
        Activities = @($activities.ToArray())
    }

    $result |
        ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $resultPath -Encoding UTF8

    Write-Host ""
    Write-Host "SESSION RESULT" -ForegroundColor Cyan
    Write-Host "Session: $SessionID"
    Write-Host "Scenario: $ScenarioID"
    Write-Host "Username: $Username"
    Write-Host "Role: $Role"
    Write-Host "Resource: $resource"
    Write-Host "Status: $status"
    Write-Host "Completed actions: $completedActions"
    Write-Host "Result file: $resultPath"

    if ($status -ne "Completed") {
        throw "Session failed: $errorMessage"
    }
}




