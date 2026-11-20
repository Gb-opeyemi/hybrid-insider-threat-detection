# PowerShell 5.1 helper. Only lifecycle metadata enters Wazuh; no labels/credentials.
function Write-WazuhSessionLifecycle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$FeedID,
        [Parameter(Mandatory=$true)][string]$LogPath,
        [Parameter(Mandatory=$true)][string]$SessionID,
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter(Mandatory=$true)][string]$HostName,
        [Parameter(Mandatory=$true)][string]$Start,
        [string]$End = '',
        [Parameter(Mandatory=$true)]
        [ValidateSet('Started','completed','failed','audit_not_verified')][string]$SourceStatus
    )
    [void][guid]::Parse($FeedID)
    [void][guid]::Parse($SessionID)
    if (-not (Test-Path -LiteralPath $LogPath -PathType Leaf)) {
        throw 'Provision the dedicated lifecycle log and restricted ACL before running.'
    }
    $status = if ($SourceStatus -ceq 'Started') { 'Started' }
              elseif ($SourceStatus -ceq 'completed') { 'Completed' }
              else { 'Failed' }
    $line = @{thesis_session = [ordered]@{
        event_type = 'controlled_session_lifecycle'; schema_version = '1'
        feed_id = $FeedID; session_id = $SessionID; username = $Username
        host = $HostName; start = $Start; end = $End
        status = $status; source_status = $SourceStatus
    }} | ConvertTo-Json -Depth 4 -Compress
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($line + "`r`n")
    # Exclusive writer + Flush(true); the Wazuh reader may retain read access.
    # Bounded contention retry supports concurrent controlled executions.
    $stream = $null
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        try {
            $stream = New-Object System.IO.FileStream($LogPath,
                [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::Read)
            break
        } catch [System.IO.IOException] {
            if ($attempt -eq 19) { throw }
            Start-Sleep -Milliseconds 100
        }
    }
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { if ($null -ne $stream) { $stream.Dispose() } }
}
