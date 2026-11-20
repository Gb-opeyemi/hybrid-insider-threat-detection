"""Generate opt-in deployment copy; preserve the inspected Windows reference byte-for-byte."""
import argparse
import hashlib
import json
from pathlib import Path


def integrate(text):
    def replace_once(old,new):
        nonlocal text
        if text.count(old)!=1: raise ValueError('Reference runner changed; re-review integration anchors')
        text=text.replace(old,new,1)
    replace_once("    [int]$SettleSeconds = 30\n", "    [int]$SettleSeconds = 30,\n\n    [string]$CompletionFeedID = '',\n    [string]$CompletionLogPath = 'C:\\ProgramData\\ThesisHybrid\\session_lifecycle.jsonl'\n")
    replace_once("$ErrorActionPreference = 'Stop'\n", "$ErrorActionPreference = 'Stop'\n\nif ($CompletionFeedID) {\n    [void][guid]::Parse($CompletionFeedID)\n    . (Join-Path $PSScriptRoot 'Write-WazuhSessionLifecycle.ps1')\n    if (-not (Test-Path -LiteralPath $CompletionLogPath -PathType Leaf)) {\n        throw 'Lifecycle log not provisioned; no activity started.'\n    }\n}\n")
    replace_once('    $started = [datetime]::UtcNow\n', '''    $started = [datetime]::UtcNow
    if ($CompletionFeedID) {
        Write-WazuhSessionLifecycle -FeedID $CompletionFeedID -LogPath $CompletionLogPath `
            -SessionID $sessionId -Username $expectedUsername -HostName $env:COMPUTERNAME `
            -Start (Format-Utc $started) -SourceStatus 'Started'
    }
''')
    replace_once('# Display results.\n', '''# Lifecycle terminal record follows the runner's original saved metadata/status.
# An activity without actual boundaries is never a completion trigger.
if ($CompletionFeedID -and $null -ne $started -and $null -ne $ended) {
    Write-WazuhSessionLifecycle -FeedID $CompletionFeedID -LogPath $CompletionLogPath `
        -SessionID $sessionId -Username $record.simulated_username -HostName $record.host `
        -Start $record.activity_start -End $record.activity_end -SourceStatus $record.status
}

# Display results.
''')
    return text


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args(argv)
    root=Path(__file__).resolve().parents[2]; out=args.output_dir.resolve()
    if not out.is_relative_to(root/'data/experiments/operational_service') or out.exists():
        parser.error('Use a fresh ignored operational_service deployment directory')
    source=root/'scripts/windows_reference/Invoke-CompletedSession.ps1'
    helper=Path(__file__).with_name('Write-WazuhSessionLifecycle.ps1')
    integrated=integrate(source.read_text(encoding='utf-8-sig'))
    out.mkdir(parents=True,mode=0o700)
    (out/source.name).write_bytes(b'\xef\xbb\xbf'+integrated.replace('\n','\r\n').encode())
    (out/helper.name).write_bytes(helper.read_bytes())
    manifest={'reference_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
              'generated_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir()},
              'reference_modified':False,'windows_executed':False}
    (out/'integration_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'status':'prepared_locally','windows_executed':False}))


if __name__=='__main__': main()
