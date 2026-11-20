"""launchd entry: load existing connection settings and Keychain credentials in memory."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
from . import session_orchestrator

ALLOWED = {'WAZUH_INDEXER_URL', 'WAZUH_INDEXER_INDEX_PATTERN', 'WAZUH_ALERT_INDEX_PATTERN',
           'WAZUH_INDEXER_CA_CERT', 'WAZUH_INDEXER_TLS_PROFILE'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--connection', type=Path, required=True)
    parser.add_argument('--check-access', action='store_true', help='Read-only feed check; never advances jobs')
    args = parser.parse_args(argv)
    os.umask(0o077)
    stage = 'connection_configuration'
    try:
        info = json.loads(args.connection.read_text())
        if set(info) != {'environment', 'keychain_service'} or set(info['environment']) != ALLOWED:
            raise ValueError('Invalid non-secret connection configuration')
        for name, value in info['environment'].items():
            if not isinstance(value, str) or not value: raise ValueError('Invalid setting')
            os.environ[name] = value
        # This uses the SAME indexer identity and existing TLS profile, not a new client.
        for name in ('WAZUH_INDEXER_USERNAME', 'WAZUH_INDEXER_PASSWORD'):
            if not os.environ.get(name):
                stage = 'keychain_lookup_' + name
                value = subprocess.run(['/usr/bin/security', 'find-generic-password', '-s', info['keychain_service'],
                    '-a', name, '-w'], check=True, capture_output=True, text=True, timeout=60 if args.check_access else 15).stdout.rstrip('\n')
                if not value: raise ValueError('Empty Keychain value')
                os.environ[name] = value
        stage = 'orchestrator_poll'
        action = 'feed-check' if args.check_access else 'once'
        code = session_orchestrator.main(['--config', args.config, action])
        print(json.dumps({'status':'poll_completed' if code == 0 else 'poll_failed',
                          'at_utc':datetime.now(timezone.utc).isoformat(), 'pid':os.getpid(),
                          'action':action, 'exit_code':code}), flush=True)
        return code
    except (OSError, ValueError, subprocess.SubprocessError, KeyError, TypeError) as exc:
        # Never print security's stdout/stderr or a credential-bearing exception.
        print(json.dumps({'status':'blocked','stage':'service_credentials','failed_stage':stage,'exception_type':type(exc).__name__,'reason':'Existing connection settings or login Keychain unavailable; no secrets logged'}))
        return 2


if __name__ == '__main__': raise SystemExit(main())
