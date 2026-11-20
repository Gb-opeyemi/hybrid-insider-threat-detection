"""Manual opt-in polling interface. No installation, continuous loop or sending."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
from .model_selection import select_model
from .operational_session_service import ALLOWED
from .tabpfn_prototype.automatic import Shadow, configuration
from .tabpfn_prototype.common import read


@contextmanager
def connection_environment(path):
    """Same private connection file/Keychain items as RF, scoped to this process."""
    names = ALLOWED | {'WAZUH_INDEXER_USERNAME', 'WAZUH_INDEXER_PASSWORD'}
    previous = {key: os.environ.get(key) for key in names}
    try:
        info = read(path)
        if (set(info) != {'environment', 'keychain_service'} or set(info['environment']) != ALLOWED
                or not isinstance(info['keychain_service'], str) or not info['keychain_service']):
            raise ValueError('Invalid existing connection configuration')
        for key, value in info['environment'].items():
            if not isinstance(value, str) or not value: raise ValueError('Invalid non-secret setting')
            os.environ[key] = value
        for key in ('WAZUH_INDEXER_USERNAME', 'WAZUH_INDEXER_PASSWORD'):
            if not os.environ.get(key):
                value = subprocess.run(['/usr/bin/security', 'find-generic-password', '-s', info['keychain_service'],
                    '-a', key, '-w'], capture_output=True, text=True, check=True, timeout=15).stdout.rstrip('\n')
                if not value: raise ValueError('Existing Keychain credential unavailable')
                os.environ[key] = value
        yield
    finally:
        for key, value in previous.items():
            if value is None: os.environ.pop(key, None)
            else: os.environ[key] = value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('action', choices=('init', 'once', 'status', 'events', 'feed-check'))
    args = parser.parse_args(argv); service = None
    os.umask(0o077)
    try:
        cfg, connection = configuration(args.config)
        selection = select_model(Path(cfg['root']))
        if args.action == 'init' and selection.model != 'tabpfn':
            raise ValueError('Select TabPFN explicitly before arming its separate shadow store')
        if selection.model == 'random_forest' and not Path(cfg['state_dir']).exists():
            print(json.dumps({'status': 'random_forest_service_unchanged', 'selected_model': 'random_forest',
                              'tabpfn_jobs_created': 0, 'alerts_published': False})); return 0
        service = Shadow(cfg)
        if args.action == 'init': service.initialize()
        elif args.action in ('once', 'feed-check'):
            if not service.meta('armed_at'): raise ValueError('Initialize the separate shadow store explicitly first')
            with connection_environment(connection):
                if args.action == 'once': service.tick(selection)
                else:
                    if service.meta('binding') != service.binding(): raise ValueError('Completion binding changed')
                    service.source_snapshot()
        elif args.action == 'status':
            print(json.dumps([dict(row) for row in service.db.execute('''SELECT jobs.id,status,stage,attempt,error,next_at,
                capture,inference,alerts,hybrid,prepared,result FROM jobs LEFT JOIN tabpfn_jobs ON jobs.id=tabpfn_jobs.id''')], indent=2))
        else:
            print(json.dumps([dict(r) for r in service.db.execute('SELECT * FROM events ORDER BY seq DESC LIMIT 100')], indent=2))
        print(json.dumps({'status': 'shadow_' + args.action + '_completed', 'selected_model': selection.model,
                          'dry_run': True, 'enable_publication': False, 'alerts_published': False,
                          'rf_service_changed': False})); return 0
    except Exception as exc:
        if service:
            with service.db: service.log(None, 'shadow_poll', 'failed', type(exc).__name__)
        print(json.dumps({'status': 'blocked', 'exception_type': type(exc).__name__,
            'reason': 'Inspect shadow state/stage audits and existing connection; no fallback or publication.',
            'alerts_published': False})); return 2
    finally:
        if service: service.close()


if __name__ == '__main__': raise SystemExit(main())
