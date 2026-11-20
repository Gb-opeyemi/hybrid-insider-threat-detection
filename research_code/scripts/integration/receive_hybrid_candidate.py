"""UNDEPLOYED receiver candidate for local tests only; no production CLI.

RF retains its original ledger and validator. TabPFN uses a separate ledger.
Both must pass this common lock/check before any future production deployment.
The live receiver is deliberately not imported/replaced by a service here.
"""
import fcntl
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from . import receive_ml_prediction as legacy
from .tabpfn_contract import validate as validate_tabpfn


def opened(path):
    fd = os.open(path, os.O_RDWR | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0))
    handle = os.fdopen(fd, 'r+b', buffering=0)
    if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
        handle.close(); raise ValueError('Pre-provisioned regular local ledger required')
    return handle


def records(handle, validator):
    handle.seek(0)
    for line in handle:
        if not line.endswith(b'\n') or len(line) > legacy.MAX_BYTES:
            raise ValueError('Incomplete/corrupt ledger; do not truncate it')
        event = legacy.strict_json(line)
        legacy.utc(event.pop('published_at_utc', None))
        validator(event)
        yield event


def receive_local(event, rf_log, tabpfn_log, lock_file):
    """Temporary-ledger test entry, never calls SSH or the production receiver CLI.

    Exactly one hybrid model may publish for an account/activity-derived session
    ID. A cross-model conflict is rejected, not acknowledged as a duplicate.
    Old RF ML-only records do not occupy the separate hybrid publication slot.
    """
    tab = event.get('event_type') == 'thesis_tabpfn_hybrid_priority'
    (validate_tabpfn if tab else legacy.validate)(event)
    paths = [Path(p).resolve() for p in (rf_log, tabpfn_log, lock_file)]
    if len(set(paths)) != 3: raise ValueError('Separate ledgers and common lock required')
    # Refuse the actual production destination even if called accidentally.
    if Path(legacy.LOG_FILE).resolve() in paths:
        raise ValueError('Local candidate cannot access the production ledger')
    with opened(lock_file) as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        with opened(rf_log) as rf, opened(tabpfn_log) as tp:
            devices = [(os.fstat(h.fileno()).st_dev, os.fstat(h.fileno()).st_ino) for h in (guard, rf, tp)]
            if len(set(devices)) != 3: raise ValueError('Ledger/lock files must not alias the same inode')
            prior = list(records(rf, legacy.validate)) + list(records(tp, validate_tabpfn))
            hybrid = tab or event.get('event_type') == 'thesis_hybrid_priority'
            if hybrid:
                for row in prior:
                    if row['event_type'] not in {'thesis_hybrid_priority', 'thesis_tabpfn_hybrid_priority'}: continue
                    if row['session_id'] == event['session_id'] and row['model'] != event['model']:
                        raise ValueError('Session hybrid result already published by another model')
            for row in prior:
                if row['prediction_id'] == event['prediction_id']:
                    if row != event: raise ValueError('Conflicting payload for existing prediction identity')
                    return {'status': 'duplicate', 'prediction_id': event['prediction_id']}
            if not tab:
                return legacy.receive(event, rf_log)  # The RF write implementation is unchanged.
            data = (legacy.canonical({**event, 'published_at_utc': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}) + '\n').encode()
            if tp.write(data) != len(data): raise OSError('Partial append; retain ledger for review')
            os.fsync(tp.fileno())
            return {'status': 'written', 'prediction_id': event['prediction_id']}
