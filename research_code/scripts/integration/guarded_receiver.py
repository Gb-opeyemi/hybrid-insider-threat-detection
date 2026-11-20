"""Undeployed model-aware receiver. All publishing keys must use this entry point.

Uses the preserved RF validator/write function and separate TabPFN JSON log.
Ownership and both histories are checked under one stable advisory lock.
"""
import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import stat
import sys
from . import receive_ml_prediction as legacy
from .receive_hybrid_candidate import opened, records
from .tabpfn_contract import validate as validate_tabpfn
from .model_publication_contract import validate_claim, session_key

DEFAULT = '/var/log/thesis-ml'


def append(handle, value, timestamp_key):
    value = {**value, timestamp_key: datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}
    data = (legacy.canonical(value)+'\n').encode()
    if handle.write(data) != len(data): raise OSError('Partial append; review ledger')
    os.fsync(handle.fileno())


def receive(value, rf_log, tabpfn_log, ownership_log, lock_file, mode='model_aware'):
    if not isinstance(value,dict):raise ValueError('JSON object required')
    if mode not in {'model_aware','legacy_rf'}: raise ValueError('Invalid guard mode')
    claim = value.get('operation') == 'claim'
    tab = value.get('event_type') == 'thesis_tabpfn_hybrid_priority'
    (validate_claim if claim else validate_tabpfn if tab else legacy.validate)(value)
    with ExitStack() as stack:
        handles = [stack.enter_context(opened(path)) for path in (lock_file,rf_log,tabpfn_log,ownership_log)]
        guard, rf, tp, owners = handles
        fcntl.flock(guard,fcntl.LOCK_EX)
        inodes = [(os.fstat(h.fileno()).st_dev,os.fstat(h.fileno()).st_ino) for h in handles]
        if len(set(inodes)) != 4: raise ValueError('Publication files must have distinct inodes')
        prior = list(records(rf,legacy.validate)) + list(records(tp,validate_tabpfn))
        ownership = []
        owners.seek(0)
        for line in owners:
            if not line.endswith(b'\n') or len(line)>legacy.MAX_BYTES: raise ValueError('Corrupt ownership history')
            row = legacy.strict_json(line);legacy.utc(row.pop('claimed_at_utc',None));validate_claim(row)
            ownership.append(row)
        by_session = {}
        for row in ownership:
            old=by_session.setdefault(session_key(row),row)
            if old != row: raise ValueError('Conflicting ownership history')
        hybrid_types = {'thesis_hybrid_priority','thesis_tabpfn_hybrid_priority'}
        history_models = {}
        for row in prior:
            if row['event_type'] in hybrid_types:
                model = 'tabpfn' if row['event_type']=='thesis_tabpfn_hybrid_priority' else 'random_forest'
                previous=history_models.setdefault(session_key(row),model)
                if previous != model: raise ValueError('Cross-model conflict in historical publication records')
                if session_key(row) in by_session and by_session[session_key(row)]['selected_model'] != model:
                    raise ValueError('Ownership/history conflict')
        if claim:
            old=by_session.get(session_key(value))
            if old and old != value: raise ValueError('Session already owned by a different job/model')
            if old:return {'status':'duplicate','prediction_id':value['prediction_id'],'guard_version':1}
            if session_key(value) in history_models:
                raise ValueError('Historical publication cannot be newly claimed or backfilled')
            if mode=='legacy_rf':raise ValueError('Automatic model-aware claims disabled during legacy RF rollback')
            append(owners,value,'claimed_at_utc')
            return {'status':'written','prediction_id':value['prediction_id'],'guard_version':1}
        # Exact retries of historical accepted events remain valid without rewriting history.
        matches=[row for row in prior if row['prediction_id']==value['prediction_id']]
        if matches:
            if any(row != value for row in matches):raise ValueError('Conflicting prediction identity')
            return {'status':'duplicate','prediction_id':value['prediction_id'],'guard_version':1}
        if mode=='legacy_rf' and tab:raise ValueError('TabPFN publication disabled during RF rollback')
        hybrid=tab or value['event_type']=='thesis_hybrid_priority'
        if hybrid:
            model='tabpfn' if tab else 'random_forest'
            if session_key(value) in history_models:raise ValueError('Session hybrid result already published')
            owner=by_session.get(session_key(value))
            if owner:
                if owner['selected_model'] != model:raise ValueError('Selected model does not own this session')
                if any(owner[k]!=value[k] for k in ('username','activity_start','activity_end')):
                    raise ValueError('Publication differs from claimed activity')
            elif not (mode=='legacy_rf' and not tab):
                raise ValueError('Model-aware hybrid publication requires a durable ownership claim')
        if not tab:
            ack=legacy.receive(value,rf_log)  # RF schema and append behaviour preserved.
        else:
            append(tp,value,'published_at_utc')
            ack={'status':'written','prediction_id':value['prediction_id']}
        return {**ack,'guard_version':1}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rf-log',default=DEFAULT+'/predictions.jsonl')
    parser.add_argument('--tabpfn-log',default=DEFAULT+'/tabpfn_predictions.jsonl')
    parser.add_argument('--ownership-log',default=DEFAULT+'/hybrid_ownership.jsonl')
    parser.add_argument('--lock-file',default=DEFAULT+'/hybrid_guard.lock')
    parser.add_argument('--policy',default='/etc/thesis-hybrid/publication-policy.json')
    args=parser.parse_args(argv)
    try:
        path=Path(args.policy)
        if path.is_symlink():raise ValueError('Unsafe policy')
        info=path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & (stat.S_IWGRP|stat.S_IWOTH):
            raise ValueError('Root-owned regular policy required')
        policy=legacy.strict_json(path.read_text())
        if set(policy)!={'schema_version','mode'} or type(policy['schema_version']) is not int or policy['schema_version']!=1:
            raise ValueError('Invalid policy')
        raw=sys.stdin.buffer.read(legacy.MAX_BYTES+1)
        if len(raw)>legacy.MAX_BYTES:raise ValueError('Oversized request')
        ack=receive(legacy.strict_json(raw),args.rf_log,args.tabpfn_log,args.ownership_log,args.lock_file,policy['mode'])
        print(legacy.canonical(ack));return 0
    except (ValueError,OSError,KeyError,TypeError,UnicodeError):
        print('{"status":"rejected","reason":"Ownership, schema or publication history unavailable/conflicting"}')
        return 2


if __name__=='__main__':raise SystemExit(main())
