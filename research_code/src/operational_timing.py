"""Best-effort, atomic timing sidecars. Never part of prediction/receiver payloads."""
import argparse
from contextlib import contextmanager
from contextvars import ContextVar
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

CURRENT = ContextVar('operational_timing', default=None)
METRICS = ('wazuh_event_retrieval', 'feature_extraction', 'preprocessing', 'model_loading',
           'model_inference', 'wazuh_evidence_correlation', 'hybrid_decision', 'publication')
SCHEMA_VERSION = 'operational_execution_timing_v1'


def utc_now(): return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
def timestamp(text): return datetime.fromisoformat(text.replace('Z', '+00:00'))


def atomic(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.parent / ('.' + path.name + '.' + str(uuid4()))
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(value, handle, indent=2, allow_nan=False); handle.write('\n')
            handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists(): temporary.unlink()


def load(path): return json.loads(Path(path).read_text(encoding='utf-8'))


def start_job(base, completion, model, status='waiting', error=None):
    """Only called on new admission. Never backfill or rewrite historical jobs."""
    try:
        from scripts.integration.receive_ml_prediction import completed_session_id
        folder = Path(base) / 'timings' / completion['session_id']
        if (folder / 'metadata.json').exists(): return
        end = timestamp(completion['end'])
        meta = {'measurement_schema_version': SCHEMA_VERSION, 'job_id': completion['session_id'],
            'session_id': completed_session_id(completion['username'].casefold(),
                _iso(timestamp(completion['start'])), _iso(end)),
            'selected_model': model, 'activity_start': completion['start'], 'activity_end': completion['end'],
            'evidence_cutoff': _iso(end + timedelta(seconds=300)), 'created_at_utc': utc_now(),
            'processing_status': status, 'processing_error_code': error,
            'instrumentation_sha256': {name:hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest()
                for name in ('operational_timing.py','timing_hooks.py','timed_replay_stage.py')}}
        atomic(folder / 'metadata.json', meta)
        refresh(folder)
    except Exception:
        warn()


def _iso(value): return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
def warn():
    try: print('Timing sidecar unavailable; prediction/publication behaviour unchanged.', file=sys.stderr)
    except Exception: pass


class Collector:
    def __init__(self, folder, clock=None, wall=None):
        self.folder = Path(folder); self.clock = clock or time.perf_counter_ns; self.wall = wall or utc_now
        self.stage = 'job'; self.attempt = None; self.inference_depth = 0
        self.depth = {}; self.new_events = []; self.active = None; self.started = None

    def save(self, event):
        try: atomic(self.folder / 'spans' / (event['span_id'] + '.json'), event)
        except Exception: warn()

    def event(self, metric, purpose, kind='operation'):
        event = {'span_id': str(uuid4()), 'metric': metric, 'purpose': purpose, 'kind': kind,
            'stage': self.stage, 'attempt_id': self.attempt, 'started_at_utc': self.wall(),
            'ended_at_utc': None, 'duration_ns': None, 'status': 'running', 'exception_type': None}
        return event

    def activate(self):
        if self.started is not None and self.active is None:
            self.active = self.event(None, 'active', 'active_processing')
            self.active['started_at_utc'] = self.started[1]
            self.save(self.active)

    @contextmanager
    def span(self, metric, purpose='primary', kind='operation'):
        key = (metric, purpose)
        if self.depth.get(key, 0):
            yield None; return  # Nested calls of one metric are measured as one interval.
        event = None; began = None
        try:
            self.activate(); event = self.event(metric, purpose, kind)
            self.save(event); self.depth[key] = 1
            event['started_at_utc'] = self.wall()
            began = self.clock()  # Journal I/O is outside the operation interval.
        except Exception: warn()
        try:
            yield event
        except BaseException as exc:
            if event: event.update(status='failed', exception_type=type(exc).__name__)
            raise
        finally:
            try: ended = self.clock() if began is not None else None
            except Exception: ended = None
            self.depth.pop(key, None)
            if event:
                try:
                    delta = ended-began if ended is not None and began is not None else None
                    event.update(ended_at_utc=self.wall(), duration_ns=delta if type(delta) is int and delta>=0 else None)
                    if event['duration_ns'] is None:event['measurement_error']='Monotonic duration unavailable; no zero substituted.'
                    if event['status'] == 'running': event['status'] = 'completed'
                    self.save(event); self.new_events.append(event)
                except Exception: warn()

    def cached_loading(self):
        try:
            event = self.event('model_loading', 'primary', 'observed_cache_reuse')
            event.update(ended_at_utc=event['started_at_utc'], duration_ns=0, status='completed',
                         note='Verified classifier reused in this polling process; no restore call executed.')
            self.save(event); self.new_events.append(event)
        except Exception: warn()

    @contextmanager
    def work(self, stage, artifact=None):
        old = self.stage, self.attempt
        self.stage = stage
        self.attempt = hashlib.sha256(str(artifact).encode()).hexdigest()[:20] if artifact else None
        try: self.activate()
        except Exception: warn()
        try: yield
        finally: self.stage, self.attempt = old

    @contextmanager
    def installed(self, active=False):
        token = CURRENT.set(self)
        if active:
            try: self.started = (self.clock(), self.wall())
            except Exception: warn()
        try: yield self
        finally:
            if active and self.active is not None:
                try:
                    delta=self.clock()-self.started[0]
                    self.active.update(duration_ns=delta if type(delta) is int and delta>=0 else None,
                        ended_at_utc=self.wall(), status='completed')
                    self.save(self.active)
                except Exception: warn()
            CURRENT.reset(token)


def collector_for(base, sid):
    folder = Path(base) / 'timings' / sid
    try:
        if (folder / 'metadata.json').is_file(): return Collector(folder)
    except Exception: warn()
    return None


def refresh(folder, status=None, error=None):
    meta = load(Path(folder) / 'metadata.json')
    if status is not None:
        meta.update(processing_status=status, processing_error_code=error)
        atomic(Path(folder) / 'metadata.json', meta)
    events = [load(p) for p in sorted((Path(folder) / 'spans').glob('*.json'))]
    report = build_report(meta, events)
    atomic(Path(folder) / 'report.json', report)
    return report


def build_report(meta, events):
    report = dict(meta)
    report.update(updated_at_utc=utc_now(), duration_unit='milliseconds', clock='time.perf_counter_ns',
        aggregation='Executed primary operations across all attempts, including failed work; verification is separate. Active intervals are not summed with component intervals.',
        durations_ms={}, unavailable_reasons={}, errors=[], verification_durations_ms={})
    def total(rows):
        known = [r for r in rows if type(r.get('duration_ns')) is int and r['duration_ns'] >= 0]
        complete = len(known) == len(rows) and bool(rows)
        return (sum(r['duration_ns'] for r in known)/1e6 if complete else None,
                sum(r['duration_ns'] for r in known)/1e6)
    for metric in METRICS:
        rows = [r for r in events if r['metric'] == metric and r['purpose'] == 'primary']
        report['durations_ms'][metric] = total(rows)[0]
        if report['durations_ms'][metric] is None:
            report['unavailable_reasons'][metric] = ('Interrupted or incomplete timing span.' if rows else
                'Operation not observed: not reached, not instrumented, or recovered without a new execution. Historical times are never inferred.')
        checks = [r for r in events if r['metric'] == metric and r['purpose'] == 'verification']
        report['verification_durations_ms'][metric] = total(checks)[0]
    active = [r for r in events if r['kind'] == 'active_processing']
    report['durations_ms']['total_active_processing'], report['recorded_active_processing_ms'] = total(active)
    if report['durations_ms']['total_active_processing'] is None:
        report['unavailable_reasons']['total_active_processing'] = 'No complete set of active intervals; scheduler/cutoff waits are never inferred as execution.'
    acks = sorted([r for r in events if r.get('ack_status') in {'written','duplicate'} and r.get('ended_at_utc')],
                  key=lambda r:r['ended_at_utc'])
    written = next((r for r in acks if r['ack_status'] == 'written'), None)
    first = written or (acks[0] if acks else None)
    report.update(publication_acknowledged_at_utc=first['ended_at_utc'] if first else None,
        publication_ack_status=first.get('ack_status') if first else None,
        completion_to_publication_latency_ms=None, completion_to_acknowledgement_latency_ms=None,
        receiver_append_timestamp_utc=None)
    if first:
        latency = (timestamp(first['ended_at_utc'])-timestamp(meta['activity_end'])).total_seconds()*1000
        if latency >= 0: report['completion_to_acknowledgement_latency_ms'] = latency
        else: report['unavailable_reasons']['completion_to_acknowledgement_latency_ms'] = 'UTC clock ordering inconsistent; no latency invented.'
        if written and latency >= 0: report['completion_to_publication_latency_ms'] = latency
    if report['completion_to_publication_latency_ms'] is None:
        report['unavailable_reasons']['completion_to_publication_latency_ms'] = 'No first-write acknowledgement observed; duplicate acknowledgement cannot establish original publication time.'
    report['unavailable_reasons']['receiver_append_timestamp_utc'] = 'The unchanged receiver acknowledgement does not include its append timestamp.'
    report['latency_boundary'] = 'Windows end to client receipt of first written acknowledgement; not the server append or dashboard indexing instant. UTC clocks may disagree.'
    report['errors'] = [{'span_id':r['span_id'], 'stage':r['stage'], 'attempt_id':r['attempt_id'],
                         'status':r['status'], 'exception_type':r.get('exception_type'),
                         'measurement_error':r.get('measurement_error'),
                         'validation_check':r.get('validation_check'),
                         'preflight_validation':r.get('preflight_validation')}
                        for r in events if r['status'] != 'completed' or r.get('duration_ns') is None]
    report['attempts'] = sorted({(r['stage'], r['attempt_id']) for r in events if r['attempt_id']})
    loads = [e for e in events if e['metric']=='model_loading' and e['purpose']=='primary']
    cached = sum(e['kind']=='observed_cache_reuse' for e in loads)
    report['model_load_count'] = len(loads)-cached
    report['model_cache_reuse_count'] = cached
    report['model_load_mode'] = ('mixed' if cached and len(loads)>cached else 'cache_reuse' if cached
                                  else 'load_attempted' if loads else 'not_observed')
    report['timing_status'] = ('incomplete' if any(r.get('duration_ns') is None for r in events)
                               else 'recorded' if events else 'not_observed')
    report['processing_status_source'] = 'Last scheduler timing snapshot; export reads no database.'
    report['operation_spans'] = events
    return report


def finish(base, sid, row):
    try:
        folder = Path(base) / 'timings' / sid
        if (folder / 'metadata.json').is_file(): refresh(folder, row['status'], row['error'])
    except Exception: warn()


def export_csv(state, destination):
    """Read sidecars only; rebuild from durable spans, never touch the job DB."""
    root = Path.cwd().resolve(); state = Path(state).resolve(); destination = Path(destination).resolve()
    if not state.is_relative_to(root / 'data/experiments/operational_service/model_aware'):
        raise ValueError('Use the isolated model-aware state directory')
    if not destination.is_relative_to(root / 'data/experiments') or destination.exists():
        raise ValueError('Use a new ignored data/experiments CSV; no overwrite')
    reports = []
    for path in sorted((state / 'timings').glob('*/metadata.json')):
        meta = load(path)
        if meta['measurement_schema_version'] != SCHEMA_VERSION: raise ValueError('Unknown timing schema')
        reports.append(build_report(meta, [load(p) for p in sorted((path.parent / 'spans').glob('*.json'))]))
    destination.parent.mkdir(parents=True, exist_ok=True)
    fields = ['job_id','session_id','selected_model','activity_start','activity_end','evidence_cutoff',
        'processing_status','measurement_schema_version','model_load_mode','model_load_count','model_cache_reuse_count','timing_status'] + [k+'_ms' for k in METRICS] + [
        'total_active_processing_ms','recorded_active_processing_ms','completion_to_publication_latency_ms',
        'completion_to_acknowledgement_latency_ms','publication_ack_status','unavailable_reasons','attempt_count','error_count']
    temporary = destination.parent / ('.' + destination.name + '.' + str(uuid4()))
    try:
        fd = os.open(temporary,os.O_WRONLY | os.O_CREAT | os.O_EXCL,0o600)
        with os.fdopen(fd,'w',newline='',encoding='utf-8') as handle:
            writer = csv.DictWriter(handle, fieldnames=fields); writer.writeheader()
            for report in reports:
                row = {k:report[k] for k in fields if k in report}
                row.update({k+'_ms':v for k,v in report['durations_ms'].items()})
                row.update(unavailable_reasons=json.dumps(report['unavailable_reasons'], sort_keys=True),
                    attempt_count=len(report['attempts']), error_count=len(report['errors']))
                writer.writerow(row)
            handle.flush(); os.fsync(handle.fileno())
        os.link(temporary,destination)  # Atomic, refuses an existing destination.
    finally:
        if temporary.exists():temporary.unlink()
    return len(reports)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    export = sub.add_parser('export'); export.add_argument('--state-dir', required=True, type=Path)
    export.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    print(json.dumps({'reports_exported':export_csv(args.state_dir,args.output),'source_modified':False})); return 0


if __name__ == '__main__': raise SystemExit(main())
