"""Opt-in completed-session orchestration. No detector or fusion definitions live here."""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from uuid import UUID

UTC = timezone.utc
FIELDS = {'schema_version', 'feed_id', 'session_id', 'username', 'host', 'start', 'end', 'status'}
STAGES = ('rf', 'hybrid', 'prepare', 'send')


def timestamp(value):
    if not isinstance(value, str): raise ValueError('Explicit timezone required')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None: raise ValueError('Explicit timezone required')
    return result.astimezone(UTC)


def iso(value): return value.astimezone(UTC).isoformat().replace('+00:00', 'Z')
def digest(value): return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
def read(path): return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def record(value, feed_id):
    if not isinstance(value, dict) or set(value) != FIELDS: raise ValueError('Invalid completion schema')
    if type(value['schema_version']) is not int or value['schema_version'] != 1 or value['feed_id'] != feed_id:
        raise ValueError('Untrusted completion feed')
    UUID(value['session_id'])
    if (not isinstance(value['username'], str) or value['username'].count('\\') != 1
            or any(not p.strip() or p != p.strip() for p in value['username'].split('\\'))
            or any(ord(c) < 32 for c in value['username'])): raise ValueError('Qualified Windows account required')
    if not isinstance(value['host'], str) or not value['host'].strip(): raise ValueError('Host required')
    start = timestamp(value['start'])
    if value['status'] == 'Started':
        if value['end'] is not None: raise ValueError('Started must not have end')
    elif value['status'] in {'Completed', 'Failed'}:
        if timestamp(value['end']) <= start: raise ValueError('Invalid activity interval')
    else: raise ValueError('Unsupported lifecycle state')
    return value


def feed_snapshot(folder, feed_id):
    """Atomic terminal records must have a matching independently saved start record."""
    folder = Path(folder)
    if read(folder / 'feed.json') != {'schema_version': 1, 'feed_id': feed_id}:
        raise ValueError('Authenticated completion mount missing or incorrect')
    starts, terminals = {}, {}
    for path in sorted(folder.glob('*.json')):
        if path.name == 'feed.json': continue
        if path.is_symlink() or path.stat().st_size > 8192: raise ValueError('Unsafe completion record')
        value = record(read(path), feed_id)
        expected = value['session_id'] + ('.started.json' if value['status'] == 'Started' else '.terminal.json')
        if path.name != expected: raise ValueError('Unexpected lifecycle filename')
        target = starts if value['status'] == 'Started' else terminals
        if value['session_id'] in target: raise ValueError('Duplicate lifecycle identity')
        target[value['session_id']] = value
    for sid, terminal in terminals.items():
        if sid not in starts or any(starts[sid][k] != terminal[k] for k in ('feed_id', 'session_id', 'username', 'host', 'start')):
            raise ValueError('Terminal record has no matching start evidence')
    return starts, terminals


def config_file(path):
    cfg = read(path)
    required = {'root', 'feed_id', 'state_dir', 'dry_run', 'enable_publication', 'ssh_host', 'host_aliases', 'max_attempts', 'retry_seconds'}
    source = cfg.get('completion_source', 'directory')
    if source not in {'directory', 'wazuh'}: raise ValueError('Unknown completion source')
    required |= {'feed_dir'} if source == 'directory' else {'completion_agent_id', 'completion_location', 'completion_source'}
    if set(cfg) - {'completion_source'} != required - {'completion_source'}: raise ValueError('Unexpected service configuration fields')
    if source == 'wazuh':
        if not isinstance(cfg['completion_agent_id'],str) or not cfg['completion_agent_id'].isdigit():
            raise ValueError('Pin the actual Windows Wazuh agent ID')
        if not isinstance(cfg['completion_location'],str) or not cfg['completion_location']:
            raise ValueError('Pin the lifecycle log location')
        UUID(cfg['feed_id'])
    for k in ('dry_run', 'enable_publication'):
        if type(cfg[k]) is not bool: raise ValueError('Boolean service flags required')
    if cfg['dry_run'] and cfg['enable_publication']: raise ValueError('Dry-run cannot enable publication')
    for k in ('max_attempts', 'retry_seconds'):
        if type(cfg[k]) is not int or cfg[k] < 1: raise ValueError('Positive retry limits required')
    if cfg['max_attempts'] > 5: raise ValueError('At most five attempts allowed')
    if not isinstance(cfg['host_aliases'], dict) or not cfg['host_aliases']: raise ValueError('Explicit source-host to telemetry-host aliases required')
    for host, aliases in cfg['host_aliases'].items():
        if not isinstance(host, str) or not isinstance(aliases, list) or not aliases or any(not isinstance(a, str) or not a for a in aliases):
            raise ValueError('Invalid host aliases')
    cfg['root'] = str(Path(cfg['root']).resolve())
    state = Path(cfg['state_dir']).resolve()
    if not state.is_relative_to(Path(cfg['root']) / 'data/experiments/operational_service'):
        raise ValueError('State must use ignored data/experiments/operational_service')
    return cfg


class Orchestrator:
    def __init__(self, cfg, now=None, runner=None):
        self.cfg = cfg; self.root = Path(cfg['root']); self.base = Path(cfg['state_dir'])
        self.clock = now or (lambda: datetime.now(UTC)); self.runner = runner or self.command
        self.base.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = (self.base / 'service.lock').open('a')
        try: fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lock.close()
            raise
        self.db = sqlite3.connect(self.base / 'state.sqlite3')
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL'); self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,record TEXT NOT NULL,hash TEXT NOT NULL,status TEXT NOT NULL,
          stage TEXT NOT NULL DEFAULT 'rf',attempt INTEGER NOT NULL DEFAULT 0,path TEXT,next_at TEXT,error TEXT,
          rf TEXT,hybrid TEXT,prepared TEXT,ack TEXT,result TEXT);
        CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY,at TEXT,job TEXT,stage TEXT,status TEXT,detail TEXT);
        CREATE TABLE IF NOT EXISTS completion_documents(index_name TEXT,document_id TEXT,payload TEXT,PRIMARY KEY(index_name,document_id));
        CREATE TABLE IF NOT EXISTS completion_queries(seq INTEGER PRIMARY KEY,at TEXT,audit TEXT);''')

    def close(self): self.db.close(); self.lock.close()
    def log(self, sid, stage, status, detail=''):
        self.db.execute('INSERT INTO events(at,job,stage,status,detail) VALUES(?,?,?,?,?)', (iso(self.clock()), sid, stage, status, detail))
    def meta(self, key):
        row = self.db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
        return row[0] if row else None
    def binding(self):
        keys = ['root','feed_id','host_aliases']
        if self.cfg.get('completion_source','directory') == 'directory': keys.append('feed_dir')
        else: keys += ['completion_source','completion_agent_id','completion_location']
        return digest({k:self.cfg[k] for k in keys})
    def source_snapshot(self):
        if self.cfg.get('completion_source','directory') == 'wazuh':
            from .wazuh_completion_feed import snapshot
            return snapshot(self)
        return feed_snapshot(self.cfg['feed_dir'], self.cfg['feed_id'])
    def initialize(self):
        if self.meta('armed_at'): raise ValueError('Already initialized; do not reset state to backfill')
        starts = {} if self.cfg.get('completion_source') == 'wazuh' else self.source_snapshot()[0]
        with self.db:
            self.db.execute('INSERT INTO meta VALUES(?,?)', ('armed_at', iso(self.clock())))
            self.db.execute('INSERT INTO meta VALUES(?,?)', ('binding', self.binding()))
            self.db.execute('INSERT INTO meta VALUES(?,?)', ('baseline_ids', json.dumps(sorted(starts))))
            self.log(None, 'init', 'armed_future_sessions_only')
    def update(self, sid, **values):
        self.db.execute('UPDATE jobs SET ' + ','.join(k+'=?' for k in values) + ' WHERE id=?', (*values.values(), sid))
    def discover(self):
        if not self.meta('armed_at'): raise ValueError('Initialize explicitly before polling')
        if self.meta('binding') != self.binding():
            raise ValueError('Completion source or host binding changed; investigation required')
        starts, terminals = self.source_snapshot()
        baseline = set(json.loads(self.meta('baseline_ids')))
        with self.db:
            for sid, value in terminals.items():
                old = self.db.execute('SELECT * FROM jobs WHERE id=?', (sid,)).fetchone()
                if old:
                    if old['hash'] != digest(value):
                        self.update(sid, status='investigation_required', error='completion_record_changed')
                        self.log(sid, 'completion', 'integrity_failure')
                    continue
                # No original dataset reads; exclude every session begun before explicit arming.
                if sid in baseline or timestamp(value['start']) < timestamp(self.meta('armed_at')): continue
                state = 'waiting' if value['status'] == 'Completed' else 'failed_execution'
                if getattr(self,'runner_terminal_statuses',{}).get(sid) == 'audit_not_verified':
                    state = 'audit_not_verified'
                identity = lambda r: (r['username'].casefold(), timestamp(r['start']), timestamp(r['end']))
                if any(identity(json.loads(r[0])) == identity(value) for r in self.db.execute('SELECT record FROM jobs')):
                    state = 'duplicate_session'
                if value['host'].casefold() not in {k.casefold() for k in self.cfg['host_aliases']}:
                    state = 'investigation_required'
                self.db.execute('INSERT INTO jobs(id,record,hash,status) VALUES(?,?,?,?)', (sid,json.dumps(value),digest(value),state))
                self.log(sid, 'completion', state)
        return starts, terminals

    def path(self, sid, stage, attempt):
        folders = {'rf':'new_completed_sessions', 'hybrid':'hybrid_session_phase1', 'prepare':'hybrid_publication_phase1', 'send':'hybrid_publication_phase1'}
        # Stable installation namespace prevents collision with other service state databases.
        name = 'auto_' + hashlib.sha256(str(self.base).encode()).hexdigest()[:12] + '_' + sid + '_' + stage + '_' + str(attempt)
        return self.root / 'data/experiments' / folders[stage] / name

    def command(self, stage, value, out, job, windows):
        args = [sys.executable, '-B', '-m']
        if stage == 'rf':
            other = self.base / (value['session_id'] + '.other_windows.json')
            other.write_text(json.dumps(windows))
            args += ['src.controlled_replay.new_session', '--username', value['username'], '--start', value['start'], '--end', value['end'],
                     '--availability-delay-seconds', '300', '--other-windows', str(other)]
        elif stage == 'hybrid': args += ['src.controlled_replay.hybrid_session', '--session-dir', job['rf']]
        elif stage == 'prepare': args += ['src.hybrid_publisher', 'prepare', '--hybrid-dir', job['hybrid']]
        else: args += ['src.hybrid_publisher', 'send', '--prepared-dir', job['prepared'], '--ssh-host', self.cfg['ssh_host']]
        args += ['--output-dir', str(out)]
        # Existing commands write sanitized diagnostics and never receive secrets as CLI arguments.
        return subprocess.run(args, cwd=self.root, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=1800 if stage in {'rf','hybrid'} else 180, check=False).returncode

    def outcome(self, stage, out, value):
        """Control flow only. Existing prepare/send gates perform full artifact verification."""
        if stage == 'rf':
            if read(out/'run_status.json').get('status') != 'completed': return 'retry', 'rf_blocked'
            plan, audit = read(out/'request.json'), read(out/'validation.json')
            expected = timestamp(value['end']) + timedelta(seconds=300)
            if (timestamp(plan['prediction_cutoff']) != expected or plan['availability_delay_seconds'] != 300
                    or timestamp(plan['actual_start']) != timestamp(value['start']) or timestamp(plan['actual_end']) != timestamp(value['end'])
                    or plan['username'].casefold() != value['username'].casefold() or audit.get('status') != 'eligible'):
                return 'stop', 'completion_interval_mismatch'
            aliases = next(v for k,v in self.cfg['host_aliases'].items() if k.casefold() == value['host'].casefold())
            hosts = audit.get('accepted_behavior_hosts', [])
            if not hosts or not {h.casefold() for h in hosts} <= {h.casefold() for h in aliases}:
                return 'stop', 'completion_host_mismatch'
        elif stage == 'hybrid':
            result = read(out/'hybrid_result.json'); audit = read(out/'alert_retrieval_audit.json')
            if result.get('wazuh_evidence_status') == 'query_failed_or_unavailable' or audit.get('status') in {'failed','configuration_missing'}:
                return 'retry', 'wazuh_query_unavailable'
            if result.get('wazuh_evidence_verified') is not True or result.get('wazuh_evidence_status') != 'verified_positive':
                return 'stop', 'Evidence Unavailable; investigation required; no negative inferred'
        elif stage == 'prepare':
            if read(out/'receipt.json').get('status') != 'prepared_locally': return 'stop', 'publisher_verification_refused'
        else:
            receipt = read(out/'receipt.json')
            if receipt.get('status') != 'acknowledged' or not receipt.get('remote_submissions'): return 'retry', 'publication_not_acknowledged'
        return 'ok', ''

    def release_prepared(self, session_ids=None):
        """Explicitly release selected held payloads; verification never runs inference."""
        if self.cfg['dry_run'] or not self.cfg['enable_publication']:
            raise ValueError('Publication remains disabled')
        if session_ids is None:
            session_ids=[r[0] for r in self.db.execute("SELECT id FROM jobs WHERE status='prepared_not_published' AND stage='send'")]
        elif not session_ids or len(set(session_ids))!=len(session_ids):
            raise ValueError('Provide distinct source session IDs')
        from .hybrid_publisher import verify_prepared
        verified=[]
        for sid in session_ids:
            row=self.db.execute('SELECT * FROM jobs WHERE id=?',(sid,)).fetchone()
            if not row or row['status']!='prepared_not_published' or row['stage']!='send' or row['ack'] is not None:
                raise ValueError('Only unpublished prepared jobs can be released')
            event=verify_prepared(Path(row['prepared']))
            saved=json.loads(row['result']); source=json.loads(row['record'])
            if (event['session_id']!=saved['session_id'] or event['rf_prediction_id']!=saved['rf_prediction_id']
                    or timestamp(event['activity_start'])!=timestamp(source['start'])
                    or timestamp(event['activity_end'])!=timestamp(source['end'])):
                raise ValueError('Prepared payload differs from the selected job')
            verified.append((sid,event['prediction_id']))
        with self.db:
            for sid,prediction in verified:
                self.update(sid,status='waiting')
                self.log(sid,'send','prepared_job_explicitly_released',prediction)
        return [sid for sid,_ in verified]

    def tick(self):
        starts, terminals = self.discover()
        for row in self.db.execute("SELECT * FROM jobs WHERE status IN ('waiting','running','retry') ORDER BY id").fetchall():
            self.process(row['id'], starts, terminals)

    def process(self, sid, starts, terminals):
        job = dict(self.db.execute('SELECT * FROM jobs WHERE id=?', (sid,)).fetchone()); value = json.loads(job['record'])
        if sid not in terminals or digest(terminals[sid]) != job['hash']:
            with self.db:
                self.update(sid,status='investigation_required',error='completion_evidence_missing_or_changed')
            return
        if timestamp(value['end']) + timedelta(seconds=300) > self.clock(): return
        if timestamp(value['end']) > self.clock() or timestamp(value['start']) > self.clock(): return
        if job['next_at'] and timestamp(job['next_at']) > self.clock(): return
        windows = []
        for other, start in starts.items():
            if other == sid or start['username'].casefold().split('\\')[-1] != value['username'].casefold().split('\\')[-1]: continue
            end = terminals.get(other, {}).get('end')
            if timestamp(start['start']) <= timestamp(value['end']) + timedelta(seconds=4) and (end is None or timestamp(end) >= timestamp(value['start']) - timedelta(seconds=4)):
                with self.db:
                    self.update(sid,status='investigation_required',error='overlapping_or_unfinished_same_account_activity')
                    self.log(sid,'attribution','investigation_required')
                return
            if end and timestamp(end)+timedelta(seconds=2) <= self.clock():
                windows.append({'username':start['username'],'start':start['start'],'end':end})
        stage = job['stage']
        if stage == 'send' and (self.cfg['dry_run'] or not self.cfg['enable_publication']):
            with self.db:
                self.update(sid,status='prepared_not_published'); self.log(sid,stage,'publication_disabled')
            return
        # Recover an existing attempt before launching anything. A crash after remote write
        # but before durable ack retries the SAME prepared payload: receiver deduplicates it.
        out = Path(job['path']) if job['path'] else self.path(sid,stage,job['attempt']+1)
        recovered = job['status'] == 'running' and out.exists()
        if not recovered:
            if job['attempt'] >= self.cfg['max_attempts']:
                with self.db: self.update(sid,status='failed',error='retry_limit_exhausted')
                return
            out = self.path(sid,stage,job['attempt']+1)
            with self.db:
                self.update(sid,status='running',attempt=job['attempt']+1,path=str(out),next_at=None)
                self.log(sid,stage,'attempt_started',str(out))
            try:
                code = self.runner(stage,value,out,job,windows)
                if isinstance(code,int) and code != 0:
                    with self.db: self.log(sid,stage,'command_failed','exit_code='+str(code))
            except (OSError,subprocess.TimeoutExpired) as exc:
                with self.db: self.log(sid,stage,'command_failed',type(exc).__name__)
        try: result, reason = self.outcome(stage,out,value)
        except (OSError,ValueError,KeyError,TypeError): result, reason = 'retry', 'stage_artifact_missing_or_invalid'
        with self.db:
            current = self.db.execute('SELECT attempt FROM jobs WHERE id=?',(sid,)).fetchone()[0]
            if result != 'ok':
                if stage == 'hybrid' and (out/'hybrid_result.json').is_file():
                    self.update(sid,result=json.dumps(read(out/'hybrid_result.json')))
                self.update(sid,status='investigation_required' if result=='stop' else ('failed' if current>=self.cfg['max_attempts'] else 'retry'),
                            error=reason,next_at=iso(self.clock()+timedelta(seconds=self.cfg['retry_seconds'])))
            elif stage == 'send':
                self.update(sid,status='published',ack=json.dumps(read(out/'receipt.json')),error=None)
            else:
                column = {'rf':'rf','hybrid':'hybrid','prepare':'prepared'}[stage]
                extra = {}
                if stage == 'hybrid': extra['result'] = json.dumps(read(out/'hybrid_result.json'))
                self.update(sid,**{column:str(out)},stage=STAGES[STAGES.index(stage)+1],attempt=0,path=None,status='waiting',error=None,next_at=None,**extra)
            self.log(sid,stage,result,reason)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('action',choices=('init','once','status','events','feed-check','feed-audit','release-prepared'))
    parser.add_argument('--session-id', action='append', help='Release only this source session ID; repeat for multiple jobs')
    args=parser.parse_args(argv)
    if args.session_id and args.action!='release-prepared': parser.error('--session-id is only valid for release-prepared')
    os.umask(0o077)
    service=None
    try:
        service=Orchestrator(config_file(args.config))
        if args.action=='init': service.initialize()
        elif args.action=='once': service.tick()
        elif args.action=='feed-audit':
            rows=service.db.execute('SELECT at,audit FROM completion_queries ORDER BY seq DESC LIMIT 5').fetchall()
            print(json.dumps([{'at':r['at'],**json.loads(r['audit'])} for r in rows],indent=2))
        elif args.action=='feed-check':
            if service.cfg.get('completion_source') != 'wazuh': raise ValueError('Use the Wazuh completion source')
            if not service.meta('armed_at'): raise ValueError('Initialize before feed check')
            if service.meta('binding') != service.binding(): raise ValueError('Completion binding changed')
            starts, terminals = service.source_snapshot()
            print(json.dumps({'status':'completion_feed_verified','started_sessions':len(starts),'terminal_sessions':len(terminals),
                              'inference_run':False,'alerts_published':False}))
        elif args.action=='release-prepared':
            released=service.release_prepared(args.session_id)
            print(json.dumps({'status':'selected_prepared_jobs_released','session_ids':released,'alerts_published_by_this_command':False}))
        elif args.action=='events':
            print(json.dumps([dict(r) for r in service.db.execute('SELECT * FROM events ORDER BY seq DESC LIMIT 100')],indent=2))
        else:
            print(json.dumps([dict(r) for r in service.db.execute('SELECT id,status,stage,attempt,error,next_at,path,rf,hybrid,prepared,ack,result FROM jobs')],indent=2))
        return 0
    except (ValueError,OSError,sqlite3.Error,KeyError,TypeError) as exc:
        if service:
            with service.db: service.log(None,'poll','failed',type(exc).__name__)
        print(json.dumps({'status':'blocked','exception_type':type(exc).__name__,'reason':'Inspect completion source, private config and durable service events; no credentials logged'}))
        return 2
    finally:
        if service: service.close()


if __name__=='__main__': raise SystemExit(main())
