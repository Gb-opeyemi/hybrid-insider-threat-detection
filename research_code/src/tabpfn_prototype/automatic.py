"""Opt-in, one-shot TabPFN shadow polling. Production RF never imports this module."""
import json
from datetime import timedelta
from pathlib import Path
from ..session_orchestrator import Orchestrator, config_file, digest, iso, timestamp
from . import acquisition, alert_capture, artifacts, new_session, hybrid_session, publisher
from .common import read

STAGES = ('capture', 'inference', 'alerts', 'hybrid', 'prepare')


def configuration(path):
    value = read(path)
    if set(value) != {'rf_config', 'connection', 'state_dir'}:
        raise ValueError('Expected RF configuration reference, connection reference and separate state_dir')
    cfg = config_file(value['rf_config'])  # Read pins only; never open the RF database.
    if cfg.get('completion_source') != 'wazuh': raise ValueError('Use the existing Wazuh lifecycle feed')
    root = Path(cfg['root']); state = Path(value['state_dir']).resolve()
    allowed = root / 'data/experiments/tabpfn_prototype'
    if state == allowed or not state.is_relative_to(allowed) or state == Path(cfg['state_dir']).resolve():
        raise ValueError('Use a separate TabPFN shadow state subdirectory')
    # Refuse aliases/hard links to a pre-existing database before any writable open.
    db = state / 'state.sqlite3'
    if db.exists() and (db.is_symlink() or db.stat().st_nlink != 1):
        raise ValueError('Unsafe shadow database')
    cfg.update(state_dir=str(state), dry_run=True, enable_publication=False)
    return cfg, Path(value['connection'])


class Shadow(Orchestrator):
    """Reuse only durable discovery/feed plumbing. No inherited RF processing/send."""
    def __init__(self, cfg, now=None):
        allowed = Path(cfg['root']).resolve() / 'data/experiments/tabpfn_prototype'
        base = Path(cfg['state_dir']).resolve()
        if base == allowed or not base.is_relative_to(allowed): raise ValueError('Separate TabPFN store required')
        if cfg['dry_run'] is not True or cfg['enable_publication'] is not False:
            raise ValueError('TabPFN automatic processing is shadow-only')
        # A new store must be empty; an existing store must have this explicit marker.
        db = base / 'state.sqlite3'
        if db.exists() and (db.is_symlink() or db.stat().st_nlink != 1):
            raise ValueError('Unsafe shadow database alias')
        marker = base / 'tabpfn_shadow.json'
        expected = {'schema_version': 1, 'selected_model': 'tabpfn', 'publication_enabled': False}
        if base.exists() and any(base.iterdir()) and (not marker.is_file() or read(marker) != expected):
            raise ValueError('Not a marked TabPFN shadow store; existing state untouched')
        super().__init__(cfg, now=now)
        if not marker.exists():
            from .common import write
            write(marker, expected)
        self.db.execute('''CREATE TABLE IF NOT EXISTS tabpfn_jobs(
            id TEXT PRIMARY KEY, pinned TEXT NOT NULL, digest TEXT NOT NULL,
            capture TEXT, inference TEXT, alerts TEXT)''')
        self.context = None

    def command(self, *args, **kwargs):
        raise PermissionError('Shadow store cannot invoke the RF command runner')

    def release_prepared(self, *args, **kwargs):
        raise PermissionError('TabPFN sending remains disabled')

    def tick(self, selection):
        self.context = None  # At most one checkpoint restoration per polling process.
        before = {r[0] for r in self.db.execute('SELECT id FROM jobs')}
        if selection.model == 'tabpfn':
            starts, terminals = self.discover()
            fresh = [r for r in self.db.execute('SELECT * FROM jobs') if r['id'] not in before]
            # Pin before execution; no classifier restoration at discovery.
            with self.db:
                for row in fresh: self.pin(row, selection)
        else:
            # Selection changes affect admission only. Existing TabPFN jobs stay TabPFN.
            if not self.meta('armed_at') or self.meta('binding') != self.binding():
                raise ValueError('Initialize explicitly; completion binding must remain unchanged')
            starts, terminals = self.source_snapshot()
        # Recovery after a crash between base discovery and pinning is fail-closed.
        with self.db:
            for row in self.db.execute('SELECT * FROM jobs WHERE id NOT IN (SELECT id FROM tabpfn_jobs)').fetchall():
                self.update(row['id'], status='investigation_required', error='job_model_pin_missing')
        for row in self.db.execute("SELECT id FROM jobs WHERE status IN ('waiting','running','retry') ORDER BY id").fetchall():
            self.process_shadow(row['id'], starts, terminals)
        with self.db: self.log(None, 'shadow_poll', 'completed', 'publication_disabled')

    def pin(self, row, selection):
        info = artifacts.frozen(self.root)[2]
        value = {'selected_model': 'tabpfn', 'selection_source': selection.source,
                 'model_contract': info, 'completion_sha256': row['hash'],
                 'completion_source_binding': self.binding(), 'created_at': iso(self.clock())}
        self.db.execute('INSERT INTO tabpfn_jobs(id,pinned,digest) VALUES(?,?,?)',
                        (row['id'], json.dumps(value), digest(value)))
        self.update(row['id'], stage='capture')
        self.log(row['id'], 'model_selection', 'pinned_tabpfn')

    def windows(self, sid, value, starts, terminals):
        windows = []
        for other, start in starts.items():
            if other == sid or start['username'].casefold().split('\\')[-1] != value['username'].casefold().split('\\')[-1]: continue
            end = terminals.get(other, {}).get('end')
            if (timestamp(start['start']) <= timestamp(value['end']) + timedelta(seconds=4)
                    and (not end or timestamp(end) >= timestamp(value['start']) - timedelta(seconds=4))):
                raise ValueError('overlapping_or_unfinished_same_account_activity')
            if end and timestamp(end) + timedelta(seconds=2) <= self.clock():
                windows.append({'username': start['username'], 'start': start['start'], 'end': end})
        return windows

    def paths(self, sid):
        return dict(self.db.execute('SELECT * FROM tabpfn_jobs WHERE id=?', (sid,)).fetchone())

    def validate_stage(self, stage, path, job, value):
        if stage == 'capture':
            _, plan, _, _ = acquisition.verified_capture(self.root, path)
            if read(path / 'acquisition.json')['completion'] != value:
                raise ValueError('Completion source binding changed')
        elif stage == 'inference':
            result, plan, audit, source = new_session.verified_inference(self.root, path)
            if source != Path(self.paths(job['id'])['capture']) or result['job_id'] != job['id']:
                raise ValueError('Inference job identity changed')
            aliases = next(v for k, v in self.cfg['host_aliases'].items() if k.casefold() == value['host'].casefold())
            if not audit['accepted_behavior_hosts'] or not {h.casefold() for h in audit['accepted_behavior_hosts']} <= {h.casefold() for h in aliases}:
                raise ValueError('completion_host_mismatch')
        elif stage == 'alerts':
            _, plan, _, source = new_session.verified_inference(self.root, self.paths(job['id'])['inference'])
            from .common import sha
            hybrid_session.saved_alerts(self.root, path, plan, sha(source / 'retrieved_events.jsonl'))
            return None
        elif stage == 'hybrid':
            paths = self.paths(job['id'])
            result, _ = hybrid_session.reverify(self.root, paths['inference'], paths['alerts'])
            if read(path / 'hybrid_result.json') != result: raise ValueError('Hybrid evidence changed')
            return result
        else:
            publisher.verify_prepared(self.root, path)
            return None
        if (timestamp(plan['actual_start']) != timestamp(value['start']) or timestamp(plan['actual_end']) != timestamp(value['end'])
                or plan['username'].casefold() != value['username'].casefold()
                or timestamp(plan['prediction_cutoff']) != timestamp(value['end']) + timedelta(seconds=300)):
            raise ValueError('Completion interval/cutoff changed')
        return None

    def execute_stage(self, stage, out, job, value, windows):
        paths = self.paths(job['id'])
        if stage == 'capture':
            aliases = next(v for k, v in self.cfg['host_aliases'].items() if k.casefold() == value['host'].casefold())
            acquisition.capture(self.root, value, windows, aliases, out, self.clock())
        elif stage == 'inference':
            # Validate features/host before restoring expensive weights.
            from ..controlled_replay.new_session import extract_completed
            _, plan, _, _ = acquisition.verified_capture(self.root, paths['capture'])
            names = artifacts.frozen(self.root)[0]
            _, audit = extract_completed(Path(paths['capture']) / 'retrieved_events.jsonl', plan, names)
            aliases = {h.casefold() for h in read(Path(paths['capture']) / 'acquisition.json')['allowed_hosts']}
            if audit['status'] != 'eligible' or not audit['accepted_behavior_hosts'] or not {h.casefold() for h in audit['accepted_behavior_hosts']} <= aliases:
                raise ValueError('Fresh features or completion host unverified')
            if self.context is None: self.context = artifacts.restore(self.root)
            new_session.infer(self.root, paths['capture'], out, job['id'], model_context=self.context)
        elif stage == 'alerts': alert_capture.capture(self.root, paths['inference'], out)
        elif stage == 'hybrid': hybrid_session.run(self.root, paths['inference'], paths['alerts'], out)
        elif stage == 'prepare': publisher.prepare(self.root, job['hybrid'], out)
        else: raise ValueError('No TabPFN send stage exists')

    def process_shadow(self, sid, starts, terminals):
        job = dict(self.db.execute('SELECT * FROM jobs WHERE id=?', (sid,)).fetchone())
        value = json.loads(job['record'])
        try:
            pinned_row = self.paths(sid); pinned = json.loads(pinned_row['pinned'])
            if (job['stage'] not in STAGES or digest(pinned) != pinned_row['digest'] or pinned['selected_model'] != 'tabpfn'
                    or pinned['completion_source_binding'] != self.binding()
                    or pinned['completion_sha256'] != job['hash'] or digest(value) != job['hash']
                    or sid not in terminals or digest(terminals[sid]) != job['hash']):
                raise ValueError('Pinned model/completion integrity failed')
            if timestamp(value['end']) + timedelta(seconds=300) > self.clock(): return
            if job['next_at'] and timestamp(job['next_at']) > self.clock(): return
            windows = self.windows(sid, value, starts, terminals)
            if artifacts.frozen(self.root)[2] != pinned['model_contract']:
                raise ValueError('Pinned TabPFN model contract changed')
        except (ValueError, OSError, KeyError, TypeError):
            with self.db:
                self.update(sid, status='investigation_required', error='model_completion_or_overlap_verification_failed')
                self.log(sid, 'verification', 'investigation_required')
            return
        # Finish all ready stages in one poll; each stage commits independently.
        for stage in STAGES[STAGES.index(job['stage']):]:
            job = dict(self.db.execute('SELECT * FROM jobs WHERE id=?', (sid,)).fetchone())
            out = Path(job['path']) if job['path'] else self.base / 'jobs' / sid / (stage + '_' + str(job['attempt'] + 1))
            recovered = job['status'] == 'running' and (out / 'output_manifest.json').is_file()
            try:
                if not recovered:
                    if job['attempt'] >= self.cfg['max_attempts']: raise ValueError('Retry limit exhausted')
                    out = self.base / 'jobs' / sid / (stage + '_' + str(job['attempt'] + 1))
                    with self.db:
                        self.update(sid, status='running', attempt=job['attempt'] + 1, path=str(out), next_at=None)
                        self.log(sid, stage, 'attempt_started')
                    self.execute_stage(stage, out, job, value, windows)
                result = self.validate_stage(stage, out, job, value)
            except Exception as exc:
                # Never serialize arbitrary transport/model exception text or raw event contents.
                with self.db:
                    attempt = self.db.execute('SELECT attempt FROM jobs WHERE id=?', (sid,)).fetchone()[0]
                    self.update(sid, status='investigation_required' if attempt >= self.cfg['max_attempts'] else 'retry',
                                error=stage + ':' + type(exc).__name__,
                                next_at=iso(self.clock() + timedelta(seconds=self.cfg['retry_seconds'])), path=None)
                    if stage == 'alerts':
                        self.update(sid, result=json.dumps({'hybrid_priority': 'Evidence Unavailable',
                            'wazuh_detected': None, 'wazuh_evidence_verified': False, 'investigation_required': True}))
                    self.log(sid, stage, 'failed', type(exc).__name__)
                return
            with self.db:
                if stage in ('capture', 'inference', 'alerts'):
                    self.db.execute('UPDATE tabpfn_jobs SET ' + stage + '=? WHERE id=?', (str(out), sid))
                if stage == 'hybrid':
                    self.update(sid, hybrid=str(out), result=json.dumps(result))
                    if result.get('wazuh_evidence_verified') is not True:
                        self.update(sid, status='investigation_required', error='Evidence Unavailable; no negative inferred', path=None)
                        self.log(sid, stage, 'investigation_required')
                        return
                if stage == 'prepare':
                    self.update(sid, status='prepared_not_published', prepared=str(out), path=None, error=None, next_at=None)
                else:
                    self.update(sid, stage=STAGES[STAGES.index(stage) + 1], status='waiting', attempt=0, path=None, next_at=None, error=None)
                self.log(sid, stage, 'recovered' if recovered else 'completed', 'publication_disabled')
