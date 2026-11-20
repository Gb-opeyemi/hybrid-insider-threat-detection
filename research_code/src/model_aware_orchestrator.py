"""Separate selector-aware scheduler; legacy RF processing code stays unchanged."""
import json
from pathlib import Path
from .session_orchestrator import Orchestrator, config_file, digest, iso
from .model_selection import Selection
from .model_aware_publication import code_contract, send_verified, verify_delivery
from .tabpfn_prototype.common import read, sha
from .tabpfn_prototype.automatic import Shadow
from . import operational_timing as timing
from .timing_hooks import Hooks, rf_child_transport, timed_shadow_class


def configuration(path):
    value=read(path)
    required={'rf_config','connection','state_dir','tabpfn_state_dir','dry_run','enable_publication','legacy_label'}
    if set(value)!=required:raise ValueError('Unexpected model-aware configuration fields')
    cfg=config_file(value['rf_config']);root=Path(cfg['root'])
    if cfg.get('completion_source')!='wazuh':raise ValueError('Use the verified Wazuh completion feed')
    state=Path(value['state_dir']).resolve();tab=Path(value['tabpfn_state_dir']).resolve();old=Path(cfg['state_dir']).resolve()
    allowed=root/'data/experiments/operational_service/model_aware'
    if state==allowed or not state.is_relative_to(allowed) or state==old or state.is_relative_to(old) or old.is_relative_to(state):
        raise ValueError('A new, isolated model-aware router store is required')
    if not tab.is_relative_to(root/'data/experiments/tabpfn_prototype/model_aware'):
        raise ValueError('Separate TabPFN model-aware worker store required')
    for path in (state/'state.sqlite3',tab/'state.sqlite3'):
        if path.exists() and (path.is_symlink() or path.stat().st_nlink!=1):raise ValueError('Unsafe database alias')
    for key in ('dry_run','enable_publication'):
        if type(value[key]) is not bool:raise ValueError('Explicit boolean publication settings required')
    if value['dry_run'] and value['enable_publication']:raise ValueError('Dry-run cannot publish')
    if value['legacy_label']!='org.thesis.hybrid-sessions':raise ValueError('Pin the original LaunchAgent label')
    cfg.update(state_dir=str(state),dry_run=value['dry_run'],enable_publication=value['enable_publication'])
    return cfg,tab,Path(value['connection']),value['legacy_label']


def model_contract(root,model):
    if model=='tabpfn':
        from .tabpfn_prototype.artifacts import frozen
        return frozen(root)[2]
    if model!='random_forest':raise ValueError('Unsupported selected model')
    from .controlled_replay.app import PILOT
    pilot=Path(root)/PILOT;manifest=read(pilot/'run_manifest.json')
    names=('training_median_imputer.joblib','imputation_verification.json','model_verification.json')
    values={name:sha(pilot/name) for name in names}
    if any(manifest['artifacts_sha256'][name]!=values[name] for name in names):raise ValueError('Frozen RF preprocessing changed')
    model_sha=sha(Path(root)/'models/random_forest_baseline.joblib')
    if model_sha!=read(pilot/'model_verification.json')['rf_sha256']:raise ValueError('RF model changed')
    return {'selected_model':model,'model_sha256':model_sha,'frozen_preprocessing_sha256':values}


class Router(Orchestrator):
    def __init__(self,cfg,tab_state,now=None):
        self.worker=None;self.tab_state=Path(tab_state)
        base=Path(cfg['state_dir']).resolve();allowed=Path(cfg['root']).resolve()/'data/experiments/operational_service/model_aware'
        if base==allowed or not base.is_relative_to(allowed):raise ValueError('Use isolated router state')
        marker=base/'model_aware.json'
        expected={'schema_version':1,'service':'model_aware'}
        if base.exists() and any(base.iterdir()) and (not marker.is_file() or read(marker)!=expected):
            raise ValueError('Do not adopt an existing operational database')
        super().__init__(cfg,now=now,runner=self.command)
        if not marker.exists():
            from .tabpfn_prototype.common import write
            write(marker,expected)
        self.db.execute('CREATE TABLE IF NOT EXISTS routes(id TEXT PRIMARY KEY,pinned TEXT,digest TEXT)')

    def close(self):
        if self.worker:self.worker.close()
        super().close()

    def route(self,sid):
        row=self.db.execute('SELECT * FROM routes WHERE id=?',(sid,)).fetchone()
        if row is None:raise ValueError('Missing pinned model route')
        value=json.loads(row['pinned'])
        if digest(value)!=row['digest'] or value['selected_model'] not in {'random_forest','tabpfn'}:
            raise ValueError('Corrupt model route')
        return value

    def tick_selected(self,selection):
        before={r[0] for r in self.db.execute('SELECT id FROM jobs')}
        # Contract is checked before admission. Failure cannot silently pin RF.
        contract=model_contract(self.root,selection.model)
        starts,terminals=self.discover()
        with self.db:
            for row in self.db.execute('SELECT * FROM jobs').fetchall():
                if row['id'] in before:continue
                value={'selected_model':selection.model,'selection_source':selection.source,'created_at':iso(self.clock()),
                       'completion_sha256':row['hash'],'binding':self.binding(),'model_contract':contract,
                       'code_sha256':code_contract(self.root)}
                self.db.execute('INSERT INTO routes VALUES(?,?,?)',(row['id'],json.dumps(value),digest(value)))
                if selection.model=='tabpfn':self.update(row['id'],stage='tabpfn')
                self.log(row['id'],'model_selection','pinned_'+selection.model)
                timing.start_job(self.base,json.loads(row['record']),selection.model,row['status'],row['error'])
        for row in self.db.execute("SELECT * FROM jobs WHERE status IN ('waiting','running','retry') ORDER BY id").fetchall():
            recorder=timing.collector_for(self.base,row['id'])
            if recorder is None:
                self.process_routed(row,starts,terminals)
            else:
                with recorder.installed(active=True): self.process_routed(row,starts,terminals)
                current=self.db.execute('SELECT * FROM jobs WHERE id=?',(row['id'],)).fetchone()
                timing.finish(self.base,row['id'],current)
        with self.db:self.log(None,'model_aware_poll','completed')

    def process_routed(self,row,starts,terminals):
        try:
            pinned=self.route(row['id'])
            if (pinned['completion_sha256']!=row['hash'] or digest(json.loads(row['record']))!=row['hash']
                    or pinned['binding']!=self.binding() or pinned['code_sha256']!=code_contract(self.root)
                    or pinned['model_contract']!=model_contract(self.root,pinned['selected_model'])):
                raise ValueError('Pinned model/completion contract changed')
            if row['id'] not in terminals or digest(terminals[row['id']])!=row['hash']:raise ValueError('Completion changed')
            if pinned['selected_model']=='random_forest' or row['stage']=='send':
                super().process(row['id'],starts,terminals)
            else:self.process_tabpfn(row,starts,terminals,pinned)
        except (ValueError,OSError,KeyError,TypeError) as exc:
            with self.db:
                self.update(row['id'],status='investigation_required',error='routing_verification:'+type(exc).__name__)
                self.log(row['id'],'routing','investigation_required',type(exc).__name__)

    def process_tabpfn(self,row,starts,terminals,pinned):
        if self.worker is None:
            cfg={**self.cfg,'state_dir':str(self.tab_state),'dry_run':True,'enable_publication':False}
            worker_class=timed_shadow_class() if timing.CURRENT.get() is not None else Shadow
            self.worker=worker_class(cfg,now=self.clock)
            if not self.worker.meta('armed_at'):
                with self.worker.db:
                    for key,value in [('armed_at',self.meta('armed_at')),('binding',self.worker.binding()),('baseline_ids','[]')]:
                        self.worker.db.execute('INSERT INTO meta VALUES(?,?)',(key,value))
        old=self.worker.db.execute('SELECT * FROM jobs WHERE id=?',(row['id'],)).fetchone()
        if old is None:
            with self.worker.db:
                self.worker.db.execute('INSERT INTO jobs(id,record,hash,status) VALUES(?,?,?,?)',
                    (row['id'],row['record'],row['hash'],'waiting'))
                self.worker.pin(row,Selection('tabpfn',pinned['selection_source']))
        elif old['hash']!=row['hash']:raise ValueError('Worker completion changed')
        current=self.worker.db.execute('SELECT * FROM jobs WHERE id=?',(row['id'],)).fetchone()
        if current['status'] in {'waiting','running','retry'}:
            if timing.CURRENT.get() is None:self.worker.process_shadow(row['id'],starts,terminals)
            else:
                with Hooks() as hooks:
                    if self.worker.context is not None:hooks.model(self.worker.context[3])
                    self.worker.process_shadow(row['id'],starts,terminals)
        current=self.worker.db.execute('SELECT * FROM jobs WHERE id=?',(row['id'],)).fetchone()
        with self.db:
            if current['status']=='prepared_not_published':
                self.update(row['id'],prepared=current['prepared'],hybrid=current['hybrid'],result=current['result'],
                            stage='send',attempt=0,path=None,next_at=None,error=None,status='waiting')
            else:
                self.update(row['id'],status=current['status'],error=current['error'],result=current['result'])

    def command(self,stage,value,out,job,windows):
        recorder=timing.CURRENT.get()
        if recorder is not None:
            with recorder.work(stage,out):
                if stage!='send':
                    with rf_child_transport(stage,out): return super().command(stage,value,out,job,windows)
                with Hooks(): return self.publish_command(stage,value,out,job,windows)
        if stage!='send':return super().command(stage,value,out,job,windows)
        return self.publish_command(stage,value,out,job,windows)

    def publish_command(self,stage,value,out,job,windows):
        selected=self.route(value['session_id'])['selected_model']
        try:
            send_verified(self.root,job['prepared'],selected,value['session_id'],self.cfg['ssh_host'],out,
                          enabled=self.cfg['enable_publication'] and not self.cfg['dry_run'],completion=value)
        except (ValueError,OSError,KeyError,TypeError):return 2
        return 0

    def outcome(self,stage,out,value):
        recorder=timing.CURRENT.get()
        if recorder is not None:
            with recorder.work('verification',out):return self.stage_outcome(stage,out,value)
        return self.stage_outcome(stage,out,value)

    def stage_outcome(self,stage,out,value):
        if stage=='send':
            row=self.db.execute('SELECT * FROM jobs WHERE id=?',(value['session_id'],)).fetchone()
            verify_delivery(self.root,out,row['prepared'],self.route(value['session_id'])['selected_model'],value['session_id'],completion=value)
            return 'ok',''
        return super().outcome(stage,out,value)
