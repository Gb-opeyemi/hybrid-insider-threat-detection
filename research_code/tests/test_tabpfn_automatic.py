"""Shadow discovery and end-to-end contracts. Synthetic clients; no live access."""
import copy
from contextlib import ExitStack, redirect_stdout
from datetime import timedelta
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch
import numpy as np
import test_features as fixture
from reproduction_fixtures import mapping, page
from test_new_session import NAMES
from test_session_orchestrator import Harness
from src.model_selection import Selection
from src.session_orchestrator import iso, timestamp
from src.controlled_replay.indexer import IndexerClient
from src.controlled_replay.hybrid_session import RULE_FILES
from src.tabpfn_prototype import acquisition, alert_capture, new_session, publisher
from src.tabpfn_prototype.automatic import Shadow, configuration
from src.tabpfn_shadow_service import connection_environment, main

TAB = Selection('tabpfn', 'environment'); RF = Selection('random_forest', 'environment')


class ArchiveClient(IndexerClient):
    def __init__(self, rows):
        self.rows = rows; self.calls = []; self.pattern = 'wazuh-archives-*'; self.tls_profile = 'strict'; self.page_size = 1000
        self.audit = {}
    def request(self, method, path, body=None):
        self.calls.append((method,path,body))
        if method == 'GET': return mapping()
        if path.endswith('/_count'): return {'count':0,'_shards':{'failed':0,'total':1}}
        if method == 'DELETE': return {}
        hits = [{'_index':'wazuh-archives-synthetic','_id':str(i),'_source':e} for i,e in enumerate(self.rows)]
        return page([] if path == '/_search/scroll' else hits, total=len(hits))


class AlertClient:
    pattern = 'wazuh-alerts-*'; tls_profile = 'strict'
    def __init__(self, rows): self.rows=rows; self.calls=[]
    def request(self, method, path, body=None):
        self.calls.append((method,path,body))
        if method == 'GET':
            data = mapping(); next(iter(data.values()))['mappings']['properties']['rule']={'properties':{'id':{'type':'keyword'}}}
            return data
        if method == 'DELETE': return {}
        return page([{'_index':'wazuh-alerts-synthetic','_id':str(i),'_source':e} for i,e in enumerate(self.rows)], total=len(self.rows))


class AutomaticTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.h=Harness(self.tmp.name); self.h.service.close()
        self.rf_state=Path(self.h.cfg['state_dir'])/'state.sqlite3'; self.before=self.rf_state.read_bytes()
        self.cfg={**self.h.cfg,'state_dir':str(self.h.root/'data/experiments/tabpfn_prototype/shadow')}
        self.service=Shadow(self.cfg, now=lambda:self.h.now); self.addCleanup(lambda:self.service.close())
        self.service.initialize(); self.calls=[]; self.failure=None; self.unknown=False
        self.info={'model':'TabPFN','selected_model':'tabpfn','model_artifact':'models/tabpfn_baseline.tabpfn_fit',
                   'model_sha256':'1'*64,'checkpoint_sha256':'2'*64}
        self.stack=ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch('src.tabpfn_prototype.artifacts.frozen', return_value=(NAMES,None,self.info,None)))
        self.stack.enter_context(patch.object(self.service,'execute_stage',side_effect=self.execute))
        self.stack.enter_context(patch.object(self.service,'validate_stage',side_effect=self.validate))
    def execute(self, stage, out, job, value, windows):
        self.calls.append((stage,value['end'])); out.mkdir(parents=True)
        if self.failure == stage: raise OSError('DO_NOT_LOG')
        (out/'output_manifest.json').write_text('{}')
    def validate(self, stage, out, job, value):
        if self.failure == stage: raise ValueError('bad saved stage')
        if stage == 'hybrid':
            return {'wazuh_evidence_verified':not self.unknown, 'wazuh_detected':None if self.unknown else 1,
                    'hybrid_priority':'Evidence Unavailable' if self.unknown else 'High Priority',
                    'telemetry_completeness':{'status':'unverified','review_required':True}}
    def ready(self):
        value=self.h.add(); self.h.advance(); return value
    def job(self, value): return dict(self.service.db.execute('SELECT * FROM jobs WHERE id=?',(value['session_id'],)).fetchone())
    def test_complete_discovery_shadow_only_and_rf_state_unchanged(self):
        value=self.ready(); self.service.tick(TAB); self.service.tick(TAB)
        self.assertEqual(self.job(value)['status'],'prepared_not_published')
        self.assertEqual([c[0] for c in self.calls],['capture','inference','alerts','hybrid','prepare'])
        self.assertIsNone(self.job(value)['rf']); self.assertIsNone(self.job(value)['ack'])
        self.assertEqual(self.rf_state.read_bytes(),self.before)
        self.assertEqual(self.service.db.execute('SELECT count(*) FROM jobs').fetchone()[0],1)
        self.assertIn('unverified',self.job(value)['result'])
        with self.assertRaises(PermissionError):self.service.release_prepared()
        with self.assertRaises(PermissionError):self.service.command('send')
    def test_cutoff_exact_and_late_poll_keeps_original_end(self):
        value=self.h.add(); self.h.advance(310); self.service.tick(TAB); self.assertEqual(self.calls,[])
        self.h.advance(1); self.service.tick(TAB); self.assertEqual(len(self.calls),5)
        self.assertTrue(all(end==value['end'] for _,end in self.calls))
    def test_failed_started_and_historical_do_not_run(self):
        self.h.add('Started'); failed=self.h.add('Failed',offset=30); self.h.add(offset=-500)
        self.h.advance(); self.service.tick(TAB)
        self.assertEqual(self.calls,[]); self.assertEqual(self.job(failed)['status'],'failed_execution')
    def test_missing_start_and_conflicting_lifecycle_block(self):
        value=self.ready(); start=self.h.feed/(value['session_id']+'.started.json'); start.unlink()
        with self.assertRaises(ValueError):self.service.tick(TAB)
        self.assertEqual(self.calls,[])
    def test_duplicate_interval_and_overlapping_activity_cannot_predict(self):
        a=self.h.add(); self.h.add(); self.h.advance(); self.service.tick(TAB)
        self.assertIn('duplicate_session',[r[0] for r in self.service.db.execute('SELECT status FROM jobs')])
        self.assertEqual(self.calls,[])
    def test_bounded_query_retries_preserve_unknown(self):
        self.failure='alerts'; value=self.ready()
        for _ in range(10): self.service.tick(TAB); self.h.advance(2)
        self.assertEqual(self.job(value)['status'],'investigation_required')
        self.assertEqual([c[0] for c in self.calls].count('inference'),1)
        self.assertEqual([c[0] for c in self.calls].count('alerts'),3)
        self.assertIn('Evidence Unavailable',self.job(value)['result'])
        self.assertNotIn('DO_NOT_LOG',str([tuple(r) for r in self.service.db.execute('SELECT * FROM events')]))
    def test_verified_empty_evidence_is_terminal_not_negative(self):
        self.unknown=True; value=self.ready(); self.service.tick(TAB); self.service.tick(TAB)
        self.assertEqual(self.job(value)['status'],'investigation_required')
        self.assertIsNone(json.loads(self.job(value)['result'])['wazuh_detected'])
        self.assertNotIn('prepare',[c[0] for c in self.calls])
    def test_restart_and_environment_switch_resume_pinned_tabpfn(self):
        self.failure='alerts'; value=self.ready(); self.service.tick(TAB)
        self.service.close(); self.service=Shadow(self.cfg,now=lambda:self.h.now)
        self.service.execute_stage=self.execute; self.service.validate_stage=self.validate
        self.failure=None; self.h.advance(2); self.service.tick(RF)
        self.assertEqual(self.job(value)['status'],'prepared_not_published')
        self.assertEqual([c[0] for c in self.calls].count('inference'),1)
        pin=json.loads(self.service.paths(value['session_id'])['pinned']); self.assertEqual(pin['selected_model'],'tabpfn')
        self.h.add(offset=100); self.h.advance(); self.service.tick(RF)
        self.assertEqual(self.service.db.execute('SELECT count(*) FROM jobs').fetchone()[0],1)
    def test_sealed_attempt_recovers_without_reprediction(self):
        value=self.ready(); self.service.tick(TAB); row=self.job(value)
        inference=self.service.paths(value['session_id'])['inference']
        with self.service.db:self.service.update(value['session_id'],stage='inference',status='running',attempt=1,path=inference)
        self.service.tick(TAB)
        self.assertEqual([c[0] for c in self.calls].count('inference'),1)
    def test_changed_pin_or_completion_never_falls_back(self):
        value=self.h.add(); self.h.advance(100); self.service.tick(TAB)
        with self.service.db:self.service.db.execute('UPDATE tabpfn_jobs SET digest=?',('bad',))
        self.h.advance(); self.service.tick(TAB)
        self.assertEqual(self.calls,[]); self.assertEqual(self.job(value)['status'],'investigation_required')
    def test_changed_verified_lifecycle_stops_existing_job(self):
        value=self.h.add(); self.h.advance(100); self.service.tick(TAB)
        value['end']=iso(timestamp(value['end'])+timedelta(seconds=1))
        self.h.write(self.h.feed/(value['session_id']+'.terminal.json'),value)
        self.h.advance(); self.service.tick(TAB); self.assertEqual(self.calls,[])
        self.assertEqual(self.job(value)['status'],'investigation_required')
    def test_unmarked_or_rf_store_rejected(self):
        with self.assertRaises(ValueError): Shadow(self.h.cfg)
        other=Path(self.cfg['state_dir']).parent/'foreign'; other.mkdir();(other/'state.sqlite3').write_bytes(b'foreign')
        with self.assertRaises(ValueError):Shadow({**self.cfg,'state_dir':str(other)})
        self.assertEqual((other/'state.sqlite3').read_bytes(),b'foreign')
    def test_model_failure_has_no_rf_fallback(self):
        self.failure='inference'; value=self.ready()
        for _ in range(6):self.service.tick(TAB);self.h.advance(2)
        self.assertEqual(self.job(value)['status'],'investigation_required')
        self.assertEqual([c[0] for c in self.calls],['capture','inference','inference','inference'])
    def test_publication_flags_rejected(self):
        with self.assertRaises(ValueError): Shadow({**self.cfg,'dry_run':False,'enable_publication':True})


class FreshAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve(); (self.root/'config').mkdir()
        (self.root/'config/experiment.json').write_text(json.dumps({'end_date':'2025-12-30'}))
        self.now=timestamp('2026-01-01T10:10:00Z')
        self.completion={'schema_version':1,'feed_id':'00000000-0000-0000-0000-000000000001',
            'session_id':'00000000-0000-0000-0000-000000000002','username':'EXAMPLE\\example.user','host':'SOURCE',
            'status':'Completed','start':'2026-01-01T10:00:00Z','end':'2026-01-01T10:01:00Z'}
        self.base=self.root/'data/experiments/tabpfn_prototype/fresh'
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        for module in (acquisition,new_session,alert_capture,__import__('src.tabpfn_prototype.hybrid_session',fromlist=['_']),publisher):
            self.stack.enter_context(patch.object(module,'code_hashes',return_value={'synthetic':'hash'}))
        self.event=fixture.event();self.event['rule']={'id':'100100','level':5}
    def capture(self,rows=None):
        client=ArchiveClient(rows if rows is not None else [self.event])
        acquisition.capture(self.root,self.completion,[],['host.example.invalid'],self.base,self.now,client)
        return client
    def test_fresh_capture_query_cutoff_context_and_integrity(self):
        client=self.capture(); _,plan,original,_=acquisition.verified_capture(self.root,self.base)
        self.assertIsNone(original); self.assertEqual(plan['prediction_cutoff'],'2026-01-01T10:06:00Z')
        self.assertEqual(plan['observation_end'],'2026-01-01T10:01:02Z')
        audit=json.loads((self.base/'retrieval_audit.json').read_text());self.assertEqual(audit['retrieved_documents'],1)
        with (self.base/'retrieved_events.jsonl').open('a') as h:h.write('{}\n')
        with self.assertRaises(ValueError):acquisition.verified_capture(self.root,self.base)
    def test_no_network_before_cutoff_or_for_failed_execution(self):
        client=Mock()
        for status,now in [('Completed',timestamp('2026-01-01T10:05:59Z')),('Failed',self.now)]:
            with self.assertRaises(ValueError):acquisition.capture(self.root,{**self.completion,'status':status},[],['host'],self.base,now,client)
        client.capture.assert_not_called()
    def test_future_receipt_rejected_not_included_by_late_retry(self):
        self.event['timestamp']='2026-01-01T10:06:00.000001Z'
        with self.assertRaises(ValueError):self.capture()
    def model(self):
        imputer=SimpleNamespace(transform=lambda frame:frame.fillna(0).to_numpy())
        info={'model':'TabPFN','selected_model':'tabpfn','model_artifact':'models/tabpfn_baseline.tabpfn_fit',
              'model_sha256':'1'*64,'checkpoint_sha256':'2'*64}
        model=Mock();model.predict.return_value=np.array([1]);model.predict_proba.return_value=np.array([[.1,.9]])
        self.stack.enter_context(patch('src.tabpfn_prototype.artifacts.frozen',return_value=(NAMES,imputer,info,None)))
        self.stack.enter_context(patch('src.tabpfn_prototype.artifacts.restore',return_value=(NAMES,imputer,info,model)))
        self.stack.enter_context(patch('src.tabpfn_prototype.artifacts.no_downloads'))
        return model
    def test_full_fresh_shadow_pipeline_dedup_attribution_hybrid_and_prepare(self):
        other=fixture.event(record='other');other['data']['win']['eventdata']['subjectUserName']='someone.else'
        self.capture([self.event,self.event,other]);model=self.model()
        run=self.base.parent/'inference'; prediction=new_session.infer(self.root,self.base,run,self.completion['session_id'])
        self.assertEqual(prediction['source'],'fresh_authenticated_wazuh_archives')
        self.assertEqual(prediction['model_inputs']['windows_event_count'],1)
        self.assertEqual(new_session.verified_inference(self.root,run)[0],prediction);model.fit.assert_not_called()
        rules=self.root/'data/wazuh/etc/rules';rules.mkdir(parents=True)
        for name in RULE_FILES:(rules/name).write_text('synthetic frozen rule fixture')
        alerts=self.base.parent/'alerts';alert_capture.capture(self.root,run,alerts,AlertClient([self.event]))
        from src.tabpfn_prototype import hybrid_session
        hybrid=self.base.parent/'hybrid';result=hybrid_session.run(self.root,run,alerts,hybrid)
        self.assertEqual(result['hybrid_priority'],'High Priority');self.assertEqual(result['matched_wazuh_rule_ids'],['100100'])
        self.assertEqual(result['telemetry_completeness']['status'],'potentially_incomplete')
        prepared=self.base.parent/'prepared';publisher.prepare(self.root,hybrid,prepared)
        self.assertEqual(publisher.verify_prepared(self.root,prepared)['model'],'TabPFN')
        with self.assertRaises(PermissionError):publisher.send(prepared)
    def test_wrong_host_rejected_before_prediction(self):
        self.capture();self.model()
        # Genuine metadata mismatch at acquisition: a verified host alias is required.
        original=new_session.read
        with patch('src.tabpfn_prototype.new_session.read', wraps=original) as reader:
            reader.side_effect=lambda p: {**original(p),'allowed_hosts':['wrong.invalid']} if Path(p).name=='acquisition.json' else original(p)
            with self.assertRaises(ValueError):new_session.infer(self.root,self.base,self.base.parent/'wrong',self.completion['session_id'])

    def test_real_shadow_stage_chain_restores_once_for_two_users(self):
        from src.tabpfn_prototype import hybrid_session
        from src.tabpfn_prototype.common import write
        feed=self.root/'feed';feed.mkdir()
        write(feed/'feed.json',{'schema_version':1,'feed_id':self.completion['feed_id']})
        second={**self.completion,'session_id':'00000000-0000-0000-0000-000000000003','username':'EXAMPLE\\another.user'}
        for value in (self.completion,second):
            write(feed/(value['session_id']+'.started.json'),{**value,'status':'Started','end':None})
            write(feed/(value['session_id']+'.terminal.json'),value)
        other=copy.deepcopy(self.event);other['data']['win']['eventdata']['subjectUserName']='another.user'
        other['data']['win']['system']['eventRecordID']='2';other['id']='other'
        rules=self.root/'data/wazuh/etc/rules';rules.mkdir(parents=True)
        for name in RULE_FILES:(rules/name).write_text('synthetic')
        self.model()
        cfg={'root':str(self.root),'feed_id':self.completion['feed_id'],'feed_dir':str(feed),
             'state_dir':str(self.root/'data/experiments/tabpfn_prototype/poll'),
             'dry_run':True,'enable_publication':False,'ssh_host':'unused',
             'host_aliases':{'SOURCE':['host.example.invalid']},'max_attempts':3,'retry_seconds':1}
        clock=[timestamp('2026-01-01T09:59:00Z')]
        service=Shadow(cfg,now=lambda:clock[0])
        try:
            # Directory fixtures are baseline-snapshotted: arm before adding lifecycle records.
            for path in feed.glob('*.started.json'):path.rename(path.with_suffix('.saved'))
            for path in feed.glob('*.terminal.json'):path.rename(path.with_suffix('.saved'))
            service.initialize()
            for path in feed.glob('*.saved'):path.rename(path.with_suffix('.json'))
            clock[0]=self.now
            with patch('src.tabpfn_prototype.acquisition.client_from_environment',side_effect=lambda:ArchiveClient([self.event,other])), \
                    patch('src.tabpfn_prototype.alert_capture.AlertClient',side_effect=lambda *a,**k:AlertClient([self.event,other])), \
                    patch.dict(os.environ,{'WAZUH_INDEXER_URL':'unused','WAZUH_ALERT_INDEX_PATTERN':'wazuh-alerts-*',
                        'WAZUH_INDEXER_USERNAME':'synthetic','WAZUH_INDEXER_PASSWORD':'synthetic','WAZUH_INDEXER_CA_CERT':'unused'}):
                service.tick(TAB)
                states=[r[0] for r in service.db.execute('SELECT status FROM jobs')]
                self.assertEqual(states,['prepared_not_published']*2)
                from src.tabpfn_prototype.artifacts import restore
                self.assertEqual(restore.call_count,1)
                service.tick(TAB);self.assertEqual(restore.call_count,1)
        finally:service.close()


class WazuhShadowFeedTests(unittest.TestCase):
    def test_shadow_reuses_authenticated_feed_schema_and_durable_audit(self):
        from test_wazuh_completion_feed import FeedTests, Client
        h=FeedTests();h.setUp()
        shadow=None
        try:
            h.now-=timedelta(seconds=400)
            cfg={**h.cfg,'state_dir':str(h.root/'data/experiments/tabpfn_prototype/wazuh_shadow')}
            shadow=Shadow(cfg,now=lambda:h.now);shadow.initialize();h.now+=timedelta(seconds=400)
            hits=[h.hit(),h.hit('completed')]
            with patch('src.wazuh_completion_feed.client_from_environment',return_value=Client(hits)), \
                    patch('src.tabpfn_prototype.artifacts.frozen',return_value=([],None,{'synthetic':'contract'},None)), \
                    patch.object(shadow,'process_shadow') as processing:
                shadow.tick(TAB)
                processing.assert_called_once()
            self.assertEqual(shadow.db.execute('SELECT count(*) FROM completion_documents').fetchone()[0],2)
            self.assertEqual(shadow.db.execute('SELECT count(*) FROM completion_queries').fetchone()[0],1)
            self.assertEqual(h.service.db.execute('SELECT count(*) FROM jobs').fetchone()[0],0)
            bad=h.hit('completed');bad['_source']['agent']['id']='999'
            with patch('src.wazuh_completion_feed.client_from_environment',return_value=Client([bad])):
                with self.assertRaises(ValueError):shadow.tick(TAB)
        finally:
            if shadow:shadow.close()
            h.tearDown()


class CredentialsAndDispatchTests(unittest.TestCase):
    def test_keychain_values_are_scoped_and_never_printed(self):
        from src.operational_session_service import ALLOWED
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'connection.json';path.write_text(json.dumps({'environment':{key:'configured' for key in ALLOWED},'keychain_service':'existing-test-service'}))
            output=io.StringIO()
            with patch.dict(os.environ,{},clear=True),patch('src.tabpfn_shadow_service.subprocess.run',return_value=SimpleNamespace(stdout='SECRET\n')) as run,redirect_stdout(output):
                with connection_environment(path):self.assertEqual(os.environ['WAZUH_INDEXER_PASSWORD'],'SECRET')
                self.assertNotIn('WAZUH_INDEXER_PASSWORD',os.environ)
                self.assertEqual(run.call_count,2)
            self.assertNotIn('SECRET',output.getvalue())
    def test_auto_dispatch_uses_new_interface_only(self):
        from src.hybrid_prototype import main as dispatch
        with patch('src.tabpfn_shadow_service.main',return_value=0) as shadow:
            self.assertEqual(dispatch(['auto','--config','local.json','status']),0)
            shadow.assert_called_once_with(['--config','local.json','status'])
