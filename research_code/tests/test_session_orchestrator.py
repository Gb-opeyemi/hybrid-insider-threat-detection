"""Synthetic orchestration tests. No indexer, model loading, SSH or real events."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from src.session_orchestrator import Orchestrator, iso, read, feed_snapshot, config_file


class Harness:
    def __init__(self, root):
        self.root=Path(root); self.now=datetime(2030,1,1,tzinfo=timezone.utc)
        self.feed=self.root/'feed'; self.feed.mkdir()
        self.feed_id=str(uuid4()); self.write(self.feed/'feed.json',{'schema_version':1,'feed_id':self.feed_id})
        self.cfg=dict(root=str(self.root),feed_dir=str(self.feed),feed_id=self.feed_id,
          state_dir=str(self.root/'data/experiments/operational_service/test'),dry_run=True,enable_publication=False,
          ssh_host='thesis-ml-manager',host_aliases={'SOURCE':['source.example.invalid']},max_attempts=3,retry_seconds=1)
        self.calls=[]; self.failure=None; self.unknown=False; self.host='source.example.invalid'
        self.service=Orchestrator(self.cfg,lambda:self.now,self.run)
    @staticmethod
    def write(path,value): path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(value))
    def add(self, status='Completed', sid=None, offset=1):
        v=dict(schema_version=1,feed_id=self.feed_id,session_id=sid or str(uuid4()),username='EXAMPLE\\user',host='SOURCE',
               start=iso(self.now+timedelta(seconds=offset)),end=None,status='Started')
        self.write(self.feed/(v['session_id']+'.started.json'),v)
        if status!='Started':
            v={**v,'end':iso(self.now+timedelta(seconds=offset+10)),'status':status}
            self.write(self.feed/(v['session_id']+'.terminal.json'),v)
        return v
    def run(self,stage,v,out,job,windows):
        self.calls.append(stage); out.mkdir(parents=True)
        if self.failure==stage: return
        if stage=='rf':
            self.write(out/'run_status.json',{'status':'completed'})
            self.write(out/'request.json',{'prediction_cutoff':iso(datetime.fromisoformat(v['end'].replace('Z','+00:00'))+timedelta(seconds=300)),
                'actual_start':v['start'],'actual_end':v['end'],'username':v['username'].casefold(),'availability_delay_seconds':300})
            self.write(out/'validation.json',{'status':'eligible','accepted_behavior_hosts':[self.host],
                'telemetry_completeness':{'status':'unverified','review_required':True}})
        elif stage=='hybrid':
            self.write(out/'hybrid_result.json',{'wazuh_evidence_verified':not self.unknown,
              'wazuh_evidence_status':'unavailable' if self.unknown else 'verified_positive',
              'hybrid_priority':'Evidence Unavailable' if self.unknown else 'High Priority',
              'telemetry_completeness_status':'unverified','telemetry_review_required':True,'unresolved_alert_count':1})
            self.write(out/'alert_retrieval_audit.json',{'status':'query_verified'})
        elif stage=='prepare': self.write(out/'receipt.json',{'status':'prepared_locally'})
        else: self.write(out/'receipt.json',{'status':'acknowledged','remote_submissions':[{'status':'written'}]})
    def advance(self,seconds=400): self.now+=timedelta(seconds=seconds)
    def ticks(self,n=5):
        for _ in range(n): self.service.tick(); self.advance(2)
    def job(self,sid): return dict(self.service.db.execute('SELECT * FROM jobs WHERE id=?',(sid,)).fetchone())
    def restart(self):
        self.service.close(); self.service=Orchestrator(self.cfg,lambda:self.now,self.run)


class OrchestratorTests(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.TemporaryDirectory(); self.h=Harness(self.tmp.name)
    def tearDown(self): self.h.service.close(); self.tmp.cleanup()
    def ready(self):
        self.h.service.initialize(); v=self.h.add(); self.h.advance(); return v
    def test_initialization_is_mandatory(self):
        with self.assertRaises(ValueError): self.h.service.tick()
    def test_five_minute_delay_and_fixed_cutoff(self):
        self.h.service.initialize(); v=self.h.add(); self.h.advance(310)
        self.h.service.tick(); self.assertEqual(self.h.calls,[])
        self.h.advance(1); self.h.service.tick(); self.assertEqual(self.h.calls,['rf'])
        request=read(Path(self.h.job(v['session_id'])['rf'])/'request.json')
        self.assertEqual(request['prediction_cutoff'],'2030-01-01T00:05:11Z')
    def test_dry_run_preserves_warning_and_never_sends(self):
        v=self.ready(); self.h.ticks()
        job=self.h.job(v['session_id']); self.assertEqual(job['status'],'prepared_not_published')
        self.assertNotIn('send',self.h.calls); self.assertTrue(json.loads(job['result'])['telemetry_review_required'])
    def test_enabled_publication_ack_and_duplicate_poll(self):
        self.h.cfg.update(dry_run=False,enable_publication=True)
        v=self.ready(); self.h.ticks(); self.h.ticks()
        job=self.h.job(v['session_id']); self.assertEqual(job['status'],'published')
        self.assertEqual(self.h.calls,['rf','hybrid','prepare','send']); self.assertIn('written',job['ack'])
    def test_start_only_is_not_completion_and_failed_is_not_processed(self):
        self.h.service.initialize(); self.h.add('Started'); v=self.h.add('Failed'); self.h.advance(); self.h.ticks()
        self.assertEqual(self.h.calls,[]); self.assertEqual(self.h.job(v['session_id'])['status'],'failed_execution')
    def test_historical_and_existing_demonstrations_not_backfilled(self):
        old=self.h.add(); self.h.service.initialize(); self.h.advance(); self.h.ticks()
        self.assertEqual(self.h.calls,[]); self.assertEqual(self.h.service.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],0)
        late=self.h.add(offset=-500); self.h.ticks(); self.assertEqual(self.h.calls,[])
    def test_forged_or_partial_record_rejected(self):
        self.h.service.initialize(); v=self.h.add()
        (self.h.feed/(v['session_id']+'.started.json')).unlink()
        with self.assertRaises(ValueError): self.h.service.tick()
    def test_changed_completion_stops_job(self):
        v=self.ready(); self.h.service.tick(); v['host']='OTHER'
        self.h.write(self.h.feed/(v['session_id']+'.started.json'),{**v,'status':'Started','end':None})
        self.h.write(self.h.feed/(v['session_id']+'.terminal.json'),v)
        self.h.ticks(); self.assertEqual(self.h.job(v['session_id'])['status'],'investigation_required')
    def test_unknown_wazuh_does_not_become_negative_or_publish(self):
        self.h.unknown=True; v=self.ready(); self.h.ticks()
        job=self.h.job(v['session_id']); self.assertEqual(job['status'],'investigation_required')
        self.assertEqual(json.loads(job['result'])['hybrid_priority'],'Evidence Unavailable')
        self.assertEqual(self.h.calls,['rf','hybrid'])
    def test_query_failure_bounded_retries(self):
        self.h.failure='hybrid'; v=self.ready(); self.h.ticks(9)
        self.assertEqual(self.h.job(v['session_id'])['status'],'failed')
        self.assertEqual(self.h.calls.count('hybrid'),3); self.assertNotIn('send',self.h.calls)
    def test_publication_failure_retries_without_reinference(self):
        self.h.cfg.update(dry_run=False,enable_publication=True); self.h.failure='send'
        v=self.ready(); self.h.ticks(5); self.h.failure=None; self.h.ticks(2)
        self.assertEqual(self.h.job(v['session_id'])['status'],'published')
        self.assertEqual(self.h.calls.count('rf'),1); self.assertEqual(self.h.calls.count('send'),3)
    def test_restart_reuses_successful_stage(self):
        v=self.ready(); self.h.service.tick(); self.h.restart(); self.h.ticks()
        self.assertEqual(self.h.job(v['session_id'])['status'],'prepared_not_published')
        self.assertEqual(self.h.calls.count('rf'),1)
    def test_crash_after_stage_artifacts_recovers_without_rerun(self):
        v=self.ready(); self.h.service.tick(); job=self.h.job(v['session_id'])
        # Recreate the state immediately before RF-success transaction committed.
        with self.h.service.db:
            self.h.service.update(v['session_id'],stage='rf',status='running',attempt=1,path=job['rf'],rf=None)
        self.h.restart(); self.h.ticks(); self.assertEqual(self.h.calls.count('rf'),1)
    def test_other_account_host_cannot_pass(self):
        self.h.host='wrong.example.invalid'; v=self.ready(); self.h.ticks()
        self.assertEqual(self.h.job(v['session_id'])['status'],'investigation_required')
        self.assertNotIn('hybrid',self.h.calls)
    def test_overlapping_account_activity_excluded(self):
        v=self.ready(); self.h.add('Started',offset=-399); self.h.ticks()
        self.assertEqual(self.h.calls,[]); self.assertEqual(self.h.job(v['session_id'])['status'],'investigation_required')
    def test_duplicate_source_ids_for_identical_interval(self):
        self.h.service.initialize(); a=self.h.add(); b=self.h.add(); self.h.advance(); self.h.ticks()
        states=[r[0] for r in self.h.service.db.execute('SELECT status FROM jobs')]
        self.assertIn('duplicate_session',states); self.assertNotIn('send',self.h.calls)
    def test_two_workers_cannot_share_state(self):
        with self.assertRaises(BlockingIOError): Orchestrator(self.h.cfg)
    def test_mount_disappearance_does_not_fall_back(self):
        self.h.service.initialize(); (self.h.feed/'feed.json').unlink()
        with self.assertRaises(OSError): self.h.service.tick()
        self.assertEqual(self.h.calls,[])
    def test_restart_after_ack_does_not_repeat_send(self):
        self.h.cfg.update(dry_run=False,enable_publication=True)
        v=self.ready(); self.h.ticks(4)
        job=self.h.job(v['session_id']); self.assertEqual(job['status'],'published')
        with self.h.service.db:
            self.h.service.update(v['session_id'],status='running',stage='send')
        self.h.restart(); self.h.ticks(2)
        self.assertEqual(self.h.calls.count('send'),1)
        self.assertEqual(self.h.job(v['session_id'])['status'],'published')
    def test_late_processing_does_not_extend_cutoff(self):
        self.h.service.initialize(); v=self.h.add(); self.h.advance(36000); self.h.ticks(1)
        job=self.h.job(v['session_id']); request=read(Path(job['rf'])/'request.json')
        self.assertEqual(request['prediction_cutoff'],'2030-01-01T00:05:11Z')

    def held_for_release(self):
        value=self.ready(); self.h.ticks()
        source=json.loads(self.h.job(value['session_id'])['record'])
        saved={'session_id':'derived-session','rf_prediction_id':'rf-prediction'}
        with self.h.service.db:
            self.h.service.update(value['session_id'],result=json.dumps(saved))
        event={**saved,'activity_start':source['start'],'activity_end':source['end'],'prediction_id':'hybrid-prediction'}
        return value,event
    def test_release_scopes_ids_and_keeps_other_held_jobs(self):
        value,event=self.held_for_release(); other=str(uuid4())
        with self.h.service.db:
            self.h.service.db.execute("INSERT INTO jobs(id,record,hash,status,stage) VALUES(?,?,?,'prepared_not_published','send')",(other,'{}','synthetic'))
        self.h.cfg.update(dry_run=False,enable_publication=True)
        with patch('src.hybrid_publisher.verify_prepared',return_value=event):
            released=self.h.service.release_prepared([value['session_id']])
        self.assertEqual(released,[value['session_id']]); self.assertEqual(self.h.job(value['session_id'])['status'],'waiting')
        self.assertEqual(self.h.job(other)['status'],'prepared_not_published'); self.assertNotIn('send',self.h.calls)
    def test_release_preserves_gates_and_dry_run(self):
        value,event=self.held_for_release()
        with self.assertRaises(ValueError): self.h.service.release_prepared([value['session_id']])
        self.h.cfg.update(dry_run=False,enable_publication=True)
        with patch('src.hybrid_publisher.verify_prepared',side_effect=ValueError('corrupt')):
            with self.assertRaises(ValueError): self.h.service.release_prepared([value['session_id']])
        self.assertEqual(self.h.job(value['session_id'])['status'],'prepared_not_published')
    def test_release_refuses_wrong_job_payload_without_state_change(self):
        value,event=self.held_for_release(); event['session_id']='different-session'
        self.h.cfg.update(dry_run=False,enable_publication=True)
        with patch('src.hybrid_publisher.verify_prepared',return_value=event):
            with self.assertRaises(ValueError): self.h.service.release_prepared([value['session_id']])
        self.assertEqual(self.h.job(value['session_id'])['status'],'prepared_not_published')

    def test_actual_command_adapter_preserves_existing_modules_and_cutoff(self):
        v=self.ready(); job={'rf':'RF_DIR','hybrid':'HYBRID_DIR','prepared':'PREPARED_DIR'}
        with patch('src.session_orchestrator.subprocess.run') as run:
            run.return_value.returncode=0
            for stage, module in [('rf','src.controlled_replay.new_session'),('hybrid','src.controlled_replay.hybrid_session'),('prepare','src.hybrid_publisher'),('send','src.hybrid_publisher')]:
                self.h.service.command(stage,v,self.h.root/'output',job,[])
                args=run.call_args.args[0]
                self.assertIn(module,args); self.assertFalse(run.call_args.kwargs.get('shell',False))
                if stage=='rf':
                    self.assertEqual(args[args.index('--availability-delay-seconds')+1],'300')
                    self.assertEqual(args[args.index('--end')+1],v['end'])
    def test_explicit_failed_query_is_retried_and_not_negative(self):
        v=self.ready(); self.h.service.tick()
        original=self.h.run
        def run(stage,value,out,job,windows):
            original(stage,value,out,job,windows)
            if stage=='hybrid':
                self.h.write(out/'hybrid_result.json',{'wazuh_evidence_status':'query_failed_or_unavailable','hybrid_priority':'Evidence Unavailable'})
                self.h.write(out/'alert_retrieval_audit.json',{'status':'failed'})
        self.h.service.runner=run; self.h.ticks(8)
        job=self.h.job(v['session_id']); self.assertEqual(job['status'],'failed')
        self.assertIn('Evidence Unavailable',job['result']); self.assertNotIn('prepare',self.h.calls)
    def test_malformed_or_unverified_prepare_never_sends(self):
        self.h.cfg.update(dry_run=False,enable_publication=True)
        self.h.failure='prepare'; v=self.ready(); self.h.ticks(8)
        self.assertNotIn('send',self.h.calls)
        self.assertEqual(self.h.job(v['session_id'])['status'],'failed')
    def test_receiver_failure_is_bounded(self):
        self.h.cfg.update(dry_run=False,enable_publication=True); self.h.failure='send'
        v=self.ready(); self.h.ticks(12)
        self.assertEqual(self.h.job(v['session_id'])['status'],'failed')
        self.assertEqual(self.h.calls.count('send'),3)
    def test_credentials_launcher_never_prints_keychain_errors(self):
        from src.operational_session_service import main
        import io
        from contextlib import redirect_stdout
        cfg=self.h.root/'connection.json'
        self.h.write(cfg,{'environment':{key:'placeholder' for key in ('WAZUH_INDEXER_URL','WAZUH_INDEXER_INDEX_PATTERN','WAZUH_ALERT_INDEX_PATTERN','WAZUH_INDEXER_CA_CERT','WAZUH_INDEXER_TLS_PROFILE')},'keychain_service':'synthetic'})
        output=io.StringIO()
        with patch.dict('os.environ',{},clear=True), patch('src.operational_session_service.subprocess.run',side_effect=subprocess.CalledProcessError(1,['security'],output='SECRET',stderr='SECRET')),redirect_stdout(output):
            result=main(['--config','unused','--connection',str(cfg)])
        self.assertEqual(result,2); self.assertNotIn('SECRET',output.getvalue())

    def test_publication_defaults_and_secure_paths(self):
        cfg=read(Path(__file__).resolve().parents[1]/'config/operational_service.example.json')
        self.assertTrue(cfg['dry_run']); self.assertFalse(cfg['enable_publication'])
        path=self.h.root/'config.json'; self.h.write(path,self.h.cfg); config_file(path)
        self.h.cfg.update(enable_publication=True); self.h.write(path,self.h.cfg)
        with self.assertRaises(ValueError): config_file(path)


if __name__=='__main__': unittest.main()
