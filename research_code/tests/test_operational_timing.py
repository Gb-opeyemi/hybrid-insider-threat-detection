"""Deterministic timing tests; no live clients, model fitting, sleeping or publishing."""
from contextlib import redirect_stderr
from copy import deepcopy
from datetime import timedelta
import csv
import io
import itertools
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
import test_features as fixture
from test_new_session import NAMES, plan
from src import operational_timing as timing
from src.timing_hooks import Hooks, rf_child_transport, timed_shadow_class
from src.controlled_replay import new_session as rf
from src.tabpfn_prototype import artifacts, new_session as tp
from src import model_aware_publication as publication

SID='00000000-0000-0000-0000-000000000001'
RECORD={'session_id':SID,'username':'EXAMPLE\\example.user','start':'2026-01-01T10:00:00Z',
        'end':'2026-01-01T10:01:00Z','status':'Completed'}


def fake_clock():
    counter=itertools.count(0,1_000_000)
    return lambda:next(counter)


class Model:
    def predict(self, frame):return (self.predict_proba(frame)[:,1]>.5).astype(int)
    def predict_proba(self,frame):return np.tile([.2,.8],(len(frame),1))


class TimingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()
        self.base=self.root/'data/experiments/operational_service/model_aware/router'
        timing.start_job(self.base,RECORD,'random_forest')
        self.folder=self.base/'timings'/SID
    def collector(self):return timing.Collector(self.folder,clock=fake_clock(),wall=lambda:'2026-01-01T10:10:00Z')
    def report(self):return timing.refresh(self.folder)
    def test_monotonic_units_and_nested_calls_not_double_counted(self):
        c=self.collector()
        with c.installed(active=True),c.work('rf','attempt1'):
            with c.span('model_inference'):
                with c.span('model_inference'):pass
        r=self.report()
        self.assertEqual(r['durations_ms']['model_inference'],1.0)
        self.assertEqual(sum(e['metric']=='model_inference' for e in r['operation_spans']),1)
        self.assertGreater(r['durations_ms']['total_active_processing'],r['durations_ms']['model_inference'])
    def test_waiting_does_not_become_active_execution(self):
        c=self.collector()
        with c.installed(active=True):pass
        r=self.report();self.assertIsNone(r['durations_ms']['total_active_processing'])
        self.assertIsNone(r['durations_ms']['model_inference'])
        self.assertEqual(r['evidence_cutoff'],'2026-01-01T10:06:00Z')
    def test_failed_stage_retains_partial_time_and_only_exception_type(self):
        c=self.collector()
        with self.assertRaises(ValueError):
            with c.installed(active=True),c.work('capture','attempt1'),c.span('wazuh_event_retrieval'):
                raise ValueError('PRIVATE_EVENT_CONTENT')
        r=self.report();self.assertEqual(r['durations_ms']['wazuh_event_retrieval'],1.0)
        self.assertEqual(r['errors'][0]['exception_type'],'ValueError')
        self.assertNotIn('PRIVATE_EVENT_CONTENT',json.dumps(r))
    def test_retry_attempts_separate_and_completed_operations_not_replayed(self):
        for name,metric in [('rf1','model_inference'),('send1','publication'),('send2','publication')]:
            c=self.collector()
            with c.installed(active=True),c.work(name,name),c.span(metric):pass
        r=self.report();self.assertEqual(r['durations_ms']['model_inference'],1)
        self.assertEqual(r['durations_ms']['publication'],2)
        self.assertEqual(len(r['attempts']),3)
        before=(self.folder/'report.json').read_bytes();self.report()
        self.assertEqual(self.report()['durations_ms'],r['durations_ms'])
    def test_interrupted_span_is_unknown_not_zero(self):
        c=self.collector();e=c.event('model_inference','primary');c.save(e)
        r=self.report();self.assertIsNone(r['durations_ms']['model_inference'])
        self.assertIn('Interrupted',r['unavailable_reasons']['model_inference'])
    def test_verification_does_not_inflate_primary_inference_features(self):
        c=self.collector()
        with c.installed(active=True),c.work('inference','a'):
            with c.span('feature_extraction'):pass
            with c.span('feature_extraction','verification'):pass
        r=self.report();self.assertEqual(r['durations_ms']['feature_extraction'],1)
        self.assertEqual(r['verification_durations_ms']['feature_extraction'],1)
    def test_known_warm_cache_is_zero_unreached_loading_is_null(self):
        self.assertIsNone(self.report()['durations_ms']['model_loading'])
        c=self.collector();c.cached_loading()
        self.assertEqual(self.report()['durations_ms']['model_loading'],0)
    def test_latency_uses_ack_utc_separately_from_monotonic_execution(self):
        c=self.collector()
        with c.installed(active=True),c.work('send','one'),c.span('publication') as e:e['ack_status']='written'
        r=self.report();self.assertEqual(r['completion_to_publication_latency_ms'],540000)
        self.assertEqual(r['publication_acknowledged_at_utc'],'2026-01-01T10:10:00Z')
        self.assertIsNone(r['receiver_append_timestamp_utc'])
        self.assertEqual(r['durations_ms']['publication'],1)
    def test_duplicate_only_ack_does_not_invent_original_publication_time(self):
        c=self.collector()
        with c.installed(active=True),c.work('send','one'),c.span('publication') as e:e['ack_status']='duplicate'
        r=self.report();self.assertIsNone(r['completion_to_publication_latency_ms'])
        self.assertEqual(r['completion_to_acknowledgement_latency_ms'],540000)
    def test_timing_io_failure_does_not_change_return_or_original_error(self):
        c=self.collector();err=io.StringIO()
        with patch('src.operational_timing.atomic',side_effect=OSError('private path')),redirect_stderr(err):
            with c.installed(active=True),c.work('rf','one'),c.span('model_inference'):value=42
            self.assertEqual(value,42)
            with self.assertRaisesRegex(ValueError,'original'):
                with c.span('model_inference'):raise ValueError('original')
        self.assertNotIn('private path',err.getvalue())
    def test_export_is_read_only_refuses_overwrite_and_uses_no_database(self):
        before={p:p.read_bytes() for p in self.folder.rglob('*.json')}
        out=self.root/'data/experiments/export/new.csv';cwd=Path.cwd()
        try:
            os.chdir(self.root)
            self.assertEqual(timing.export_csv(self.base,out),1)
            with self.assertRaises(ValueError):timing.export_csv(self.base,out)
        finally:os.chdir(cwd)
        self.assertEqual(before,{p:p.read_bytes() for p in self.folder.rglob('*.json')})
        with out.open() as handle:rows=list(csv.DictReader(handle))
        self.assertEqual(rows[0]['model_inference_ms'],'')
    def test_historical_job_without_metadata_is_not_backfilled(self):
        self.assertIsNone(timing.collector_for(self.base,'old'))
        timing.finish(self.base,'old',{'status':'published','error':None})
        self.assertFalse((self.base/'timings/old').exists())
    def test_serialization_is_finite_and_atomic_temporary_files_cleaned(self):
        with self.assertRaises(ValueError):timing.atomic(self.folder/'bad.json',{'value':float('nan')})
        self.assertFalse((self.folder/'bad.json').exists())
        self.assertEqual(list(self.folder.glob('.bad.json.*')),[])


class HooksTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.base=self.root/'data/experiments/operational_service/model_aware/router'
        timing.start_job(self.base,RECORD,'random_forest');self.folder=self.base/'timings'/SID
    def collector(self):return timing.Collector(self.folder,clock=fake_clock(),wall=lambda:'2026-01-01T10:10:00Z')
    def test_rf_prediction_model_loading_and_preprocessing_preserve_values(self):
        model=Model();raw=pd.DataFrame([[1.,2.]])
        expected=model.predict_proba(raw).copy();original_predict=model.predict
        instance_state=dict(vars(model))
        original_astype=pd.DataFrame.astype
        c=self.collector();c.inference_depth=1
        with patch.object(rf,'load_model',return_value=model):
            with c.installed(active=True),c.work('rf','one'),Hooks():
                loaded=rf.load_model(None,None)
                frame=pd.DataFrame([[1.,2.]]).astype(float)
                self.assertEqual(loaded.predict(frame).tolist(),[1])
                np.testing.assert_array_equal(loaded.predict_proba(frame),expected)
                self.assertEqual(vars(model),instance_state)
        self.assertEqual(model.predict,original_predict);self.assertIs(pd.DataFrame.astype,original_astype)
        r=timing.refresh(self.folder)
        for key in ('model_loading','model_inference','preprocessing'):self.assertIsNotNone(r['durations_ms'][key])
        self.assertEqual(len([e for e in r['operation_spans'] if e['metric']=='model_inference']),2)
    def test_tabpfn_restoration_and_actual_predict_calls_are_separate(self):
        meta=timing.load(self.folder/'metadata.json');meta['selected_model']='tabpfn';timing.atomic(self.folder/'metadata.json',meta)
        model=Model();c=self.collector();c.inference_depth=1
        with patch.object(artifacts,'restore',return_value=(NAMES,None,{},model)),patch.object(artifacts,'no_downloads'):
            with c.installed(active=True),c.work('inference','one'),Hooks():
                restored=artifacts.restore(self.root)[3]
                label,proba=artifacts.predict(restored,pd.DataFrame([[0.]*23],columns=NAMES))
        self.assertEqual((label,proba),(1,[.2,.8]))
        r=timing.refresh(self.folder)
        self.assertIsNotNone(r['durations_ms']['model_loading']);self.assertIsNotNone(r['durations_ms']['model_inference'])
        self.assertEqual(r['selected_model'],'tabpfn')
    def test_real_feature_extractor_is_unchanged_and_not_counted_as_prediction(self):
        path=self.root/'capture.jsonl';path.write_text(json.dumps(fixture.event())+'\n')
        expected=rf.extract_completed(path,plan(),NAMES);c=self.collector();c.inference_depth=1
        original=rf.extract_completed
        with c.installed(active=True),c.work('rf','one'),Hooks():observed=rf.extract_completed(path,plan(),NAMES)
        self.assertEqual(expected,observed);self.assertIs(rf.extract_completed,original)
        r=timing.refresh(self.folder);self.assertIsNotNone(r['durations_ms']['feature_extraction'])
        self.assertIsNone(r['durations_ms']['model_inference'])
    def test_claim_is_not_confused_with_actual_prediction_publication(self):
        c=self.collector()
        def ssh(value,*args):return {'status':'written','prediction_id':'synthetic','guard_version':1}
        with patch.object(publication,'_ssh_send',side_effect=ssh):
            with c.installed(active=True),c.work('send','one'),Hooks():
                publication._ssh_send({'operation':'claim'})
                publication._ssh_send({'event_type':'thesis_tabpfn_hybrid_priority'})
        r=timing.refresh(self.folder)
        self.assertEqual(r['durations_ms']['publication'],1)
        self.assertEqual(len([e for e in r['operation_spans'] if e['metric']=='ownership_claim']),1)
    def test_rf_subprocess_wrapper_preserves_arguments_timeouts_and_streams(self):
        c=self.collector();command=['python','-B','-m','src.controlled_replay.new_session','--username','EXAMPLE\\user']
        with patch('subprocess.run',return_value=SimpleNamespace(returncode=0)) as run:
            with c.installed(active=True),c.work('rf','out'),rf_child_transport('rf','out'):
                import subprocess
                subprocess.run(command,timeout=1800,stdin='unchanged')
            wrapped=run.call_args.args[0]
        self.assertEqual(wrapped[:4],['python','-B','-m','src.timed_replay_stage'])
        self.assertEqual(wrapped[wrapped.index('--')+1:],command[4:])
        self.assertEqual(run.call_args.kwargs,{'timeout':1800,'stdin':'unchanged'})
    def test_timed_child_runs_original_main_once_without_argument_changes(self):
        from src.timed_replay_stage import main
        descriptor=self.folder/'child.json';timing.atomic(descriptor,{'journal_dir':str(self.folder),'stage':'rf','artifact':'out'})
        cwd=Path.cwd()
        try:
            os.chdir(self.root)
            with patch.object(rf,'main',return_value=2) as original:
                self.assertEqual(main(['--stage','rf','--descriptor',str(descriptor),'--','--username','EXAMPLE\\user']),2)
                original.assert_called_once_with(['--username','EXAMPLE\\user'])
        finally:os.chdir(cwd)
    def test_missing_child_descriptor_falls_back_to_original_main(self):
        from src.timed_replay_stage import main
        err=io.StringIO()
        with patch.object(rf,'main',return_value=0) as original,redirect_stderr(err):
            self.assertEqual(main(['--stage','rf','--descriptor',str(self.root/'missing'),'--','--output-dir','unchanged']),0)
            original.assert_called_once_with(['--output-dir','unchanged'])
        self.assertIn('behaviour unchanged',err.getvalue())

    def test_hook_installation_failure_does_not_block_original_processing(self):
        c=self.collector();err=io.StringIO()
        with patch.object(Hooks,'install',side_effect=RuntimeError('secret')),redirect_stderr(err):
            with c.installed(active=True),Hooks():value=Model().predict(pd.DataFrame([[1.]]))
        self.assertEqual(value.tolist(),[1]);self.assertNotIn('secret',err.getvalue())

    def test_journal_io_is_outside_the_operation_duration(self):
        state={'ns':0}
        c=timing.Collector(self.folder,clock=lambda:state['ns'],wall=lambda:'2026-01-01T10:10:00Z')
        original=c.save
        def slow_save(event):state['ns']+=100_000_000;original(event)
        with patch.object(c,'save',side_effect=slow_save):
            with c.installed(active=True),c.work('rf','one'),c.span('model_inference'):
                state['ns']+=2_000_000
        r=timing.refresh(self.folder)
        self.assertEqual(r['durations_ms']['model_inference'],2)
        self.assertGreater(r['durations_ms']['total_active_processing'],2)

    def test_unverified_receiver_ack_does_not_establish_publication_latency(self):
        c=self.collector()
        with patch.object(publication,'_ssh_send',return_value={'status':'written'}):
            with c.installed(active=True),c.work('send','one'),Hooks():
                publication._ssh_send({'event_type':'thesis_tabpfn_hybrid_priority'})
        self.assertIsNone(timing.refresh(self.folder)['completion_to_publication_latency_ms'])

    def test_warm_tabpfn_worker_marks_observed_zero_restore(self):
        from src.tabpfn_prototype.automatic import Shadow
        Worker=timed_shadow_class();worker=Worker.__new__(Worker)
        model=Model();worker.context=(NAMES,None,{},model)
        c=self.collector()
        def original(self,*args):
            c.inference_depth+=1
            try:return self.context[3].predict(pd.DataFrame([[0.]*23]))
            finally:c.inference_depth-=1
        with patch.object(Shadow,'execute_stage',original):
            with c.installed(active=True),Hooks() as hooks:
                hooks.model(model);worker.execute_stage('inference','attempt',{'id':SID},RECORD,[])
        r=timing.refresh(self.folder)
        self.assertEqual(r['durations_ms']['model_loading'],0)
        self.assertIsNotNone(r['durations_ms']['model_inference'])


class SchedulerTimingTests(unittest.TestCase):
    def test_new_jobs_report_wait_failure_and_publication_without_backfill(self):
        # Reuse only the existing synthetic scheduler harness. Its fake stages
        # intentionally have no model call, so inference MUST remain null.
        from test_model_aware_orchestrator import RouterTests, RF
        h=RouterTests('test_rf_uses_original_processing_and_guarded_send');h.setUp()
        try:
            value=h.h.add();h.h.advance(100);h.service.tick_selected(RF)
            folder=h.service.base/'timings'/value['session_id']
            report=timing.load(folder/'report.json')
            self.assertEqual(report['processing_status'],'waiting')
            self.assertIsNone(report['durations_ms']['total_active_processing'])
            h.h.advance(300);h.polls(RF)
            report=timing.load(folder/'report.json')
            self.assertEqual(report['processing_status'],'published')
            self.assertIsNotNone(report['durations_ms']['total_active_processing'])
            self.assertIsNone(report['durations_ms']['model_inference'])
            self.assertEqual(h.original.read_bytes(),h.before)
        finally:h.doCleanups()

    def test_failed_executions_have_correct_status_and_no_inference(self):
        from test_model_aware_orchestrator import RouterTests, RF
        h=RouterTests('test_rf_uses_original_processing_and_guarded_send');h.setUp()
        try:
            value=h.h.add('Failed');h.h.advance(400);h.service.tick_selected(RF)
            report=timing.load(h.service.base/'timings'/value['session_id']/'report.json')
            self.assertEqual(report['processing_status'],'failed_execution')
            self.assertIsNone(report['durations_ms']['model_inference'])
        finally:h.doCleanups()

    def test_recovered_stage_does_not_copy_or_repeat_old_component_timings(self):
        from test_model_aware_orchestrator import RouterTests, RF
        h=RouterTests('test_rf_uses_original_processing_and_guarded_send');h.setUp()
        try:
            value=h.h.add();h.h.advance(400);h.service.tick_selected(RF)
            row=h.job(value);folder=h.service.base/'timings'/value['session_id']
            c=timing.Collector(folder,clock=fake_clock())
            with c.installed(active=True),c.work('rf',row['rf']),c.span('model_inference'):pass
            with h.service.db:
                h.service.update(value['session_id'],status='running',stage='rf',attempt=1,path=row['rf'])
            h.service.tick_selected(RF)
            report=timing.load(folder/'report.json')
            self.assertEqual(report['durations_ms']['model_inference'],1)
            self.assertEqual(h.h.calls.count('rf'),1)
        finally:h.doCleanups()
