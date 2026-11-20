"""Reproduce negative clock skew on synthetic input, never retry a real job."""
from pathlib import Path
from types import SimpleNamespace
import json
import tempfile
import unittest
from unittest.mock import patch
from src import operational_timing as timing
from src.controlled_replay.new_session import extract_completed
from src.tabpfn_prototype.automatic import Shadow
from src.timing_hooks import Hooks, timed_shadow_class
from test_new_session import plan, NAMES
from test_features import event
import test_tabpfn_automatic as fixtures


class ClockGuardRegressionTests(unittest.TestCase):
    def test_negative_clock_skew_blocks_identically_and_is_recorded_before_loading(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'capture';source.mkdir()
            item=event(at='2026-01-01T10:00:10Z')
            # Same signature as the live failure: receipt predates Windows clock.
            item['timestamp']='2026-01-01T09:51:20Z'  # -530 seconds
            capture=source/'retrieved_events.jsonl';capture.write_text(json.dumps(item)+'\n')
            (source/'acquisition.json').write_text(json.dumps({'allowed_hosts':['host.example.invalid']}))
            request=plan('EXAMPLE\\example.user')
            baseline_raw,baseline_audit=extract_completed(capture,request,NAMES)
            self.assertEqual(baseline_audit['reasons'],['clock_disagreement_over_300s'])
            for instrumented in (False,True):
                cls=timed_shadow_class() if instrumented else Shadow
                worker=cls.__new__(cls);worker.root=root;worker.context=None
                worker.paths=lambda sid:{'capture':str(source)}
                c=timing.Collector(root/'timing')
                with patch('src.tabpfn_prototype.acquisition.verified_capture',return_value=(source,request,None,'hash')), \
                        patch('src.tabpfn_prototype.artifacts.frozen',return_value=(NAMES,None,{},None)), \
                        patch('src.tabpfn_prototype.artifacts.restore') as restore, \
                        patch('src.tabpfn_prototype.new_session.infer') as infer:
                    if instrumented:
                        with c.installed(active=True),Hooks():
                            with self.assertRaisesRegex(ValueError,'^Fresh features or completion host unverified$'):
                                worker.execute_stage('inference',root/'new_attempt',{'id':'synthetic'}, {},[])
                    else:
                        with self.assertRaisesRegex(ValueError,'^Fresh features or completion host unverified$'):
                            worker.execute_stage('inference',root/'new_attempt',{'id':'synthetic'}, {},[])
                    restore.assert_not_called();infer.assert_not_called()
                self.assertFalse((root/'new_attempt').exists())
                if instrumented:
                    failures=[e for e in c.new_events if e['status']=='failed']
                    self.assertEqual(len(failures),1)
                    error=failures[0]
                    self.assertEqual(error['exception_type'],'ValueError')
                    self.assertEqual(error['preflight_validation']['reasons'],['clock_disagreement_over_300s'])
                    self.assertEqual(error['preflight_validation']['counts']['clock_disagreement_over_300s'],1)
                    self.assertEqual(error['preflight_validation']['behavior_receipt_minus_event_seconds_min'],-530)
                    self.assertFalse(any(e['metric'] in {'model_loading','model_inference'} for e in c.new_events))
                    self.assertNotIn('example.user',json.dumps(error))
                    report=timing.build_report({'activity_end':request['actual_end']},c.new_events)
                    self.assertEqual(report['errors'][0]['preflight_validation']['reasons'],['clock_disagreement_over_300s'])
                    self.assertIsNone(report['durations_ms']['model_loading'])
                    self.assertIsNone(report['durations_ms']['model_inference'])
            after_raw,after_audit=extract_completed(capture,request,NAMES)
            self.assertEqual((after_raw,after_audit),(baseline_raw,baseline_audit))

    def test_eligible_tabpfn_executes_original_inference_with_timing_enabled(self):
        # Existing fixture makes a fresh synthetic verified capture and mocks ONLY
        # fitted weights/imputer restoration. Real extraction/infer validation runs.
        h=fixtures.FreshAcquisitionTests('test_full_fresh_shadow_pipeline_dedup_attribution_hybrid_and_prepare')
        h.setUp()
        try:
            h.capture();model=h.model()
            Worker=timed_shadow_class();worker=Worker.__new__(Worker)
            worker.root=h.root;worker.context=None;worker.paths=lambda sid:{'capture':str(h.base)}
            collector=timing.Collector(h.root/'timing')
            output=h.base.parent/'timed_inference'
            with collector.installed(active=True),Hooks():
                worker.execute_stage('inference',output,{'id':h.completion['session_id']},h.completion,[])
            result=json.loads((output/'result.json').read_text())
            self.assertEqual(result['classification'],'malicious')
            self.assertEqual(result['malicious_probability'],.9)
            self.assertEqual(len(result['model_inputs']),23)
            self.assertTrue(any(e['metric']=='model_loading' and e['purpose']=='primary' for e in collector.new_events))
            self.assertTrue(any(e['metric']=='model_inference' and e['purpose']=='primary' for e in collector.new_events))
            self.assertTrue(any(e['metric']=='feature_extraction' and e['purpose']=='primary' for e in collector.new_events))
            self.assertEqual([e for e in collector.new_events if e['status']=='failed'],[])
            model.fit.assert_not_called()
        finally:h.doCleanups()
