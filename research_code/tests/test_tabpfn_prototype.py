"""Synthetic and mocked local tests. No Wazuh, original datasets or real models."""
import ast
import copy
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch
import numpy as np
import pandas as pd
from src import features as ref
from src.controlled_replay.new_session import extract_completed
from src.hybrid_priority import FUSION_POLICY_VERSION
from src.hybrid_publisher import synthetic_hybrid
from src.model_selection import Selection
from src.prototype_jobs import Job
from src.tabpfn_prototype import artifacts, hybrid_session, new_session, publisher
from src.tabpfn_prototype.common import identity, manifest, seal, write
from scripts.integration import receive_ml_prediction as legacy
from scripts.integration.receive_hybrid_candidate import receive_local
import test_features as fixture
from test_new_session import NAMES, plan


def event():
    rf = synthetic_hybrid()
    value = {k:v for k,v in rf.items() if k in publisher.FIELDS}
    value.update(event_type='thesis_tabpfn_hybrid_priority', mode='completed_session_tabpfn_hybrid',
        selected_model='tabpfn', model='TabPFN', model_artifact='models/tabpfn_baseline.tabpfn_fit',
        model_sha256='1'*64, checkpoint_sha256='2'*64, feature_schema_sha256='3'*64,
        ml_prediction_id='4'*64, ml_classification=rf['rf_classification'],
        ml_malicious_probability=rf['rf_malicious_probability'], benign_probability=1-rf['rf_malicious_probability'],
        prediction_score=rf['rf_malicious_probability'], fusion_adapter='tabpfn_to_existing_binary_policy_v1')
    value['prediction_id'] = identity(value)
    return publisher.validate(value)


class LocalTabPFNTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def test_fusion_four_cases_and_unknown_without_rf_fields(self):
        payload = event()
        prediction = {**payload, 'job_id':'synthetic', 'classification':'malicious',
                      'malicious_probability':.9, 'telemetry_completeness':{'status':'unverified'}}
        for label, wz, expected in [(1,1,'High Priority'),(1,0,'Needs Review'),(0,1,'Needs Review'),(0,0,'Low Risk'),(0,None,'Evidence Unavailable')]:
            prediction['classification'] = 'malicious' if label else 'benign'
            result = hybrid_session.combine(prediction, {'wazuh_detected':wz,'wazuh_evidence_verified':wz is not None,
                'evidence_status':'verified_positive' if wz == 1 else 'unavailable'})
            self.assertEqual(result['hybrid_priority'], expected)
            self.assertFalse(any(k.startswith('rf_') for k in result))
            self.assertEqual(result['fusion_policy_version'], FUSION_POLICY_VERSION)

    def test_strict_tabpfn_contract_and_distinct_rf_identity(self):
        value = event()
        self.assertNotEqual(value['prediction_id'], synthetic_hybrid()['prediction_id'])
        with self.assertRaises(ValueError): legacy.validate(value)
        self.assertEqual(value['model'], 'TabPFN')
        for change in ({'selected_model':'random_forest'}, {'model':'Random Forest'}, {'checkpoint_sha256':'bad'},
                       {'wazuh_detected':None}, {'wazuh_detected':0}, {'wazuh_detected':True},
                       {'wazuh_evidence_verified':False}, {'wazuh_evidence_status':'unavailable'},
                       {'ml_malicious_probability':float('nan')}, {'benign_probability':True},
                       {'prediction_cutoff':'2026-01-01T10:06:01Z'}, {'session_id':'wrong'},
                       {'hybrid_priority':'Low Risk'}, {'investigation_required':False},
                       {'telemetry_completeness_status':'complete'}, {'unresolved_alert_count':0},
                       {'extra':'unexpected'}, {'matched_rule_ids':'110511'}):
            with self.subTest(change=list(change)), self.assertRaises(ValueError): publisher.validate({**value, **change})

    def test_needs_review_preserves_probability_without_threshold(self):
        value = event()
        value.update(ml_classification='benign', ml_malicious_probability=.8, benign_probability=.2,
                     prediction_score=.2, hybrid_priority='Needs Review')
        # Classification is saved predict(), not a new >.5 decision in the receiver.
        publisher.validate(value)

    def test_tabpfn_publication_always_disabled(self):
        with patch('src.prediction_publisher.subprocess.run') as network:
            with self.assertRaises(PermissionError): publisher.send(event(), 'not-used')
            network.assert_not_called()

    def test_fitted_predictions_never_fit_and_validate_probabilities(self):
        model = Mock()
        model.predict.return_value = np.array([1]); model.predict_proba.return_value = np.array([[.1,.9]])
        frame = pd.DataFrame([[0.]*23], columns=NAMES)
        with patch('src.tabpfn_prototype.artifacts.no_downloads'):
            self.assertEqual(artifacts.predict(model, frame), (1, [.1,.9]))
            model.fit.assert_not_called()
            for probabilities in ([[.1,.8]], [[np.nan,1]], [[-1,2]], [[True,True]]):
                model.predict_proba.return_value=np.asarray(probabilities)
                with self.assertRaises(ValueError): artifacts.predict(model, frame)

    def test_inference_bad_vector_rejected_before_model(self):
        model = Mock()
        for frame in (pd.DataFrame([[0.]*22]), pd.DataFrame([[np.nan]*23]), pd.DataFrame([[-1.]*23])):
            with self.assertRaises(ValueError): artifacts.predict(model, frame)
        model.predict.assert_not_called()

    def test_float32_probability_roundoff_preserved(self):
        model=Mock();model.predict.return_value=np.array([1])
        probabilities=np.array([[.1,.9]],dtype=np.float32)
        model.predict_proba.return_value=probabilities
        with patch('src.tabpfn_prototype.artifacts.no_downloads'):
            _, values=artifacts.predict(model,pd.DataFrame([[0.]*23],columns=NAMES))
        self.assertEqual(values,probabilities.astype(float)[0].tolist())
        value=event();value.update(benign_probability=values[0],ml_malicious_probability=values[1],prediction_score=values[1])
        publisher.validate(value)

    def test_inference_and_reverification_float32_parity_and_wrong_model(self):
        source=self.root/'source';source.mkdir()
        capture=source/'retrieved_events.jsonl';capture.write_text(json.dumps(fixture.event())+'\n')
        request=plan();raw,audit=extract_completed(capture,request,NAMES)
        inputs={name:0.0 if raw[name] is None else float(raw[name]) for name in NAMES}
        write(source/'raw_features.json',raw);write(source/'result.json',{'model_inputs':inputs})
        imputer=SimpleNamespace(transform=lambda frame:frame.fillna(0).to_numpy())
        info={'model':'TabPFN','selected_model':'tabpfn','model_artifact':'models/tabpfn_baseline.tabpfn_fit',
              'model_sha256':'1'*64,'checkpoint_sha256':'2'*64}
        model=Mock();model.predict.return_value=np.array([1])
        model.predict_proba.return_value=np.array([[.1,.9]],dtype=np.float32)
        folder=self.root/'data/experiments/tabpfn_prototype/job/inference'
        with patch('src.tabpfn_prototype.new_session.source_capture',return_value=(source,request,{},'sourcehash')), \
                patch('src.tabpfn_prototype.new_session.artifacts.restore',return_value=(NAMES,imputer,dict(info),model)), \
                patch('src.tabpfn_prototype.new_session.artifacts.frozen',return_value=(NAMES,imputer,dict(info),None)), \
                patch('src.tabpfn_prototype.new_session.code_hashes',return_value={'synthetic':'hash'}), \
                patch('src.tabpfn_prototype.artifacts.no_downloads'):
            result=new_session.infer(self.root,source,folder,'synthetic_job')
            checked=new_session.verified_inference(self.root,folder)[0]
            self.assertEqual(checked,result)
            self.assertEqual(result['model_inputs'],inputs)
            self.assertEqual(result['telemetry_completeness'],audit['telemetry_completeness'])
            model.fit.assert_not_called()
            for change in ({'model':'Random Forest'}, {'synthetic':True}, {'mode':'live'}, {'event_type':'other'}):
                (folder/'result.json').write_text(json.dumps({**result,**change}))
                (folder/'output_manifest.json').unlink();seal(folder)
                with self.subTest(change=change), self.assertRaises(ValueError):new_session.verified_inference(self.root,folder)

    def test_receiver_candidate_contract_has_no_numeric_runtime_dependency(self):
        import subprocess,sys
        # -S removes site packages. The candidate must still import as a small receiver.
        subprocess.run([sys.executable,'-B','-S','-c',
                        'import scripts.integration.receive_hybrid_candidate'],check=True,capture_output=True)

    def test_source_requires_original_300_second_cutoff(self):
        p = self.root / 'request.json'; bad = plan(); bad['availability_delay_seconds']=60
        p.write_text(json.dumps(bad))
        with patch('src.tabpfn_prototype.new_session.verified_completed_session',return_value=([{}],'hash')):
            with self.assertRaises(ValueError): new_session.source_capture(self.root, self.root)

    def test_shared_extractor_is_called_not_reimplemented(self):
        self.assertIs(new_session.extract_completed, extract_completed)
        capture = self.root/'capture.jsonl'; capture.write_text(json.dumps(fixture.event())+'\n')
        raw, audit = new_session.extract_completed(capture, plan(), NAMES)
        self.assertEqual(audit['status'],'eligible')
        self.assertEqual(len(raw),23)
        self.assertEqual(raw['windows_event_count'],1)
        self.assertIsNone(raw['object_deletion_event_count'])

    def test_manifest_rejects_changed_and_path_escape_artifacts(self):
        folder=self.root/'run';folder.mkdir();write(folder/'result.json',{'selected_model':'tabpfn'});seal(folder)
        manifest(folder,{'result.json'})
        (folder/'result.json').write_text('{}')
        with self.assertRaises(ValueError): manifest(folder,{'result.json'})
        (folder/'output_manifest.json').write_text(json.dumps({'../outside':'0'*64}))
        with self.assertRaises(ValueError): manifest(folder,set())

    def test_wrong_tabpfn_artifact_prevents_restore(self):
        with patch('src.tabpfn_prototype.artifacts.frozen',side_effect=ValueError('hash mismatch')):
            with self.assertRaises(ValueError): artifacts.restore(self.root)

    def test_query_failure_keeps_unknown_and_no_payload(self):
        folder=self.root/'data/experiments/tabpfn_prototype/job/hybrid'
        with patch('src.tabpfn_prototype.hybrid_session.reverify',side_effect=ValueError('unavailable')):
            with self.assertRaises(ValueError): hybrid_session.run(self.root,self.root,self.root,folder)
        value=json.loads((folder/'hybrid_result.json').read_text())
        self.assertIsNone(value['wazuh_detected']);self.assertTrue(value['investigation_required'])
        self.assertEqual(value['hybrid_priority'],'Evidence Unavailable')
        self.assertFalse((folder/'hybrid_payload.json').exists())

    def test_no_classifier_fitting_calls_in_new_modules(self):
        for path in (Path(__file__).resolve().parents[1]/'src/tabpfn_prototype').glob('*.py'):
            tree=ast.parse(path.read_text())
            calls=[node.func.attr for node in ast.walk(tree) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)]
            self.assertNotIn('fit',calls);self.assertNotIn('fit_transform',calls);self.assertNotIn('fit_resample',calls)


class ReceiverCandidateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.paths=[root/name for name in ('rf.jsonl','tabpfn.jsonl','guard.lock')]
        for p in self.paths:p.touch()

    def receive(self,value):return receive_local(value,*self.paths)

    def test_tabpfn_valid_duplicate_restart_and_unchanged_rf_ledger(self):
        before=self.paths[0].read_bytes()
        self.assertEqual(self.receive(event())['status'],'written')
        self.assertEqual(self.receive(event())['status'],'duplicate')
        self.assertEqual(self.paths[0].read_bytes(),before)
        self.assertEqual(len(self.paths[1].read_text().splitlines()),1)

    def test_cross_model_rejected_in_both_orders(self):
        for first,second in [(synthetic_hybrid(),event()),(event(),synthetic_hybrid())]:
            with self.subTest(first=first['model']):
                for p in self.paths:p.write_bytes(b'')
                self.receive(first)
                before=[p.read_bytes() for p in self.paths[:2]]
                with self.assertRaisesRegex(ValueError,'another model'):self.receive(second)
                self.assertEqual(before,[p.read_bytes() for p in self.paths[:2]])

    def test_preexisting_rf_history_blocks_tabpfn_without_backfill(self):
        legacy.receive(synthetic_hybrid(),self.paths[0])
        with self.assertRaisesRegex(ValueError,'another model'):self.receive(event())

    def test_rollback_rf_for_different_session_after_tabpfn_record(self):
        self.receive(event())
        rf=synthetic_hybrid(False)
        self.assertEqual(self.receive(rf)['status'],'written')
        self.assertEqual(self.receive(rf)['status'],'duplicate')
        for line in self.paths[0].read_text().splitlines():
            value=legacy.strict_json(line);value.pop('published_at_utc');legacy.validate(value)

    def test_original_rf_ml_record_does_not_occupy_hybrid_slot(self):
        self.receive(legacy_event := __import__('src.prediction_publisher',fromlist=['synthetic_completed']).synthetic_completed())
        self.assertEqual(self.receive(event())['status'],'written')

    def test_conflicting_same_identity_rejected(self):
        value=event();self.receive(value)
        value['source_results_sha256']='f'*64
        with self.assertRaisesRegex(ValueError,'Conflicting'):self.receive(value)

    def test_corrupt_history_rejected_without_append(self):
        self.paths[0].write_bytes(b'broken')
        with self.assertRaises(ValueError):self.receive(event())
        self.assertEqual(self.paths[1].read_bytes(),b'')

    def test_failed_receiver_and_production_path_rejected(self):
        self.paths[1].unlink()
        with self.assertRaises(OSError):self.receive(event())
        with self.assertRaisesRegex(ValueError,'production'):
            receive_local(event(),Path(legacy.LOG_FILE),self.paths[1],self.paths[2])

    def test_hardlinked_ledgers_rejected(self):
        import os
        self.paths[1].unlink();os.link(self.paths[0],self.paths[1])
        with self.assertRaisesRegex(ValueError,'inode'):self.receive(event())

    def test_concurrent_cross_model_submissions_have_one_winner(self):
        from concurrent.futures import ThreadPoolExecutor
        def submit(value):
            try:return self.receive(value)['status']
            except ValueError:return 'rejected'
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(submit,[event(),synthetic_hybrid()]))
        self.assertEqual(sorted(results),['rejected','written'])
        self.assertEqual(sum(len(p.read_text().splitlines()) for p in self.paths[:2]),1)
