"""Synthetic publication, provenance and mixed-ledger checks; never SSH."""
import copy
import json
from pathlib import Path
import re
import subprocess
import tempfile
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
import xml.etree.ElementTree as ET

from scripts.integration.receive_ml_prediction import (receive, validate_hybrid, prediction_id, strict_json,
                                                       LOG_FILE, HYBRID_POLICY)
from src.hybrid_priority import FUSION_POLICY_VERSION
from src.hybrid_publisher import synthetic_hybrid, verified_hybrid, main
from src.prediction_publisher import synthetic, synthetic_completed, send, _ssh_send, sha
from src.controlled_replay.hybrid_session import RULE_FILES, alert_query, hybrid_result


class HybridReceiverTests(unittest.TestCase):
    def test_distinct_identity_legacy_coexistence_and_retries(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / 'log'; log.touch()
            for event in (synthetic(), synthetic_completed(), synthetic_hybrid()):
                self.assertEqual(receive(event, log)['status'], 'written')
                before = log.read_bytes()
                self.assertEqual(receive(event, log)['status'], 'duplicate')
                self.assertEqual(log.read_bytes(), before)
            records = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(len(records), 3)
            self.assertEqual(len({r['prediction_id'] for r in records}), 3)
            self.assertTrue(all('published_at_utc' in r for r in records))
            self.assertEqual(records[-1]['unresolved_alert_count'], 1)

    def test_changed_prediction_same_identity_conflicts(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / 'log'; log.touch(); event = synthetic_hybrid(); receive(event, log)
            changed = {**event, 'source_results_sha256': '1'*64}
            self.assertEqual(prediction_id(changed), event['prediction_id'])
            with self.assertRaisesRegex(ValueError, 'Conflicting'): receive(changed, log)
            self.assertEqual(len(log.read_text().splitlines()), 1)

    def test_unverified_missing_negative_and_malformed_evidence_rejected(self):
        changes = [{'wazuh_evidence_verified': False}, {'wazuh_detected': None}, {'wazuh_detected': 0},
                   {'wazuh_detected': True}, {'matched_rule_ids': ''}, {'verified_matching_alerts': 0},
                   {'unresolved_rule_ids': ''}, {'telemetry_completeness_status': 'complete'},
                   {'rf_malicious_probability': float('nan')}, {'rf_malicious_probability': True},
                   {'fusion_policy_version': 'other'}, {'investigation_required': False},
                   {'hybrid_priority': 'Low Risk'}, {'prediction_id': '0'*64}, {'extra': 'not allowed'},
                   {'mode': 'live'}, {'rf_prediction_id': '0'*64}]
        for change in changes:
            with self.subTest(change=list(change)), self.assertRaises(ValueError):
                validate_hybrid({**synthetic_hybrid(), **change})
        with self.assertRaises(ValueError): strict_json('{"a":1,"a":2}')

    def test_rf_publication_workflow_still_refuses_hybrid_payload(self):
        with patch('src.prediction_publisher.subprocess.run') as network:
            with self.assertRaises(ValueError): send(synthetic_hybrid(), 'thesis-ml-manager')
            network.assert_not_called()

    def test_shared_ssh_transport_checks_receiver_errors(self):
        event = synthetic_hybrid()
        for code, response in [(2, ''), (0, '{"status":"written","prediction_id":"wrong"}')]:
            with patch('src.prediction_publisher.subprocess.run', return_value=subprocess.CompletedProcess([], code, response, 'hidden')):
                with self.assertRaises(ValueError): _ssh_send(event, 'thesis-ml-manager', validate_hybrid)
        ack = {'status': 'written', 'prediction_id': event['prediction_id']}
        with patch('src.prediction_publisher.subprocess.run', return_value=subprocess.CompletedProcess([], 0, json.dumps(ack), '')) as call:
            self.assertEqual(_ssh_send(event, 'thesis-ml-manager', validate_hybrid), ack)
            self.assertIn('StrictHostKeyChecking=yes', call.call_args.args[0])
            self.assertEqual(json.loads(call.call_args.kwargs['input']), event)

    def test_invalid_prepared_directory_never_reaches_ssh(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve(); prepared=root/'bad'; prepared.mkdir()
            (prepared/'manifest.json').write_text('{}')
            out=root/'data/experiments/send'
            with patch('src.hybrid_publisher.Path.cwd',return_value=root), \
                 patch('src.hybrid_publisher._ssh_send') as transport, redirect_stdout(io.StringIO()):
                code=main(['send','--prepared-dir',str(prepared),'--ssh-host','thesis-ml-manager','--output-dir',str(out)])
            self.assertEqual(code,2)
            transport.assert_not_called()
            self.assertEqual(json.loads((out/'receipt.json').read_text())['status'],'blocked')
            self.assertEqual(json.loads((out/'receipt.json').read_text())['failed_stage'],'prepared_source_verification')


class HybridProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.source = self.root / 'data/experiments/new_completed_sessions/synthetic'
        self.run = self.root / 'data/experiments/hybrid_session_phase1/synthetic'
        self.source.mkdir(parents=True); self.run.mkdir(parents=True)
        self.rf = synthetic_completed()
        self.rf['synthetic'] = False
        self.rf['prediction_id'] = prediction_id(self.rf)
        self.plan = {'observation_start': self.rf['observation_start'], 'observation_end': self.rf['observation_end'],
                     'evidence_start': '2026-01-01T00:00:00Z', 'prediction_cutoff': self.rf['prediction_cutoff']}
        self.write(self.source / 'request.json', self.plan)
        self.write(self.source / 'validation.json', {'accepted_behavior_hosts': {'synthetic-host': 1}})
        for name in ('result.json', 'provenance.json', 'retrieved_events.jsonl'): self.write(self.source / name, {})
        self.write(self.source / 'output_manifest.json', {p.name: sha(p) for p in self.source.iterdir()})
        self.evidence = {'wazuh_detected': 1, 'wazuh_evidence_verified': True, 'evidence_status': 'verified_positive',
                         'matched_rule_ids': ['100100'], 'matched': [{'rule_id': '100100'}], 'unresolved': [], 'rejected': []}
        self.result = hybrid_result(self.rf, self.evidence)
        self.write(self.run / 'hybrid_result.json', self.result)
        self.write(self.run / 'run_status.json', {'status': 'completed_dry_run', 'dry_run': True,
            'alerts_published': False, 'test_partition_accessed': False, 'hybrid_priority': self.result['hybrid_priority'],
            'investigation_required': True, 'wazuh_evidence_status': 'verified_positive'})
        self.write(self.run / 'alert_retrieval_audit.json', {'status': 'query_verified', 'complete_scroll': True,
            'certificate_verification_required': True, 'hostname_verification': True, 'documents': 1,
            'mapping_field_types': [{'data.win.system.systemTime': 'keyword'}], 'query': alert_query(self.plan, 'keyword')})
        (self.run / 'retrieved_alerts.jsonl').write_text(json.dumps({'index': 'synthetic', 'document_id': 'one', 'source': {}})+'\n')
        code_paths = [self.root/'src/controlled_replay/hybrid_session.py', self.root/'src/hybrid_priority.py']
        rule_paths = [self.root/'data/wazuh/etc/rules'/n for n in RULE_FILES]
        for path in code_paths + rule_paths:
            path.parent.mkdir(parents=True, exist_ok=True); path.write_text('synthetic provenance fixture')
        self.write(self.run / 'provenance.json', {'source_session_dir': str(self.source),
            'session_manifest_sha256': sha(self.source/'output_manifest.json'),
            'code_sha256': {str(p):sha(p) for p in code_paths},
            'frozen_rule_files_sha256': {str(p):sha(p) for p in rule_paths},
            'operational_source': 'actual_indexer_alerts; no retrospective baseline substitution'})
        self.remanifest()

    @staticmethod
    def write(path, value): path.write_text(json.dumps(value))

    def remanifest(self):
        self.write(self.run/'output_manifest.json', {p.name:sha(p) for p in self.run.iterdir() if p.name!='output_manifest.json'})

    def verify(self):
        with patch('src.hybrid_publisher.verified_completed_session', return_value=([self.rf],sha(self.source/'output_manifest.json'))) as gate, \
             patch('src.hybrid_publisher.verified_event_context', return_value=(None,set())), \
             patch('src.hybrid_publisher.match_alerts', return_value=self.evidence):
            result = verified_hybrid(self.run,self.root)
            gate.assert_called_once_with(self.source,self.root)
            return result

    def test_valid_saved_result_reverified_and_minimal_payload_created(self):
        event,_ = self.verify()
        self.assertEqual(event['event_type'],'thesis_hybrid_priority')
        self.assertEqual(event['rf_prediction_id'], self.rf['prediction_id'])
        self.assertNotEqual(event['prediction_id'],self.rf['prediction_id'])
        self.assertNotIn('model_inputs',event)

    def test_manifest_provenance_unverified_evidence_and_recomputed_mismatch(self):
        original = (self.run/'hybrid_result.json').read_text()
        (self.run/'hybrid_result.json').write_text('tampered')
        with self.assertRaises(ValueError): self.verify()
        (self.run/'hybrid_result.json').write_text(original)
        for key,value in [('wazuh_evidence_verified',False),('session_id','00000000-0000-4000-8000-000000000001'),
                          ('rf_malicious_probability',.2),('hybrid_priority','Low Risk')]:
            changed = copy.deepcopy(self.result); changed[key] = value
            self.write(self.run/'hybrid_result.json',changed); self.remanifest()
            with self.subTest(key=key), self.assertRaises(ValueError): self.verify()
        (self.run/'hybrid_result.json').write_text(original); self.remanifest()
        path=self.run/'provenance.json'; doc=json.loads(path.read_text());doc['operational_source']='offline approximation'
        self.write(path,doc);self.remanifest()
        with self.assertRaises(ValueError): self.verify()


class HybridRuleTests(unittest.TestCase):
    def test_distinct_rule_ids_and_predicates(self):
        root=ET.parse('config/phase3_hybrid_priority_rules.xml').getroot()
        self.assertEqual(HYBRID_POLICY,FUSION_POLICY_VERSION)
        self.assertEqual({r.attrib['id'] for r in root}, {'110510','110511','110512'})
        legacy={r.attrib['id'] for r in ET.parse('config/phase2_ml_replay_rules.xml').getroot()}
        self.assertFalse(legacy & {r.attrib['id'] for r in root})
        for event,expected in [(synthetic_hybrid(),{'110510','110511'}),
                               (synthetic_hybrid(False),{'110510','110512'}), (synthetic(),set())]:
            matched=set()
            for rule in root:
                parent=rule.findtext('if_sid')
                if parent and parent not in matched:continue
                if rule.findtext('location') and not re.search(rule.findtext('location'),LOG_FILE):continue
                def value(k):
                    v=event.get(k,'');return str(v).lower() if type(v) is bool else str(v)
                if all(re.search(f.text,value(f.attrib['name'])) for f in rule.findall('field')):
                    matched.add(rule.attrib['id'])
            self.assertEqual(matched,expected)


if __name__=='__main__':unittest.main()
