"""Synthetic operational evidence tests; never query Wazuh or evaluation data."""
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import test_features as fixture
from src import features as ref
from src.controlled_replay.hybrid_session import (
    AlertClient, RULE_FILES, alert_query, fetch_alerts, hybrid_result, main, match_alerts,
    verified_event_context,
)
from src.controlled_replay.indexer import RetrievalError
from src.controlled_replay.new_session import request_window
from src.prediction_publisher import synthetic_completed, sha, canonical
from scripts.integration.receive_ml_prediction import validate as validate_published_prediction


def plan():
    return request_window('EXAMPLE\\example.user', '2026-01-01T10:00:00Z', '2026-01-01T10:01:00Z',
                          ref.timestamp('2026-01-01T00:00:00Z'), now=ref.timestamp('2026-01-02T00:00:00Z'))


class OperationalHybridTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan()
        self.source = fixture.event()
        self.source['rule'] = {'id': '100100', 'level': 5}
        win = self.source['data']['win']
        self.event = ref.Event(win['system'], win['eventdata'], self.source)
        self.index = ref.EvidenceIndex({'example.user'}); self.index.inspect(self.event)
        self.hosts = {self.event.host: 1}; self.digests = {self.event.digest()}

    def match(self, sources):
        return match_alerts([{'index': 'synthetic-alert-index', 'document_id': str(i), 'source': d}
                             for i, d in enumerate(sources)], self.plan, self.index, self.digests, self.hosts)

    def test_four_fusion_combinations_and_unknown(self):
        # A verified negative is a pure fusion input fixture, not a production
        # inference from an empty operational search.
        for rf, wazuh, priority in [(0, 0, 'Low Risk'), (0, 1, 'Needs Review'),
                                     (1, 0, 'Needs Review'), (1, 1, 'High Priority')]:
            e = synthetic_completed('malicious' if rf else 'benign')
            r = hybrid_result(e, {'wazuh_detected': wazuh, 'wazuh_evidence_verified': True})
            self.assertEqual(r['hybrid_priority'], priority)
            self.assertEqual(r['investigation_required'], priority != 'Low Risk')
        r = hybrid_result(synthetic_completed(), self.match([]))
        self.assertIsNone(r['wazuh_detected'])
        self.assertEqual(r['hybrid_priority'], 'Evidence Unavailable')
        with self.assertRaises(ValueError): validate_published_prediction(r)

    def test_real_rule_identity_exact_event_and_duplicate_handling(self):
        r = self.match([self.source, self.source])
        self.assertEqual(r['wazuh_detected'], 1)
        self.assertEqual(r['matched_rule_ids'], ['100100'])
        self.assertEqual(len(r['matched']), 1)

    def test_positive_evidence_json_encodes_digest_without_changing_matching(self):
        evidence = self.match([self.source, self.source])
        self.assertIsInstance(self.event.digest(), bytes)
        self.assertIn(self.event.digest(), self.digests)
        result = hybrid_result(synthetic_completed('malicious'), evidence)
        saved = json.loads(canonical(result))
        digest = saved['wazuh_evidence']['matched'][0]['event_digest']
        self.assertEqual(digest, self.event.digest().hex())
        self.assertEqual(len(digest), 64)
        self.assertEqual(len(saved['wazuh_evidence']['matched']), 1)
        self.assertEqual(saved['hybrid_priority'], 'High Priority')

    def test_incorrect_host_user_namespace_time_and_record_never_assigned(self):
        changes = [('system', 'computer', 'another-host'), ('eventdata', 'subjectUserName', 'another.user'),
                   ('eventdata', 'subjectDomainName', 'OTHER'), ('system', 'systemTime', '2026-01-01T10:02:00Z'),
                   ('system', 'eventRecordID', 'different-record')]
        for section, key, value in changes:
            bad = copy.deepcopy(self.source); bad['data']['win'][section][key] = value
            with self.subTest(key=key): self.assertIsNone(self.match([bad])['wazuh_detected'])

    def test_post_cutoff_alert_and_fusion_publisher_alert_ignored(self):
        bad = copy.deepcopy(self.source); bad['timestamp'] = '2026-01-01T10:06:00.000001Z'
        recursive = copy.deepcopy(self.source); recursive['rule']['id'] = '110501'
        self.assertIsNone(self.match([bad, recursive])['wazuh_detected'])

    def test_watcher_summary_missing_clock_and_incomplete_coverage_unknown(self):
        summary = {'timestamp': '2026-01-01T10:00:30Z', 'rule': {'id': '100301'},
                   'data': {'m03': {'username': 'example.user', 'unique_files': '40'}}}
        missing = copy.deepcopy(self.source); del missing['timestamp']
        r = self.match([summary, missing])
        self.assertIsNone(r['wazuh_detected'])
        self.assertEqual(len(r['unresolved']), 2)
        self.assertFalse(r['negative_decision_verified'])
        # A proven positive remains an OR-positive even with unresolved others.
        self.assertEqual(self.match([summary, self.source])['wazuh_detected'], 1)

    def test_context_reuses_reference_attribution_and_excludes_artifacts(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'capture.jsonl'
            path.write_text(json.dumps(self.source) + '\n')
            _, digests = verified_event_context(path, self.plan, self.hosts)
            self.assertEqual(digests, self.digests)
            artifact = copy.deepcopy(self.source)
            artifact['data']['win']['eventdata']['relativeTargetName'] = 'M05Results\\worker.json'
            path.write_text(json.dumps(artifact) + '\n')
            _, digests = verified_event_context(path, self.plan, self.hosts)
            self.assertEqual(digests, set())

    def test_query_includes_summaries_and_never_ml_alerts(self):
        q = alert_query(self.plan, 'keyword')
        self.assertNotIn('110501', str(q))
        self.assertIn('100301', str(q))
        self.assertIn(self.plan['prediction_cutoff'], str(q))
        self.assertNotIn('example.user', str(q))  # Identity assessed after full evidence query.

    def test_alert_client_keeps_read_only_endpoint_policy(self):
        with patch('src.controlled_replay.indexer.tls_context'):
            with patch('src.controlled_replay.indexer.build_opener'):
                c = AlertClient('https://example.invalid', 'wazuh-alerts-*', 'synthetic', 'synthetic', None)
        self.assertEqual(c.pattern, 'wazuh-alerts-*')
        with self.assertRaises(RetrievalError): c.request('PUT', '/wazuh-alerts-*/_doc/test', {})
        with self.assertRaises(ValueError): AlertClient('https://example.invalid', '*', 'x', 'x', None)

    def test_partial_query_rejected_and_context_cleaned(self):
        class Client:
            pattern = 'wazuh-alerts-*'; tls_profile = 'strict'
            def __init__(self): self.cleaned = False
            def request(self, method, path, body=None):
                if method == 'GET': return {'ignored': {}}
                if method == 'DELETE': self.cleaned = True; return {}
                return {'_scroll_id': 'synthetic', 'timed_out': False, '_shards': {'total': 2, 'failed': 1}}
        client = Client()
        with patch('src.controlled_replay.hybrid_session.validate_mapping', return_value='keyword'):
            # Supply actual mapping shape before testing partial-response handling.
            original = client.request
            def request(method, path, body=None):
                if method == 'GET': return {'index': {'mappings': {'properties': {'rule': {'properties': {'id': {'type': 'keyword'}}}}}}}
                return original(method, path, body)
            client.request = request
            with self.assertRaises(RetrievalError): fetch_alerts(client, self.plan)
        self.assertTrue(client.cleaned)

    def test_cli_query_failure_produces_unknown_without_any_publication(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve(); run = root / 'session'; run.mkdir()
            (root / 'src').mkdir(); (root / 'src/hybrid_priority.py').write_text('# synthetic provenance fixture')
            (run / 'request.json').write_text(json.dumps(self.plan))
            (run / 'validation.json').write_text(json.dumps({'accepted_behavior_hosts': self.hosts}))
            (run / 'output_manifest.json').write_text('{}')
            for name in RULE_FILES:
                path = root / 'data/wazuh/etc/rules' / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('<group/>')
            keys = ('WAZUH_INDEXER_URL', 'WAZUH_INDEXER_USERNAME', 'WAZUH_INDEXER_PASSWORD', 'WAZUH_INDEXER_CA_CERT')
            for configured in (True, False):
                out = root / 'data/experiments' / str(configured)
                with patch('src.controlled_replay.hybrid_session.Path.cwd', return_value=root), \
                     patch.dict(os.environ, dict.fromkeys(keys, 'synthetic') if configured else {}, clear=True), \
                     patch('src.controlled_replay.hybrid_session.verified_completed_session',
                           return_value=([synthetic_completed()], sha(run / 'output_manifest.json'))), \
                     patch('src.controlled_replay.hybrid_session.verified_event_context', return_value=(self.index, self.digests)), \
                     patch('src.controlled_replay.hybrid_session.AlertClient', side_effect=RetrievalError('synthetic failure')) as client, \
                     redirect_stdout(io.StringIO()):
                    code = main(['--session-dir', str(run), '--output-dir', str(out)])
                self.assertEqual(code, 0)
                result = json.loads((out / 'hybrid_result.json').read_text())
                self.assertIsNone(result['wazuh_detected'])
                self.assertTrue(result['investigation_required'])
                self.assertFalse(result['alerts_published'])
                expected = 'query_failed_or_unavailable' if configured else 'configuration_missing'
                self.assertEqual(result['wazuh_evidence']['evidence_status'], expected)
                if configured:
                    client.assert_called_once()
                else:
                    client.assert_not_called()
                    self.assertEqual(result['wazuh_evidence']['missing_environment_variables'], list(keys))
                    audit = json.loads((out / 'alert_retrieval_audit.json').read_text())
                    self.assertFalse(audit['network_attempted'])

    def test_cli_positive_output_and_serialization_failure_are_separate_from_rf_gate(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve(); run = root / 'session'; run.mkdir()
            (root / 'src').mkdir(); (root / 'src/hybrid_priority.py').write_text('# synthetic provenance')
            (run / 'request.json').write_text(json.dumps(self.plan))
            (run / 'validation.json').write_text(json.dumps({'accepted_behavior_hosts': self.hosts}))
            (run / 'output_manifest.json').write_text('{}')
            for name in RULE_FILES:
                path = root / 'data/wazuh/etc/rules' / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('<group/>')
            rows = [{'index': 'synthetic-index', 'document_id': 'one', 'source': self.source}]
            for bad_metadata in (False, True):
                out = root / 'data/experiments' / str(bad_metadata)
                # Exercise the real positive fusion/serialization path first,
                # then check that a future metadata mistake is labelled correctly.
                def make_result(event, evidence):
                    return {'not_json': b'\x00'} if bad_metadata else hybrid_result(event, evidence)
                with patch('src.controlled_replay.hybrid_session.Path.cwd', return_value=root), \
                     patch.dict(os.environ, dict.fromkeys(('WAZUH_INDEXER_URL', 'WAZUH_INDEXER_USERNAME',
                                     'WAZUH_INDEXER_PASSWORD', 'WAZUH_INDEXER_CA_CERT'), 'synthetic'), clear=True), \
                     patch('src.controlled_replay.hybrid_session.verified_completed_session',
                           return_value=([synthetic_completed()], sha(run / 'output_manifest.json'))), \
                     patch('src.controlled_replay.hybrid_session.verified_event_context', return_value=(self.index, self.digests)), \
                     patch('src.controlled_replay.hybrid_session.AlertClient'), \
                     patch('src.controlled_replay.hybrid_session.fetch_alerts',
                           side_effect=lambda *a, **kw: (rows, {'status': 'query_verified', 'completed_stages': []})), \
                     patch('src.controlled_replay.hybrid_session.hybrid_result', side_effect=make_result), \
                     redirect_stdout(io.StringIO()):
                    code = main(['--session-dir', str(run), '--output-dir', str(out)])
                status = json.loads((out / 'run_status.json').read_text())
                if bad_metadata:
                    self.assertEqual(code, 2)
                    self.assertEqual(status['failure']['failing_stage'], 'hybrid_result_serialization')
                    self.assertEqual(status['failure']['exception_type'], 'TypeError')
                    self.assertFalse((out / 'hybrid_result.json').exists())
                else:
                    self.assertEqual(code, 0)
                    self.assertEqual(status['status'], 'completed_dry_run')
                    saved = json.loads((out / 'hybrid_result.json').read_text())
                    self.assertEqual(saved['hybrid_priority'], 'High Priority')


if __name__ == '__main__': unittest.main()
