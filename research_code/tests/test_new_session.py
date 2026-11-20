"""New-session tests use synthetic telemetry and mocked network/models only."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import numpy as np

import test_features as fixture
from src import features as ref
from src.controlled_replay.new_session import (check_competing_windows, extract_completed,
    main, new_data_boundary, request_window, compare_runs)

NAMES = [n for n in ref.MODEL_INPUTS if n != 'scp_process_count']
BOUNDARY = ref.timestamp('2026-01-01T00:00:00Z')
NOW = ref.timestamp('2026-01-02T00:00:00Z')


def plan(username='example.user'):
    return request_window(username, '2026-01-01T10:00:00Z', '2026-01-01T10:01:00Z', BOUNDARY, now=NOW)


class NewSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def capture(self, events):
        path = self.root / 'events.jsonl'
        path.write_text(''.join(json.dumps(e) + '\n' for e in events))
        return path

    def test_reference_extractor_parity_all_23_features(self):
        items = [fixture.event(), fixture.event(eid='4663', record='2', data={
            'subjectUserName': 'example.user', 'subjectDomainName': 'EXAMPLE', 'objectType': 'File',
            'objectName': 'C:\\synthetic.txt', 'accessMask': '0x10003'})]
        path = self.capture(items)
        values, audit = extract_completed(path, plan(), NAMES)
        with redirect_stdout(io.StringIO()):
            rows, _ = ref.extract([fixture.ground()], fixture.ledger(), [path], [],
                                  BOUNDARY, NOW, padding=2)
        expected = {n: None if rows[0][n] == '' else rows[0][n] for n in NAMES}
        self.assertEqual(values, expected)
        self.assertEqual(audit['status'], 'eligible')
        self.assertIsNone(values['object_deletion_event_count'])

    def test_duplicates_orchestration_and_other_accounts(self):
        normal = fixture.event()
        artifact = fixture.event(record='artifact'); artifact['data']['win']['eventdata']['relativeTargetName'] = 'M05Results\\fake.json'
        other = fixture.event(record='other'); other['data']['win']['eventdata']['subjectUserName'] = 'other.user'
        values, audit = extract_completed(self.capture([normal, normal, artifact, other]), plan(), NAMES)
        self.assertEqual(values['windows_event_count'], 1)
        self.assertEqual(audit['counts']['duplicate_attributed'], 1)
        self.assertEqual(audit['counts']['orchestration_excluded'], 1)

    def test_invalid_or_future_receipt_capture_rejected(self):
        for at in [None, '2026-01-01T10:06:00.000001Z']:
            e = fixture.event(); e['timestamp'] = at
            with self.assertRaises(ValueError): extract_completed(self.capture([e]), plan(), NAMES)

    def test_default_cutoff_is_separate_from_event_window(self):
        p = plan()
        self.assertEqual(p['observation_start'], '2026-01-01T09:59:58Z')
        self.assertEqual(p['observation_end'], '2026-01-01T10:01:02Z')
        self.assertEqual(p['prediction_cutoff'], '2026-01-01T10:06:00Z')
        self.assertEqual(p['availability_delay_seconds'], 300)
        for seconds in [True, 1, -1, 2.5]:
            with self.assertRaises(ValueError):
                request_window('example.user', p['actual_start'], p['actual_end'], BOUNDARY,
                               now=NOW, availability_delay_seconds=seconds)

    def test_cutoff_must_have_passed_before_processing(self):
        with self.assertRaisesRegex(ValueError, 'availability cutoff'):
            request_window('example.user', '2026-01-01T10:00:00Z', '2026-01-01T10:01:00Z',
                           BOUNDARY, now=ref.timestamp('2026-01-01T10:05:59.999999Z'))
        p = request_window('example.user', '2026-01-01T10:00:00Z', '2026-01-01T10:01:00Z',
                           BOUNDARY, now=ref.timestamp('2026-01-01T10:06:00Z'))
        self.assertEqual(p['prediction_cutoff'], '2026-01-01T10:06:00Z')

    def test_five_minute_receipt_boundary_and_60_second_override(self):
        e = fixture.event(at='2026-01-01T10:01:00Z')
        e['timestamp'] = '2026-01-01T10:06:00Z'
        values, audit = extract_completed(self.capture([e]), plan(), NAMES)
        self.assertEqual(values['windows_event_count'], 1)
        self.assertEqual(audit['status'], 'eligible')
        self.assertEqual(audit['telemetry_availability']['behavioral_events_after_original_cutoff'], 1)
        shorter = request_window('example.user', plan()['actual_start'], plan()['actual_end'], BOUNDARY,
                                 now=NOW, availability_delay_seconds=60)
        with self.assertRaises(ValueError): extract_completed(self.capture([e]), shorter, NAMES)
        self.assertEqual(shorter['observation_end'], plan()['observation_end'])

    def test_missing_features_are_flagged_without_claiming_completeness(self):
        _, audit = extract_completed(self.capture([fixture.event()]), plan(), NAMES)
        completeness = audit['telemetry_completeness']
        self.assertIsNone(completeness['complete'])
        self.assertEqual(completeness['status'], 'potentially_incomplete')
        self.assertEqual(completeness['missing_features'], audit['missing_features'])
        self.assertTrue(completeness['review_required'])

    def test_late_event_included_but_later_generated_activity_excluded(self):
        late = fixture.event(); late['timestamp'] = '2026-01-01T10:02:00Z'
        outside = fixture.event(at='2026-01-01T10:01:03Z', record='outside')
        outside['timestamp'] = '2026-01-01T10:01:04Z'
        values, audit = extract_completed(self.capture([late, late, outside]), plan(), NAMES)
        self.assertEqual(values['windows_event_count'], 1)
        self.assertEqual(audit['counts']['duplicate_attributed'], 1)
        self.assertEqual(audit['telemetry_availability']['in_window_documents_after_original_cutoff'], 2)
        self.assertEqual(audit['telemetry_availability']['behavioral_events_after_original_cutoff'], 1)
        self.assertEqual(audit['telemetry_availability']['behavior_receipt_minus_event_seconds_max'],
                         (ref.timestamp(late['timestamp']) - ref.timestamp(late['data']['win']['system']['systemTime'])).total_seconds())

    def test_configurable_old_cutoff_and_unchanged_missing_features(self):
        old = request_window('example.user', '2026-01-01T10:00:00Z', '2026-01-01T10:01:00Z',
                             BOUNDARY, now=NOW, availability_delay_seconds=2)
        path = self.capture([fixture.event()])
        before, before_audit = extract_completed(path, old, NAMES)
        after, after_audit = extract_completed(path, plan(), NAMES)
        self.assertEqual(before, after)
        self.assertEqual(before_audit['missing_features'], after_audit['missing_features'])

    def test_preserved_prediction_comparison_checks_boundaries(self):
        old, new = self.root / 'old', self.root / 'new'
        old.mkdir(); new.mkdir()
        p = plan()
        for path in [old, new]:
            (path / 'request.json').write_text(json.dumps(p))
            (path / 'run_status.json').write_text('{"status":"completed"}')
        (old / 'result.json').write_text('{"classification":"benign","malicious_probability":0.375}')
        (new / 'result.json').write_text('{"classification":"benign","malicious_probability":0.1}')
        result = compare_runs(old, new)
        self.assertEqual(result['previous_prediction']['malicious_probability'], .375)
        self.assertEqual(result['current_prediction']['malicious_probability'], .1)
        p['actual_end'] = '2026-01-01T11:00:00Z'
        (new / 'request.json').write_text(json.dumps(p))
        with self.assertRaises(ValueError): compare_runs(old, new)

    def test_future_identity_evidence_cannot_repair_an_earlier_event(self):
        first = fixture.event()
        first['data']['win']['eventdata']['subjectDomainName'] = ''
        later = fixture.event(at='2026-01-01T10:00:30Z', record='later')
        _, audit = extract_completed(self.capture([first, later]), plan('EXAMPLE\\example.user'), NAMES)
        self.assertEqual(audit['status'], 'blocked')
        self.assertIn('requested_namespace_not_verified_as_of_event', audit['reasons'])

    def test_unqualified_event_retains_reference_features_and_explicit_warning(self):
        e = fixture.event(); e['data']['win']['eventdata']['subjectDomainName'] = ''
        path = self.capture([e])
        values, audit = extract_completed(path, plan(), NAMES)
        with redirect_stdout(io.StringIO()):
            rows, _ = ref.extract([fixture.ground()], fixture.ledger(), [path], [], BOUNDARY, NOW, padding=2)
        self.assertEqual(values, {n: None if rows[0][n] == '' else rows[0][n] for n in NAMES})
        self.assertEqual(audit['counts']['requested_account_namespace_unknown_as_of_event'], 1)
        self.assertTrue(any('namespace is not proven' in w for w in audit['limitations']))

    def test_wrong_domain_is_not_silently_collapsed_to_basename(self):
        _, audit = extract_completed(self.capture([fixture.event()]), plan('WRONG\\example.user'), NAMES)
        self.assertEqual(audit['status'], 'blocked')
        self.assertIn('requested_namespace_not_verified_as_of_event', audit['reasons'])

    def test_conflicting_namespaces_without_sid_alias_evidence_block(self):
        first = fixture.event()
        other = fixture.event(record='other', at='2026-01-01T10:00:30Z')
        other['data']['win']['eventdata']['subjectDomainName'] = 'OTHER'
        _, audit = extract_completed(self.capture([first, other]), plan(), NAMES)
        self.assertIn('requested_account_identity_unresolved', audit['reasons'])

    def test_host_process_guid_linkage_is_reused(self):
        create = fixture.event(eid='1', provider=ref.SYSMON, at='2026-01-01T09:59:00Z', record='create',
            data={'user': 'EXAMPLE\\example.user', 'processGuid': '{synthetic}', 'image': 'C:\\tools\\sftp.exe'})
        network = fixture.event(eid='3', provider=ref.SYSMON, record='network', data={
            'processGuid': '{synthetic}', 'image': 'C:\\tools\\sftp.exe', 'destinationIp': '192.0.2.1',
            'destinationPort': '22', 'initiated': 'true'})
        values, audit = extract_completed(self.capture([create, network]), plan(), NAMES)
        self.assertEqual(audit['status'], 'eligible')
        self.assertEqual(audit['counts']['process_guid_linked'], 1)
        self.assertEqual(values['sftp_network_connection_count'], 1)
        self.assertEqual(values['process_create_count'], 0)

    def test_no_activity_abstains_and_never_fabricates_zeros(self):
        e = fixture.event(at='2026-01-01T09:00:00Z')
        values, audit = extract_completed(self.capture([e]), plan(), NAMES)
        self.assertEqual(audit['status'], 'blocked')
        self.assertTrue(all(v is None for v in values.values()))

    def test_unknown_timezone_reversed_future_and_original_period_rejected(self):
        args = [
            ('2026-01-01T10:00:00', '2026-01-01T10:01:00Z'),
            ('2026-01-01T10:01:00Z', '2026-01-01T10:00:00Z'),
            ('2026-01-03T10:00:00Z', '2026-01-03T10:01:00Z'),
            ('2025-12-31T10:00:00Z', '2025-12-31T10:01:00Z')]
        for start, end in args:
            with self.assertRaises(ValueError): request_window('example.user', start, end, BOUNDARY, now=NOW)
        with self.assertRaises(ValueError): request_window('example.user', '2026-01-01T10:00:00Z',
            '2026-01-01T10:01:00Z', BOUNDARY, '2025-12-31T00:00:00Z', now=NOW)

    def test_known_padded_overlap_rejected(self):
        p = plan()
        with self.assertRaisesRegex(ValueError, 'overlap'):
            check_competing_windows(p, [{'username': 'EXAMPLE\\example.user',
                'start': '2026-01-01T10:01:01Z', 'end': '2026-01-01T10:02:00Z'}], now=NOW)
        check_competing_windows(p, [{'username': 'other.user',
            'start': '2026-01-01T10:00:00Z', 'end': '2026-01-01T10:01:00Z'}], now=NOW)

    def test_original_dataset_and_recovery_day_are_outside_new_query_scope(self):
        (self.root / 'config').mkdir()
        (self.root / 'config/experiment.json').write_text('{"end_date":"2026-11-08"}')
        self.assertEqual(new_data_boundary(self.root), ref.timestamp('2026-11-10T00:00:00Z'))

    def test_large_matched_clock_disagreement_blocks_prediction(self):
        e = fixture.event(); e['timestamp'] = '2026-01-01T10:00:30Z'
        e['data']['win']['system']['systemTime'] = '2026-01-01T09:59:59Z'
        # Broaden only the synthetic session to include a >300s clock gap.
        p = request_window('example.user', '2026-01-01T09:50:00Z', '2026-01-01T10:01:00Z', BOUNDARY, now=NOW)
        e['data']['win']['system']['systemTime'] = '2026-01-01T09:51:00Z'
        _, audit = extract_completed(self.capture([e]), p, NAMES)
        self.assertIn('clock_disagreement_over_300s', audit['reasons'])

    def test_cli_predicts_locally_only_with_fixed_feature_frame(self):
        output = self.root / 'data/experiments/new'
        model = SimpleNamespace(predict=Mock(return_value=np.array([0])),
                                predict_proba=Mock(return_value=np.array([[.8, .2]])))
        imputer = SimpleNamespace(transform=lambda frame: frame.fillna(0).to_numpy())
        info = {'training_missing_counts': dict.fromkeys(NAMES, 0)}
        def capture(client, start, cutoff, path, **kw):
            self.assertEqual(kw['event_start'], BOUNDARY)
            path.write_text(json.dumps(fixture.event()) + '\n')
            return {'source': 'wazuh_indexer', 'retrieved_documents': 1}
        artifact_hashes = {str(self.root / 'models/random_forest_baseline.joblib'): 'synthetic'}
        # Create a synthetic file/hash for immutable-input verification.
        from src.ground_truth import sha256
        model_file = self.root / 'models/random_forest_baseline.joblib'
        model_file.parent.mkdir(); model_file.write_bytes(b'synthetic; never deserialized')
        artifact_hashes[str(model_file)] = sha256(model_file)
        env = dict.fromkeys(['WAZUH_INDEXER_URL','WAZUH_INDEXER_INDEX_PATTERN','WAZUH_INDEXER_CA_CERT',
                            'WAZUH_INDEXER_USERNAME','WAZUH_INDEXER_PASSWORD'], 'synthetic')
        with patch.dict(os.environ, env), patch('src.controlled_replay.new_session.new_data_boundary', return_value=BOUNDARY), \
             patch('src.controlled_replay.new_session.load_artifacts', return_value=(NAMES, model, imputer, info, artifact_hashes)), \
             patch('src.controlled_replay.new_session.IndexerClient') as client, redirect_stdout(io.StringIO()):
            client.return_value.capture.side_effect = lambda *a, **kw: capture(None, *a, **kw)
            code = main(['--root', str(self.root), '--username', 'example.user', '--start', '2026-01-01T10:00:00Z',
                         '--end', '2026-01-01T10:01:00Z', '--output-dir', str(output)])
        self.assertEqual(code, 0, (output / 'run_status.json').read_text())
        result = json.loads((output / 'result.json').read_text())
        self.assertEqual(result['telemetry_availability']['availability_delay_seconds'], 300)
        self.assertIsNone(result['telemetry_completeness']['complete'])
        self.assertFalse(result['alerts_published'])
        self.assertEqual(result['classification'], 'benign')
        self.assertEqual(result['malicious_probability'], .2)
        self.assertEqual(list(model.predict.call_args.args[0]), NAMES)
        self.assertEqual(len(result['model_inputs']), 23)


if __name__ == '__main__':
    unittest.main()
