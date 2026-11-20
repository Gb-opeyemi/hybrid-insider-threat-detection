"""Synthetic-only publisher/receiver tests; never SSH or read research datasets."""
import copy
import json
import multiprocessing
import re
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

from scripts.integration.receive_ml_prediction import (LOG_FILE, canonical, prediction_id,
    receive, strict_json, validate)
from src.prediction_publisher import from_result, send, synthetic, synthetic_completed, verified_results


def worker(path, queue):
    queue.put(receive(synthetic(), path)['status'])


class ReceiverTests(unittest.TestCase):
    def test_synthetic_roundtrip_and_retry_after_lost_ack(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'new.jsonl'; path.touch()
            event = synthetic()
            self.assertEqual(receive(event, path)['status'], 'written')
            before = path.read_bytes()
            self.assertEqual(receive(copy.deepcopy(event), path)['status'], 'duplicate')
            self.assertEqual(path.read_bytes(), before)
            record = json.loads(before)
            self.assertEqual({k: v for k, v in record.items() if k != 'published_at_utc'}, event)
            self.assertIn('published_at_utc', record)

    def test_changed_prediction_same_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'new.jsonl'; path.touch()
            event = synthetic(); receive(event, path)
            changed = {**event, 'classification': 'benign', 'malicious_probability': .05}
            self.assertEqual(prediction_id(changed), event['prediction_id'])
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, 'Conflicting'):
                receive(changed, path)
            self.assertEqual(path.read_bytes(), before)

    def test_concurrent_submissions_append_once(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'new.jsonl'; path.touch()
            ctx = multiprocessing.get_context('fork')
            queue = ctx.Queue()
            processes = [ctx.Process(target=worker, args=(path, queue)) for _ in range(4)]
            for p in processes: p.start()
            for p in processes:
                p.join(5); self.assertEqual(p.exitcode, 0)
            states = [queue.get(timeout=2) for _ in processes]
            self.assertEqual(states.count('written'), 1)
            self.assertEqual(states.count('duplicate'), 3)
            self.assertEqual(len(path.read_text().splitlines()), 1)

    def test_corrupt_or_partial_ledger_fails_closed(self):
        for content in [b'{"partial":', b'not json\n']:
            with tempfile.TemporaryDirectory() as d:
                path = Path(d) / 'new.jsonl'; path.write_bytes(content)
                with self.assertRaises(ValueError): receive(synthetic(), path)
                self.assertEqual(path.read_bytes(), content)

    def test_no_file_creation_or_symlink_following(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'missing'
            with self.assertRaises(OSError): receive(synthetic(), path)
            target = Path(d) / 'target'; target.touch(); path.symlink_to(target)
            with self.assertRaises(OSError): receive(synthetic(), path)
            self.assertEqual(target.read_bytes(), b'')

    def test_reject_nonfinite_live_mode_extra_fields_and_invalid_identity(self):
        for changes in [{'malicious_probability': float('nan')}, {'malicious_probability': True},
                        {'mode': 'live'}, {'username': 'bad\nname'}, {'Role': 'student'},
                        {'prediction_id': 'f'*64}, {'observation_start': '2027-01-01T00:00:00Z'}]:
            with self.assertRaises(ValueError): validate({**synthetic(), **changes})
        with self.assertRaises(ValueError): strict_json('{"key":1,"key":2}')
        with self.assertRaises(ValueError): strict_json('{"key":NaN}')


class PublisherTests(unittest.TestCase):
    def test_conversion_preserves_result_without_features_or_ground_truth(self):
        event = synthetic()
        original = {'source': 'wazuh_indexer', 'indexer_verified': True, 'feature_parity': 'matched',
            'mode': event['mode'], 'session_id': event['session_id'], 'account': event['username'],
            'observation_period': {'start': event['observation_start'], 'end': event['observation_end']},
            'prediction_cutoff': event['prediction_cutoff'], 'model': event['model'],
            'model_artifact': event['model_artifact'], 'model_sha256': event['model_sha256'],
            'classification': event['classification'], 'malicious_probability': event['malicious_probability'],
            'model_inputs': {'sensitive': 123}, 'ScenarioID': 'DO_NOT_PUBLISH', 'GroundTruthLabel': 1}
        result = from_result(original, '1'*64)
        self.assertEqual(result['malicious_probability'], .95)
        self.assertEqual(result['username'], original['account'])
        self.assertFalse(result['synthetic'])
        for field in ['model_inputs', 'ScenarioID', 'GroundTruthLabel']:
            self.assertNotIn(field, result)
        with self.assertRaises(ValueError): from_result({**original, 'source': 'local_pilot_cache'}, '1'*64)

    def test_ssh_fixed_command_verified_host_and_stdin_payload(self):
        event = synthetic()
        ack = {'prediction_id': event['prediction_id'], 'status': 'written'}
        with patch('src.prediction_publisher.subprocess.run', return_value=subprocess.CompletedProcess([], 0, canonical(ack), '')) as call:
            self.assertEqual(send(event, 'thesis-ml-manager'), ack)
            args, kwargs = call.call_args
            self.assertIn('StrictHostKeyChecking=yes', args[0])
            self.assertIn('BatchMode=yes', args[0])
            self.assertEqual(args[0][-2:], ['thesis-ml-manager', 'publish-ml-prediction'])
            self.assertEqual(json.loads(kwargs['input']), event)
            self.assertNotIn('shell', kwargs)
        with self.assertRaises(ValueError): send(event, '-oProxyCommand=bad')

    def test_invalid_ack_or_ssh_failure_not_success(self):
        for code, stdout in [(255, ''), (0, '{"status":"written","prediction_id":"wrong"}')]:
            with patch('src.prediction_publisher.subprocess.run', return_value=subprocess.CompletedProcess([], code, stdout, '')):
                with self.assertRaises(ValueError): send(synthetic(), 'thesis-ml-manager')

    def test_manifest_tampering_blocks_preparation(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d); (p / 'results.json').write_text('[]')
            (p / 'output_manifest.json').write_text('{"results.json":"wrong"}')
            with self.assertRaises(ValueError): verified_results(p)


class ProposedRuleTests(unittest.TestCase):
    """Predicate checks, NOT a substitute for the native Wazuh logtest engine."""
    def setUp(self):
        self.root = ET.parse('config/phase2_ml_replay_rules.xml').getroot()

    def matching(self, event, location=LOG_FILE):
        matched = set()
        for rule in self.root.findall('rule'):
            parent = rule.findtext('if_sid')
            if parent and parent not in matched: continue
            loc = rule.findtext('location')
            if loc and not re.search(loc, location): continue
            def value(k):
                v = event.get(k, '')
                return str(v).lower() if type(v) is bool else str(v)
            if all(re.search(field.text, value(field.attrib['name'])) for field in rule.findall('field')):
                matched.add(rule.attrib['id'])
        return matched

    def test_synthetic_malicious_and_benign_predicates(self):
        self.assertEqual(self.matching(synthetic()), {'110500', '110501'})
        self.assertEqual(self.matching(synthetic('benign')), {'110500', '110502'})
        self.assertEqual(self.matching(synthetic_completed()), {'110500', '110501'})
        self.assertEqual(self.matching(synthetic_completed('benign')), {'110500', '110502'})
        for rule in self.root.findall('rule')[1:]:
            self.assertIn('HISTORICAL REPLAY', rule.findtext('description'))
            self.assertIn('Not a live incident', rule.findtext('description'))

    def test_other_modes_sources_and_partial_classes_do_not_trigger(self):
        self.assertEqual(self.matching({**synthetic(), 'mode': 'live'}), set())
        self.assertEqual(self.matching(synthetic(), '/var/log/other.jsonl'), set())
        self.assertEqual(self.matching({**synthetic(), 'classification': 'not_malicious'}), {'110500'})
        self.assertEqual(self.matching({**synthetic(), 'event_type': 'other'}), set())

    def test_localfile_points_to_dedicated_json_log(self):
        conf = ET.parse('config/phase2_ml_replay_localfile.xml').getroot()
        self.assertEqual(conf.findtext('location'), LOG_FILE)
        self.assertEqual(conf.findtext('log_format'), 'json')


if __name__ == '__main__':
    unittest.main()
