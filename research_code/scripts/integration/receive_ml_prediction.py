#!/usr/bin/env python3
"""Standalone forced-SSH receiver. Stdlib only; one validated JSON per request.

The pre-provisioned JSONL file is also the durable deduplication ledger. Never
rotate/truncate/delete it without preserving the ledger (see deployment guide).
"""
import argparse
import fcntl
import hashlib
import json
import math
import os
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, NAMESPACE_URL, uuid5

LOG_FILE = '/var/log/thesis-ml/predictions.jsonl'
MAX_BYTES = 8192
FIELDS = {'schema_version', 'event_type', 'mode', 'historical_replay', 'synthetic',
          'prediction_id', 'session_id', 'username', 'observation_start', 'observation_end',
          'prediction_cutoff', 'model', 'model_artifact', 'model_sha256', 'classification',
          'malicious_probability', 'source_results_sha256'}
SESSION_FIELDS = {'source_mode', 'session_id_source', 'activity_start', 'activity_end',
                  'benign_probability', 'prediction_score', 'telemetry_completeness_status',
                  'telemetry_review_required', 'telemetry_missing_features'}
HYBRID_FIELDS = {'schema_version', 'event_type', 'mode', 'historical_replay', 'synthetic',
    'prediction_id', 'session_id', 'session_id_source', 'username', 'activity_start', 'activity_end',
    'observation_start', 'observation_end', 'prediction_cutoff', 'model', 'model_artifact', 'model_sha256',
    'source_results_sha256', 'rf_prediction_id', 'rf_classification', 'rf_malicious_probability',
    'wazuh_detected', 'wazuh_evidence_verified', 'wazuh_evidence_status', 'matched_rule_ids',
    'verified_matching_alerts', 'unresolved_alert_count', 'unresolved_rule_ids', 'unresolved_evidence_reasons',
    'hybrid_priority', 'investigation_required', 'fusion_policy_version',
    'telemetry_completeness_status', 'telemetry_review_required', 'telemetry_missing_features'}
HYBRID_POLICY = 'rf_wazuh_priority_v1_exploratory'
CUSTOM_RULE_IDS = {'100100', '100101', '100200', '100201', '100301', '100401', '100501'}


def completed_session_id(username, start, end):
    """Stable integration ID, not a fabricated simulation/ledger SessionID."""
    return str(uuid5(NAMESPACE_URL, 'thesis-ml-completed-session:' + canonical(
        [username.casefold(), start, end])))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def prediction_id(event):
    identity = {k: event[k] for k in ['schema_version', 'event_type', 'mode', 'synthetic',
        'session_id', 'observation_start', 'observation_end', 'model_sha256']}
    return hashlib.sha256(canonical(identity).encode()).hexdigest()


def utc(value):
    if not isinstance(value, str) or len(value) > 40 or not value.endswith('Z'):
        raise ValueError('UTC timestamps with Z suffix required')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return parsed


def validate_ml(event):
    if not isinstance(event, dict) or set(event) not in (FIELDS, FIELDS | SESSION_FIELDS):
        raise ValueError('Unexpected prediction fields')
    completed = set(event) == FIELDS | SESSION_FIELDS
    if (type(event['schema_version']) is not int or event['schema_version'] != 1
            or event['event_type'] != 'thesis_ml_prediction' or event['mode'] != 'controlled_replay'
            or event['historical_replay'] is not True or type(event['synthetic']) is not bool):
        raise ValueError('Only schema-1 controlled historical replay predictions are accepted')
    if event['classification'] not in {'benign', 'malicious'} or event['model'] != 'Random Forest':
        raise ValueError('Unexpected class/model')
    if event['model_artifact'] != 'models/random_forest_baseline.joblib':
        raise ValueError('Unexpected model artifact')
    score = event['malicious_probability']
    if type(score) not in {int, float} or not math.isfinite(score) or not 0 <= score <= 1:
        raise ValueError('Invalid malicious probability')
    # Preserve predict()'s result; do not invent a second decision threshold.
    if not isinstance(event['username'], str) or not 1 <= len(event['username']) <= 128 or any(ord(c) < 32 or ord(c) == 127 for c in event['username']):
        raise ValueError('Invalid username')
    if not isinstance(event['session_id'], str) or str(UUID(event['session_id'])) != event['session_id']:
        raise ValueError('Invalid session identifier')
    for k in ['model_sha256', 'source_results_sha256', 'prediction_id']:
        if not isinstance(event[k], str) or not re.fullmatch('[0-9a-f]{64}', event[k]):
            raise ValueError('Invalid digest')
    if utc(event['observation_start']) > utc(event['observation_end']):
        raise ValueError('Invalid observation boundaries/cutoff')
    if completed:
        if event['source_mode'] != 'completed_session_test' or event['session_id_source'] != 'derived_account_activity_uuid5':
            raise ValueError('Invalid completed-session source')
        start, end = utc(event['activity_start']), utc(event['activity_end'])
        if not (start < end and utc(event['observation_start']) == start - timedelta(seconds=2)
                and utc(event['observation_end']) == end + timedelta(seconds=2)
                and utc(event['prediction_cutoff']) >= utc(event['observation_end'])):
            raise ValueError('Invalid completed-session activity/cutoff')
        if event['session_id'] != completed_session_id(event['username'], event['activity_start'], event['activity_end']):
            raise ValueError('Derived session identity mismatch')
        for key in ('benign_probability', 'prediction_score'):
            value = event[key]
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError('Invalid probability')
        expected_score = score if event['classification'] == 'malicious' else event['benign_probability']
        if abs(score + event['benign_probability'] - 1) > 1e-9 or abs(expected_score - event['prediction_score']) > 1e-9:
            raise ValueError('Inconsistent probability scores')
        if (event['telemetry_completeness_status'] not in {'potentially_incomplete', 'unverified'}
                or event['telemetry_review_required'] is not True
                or not isinstance(event['telemetry_missing_features'], str)
                or len(event['telemetry_missing_features']) > 2048
                or any(ord(c) < 32 for c in event['telemetry_missing_features'])):
            raise ValueError('Invalid telemetry completeness metadata')
    elif event['prediction_cutoff'] != event['observation_end']:
        raise ValueError('Invalid Phase 1 cutoff')
    if event['prediction_id'] != prediction_id(event):
        raise ValueError('Prediction identity mismatch')
    if len(canonical(event).encode()) > MAX_BYTES - 128:
        raise ValueError('Prediction too large')
    return event


def validate_hybrid(event):
    if not isinstance(event, dict) or set(event) != HYBRID_FIELDS:
        raise ValueError('Unexpected hybrid fields')
    if (event['event_type'] != 'thesis_hybrid_priority' or event['mode'] != 'completed_session_hybrid'
            or event['fusion_policy_version'] != HYBRID_POLICY
            or event['wazuh_evidence_verified'] is not True
            or type(event['wazuh_detected']) is not int or event['wazuh_detected'] != 1
            or event['wazuh_evidence_status'] != 'verified_positive'):
        raise ValueError('Verified operational positive evidence and known fusion policy required')
    # Reuse the existing completed-session identity, model, time, score and
    # completeness validation. RF publishing itself still accepts only ML events.
    legacy = {k: event[k] for k in FIELDS & HYBRID_FIELDS}
    p = event['rf_malicious_probability']; classification = event['rf_classification']
    if type(p) not in (float, int) or not math.isfinite(p) or not 0 <= p <= 1:
        raise ValueError('Invalid RF probability')
    legacy.update(event_type='thesis_ml_prediction', mode='controlled_replay',
        source_mode='completed_session_test', classification=classification, malicious_probability=p,
        benign_probability=1-p, prediction_score=p if classification == 'malicious' else 1-p,
        **{k: event[k] for k in SESSION_FIELDS - {'source_mode', 'benign_probability', 'prediction_score'}})
    legacy['prediction_id'] = prediction_id(legacy)
    validate_ml(legacy)
    if event['rf_prediction_id'] != legacy['prediction_id']:
        raise ValueError('RF identity mismatch')
    if (event['hybrid_priority'] != ('High Priority' if classification == 'malicious' else 'Needs Review')
            or event['investigation_required'] is not True):
        raise ValueError('Inconsistent hybrid decision')
    if (type(event['verified_matching_alerts']) is not int or event['verified_matching_alerts'] < 1
            or type(event['unresolved_alert_count']) is not int or event['unresolved_alert_count'] < 0):
        raise ValueError('Invalid evidence counts')
    for name in ('matched_rule_ids', 'unresolved_rule_ids'):
        value = event[name]
        if not isinstance(value, str): raise ValueError('Rule IDs must be a flat string')
        ids = value.split(',') if value else []
        if len(ids) != len(set(ids)) or ids != sorted(ids) or not set(ids) <= CUSTOM_RULE_IDS:
            raise ValueError('Unexpected/duplicate rule ID')
    if not event['matched_rule_ids'] or len(event['matched_rule_ids'].split(',')) > event['verified_matching_alerts']:
        raise ValueError('Missing verified rule evidence')
    reason = event['unresolved_evidence_reasons']
    if not isinstance(reason, str) or len(reason) > 1024 or any(ord(c) < 32 for c in reason):
        raise ValueError('Invalid unresolved-evidence metadata')
    if bool(event['unresolved_alert_count']) != bool(event['unresolved_rule_ids']) or bool(event['unresolved_alert_count']) != bool(reason):
        raise ValueError('Unresolved evidence must remain visible')
    if event['prediction_id'] != prediction_id(event): raise ValueError('Hybrid identity mismatch')
    if len(canonical(event).encode()) > MAX_BYTES - 128: raise ValueError('Hybrid event too large')
    return event


def validate(event):
    if isinstance(event, dict) and event.get('event_type') == 'thesis_hybrid_priority':
        return validate_hybrid(event)
    return validate_ml(event)


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))


def receive(event, log_file):
    validate(event)
    flags = os.O_RDWR | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0)
    # No creation: an administrator must provision this dedicated regular file.
    fd = os.open(log_file, flags)
    with os.fdopen(fd, 'r+b', buffering=0) as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('Dedicated log must be a regular file')
        duplicate = False
        for line in handle:
            if not line.endswith(b'\n') or len(line) > MAX_BYTES:
                raise ValueError('Incomplete/corrupt ledger; manual review required')
            prior = strict_json(line)
            published = prior.pop('published_at_utc', None)
            utc(published)
            validate(prior)
            if prior['prediction_id'] == event['prediction_id']:
                if prior != event:
                    raise ValueError('Conflicting prediction for an existing identity')
                duplicate = True
        if duplicate:
            return {'status': 'duplicate', 'prediction_id': event['prediction_id']}
        record = {**event, 'published_at_utc': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}
        data = (canonical(record) + '\n').encode()
        if handle.write(data) != len(data):
            raise OSError('Partial append; retain ledger for review')
        os.fsync(fd)
        return {'status': 'written', 'prediction_id': event['prediction_id']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log-file', type=Path, default=Path(LOG_FILE))
    args = parser.parse_args(argv)
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError('Input too large')
        result = receive(strict_json(raw), args.log_file)
    except (ValueError, OSError, TypeError, KeyError, UnicodeError):
        print('{"status":"rejected","reason":"Invalid prediction, conflicting identity or unavailable/corrupt ledger"}')
        return 2
    print(canonical(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
