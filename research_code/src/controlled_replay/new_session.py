"""Local-only RF inference for an operator-recorded, newly completed session."""
from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from datetime import datetime, time, timedelta, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from .. import features as ref
from ..ground_truth import sha256
from ..experimental_replay.core import feature_values
from .app import PILOT, dump, load_model, predict
from .indexer import IndexerClient


def new_data_boundary(root: Path) -> datetime:
    config = json.loads((root / 'config/experiment.json').read_text())
    # Reserve the documented next-day M05 recovery as original research data.
    day = datetime.fromisoformat(config['end_date']).date() + timedelta(days=2)
    return datetime.combine(day, time.min, timezone.utc)


def account_name(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or any(ord(c) < 32 for c in value):
        raise ValueError('Provide a Windows username without surrounding whitespace or control characters')
    normalized = ref.normalized_identity(value)
    if normalized.count('\\') > 1 or any(not p or p == '-' for p in normalized.split('\\')) or '@' in normalized:
        raise ValueError('Use username or DOMAIN\\username, matching the Windows event identity')
    return normalized


def request_window(username: str, start: str, end: str, boundary: datetime,
                   evidence_start: str | None = None, now: datetime | None = None,
                   availability_delay_seconds: int = 300) -> dict:
    name = account_name(username)
    began, ended = ref.timestamp(start), ref.timestamp(end)
    now = now or datetime.now(timezone.utc)
    if began >= ended:
        raise ValueError('Session end must be after start')
    if type(availability_delay_seconds) is not int or availability_delay_seconds < 2:
        raise ValueError('Availability delay must be an integer of at least two seconds')
    lower, upper = began - timedelta(seconds=2), ended + timedelta(seconds=2)
    cutoff = ended + timedelta(seconds=availability_delay_seconds)
    if cutoff > now:
        raise ValueError('Wait until the telemetry availability cutoff has passed: ' + ref.iso(cutoff))
    if lower < boundary:
        raise ValueError('This command accepts only new sessions after the original dataset and late-recovery day')
    context_start = ref.timestamp(evidence_start) if evidence_start else max(boundary, lower - timedelta(hours=24))
    if context_start < boundary or context_start > lower:
        raise ValueError('Evidence start must be after the original dataset/recovery and no later than observation start')
    return {'username': name, 'supplied_username': username, 'supplied_start': start, 'supplied_end': end,
            'actual_start': ref.iso(began), 'actual_end': ref.iso(ended),
            'observation_start': ref.iso(lower), 'observation_end': ref.iso(upper),
            'prediction_cutoff': ref.iso(cutoff), 'evidence_start': ref.iso(context_start),
            'availability_delay_seconds': availability_delay_seconds,
            'availability_policy': 'fixed_event_window_with_delayed_receipt_v1',
            'new_data_boundary': ref.iso(boundary), 'padding_seconds': 2,
            'boundary_source': 'operator_supplied_completed_activity; not ledger-verified',
            'overlap_check': 'No competing-window metadata supplied; operator must isolate same-account activity'}


def check_competing_windows(plan: dict, entries: list[dict], now: datetime | None = None) -> None:
    if not isinstance(entries, list):
        raise ValueError('Other windows must be a JSON list of username/start/end objects')
    selected_base = plan['username'].rsplit('\\', 1)[-1]
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'username', 'start', 'end'}:
            raise ValueError('Other-window objects accept only username, start and end')
        other = request_window(entry['username'], entry['start'], entry['end'],
                               ref.timestamp(plan['new_data_boundary']), now=now,
                               availability_delay_seconds=2)
        if other['username'].rsplit('\\', 1)[-1] != selected_base:
            continue
        if max(ref.timestamp(other['observation_start']), ref.timestamp(plan['observation_start'])) <= min(
                ref.timestamp(other['observation_end']), ref.timestamp(plan['observation_end'])):
            raise ValueError('Known same-account padded windows overlap; no attribution/prediction permitted')
    plan['overlap_check'] = 'No overlap with supplied competing windows; unreported concurrency remains unknown'


def load_artifacts(root: Path):
    """Read frozen preprocessing/model only; no old cohorts, fit or TabPFN load."""
    pilot = root / PILOT
    manifest = json.loads((pilot / 'run_manifest.json').read_text())
    files = [pilot / n for n in ['training_median_imputer.joblib', 'imputation_verification.json', 'model_verification.json']]
    for p in files:
        if sha256(p) != manifest['artifacts_sha256'][p.name]:
            raise ValueError('Frozen preprocessing/model provenance changed')
    info = json.loads(files[1].read_text()); model_info = json.loads(files[2].read_text())
    names = info['feature_names']
    if (len(names) != 23 or set(names) != set(ref.MODEL_INPUTS) - {'scp_process_count'}
            or info['scaling'] != 'none' or info['missing_indicator'] is not False):
        raise ValueError('Unexpected frozen feature/preprocessing schema')
    # load_model checks artifact hash, numerical dependency versions and feature order.
    model = load_model(root, {'names': names, 'model_info': model_info})
    imputer = joblib.load(files[0])
    if list(imputer.feature_names_in_) != names or imputer.strategy != 'median' or imputer.add_indicator:
        raise ValueError('Frozen imputer schema differs')
    np.testing.assert_allclose(imputer.statistics_, [info['statistics'][n] for n in names], rtol=0, atol=0)
    files += [root / 'models/random_forest_baseline.joblib', root / 'src/features.py',
              root / 'src/controlled_replay/app.py', root / 'src/controlled_replay/indexer.py', Path(__file__).resolve()]
    return names, model, imputer, info, {str(p): sha256(p) for p in files}


def compare_runs(previous: Path, current: Path) -> dict:
    """Compare preserved predictions for exactly the same account/activity."""
    plans = [json.loads((p / 'request.json').read_text()) for p in (previous, current)]
    keys = ('username', 'actual_start', 'actual_end', 'observation_start', 'observation_end')
    if any(plans[0][key] != plans[1][key] for key in keys):
        raise ValueError('Comparison requires the same account and activity/observation boundaries')
    def read(path, name):
        return json.loads((path / name).read_text()) if (path / name).exists() else {}
    old, new = [read(p, 'result.json') for p in (previous, current)]
    old_features, new_features = [read(p, 'raw_features.json') for p in (previous, current)]
    return {'previous_run': str(previous), 'current_run': str(current),
            'same_activity_and_observation_window': True,
            'previous_cutoff': plans[0]['prediction_cutoff'], 'current_cutoff': plans[1]['prediction_cutoff'],
            'previous_prediction': {k: old.get(k) for k in ('classification', 'benign_probability', 'malicious_probability')},
            'current_prediction': {k: new.get(k) for k in ('classification', 'benign_probability', 'malicious_probability')},
            'previous_status': read(previous, 'run_status.json').get('status'),
            'current_status': read(current, 'run_status.json').get('status'),
            'changed_raw_features': {k: {'previous': old_features.get(k), 'current': new_features.get(k)}
                                     for k in sorted(old_features.keys() | new_features.keys())
                                     if old_features.get(k) != new_features.get(k)},
            'note': 'A previously blocked run has no prediction; absent scores remain null.'}


def extract_completed(capture: Path, plan: dict, names: list[str]) -> tuple[dict, dict]:
    """Original attribution primitives and formulas; no invented ledger/labels."""
    username = account_name(plan['username']); base = username.rsplit('\\', 1)[-1]
    qualified = '\\' in username
    start, end = ref.timestamp(plan['actual_start']), ref.timestamp(plan['actual_end'])
    cutoff = ref.timestamp(plan['prediction_cutoff']); history_start = ref.timestamp(plan['evidence_start'])
    boundary = ref.timestamp(plan['new_data_boundary'])
    index = ref.EvidenceIndex({base})
    stats, errors = Counter(), []
    for event in ref.events([capture], stats, errors):
        try:
            if not (history_start <= ref.timestamp(event.envelope.get('timestamp')) <= cutoff
                    and boundary <= event.time() and event.available() <= cutoff):
                raise ValueError('outside bounded new-session capture')
        except ValueError:
            stats['invalid_or_outside_capture_timestamps'] += 1
            continue
        index.inspect(event)
    if errors or any(stats[n] for n in ['non_windows_records', 'malformed_json', 'malformed_eventdata',
            'unreadable_files', 'invalid_or_outside_capture_timestamps']):
        raise ValueError('Invalid/missing/out-of-cutoff capture timestamps or telemetry integrity failure')
    window = ref.Window('operator-window', base, start, end, 'operator_supplied')
    matcher = ref.Matcher([window], 2)
    acc = ref.Accumulator(); counts = Counter(); stage_stats = Counter(); stage_errors = []
    identities, channels, hosts, event_times, ready_times = Counter(), Counter(), Counter(), [], []
    window_delays, behavior_delays = [], []
    original_cutoff = end + timedelta(seconds=2)
    delay_counts = Counter({'in_window_documents': 0, 'in_window_documents_after_original_cutoff': 0,
                            'unique_attributed_after_original_cutoff': 0,
                            'behavioral_events_after_original_cutoff': 0})
    for event in ref.events([capture], stage_stats, stage_errors):
        if not ref.supported_families(event) or not event.host:
            continue
        moment, ready = event.time(), event.available()
        if not matcher.candidates(base, moment) or ready < start or ready > cutoff:
            continue
        delay = (ref.timestamp(event.envelope['timestamp']) - moment).total_seconds()
        window_delays.append(delay)
        delay_counts['in_window_documents'] += 1
        delay_counts['in_window_documents_after_original_cutoff'] += ready > original_cutoff
        user, source = index.identity(event)
        direct = ref.direct_identity(event)
        direct_base = direct.rsplit('\\', 1)[-1]
        if user != base:
            if direct_base == base:
                counts['requested_account_identity_unresolved'] += 1
            elif not direct and event.provider == ref.SYSMON:
                counts['unresolved_sysmon_in_window_all_accounts'] += 1
                guid = str(event.data.get('processGuid', '')).casefold()
                # Report ambiguous lineage with evidence relating it to this
                # account; never assume every anonymous Sysmon event is theirs.
                if any(r[0] <= ready and r[3].rsplit('\\', 1)[-1] == base
                       for r in index.process_history.get((event.host, guid), [])):
                    counts['requested_account_process_unresolved'] += 1
            continue
        if not any(known <= ready for known in index.domain_first[base].values()):
            counts['requested_account_namespace_unknown_as_of_event'] += 1
        if qualified:
            domain = username.rsplit('\\', 1)[0]
            known = index.domain_first[base].get(domain)
            if known is None or known > ready:
                counts['requested_namespace_not_verified_as_of_event'] += 1
                continue
        counts['raw_attributed'] += 1
        digest = event.digest()
        if digest in acc.used:
            counts['duplicate_attributed'] += 1
            continue
        acc.used.add(digest); acc.locations.add((event.host, moment.date().isoformat()))
        counts['unique_attributed'] += 1
        delay_counts['unique_attributed_after_original_cutoff'] += ready > original_cutoff
        counts['process_guid_linked'] += source == 'host_process_guid'
        counts['padding_only'] += not start <= moment <= end
        counts['clock_disagreement_over_300s'] += abs((ref.timestamp(event.envelope['timestamp']) - moment).total_seconds()) > 300
        if ref.is_artifact(event):
            counts['orchestration_excluded'] += 1
            continue
        ref.add_features(acc, event, user, index, ['restricted'])
        behavior_delays.append(delay)
        delay_counts['behavioral_events_after_original_cutoff'] += ready > original_cutoff
        identities[direct or 'verified_process_guid_linkage'] += 1
        channels[event.system['channel']] += 1; hosts[event.host] += 1
        event_times.append(moment); ready_times.append(ready)
    if stage_errors:
        raise ValueError('Capture changed/unreadable during second extraction pass')
    observed = index.families_before(acc.locations, cutoff)
    values = feature_values(acc, observed, names)
    reasons = []
    if not acc.counts['windows_event_count']: reasons.append('no_unambiguous_behavioral_events')
    for key in ['requested_account_identity_unresolved', 'requested_account_process_unresolved',
                'requested_namespace_not_verified_as_of_event', 'clock_disagreement_over_300s']:
        if counts[key]: reasons.append(key)
    missing = [n for n, v in values.items() if v is None]
    # Structural consistency, not a new feature formula or classifier threshold.
    for n, v in values.items():
        if v is not None and (not isinstance(v, (int, float)) or not np.isfinite(v) or v < 0 or int(v) != v):
            reasons.append('invalid_count_' + n)
    for child, parent in [('unique_action_signatures', 'windows_event_count'), ('file_access_count', 'windows_event_count'),
            ('distinct_smb_paths', 'smb_access_check_count'), ('distinct_network_destinations', 'network_connection_count'),
            ('sftp_network_connection_count', 'network_connection_count'), ('ssh_process_count', 'process_create_count')]:
        if values[child] is not None and values[parent] is not None and values[child] > values[parent]:
            reasons.append('inconsistent_' + child)
    audit = {'status': 'eligible' if not reasons else 'blocked', 'reasons': reasons, 'counts': dict(counts),
        'capture_schema_counts': dict(stats), 'missing_features': missing, 'observed_families': sorted(observed),
        'requested_identity': username, 'qualified_identity_required': qualified,
        'causal_namespace_evidence': {domain: ref.iso(t) for domain, t in index.domain_first[base].items() if t <= cutoff},
        'accepted_behavior_identities': dict(identities), 'accepted_behavior_channels': dict(channels),
        'accepted_behavior_hosts': dict(hosts),
        'first_accepted_event_utc': ref.iso(min(event_times)) if event_times else None,
        'last_accepted_event_utc': ref.iso(max(event_times)) if event_times else None,
        'last_accepted_availability_utc': ref.iso(max(ready_times)) if ready_times else None,
        'telemetry_completeness': {
            'status': 'potentially_incomplete' if missing else 'unverified',
            'complete': None,
            'missing_features': missing,
            'review_required': True,
            'reason': 'Missing feature values require review; collection completeness is not established by a successful query or elapsed cutoff.'
                      if missing else 'No missing feature values, but no independent collection watermark or audit-coverage guarantee is available.',
        },
        'telemetry_availability': {
            'prediction_cutoff': ref.iso(cutoff), 'original_end_plus_2s_cutoff': ref.iso(original_cutoff),
            'availability_delay_seconds': (cutoff - end).total_seconds(),
            **dict(delay_counts),
            'window_receipt_minus_event_seconds_min': min(window_delays) if window_delays else None,
            'window_receipt_minus_event_seconds_max': max(window_delays) if window_delays else None,
            'behavior_receipt_minus_event_seconds_min': min(behavior_delays) if behavior_delays else None,
            'behavior_receipt_minus_event_seconds_median': float(np.median(behavior_delays)) if behavior_delays else None,
            'behavior_receipt_minus_event_seconds_max': max(behavior_delays) if behavior_delays else None,
            'late_definition': 'Available after the original session-end-plus-two-second cutoff',
            'delay_interpretation': 'Receipt minus Windows event time; includes possible clock disagreement, not independently measured network latency',
            'events_after_current_cutoff': 'unknown; excluded by retrieval query',
        },
        'overlap_check': plan['overlap_check'],
        'saved_session_feature_parity': 'not_available_for_new_session',
        'limitations': ['Account plus time window does not prove which activity caused each event.',
            'Unreported same-account overlap cannot be established from username/start/end alone.',
            'Coverage and identity linkage depend on the explicitly bounded evidence history.',
            'Telemetry after the configured availability cutoff is excluded; excluded counts are unknown.',
            'Reaching the availability cutoff does not prove telemetry completeness; review the completeness flag and missing features.',
            'Delayed-receipt policy is separate from the original training end+2s protocol; feature formulas and event-time bounds are unchanged.'] +
            (['Some unqualified identities rely on the original basename policy and operator account input; namespace is not proven for those events.']
             if counts['requested_account_namespace_unknown_as_of_event'] else [])}
    return values, audit


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--username', required=True)
    parser.add_argument('--start', required=True, help='Recorded actual start, explicit timezone')
    parser.add_argument('--end', required=True, help='Recorded actual end, explicit timezone')
    parser.add_argument('--evidence-start', help='Optional prior context; default 24h before observation, clipped to new data boundary')
    parser.add_argument('--availability-delay-seconds', type=int, default=300,
                        help='Receipt/availability cutoff after session end (default 300; minimum 2)')
    parser.add_argument('--other-windows', type=Path, help='Optional JSON list of other completed username/start/end intervals')
    parser.add_argument('--compare-run', type=Path, help='Preserved new-session run for same-account/window comparison')
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    root, out = args.root.resolve(), args.output_dir.resolve()
    if not out.is_relative_to(root / 'data/experiments') or out == root / 'data/experiments':
        parser.error('Use a new ignored data/experiments/ directory')
    try: out.mkdir(parents=True, exist_ok=False)
    except FileExistsError: parser.error('Output exists; use a new directory')
    status = {'mode': 'completed_session_test', 'status': 'blocked', 'alerts_published': False,
              'models_retrained': False, 'test_partition_accessed': False}
    try:
        plan = request_window(args.username, args.start, args.end, new_data_boundary(root), args.evidence_start,
                              availability_delay_seconds=args.availability_delay_seconds)
        if args.other_windows:
            check_competing_windows(plan, json.loads(args.other_windows.read_text()))
        dump(out / 'request.json', plan)
        names, model, imputer, info, hashes = load_artifacts(root)
        keys = ['WAZUH_INDEXER_URL', 'WAZUH_INDEXER_INDEX_PATTERN', 'WAZUH_INDEXER_CA_CERT',
                'WAZUH_INDEXER_USERNAME', 'WAZUH_INDEXER_PASSWORD']
        config = {k: os.environ.get(k) for k in keys}
        if not all(config.values()): raise ValueError('Set the existing WAZUH_INDEXER URL, index pattern, CA certificate and credential variables locally')
        client = IndexerClient(config[keys[0]], config[keys[1]], config[keys[3]], config[keys[4]], config[keys[2]],
                               tls_profile=os.environ.get('WAZUH_INDEXER_TLS_PROFILE', 'strict'))
        capture = out / 'retrieved_events.jsonl'
        retrieval = client.capture(ref.timestamp(plan['evidence_start']), ref.timestamp(plan['prediction_cutoff']),
                                   capture, event_start=ref.timestamp(plan['new_data_boundary']))
        dump(out / 'retrieval_audit.json', retrieval)
        before = sha256(capture)
        raw, audit = extract_completed(capture, plan, names)
        dump(out / 'raw_features.json', raw)
        audit['missingness_not_observed_in_training'] = [n for n in audit['missing_features'] if info['training_missing_counts'][n] == 0]
        dump(out / 'validation.json', audit)
        status.update(telemetry_completeness=audit['telemetry_completeness'],
                      telemetry_availability=audit['telemetry_availability'],
                      missing_features_imputed=[])
        if audit['status'] != 'eligible': raise ValueError('Attribution/clock/feature validation failed; see validation.json')
        if sha256(capture) != before: raise ValueError('Retrieved capture changed during extraction')
        if any(sha256(Path(p)) != digest for p, digest in hashes.items()): raise ValueError('Frozen artifacts/code changed')
        frame = pd.DataFrame([raw], columns=names).astype(float)
        transformed = imputer.transform(frame)
        labels, probabilities = predict(model, names, transformed)
        label, proba = int(labels[0]), probabilities[0]
        result = {'mode': 'completed_session_test', 'source': 'wazuh_indexer', 'username': plan['username'],
            'activity_period': {'start': plan['actual_start'], 'end': plan['actual_end']},
            'observation_period': {'start': plan['observation_start'], 'end': plan['observation_end'], 'bounds': 'inclusive'},
            'prediction_cutoff': plan['prediction_cutoff'], 'model': 'Random Forest',
            'telemetry_availability': audit['telemetry_availability'],
            'telemetry_completeness': audit['telemetry_completeness'],
            'model_artifact': 'models/random_forest_baseline.joblib',
            'model_sha256': hashes[str(root / 'models/random_forest_baseline.joblib')],
            'classification': 'malicious' if label else 'benign', 'benign_probability': float(proba[0]),
            'malicious_probability': float(proba[1]), 'prediction_score': float(proba[label]),
            'model_inputs': dict(zip(names, transformed[0].tolist())), 'missing_features_imputed': audit['missing_features'],
            'warnings': audit['limitations'] + (['New missingness pattern not observed during training'] if audit['missingness_not_observed_in_training'] else []),
            'validation': 'passed_processing_checks; accuracy_requires_independent_ground_truth',
            'alerts_published': False}
        dump(out / 'result.json', result)
        dump(out / 'provenance.json', {'artifact_and_code_sha256': hashes, 'capture_sha256': before,
            'feature_names': names, 'imputation': 'Frozen training-only medians; transform only; no external scaling',
            'new_session_labels_used': False, 'legacy_dataset_rows_read': False})
        status.update(status='completed', classification=result['classification'], benign_probability=proba[0],
                      telemetry_availability=audit['telemetry_availability'],
                      malicious_probability=proba[1], missing_features_imputed=audit['missing_features'],
                      missingness_not_observed_in_training=audit['missingness_not_observed_in_training'],
                      events_with_unverified_namespace=audit['counts'].get('requested_account_namespace_unknown_as_of_event', 0))
    except (ValueError, OSError, KeyError, TypeError, AssertionError) as exc:
        status['reason'] = str(exc) if isinstance(exc, (ValueError, OSError)) else 'Input/schema/artifact validation failed'
    dump(out / 'run_status.json', status)
    if args.compare_run and (out / 'request.json').exists():
        previous = args.compare_run.resolve()
        if not previous.is_relative_to(root / 'data/experiments/new_completed_sessions') or previous == out:
            dump(out / 'comparison.json', {'status': 'comparison_refused', 'reason': 'Use a preserved new-session experiment directory'})
        else:
            try:
                dump(out / 'comparison.json', compare_runs(previous, out))
            except (ValueError, OSError, KeyError):
                dump(out / 'comparison.json', {'status': 'comparison_refused', 'reason': 'Missing or inconsistent preserved run metadata'})
    dump(out / 'output_manifest.json', {p.name: sha256(p) for p in sorted(out.iterdir()) if p.is_file()})
    print(json.dumps(status, indent=2))
    return 0 if status['status'] == 'completed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
