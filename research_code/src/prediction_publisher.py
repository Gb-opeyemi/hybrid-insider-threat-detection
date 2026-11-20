"""Prepare verified historical predictions locally; explicit SSH send separately."""
import argparse
import hashlib
import json
import re
import subprocess
import math
from datetime import datetime, timezone
from pathlib import Path

from scripts.integration.receive_ml_prediction import (canonical, prediction_id, strict_json, validate_ml as validate,
    completed_session_id, utc)


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def write(path, value):
    with path.open('x', encoding='utf-8') as handle:
        handle.write(canonical(value) + '\n')


def from_result(result, source_sha):
    if (result.get('source') != 'wazuh_indexer' or result.get('indexer_verified') is not True
            or result.get('feature_parity') != 'matched' or result.get('mode') != 'controlled_replay'):
        raise ValueError('Only verified indexer Phase 1 results can be prepared')
    event = {'schema_version': 1, 'event_type': 'thesis_ml_prediction', 'mode': result['mode'],
        'historical_replay': True, 'synthetic': False, 'session_id': result['session_id'],
        'username': result['account'], 'observation_start': result['observation_period']['start'],
        'observation_end': result['observation_period']['end'], 'prediction_cutoff': result['prediction_cutoff'],
        'model': result['model'], 'model_artifact': result['model_artifact'], 'model_sha256': result['model_sha256'],
        'classification': result['classification'], 'malicious_probability': result['malicious_probability'],
        'source_results_sha256': source_sha}
    event['prediction_id'] = prediction_id(event)
    return validate(event)


def synthetic(classification='malicious'):
    event = {'schema_version': 1, 'event_type': 'thesis_ml_prediction', 'mode': 'controlled_replay',
        'historical_replay': True, 'synthetic': True,
        'session_id': '00000000-0000-4000-8000-000000000001' if classification == 'malicious' else '00000000-0000-4000-8000-000000000002',
        'username': 'synthetic.example', 'observation_start': '2026-01-01T10:00:00Z',
        'observation_end': '2026-01-01T10:01:00Z', 'prediction_cutoff': '2026-01-01T10:01:00Z',
        'model': 'Random Forest', 'model_artifact': 'models/random_forest_baseline.joblib',
        'model_sha256': '0' * 64, 'source_results_sha256': '0' * 64,
        'classification': classification, 'malicious_probability': .95 if classification == 'malicious' else .05}
    event['prediction_id'] = prediction_id(event)
    return validate(event)


def synthetic_completed(classification='malicious'):
    event = synthetic(classification)
    event.update(source_mode='completed_session_test', session_id_source='derived_account_activity_uuid5',
        activity_start='2026-01-01T10:00:00Z', activity_end='2026-01-01T10:01:00Z',
        observation_start='2026-01-01T09:59:58Z', observation_end='2026-01-01T10:01:02Z',
        prediction_cutoff='2026-01-01T10:06:00Z', benign_probability=1 - event['malicious_probability'],
        prediction_score=.95, telemetry_completeness_status='unverified',
        telemetry_review_required=True, telemetry_missing_features='')
    # Separate synthetic activities keep the benign/malicious transport tests distinct.
    if classification == 'benign':
        event.update(activity_start='2026-01-02T10:00:00Z', activity_end='2026-01-02T10:01:00Z',
                     observation_start='2026-01-02T09:59:58Z', observation_end='2026-01-02T10:01:02Z',
                     prediction_cutoff='2026-01-02T10:06:00Z')
    event['session_id'] = completed_session_id(event['username'], event['activity_start'], event['activity_end'])
    event['prediction_id'] = prediction_id(event)
    return validate(event)


def verified_results(run):
    manifest = strict_json((run / 'output_manifest.json').read_text())
    for name, digest in manifest.items():
        path = (run / name).resolve()
        if path.parent != run.resolve() or sha(path) != digest:
            raise ValueError('Phase 1 output integrity failure')
    required = {'run_status.json', 'feature_parity.json', 'results.json'}
    if not required <= manifest.keys():
        raise ValueError('Phase 1 verification artifacts absent from manifest')
    status = strict_json((run / 'run_status.json').read_text())
    if (status.get('status') != 'completed' or status.get('indexer_verified') is not True
            or status.get('test_partition_accessed') is not False or status.get('models_retrained') is not False):
        raise ValueError('Completed training-only indexer run required')
    parity = strict_json((run / 'feature_parity.json').read_text())
    if len(parity['comparisons']) != 138 or len(parity['boundaries']) != 8 or not all(r['Matches'] is True for r in parity['comparisons'] + parity['boundaries']):
        raise ValueError('Original two-case feature parity must pass')
    results = strict_json((run / 'results.json').read_text())
    if len(results) != 2 or len({r['session_id'] for r in results}) != 2:
        raise ValueError('Original two-case Phase 1 results required')
    return [from_result(r, manifest['results.json']) for r in results], sha(run / 'output_manifest.json')


def verified_completed_session(run, root=None):
    """Separate gate for completed new simulations; never bypass Phase 1 parity."""
    from .controlled_replay.app import PILOT
    from .diagnostics.delayed_ingestion import validate_request

    root = (root or Path.cwd()).resolve()
    run = run.resolve()
    if not run.is_relative_to(root / 'data/experiments/new_completed_sessions'):
        raise ValueError('Use a preserved new-session experiment directory')
    manifest = strict_json((run / 'output_manifest.json').read_text())
    required = {'run_status.json', 'result.json', 'request.json', 'validation.json',
                'retrieval_audit.json', 'retrieved_events.jsonl', 'provenance.json', 'raw_features.json'}
    if not required <= manifest.keys():
        raise ValueError('Completed-session verification artifacts absent from manifest')
    for name, digest in manifest.items():
        path = (run / name).resolve()
        if path.parent != run or sha(path) != digest:
            raise ValueError('Completed-session output integrity failure')
    docs = {name: strict_json((run / (name + '.json')).read_text()) for name in
            ('run_status', 'result', 'request', 'validation', 'retrieval_audit', 'provenance', 'raw_features')}
    status, result, plan, audit, retrieval, provenance, raw = (docs[n] for n in docs)
    if (status.get('status') != 'completed' or status.get('mode') != 'completed_session_test'
            or any(status.get(k) is not False for k in ('test_partition_accessed', 'models_retrained', 'alerts_published'))
            or result.get('mode') != 'completed_session_test' or result.get('source') != 'wazuh_indexer'
            or result.get('alerts_published') is not False
            or result.get('validation') != 'passed_processing_checks; accuracy_requires_independent_ground_truth'):
        raise ValueError('Completed local-only indexer session required')
    if any(status.get(key) != result.get(key) for key in ('classification', 'benign_probability', 'malicious_probability')):
        raise ValueError('Saved completion status and prediction disagree')
    validate_request(plan)
    if utc(plan['prediction_cutoff']) > datetime.now(timezone.utc):
        raise ValueError('Availability cutoff has not passed')
    # Read configuration only, never any original cohort/dataset rows.
    from .controlled_replay.new_session import new_data_boundary
    if utc(plan['observation_start']) < new_data_boundary(root) or utc(plan['evidence_start']) < new_data_boundary(root):
        raise ValueError('Original experiment/recovery period is forbidden')
    if (result['username'] != plan['username'] or audit.get('requested_identity') != plan['username']
            or result['activity_period'] != {'start': plan['actual_start'], 'end': plan['actual_end']}
            or any(result['observation_period'][k] != plan['observation_' + k] for k in ('start', 'end'))
            or result['prediction_cutoff'] != plan['prediction_cutoff']
            or audit.get('status') != 'eligible' or audit.get('reasons') != []
            or audit['counts'].get('unique_attributed', 0) < 1
            or any(audit['counts'].get(k, 0) for k in ('requested_account_identity_unresolved',
                'requested_account_process_unresolved', 'requested_namespace_not_verified_as_of_event',
                'clock_disagreement_over_300s'))):
        raise ValueError('Session attribution/boundary verification failed')
    if (not utc(plan['observation_start']) <= utc(audit['first_accepted_event_utc']) <= utc(plan['observation_end'])
            or not utc(plan['observation_start']) <= utc(audit['last_accepted_event_utc']) <= utc(plan['observation_end'])
            or utc(audit['last_accepted_availability_utc']) > utc(plan['prediction_cutoff'])):
        raise ValueError('Accepted events outside observation/availability bounds')
    if (retrieval.get('source') != 'wazuh_indexer' or retrieval.get('complete_scroll') is not True
            or retrieval.get('certificate_verification_required') is not True or retrieval.get('hostname_verification') is not True
            or retrieval.get('availability_cutoff') != plan['prediction_cutoff']
            or retrieval.get('missing_or_unparseable_system_time_in_receipt_interval') != 0
            or retrieval.get('retrieved_documents') != audit['capture_schema_counts']['input_records']
            or provenance.get('capture_sha256') != manifest['retrieved_events.jsonl']
            or provenance.get('new_session_labels_used') is not False or provenance.get('legacy_dataset_rows_read') is not False):
        raise ValueError('Indexer retrieval/provenance checks failed')
    frozen = root / PILOT
    frozen_manifest = strict_json((frozen / 'run_manifest.json').read_text())
    info = strict_json((frozen / 'imputation_verification.json').read_text())
    model_info = strict_json((frozen / 'model_verification.json').read_text())
    files = [frozen / n for n in ('training_median_imputer.joblib', 'imputation_verification.json', 'model_verification.json')]
    for path in files:
        if sha(path) != frozen_manifest['artifacts_sha256'][path.name]:
            raise ValueError('Frozen training preprocessing provenance changed')
    files += [root / 'models/random_forest_baseline.joblib', root / 'src/features.py',
              root / 'src/controlled_replay/indexer.py', root / 'src/controlled_replay/app.py']
    for path in files:
        if provenance['artifact_and_code_sha256'].get(str(path)) != sha(path):
            raise ValueError('Frozen model, feature or retrieval provenance mismatch')
    names = info['feature_names']
    from .features import MODEL_INPUTS
    if (len(names) != 23 or provenance['feature_names'] != names or list(result['model_inputs']) != names
            or set(names) != set(MODEL_INPUTS) - {'scp_process_count'}
            or set(raw) != set(names) or info.get('scaling') != 'none' or info.get('missing_indicator') is not False
            or result['model_sha256'] != sha(root / 'models/random_forest_baseline.joblib')
            or result['model_sha256'] != model_info['rf_sha256']):
        raise ValueError('Original 23-feature schema/model required')
    missing = [name for name in names if raw[name] is None]
    if result['missing_features_imputed'] != missing or audit['missing_features'] != missing:
        raise ValueError('Inconsistent missing-feature evidence')
    for name in names:
        value = result['model_inputs'][name]
        expected = info['statistics'][name] if raw[name] is None else raw[name]
        if type(value) not in (int, float) or not math.isfinite(value) or value != expected:
            raise ValueError('Saved model inputs differ from raw features/frozen medians')
    completeness = result.get('telemetry_completeness', audit.get('telemetry_completeness'))
    if completeness is not None and (completeness.get('complete') is not None
            or completeness.get('status') not in {'potentially_incomplete', 'unverified'}
            or completeness.get('missing_features') != missing or completeness.get('review_required') is not True):
        raise ValueError('Invalid saved telemetry completeness status')
    if 'telemetry_completeness' in result and result['telemetry_completeness'] != audit.get('telemetry_completeness'):
        raise ValueError('Inconsistent completeness reports')
    event = {'schema_version': 1, 'event_type': 'thesis_ml_prediction', 'mode': 'controlled_replay',
        'historical_replay': True, 'synthetic': False, 'source_mode': 'completed_session_test',
        'session_id_source': 'derived_account_activity_uuid5',
        'session_id': completed_session_id(result['username'], plan['actual_start'], plan['actual_end']),
        'username': result['username'], 'activity_start': plan['actual_start'], 'activity_end': plan['actual_end'],
        'observation_start': plan['observation_start'], 'observation_end': plan['observation_end'],
        'prediction_cutoff': plan['prediction_cutoff'], 'model': result['model'],
        'model_artifact': result['model_artifact'], 'model_sha256': result['model_sha256'],
        'classification': result['classification'], 'malicious_probability': result['malicious_probability'],
        'benign_probability': result['benign_probability'], 'prediction_score': result['prediction_score'],
        'telemetry_completeness_status': completeness['status'] if completeness else 'unverified',
        'telemetry_review_required': True, 'telemetry_missing_features': ','.join(missing),
        'source_results_sha256': manifest['result.json']}
    event['prediction_id'] = prediction_id(event)
    return [validate(event)], sha(run / 'output_manifest.json')


def send(event, host):
    return _ssh_send(event, host, validate)


def _ssh_send(event, host, validator):
    """Shared fixed SSH transport; every caller supplies its strict schema gate."""
    validator(event)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', host):
        raise ValueError('Use a simple preconfigured SSH host alias')
    command = ['ssh', '-T', '-a', '-x', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'ClearAllForwardings=yes', '-o', 'ConnectTimeout=10', '--', host, 'publish-ml-prediction']
    try:
        reply = subprocess.run(command, input=canonical(event) + '\n', text=True,
                               capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('SSH failed/timed out; remote status unknown; retry is idempotent') from None
    if reply.returncode != 0:
        raise ValueError('SSH/receiver rejected submission; no remote stderr or payload printed')
    ack = strict_json(reply.stdout)
    if ack.get('prediction_id') != event['prediction_id'] or ack.get('status') not in {'written', 'duplicate'}:
        raise ValueError('Unexpected receiver acknowledgement; retain artifacts and review')
    return ack


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prep = sub.add_parser('prepare', help='Local only; no SSH/network')
    source = prep.add_mutually_exclusive_group(required=True)
    source.add_argument('--phase1-dir', type=Path)
    source.add_argument('--completed-session-dir', type=Path)
    prep.add_argument('--output-dir', type=Path, required=True)
    publish = sub.add_parser('send', help='Explicit remote append; only after server review and synthetic logtest')
    publish.add_argument('--payload-file', type=Path, required=True)
    publish.add_argument('--ssh-host', required=True)
    publish.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    out = args.output_dir.resolve()
    if not out.is_relative_to(Path.cwd().resolve() / 'data/experiments'):
        parser.error('Use a new ignored data/experiments/ directory')
    try:
        out.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        parser.error('Output exists; use a new directory')
    receipt = {'action': args.action, 'status': 'blocked', 'remote_submissions': []}
    try:
        if args.action == 'prepare':
            events, digest = (verified_completed_session(args.completed_session_dir) if args.completed_session_dir
                              else verified_results(args.phase1_dir))
            write(out / 'predictions.json', events)
            for name in ['malicious', 'benign']:
                write(out / f'synthetic_{name}.json', (synthetic_completed if args.completed_session_dir else synthetic)(name))
            receipt.update(status='prepared_locally', network_used=False,
                           prediction_ids=[e['prediction_id'] for e in events])
            receipt['completed_session_manifest_sha256' if args.completed_session_dir else 'phase1_manifest_sha256'] = digest
        else:
            payload = strict_json(args.payload_file.read_text())
            events = payload if isinstance(payload, list) else [payload]
            if not 1 <= len(events) <= 2:
                raise ValueError('Only the two-case pilot or a single synthetic event may be sent')
            for event in events:
                validate(event)
            for event in events:
                receipt['remote_submissions'].append(send(event, args.ssh_host))
            receipt.update(status='acknowledged', payload_sha256=sha(args.payload_file), ssh_host=args.ssh_host)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        receipt['reason'] = str(exc) if isinstance(exc, ValueError) else 'Input/transport validation failed'
    write(out / 'receipt.json', receipt)
    write(out / 'manifest.json', {p.name: sha(p) for p in sorted(out.iterdir()) if p.is_file()})
    print(canonical(receipt))
    return 0 if receipt['status'] != 'blocked' else 2


if __name__ == '__main__':
    raise SystemExit(main())
