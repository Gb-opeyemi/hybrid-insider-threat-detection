"""Parity-gated Random Forest inference for two completed TRAINING sessions."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sqlite3
import warnings
from collections import Counter
from contextlib import redirect_stdout
from importlib.metadata import version
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.exceptions import InconsistentVersionWarning

from .. import features as ref
from ..ground_truth import sha256
from ..experimental_replay.preflight import read_csv, training_prefix, training_schedule
from .indexer import IndexerClient, validate_envelope

# External, verified artifact bundle. No private experiment folder is distributed.
PILOT = Path(os.environ.get('THESIS_ARTIFACT_BUNDLE', 'artifacts/frozen_baseline'))


def dump(path: Path, value) -> None:
    with path.open('x', encoding='utf-8') as handle:
        json.dump(value, handle, indent=2, allow_nan=False)
        handle.write('\n')


def logical_hash(rows: list[dict]) -> str:
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def prepare(root: Path, pilot: Path) -> dict:
    """Select cases and verify the frozen imputer; no fitting or inference."""
    manifest = read_csv(root / 'data/processed/train_manifest.csv')
    if not manifest or any(r['Partition'] != 'train' or r['Included'] != 'true'
                           or not 1 <= int(r['SimulationDay']) <= 8 for r in manifest):
        raise ValueError('Only included Day 1–8 training metadata is permitted')
    schedule = training_schedule(root / 'data/ground_truth/dataset_schedule_v3.csv')
    allowed = {r['SessionID'] for r in schedule}
    needed = {r['SessionID'] for r in manifest}
    if len(needed) != len(manifest) or not needed <= allowed:
        raise ValueError('Training manifest IDs disagree with training schedule')
    reference = training_prefix(root / 'data/processed/session_features.csv', needed, allowed)
    raw = training_prefix(root / 'data/notebook_outputs/session_features_jupyter.csv', needed, allowed)
    ground = training_prefix(root / 'data/processed/session_ground_truth.csv', allowed, allowed)
    prepared = read_csv(root / 'data/notebook_outputs/ml_ready/train_ml.csv')
    if not prepared or {r['SessionID'] for r in prepared} != needed or len(prepared) != len(needed):
        raise ValueError('Prepared training records disagree')
    names = [n for n in prepared[0] if n not in {'SessionID', 'GroundTruthLabel'}]
    if len(names) != 23 or set(names) != set(ref.MODEL_INPUTS) - {'scp_process_count'}:
        raise ValueError('Unexpected trained 23-feature allowlist')
    # Prior replay persisted and verified the original Notebook 06 medians.
    previous = json.loads((pilot / 'run_manifest.json').read_text())
    for filename in ['training_median_imputer.joblib', 'imputation_verification.json', 'model_verification.json']:
        if sha256(pilot / filename) != previous['artifacts_sha256'][filename]:
            raise ValueError('Frozen preprocessing/model verification artifact changed')
    info = json.loads((pilot / 'imputation_verification.json').read_text())
    model_info = json.loads((pilot / 'model_verification.json').read_text())
    if info['feature_names'] != names or info['scaling'] != 'none' or info['missing_indicator'] is not False:
        raise ValueError('Frozen preprocessing contract disagrees')
    imputer = joblib.load(pilot / 'training_median_imputer.joblib')
    if list(imputer.feature_names_in_) != names or imputer.strategy != 'median' or imputer.add_indicator:
        raise ValueError('Frozen imputer feature contract disagrees')
    raw_by = {r['SessionID']: r for r in raw}
    X = pd.DataFrame([{n: float(raw_by[r['SessionID']][n]) if raw_by[r['SessionID']][n] != '' else np.nan
                       for n in names} for r in prepared], columns=names)
    # Independent TRAIN-ONLY median check; no new learned transformation is fitted.
    np.testing.assert_allclose(np.nanmedian(X, axis=0), imputer.statistics_, atol=0, rtol=0)
    np.testing.assert_allclose(imputer.statistics_, [info['statistics'][n] for n in names], atol=0, rtol=0)
    np.testing.assert_allclose(imputer.transform(X), [[float(r[n]) for n in names] for r in prepared], atol=1e-12, rtol=0)
    by_sid = {r['SessionID']: r for r in reference}
    selections = []
    for label in ['0', '1']:
        eligible = [r for r in manifest if r['GroundTruthLabel'] == label]
        if not eligible:
            raise ValueError('A training class is absent')
        chosen = min(eligible, key=lambda r: (ref.timestamp(r['ActualExecutionUTC']), r['SessionID']))
        sid = chosen['SessionID']
        if by_sid[sid]['ExperimentIncluded'] != 'true':
            raise ValueError('Selected session is not experiment eligible')
        selections.append({**chosen, **{n: by_sid[sid][n] for n in
            ['WindowStartUTC', 'WindowEndUTC', 'ObservationStartUTC', 'ObservationEndUTC']}})
    # Include ALL known training windows (even excluded rows) to preserve overlap ambiguity.
    ledger = []
    with (root / 'data/ground_truth/execution_ledger.csv').open(encoding='utf-8-sig', newline='') as handle:
        for r in csv.DictReader(handle):
            if r['SessionID'] not in allowed:
                break
            ledger.append(r)
    inputs = {'train_manifest': manifest, 'training_schedule_prefix': schedule,
              'reference_training_prefix': reference, 'notebook_training_prefix': raw,
              'ground_truth_training_prefix': ground, 'ledger_training_prefix': ledger}
    return {'names': names, 'selections': selections, 'ground': ground, 'ledger': ledger,
        'raw': raw_by, 'reference': by_sid, 'prepared': {r['SessionID']: r for r in prepared},
        'imputer': imputer, 'model_info': model_info,
        'input_hashes': {k: logical_hash(v) for k, v in inputs.items()},
        'file_hashes': {str(p.relative_to(root)): sha256(p) for p in [
            root / 'models/random_forest_baseline.joblib', root / 'data/notebook_outputs/ml_ready/train_ml.csv',
            root / 'data/processed/train_manifest.csv', pilot / 'training_median_imputer.joblib',
            pilot / 'imputation_verification.json', pilot / 'run_manifest.json']}}


def load_model(root: Path, context: dict):
    path = root / 'models/random_forest_baseline.joblib'
    if sha256(path) != context['model_info']['rf_sha256']:
        raise ValueError('Random Forest hash differs from verified pilot')
    for name in ['scikit-learn', 'numpy', 'pandas', 'joblib']:
        if version(name) != context['model_info']['dependencies'][name]:
            raise ValueError(f'{name} version differs from verified model environment')
    with warnings.catch_warnings():
        warnings.simplefilter('error', InconsistentVersionWarning)
        model = joblib.load(path)
    if list(model.feature_names_in_) != context['names'] or list(model.classes_) != [0, 1]:
        raise ValueError('Random Forest schema/order/classes disagree')
    return model


def cache_capture(cache: Path, output: Path, start, cutoff) -> dict:
    """Local smoke test only; never described as an indexer retrieval."""
    before = sha256(cache)
    counts = Counter()
    with sqlite3.connect(f'file:{cache}?mode=ro', uri=True) as connection, output.open('x') as handle:
        for (payload,) in connection.execute('SELECT payload FROM events WHERE ready<=? ORDER BY ready,sequence',
                                             (cutoff.isoformat(timespec='microseconds'),)):
            envelope = json.loads(payload)
            win = envelope['data']['win']
            e = ref.Event(win['system'], win.get('eventdata', {}), envelope)
            if not ref.supported_families(e):
                counts['unsupported_provider_channel'] += 1
                continue
            if ref.timestamp(envelope['timestamp']) < start:
                counts['before_evidence_start'] += 1
                continue
            validate_envelope(envelope, start, cutoff)
            handle.write(json.dumps(envelope, separators=(',', ':')) + '\n')
            counts['retrieved_documents'] += 1
    if sha256(cache) != before:
        raise ValueError('Pilot cache changed during read')
    return {'source': 'local_pilot_cache', 'indexer_verified': False, 'cache_sha256': before,
            'receipt_start': ref.iso(start), 'availability_cutoff': ref.iso(cutoff), **counts}


def extract_sessions(capture: Path, context: dict, log: Path) -> tuple[dict, dict]:
    # Call the original implementation directly: no duplicate feature formulas,
    # no rolling state, no new identity/overlap/availability policy.
    with log.open('x') as handle, redirect_stdout(handle):
        rows, report = ref.extract(context['ground'], context['ledger'], [capture], [],
            ref.timestamp('2026-10-26T00:00:00Z'), ref.timestamp('2026-11-03T00:00:00Z'),
            padding=2, identity_anchors=ref.verified_anchors(context['ground'], capture.parent))
    selected = {r['SessionID'] for r in context['selections']}
    return {r['SessionID']: r for r in rows if r['SessionID'] in selected}, report


def verify_parity(actual: dict, context: dict) -> tuple[list[dict], list[dict], np.ndarray]:
    comparisons, raw_frames = [], []
    names = context['names']
    for case in context['selections']:
        sid = case['SessionID']; r = actual[sid]
        for n in names:
            value = None if r[n] == '' else float(r[n])
            for label, source in [('reference', context['reference']), ('notebook', context['raw'])]:
                expected = None if source[sid][n] == '' else float(source[sid][n])
                comparisons.append({'SessionID': sid, 'Stage': 'raw', 'Source': label,
                    'Feature': n, 'Actual': value, 'Expected': expected, 'Matches': value == expected})
        raw_frames.append({n: float(r[n]) if r[n] != '' else np.nan for n in names})
    values = context['imputer'].transform(pd.DataFrame(raw_frames, columns=names))
    for case, row in zip(context['selections'], values):
        sid = case['SessionID']
        for n, value in zip(names, row):
            expected = float(context['prepared'][sid][n])
            comparisons.append({'SessionID': sid, 'Stage': 'imputed', 'Source': 'prepared_training',
                'Feature': n, 'Actual': float(value), 'Expected': expected, 'Matches': bool(value == expected)})
    # Boundary parity is mandatory as well as feature parity.
    boundaries = [{'SessionID': c['SessionID'], 'Field': n, 'Matches': actual[c['SessionID']][n] == c[n]}
        for c in context['selections'] for n in ['WindowStartUTC', 'WindowEndUTC', 'ObservationStartUTC', 'ObservationEndUTC']]
    return comparisons, boundaries, values


def predict(model, names: list[str], values: np.ndarray) -> tuple[list, list]:
    """Only the explicitly ordered numeric feature frame reaches the model."""
    if (values.ndim != 2 or values.shape[1] != 23 or len(names) != 23
            or set(names) != set(ref.MODEL_INPUTS) - {'scp_process_count'}
            or not np.isfinite(values).all() or np.any(values < 0)):
        raise ValueError('Invalid 23-feature model matrix')
    frame = pd.DataFrame(values, columns=names)
    return model.predict(frame).tolist(), model.predict_proba(frame).tolist()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--output-dir', type=Path, required=True, help='New directory under data/experiments/')
    parser.add_argument('--source', choices=['indexer', 'pilot-cache'], default='indexer')
    parser.add_argument('--session-id', help='Optional one of the two preselected training sessions')
    parser.add_argument('--evidence-start', default='2026-10-22T00:00:00Z')
    args = parser.parse_args(argv)
    root = args.root.resolve(); out = args.output_dir.resolve()
    if not out.is_relative_to(root / 'data/experiments') or out == root / 'data/experiments':
        parser.error('Use a new ignored data/experiments/ directory')
    try:
        out.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        parser.error('Output already exists; use a new run directory')
    status = {'mode': 'controlled_replay', 'source': args.source, 'status': 'blocked',
              'alerts_published': False, 'models_retrained': False, 'test_partition_accessed': False}
    try:
        pilot = root / PILOT
        context = prepare(root, pilot)
        if args.session_id:
            context['selections'] = [r for r in context['selections'] if r['SessionID'] == args.session_id]
            if not context['selections']:
                raise ValueError('Phase 1 permits only the two preselected training sessions')
        start = ref.timestamp(args.evidence_start)
        cutoff = max(ref.timestamp(c['ObservationEndUTC']) for c in context['selections'])
        if start > ref.timestamp('2026-10-22T00:00:00Z') or start >= cutoff:
            raise ValueError('Retain the documented pre-session identity/coverage evidence from October 22')
        dump(out / 'selection_plan.json', {'selection': 'Earliest eligible training session in each binary class, ordered by actual execution then SessionID; chosen before inference',
            'cases': context['selections'], 'feature_names': context['names'], 'padding_seconds': 2,
            'prediction_cutoff': 'ObservationEndUTC', 'evidence_start': ref.iso(start),
            'metadata_usage': 'Intervals/account routing/overlap checks and offline parity only; never numeric model inputs'})
        model = load_model(root, context)
        capture = out / 'retrieved_events.jsonl'
        if args.source == 'pilot-cache':
            if cutoff.date().isoformat() != '2026-10-26':
                raise ValueError('Local cache is restricted to Day 1')
            audit = cache_capture(pilot / 'events.sqlite', capture, start, cutoff)
        else:
            config = {key: os.environ.get(key) for key in ['WAZUH_INDEXER_URL', 'WAZUH_INDEXER_INDEX_PATTERN',
                       'WAZUH_INDEXER_CA_CERT', 'WAZUH_INDEXER_USERNAME', 'WAZUH_INDEXER_PASSWORD']}
            if not all(config.values()):
                raise ValueError('Set WAZUH_INDEXER_URL, WAZUH_INDEXER_INDEX_PATTERN, WAZUH_INDEXER_CA_CERT, WAZUH_INDEXER_USERNAME and WAZUH_INDEXER_PASSWORD locally')
            ca = Path(config['WAZUH_INDEXER_CA_CERT'])
            if not ca.is_file() or not os.access(ca, os.R_OK):
                raise ValueError('Indexer CA file must exist and be readable by the Python process on this machine')
            client = IndexerClient(config['WAZUH_INDEXER_URL'], config['WAZUH_INDEXER_INDEX_PATTERN'],
                config['WAZUH_INDEXER_USERNAME'], config['WAZUH_INDEXER_PASSWORD'], str(ca),
                tls_profile=os.environ.get('WAZUH_INDEXER_TLS_PROFILE', 'strict'))
            audit = client.capture(start, cutoff, capture)
        dump(out / 'retrieval_audit.json', audit)
        actual, report = extract_sessions(capture, context, out / 'extraction.log')
        dump(out / 'extraction_audit.json', {'validation_status': report['validation_status'],
            'index_counts': report['index_counts'], 'streams': report['streams'], 'errors': report['errors'],
            'selected_session_quality': [{k: v for k, v in actual[c['SessionID']].items() if k not in ref.FEATURES}
                                         for c in context['selections']]})
        comparisons, boundaries, values = verify_parity(actual, context)
        dump(out / 'feature_parity.json', {'comparisons': comparisons, 'boundaries': boundaries})
        if report['validation_status'] == 'errors' or not all(r['Matches'] for r in comparisons + boundaries):
            raise ValueError('Feature/boundary parity or telemetry integrity failed; see feature_parity.json; no predictions produced')
        if any(actual[c['SessionID']]['FeatureMLTrainingEligible'] != 'true' for c in context['selections']):
            raise ValueError('Selected session has ambiguous, missing, clock-unreliable or otherwise ineligible evidence')
        # Check immutable inputs BEFORE inference as well as at the end.
        for path, expected in context['file_hashes'].items():
            if sha256(root / path) != expected:
                raise ValueError('A protected input changed')
        labels, probabilities = predict(model, context['names'], values)
        results = []
        ground_by = {r['SessionID']: r for r in context['ground']}
        for case, label, proba, row in zip(context['selections'], labels, probabilities, values):
            sid = case['SessionID']
            results.append({'mode': 'controlled_replay', 'source': audit['source'],
                'indexer_verified': args.source == 'indexer', 'session_id': sid,
                'account': ground_by[sid]['Username'],
                'activity_period': {'start': case['WindowStartUTC'], 'end': case['WindowEndUTC']},
                'observation_period': {'start': case['ObservationStartUTC'], 'end': case['ObservationEndUTC'], 'bounds': 'inclusive'},
                'prediction_cutoff': case['ObservationEndUTC'], 'model': 'Random Forest',
                'model_artifact': 'models/random_forest_baseline.joblib', 'model_sha256': context['model_info']['rf_sha256'],
                'classification': 'malicious' if label == 1 else 'benign', 'malicious_probability': float(proba[1]),
                'prediction_score': float(proba[label]), 'prediction_score_definition': 'Probability of the predicted class; malicious_probability is always class 1',
                'decision_policy': 'Saved classifier predict(); no threshold adjustment',
                'raw_features': {n: None if actual[sid][n] == '' else actual[sid][n] for n in context['names']},
                'model_inputs': dict(zip(context['names'], row.tolist())), 'feature_parity': 'matched', 'alerts_published': False})
        dump(out / 'results.json', results)
        dump(out / 'provenance.json', {'input_prefix_sha256': context['input_hashes'],
            'input_file_sha256': context['file_hashes'], 'capture_sha256': sha256(capture),
            'code_sha256': {str(p.relative_to(root)): sha256(p) for p in [root / 'src/features.py',
                root / 'src/experimental_replay/preflight.py', *sorted((root / 'src/controlled_replay').glob('*.py'))]},
            'runtime': {n: version(n) for n in ['scikit-learn', 'numpy', 'pandas', 'joblib']},
            'preprocessing': 'Original verified train-only median imputer; transform only; no scaling or indicators',
            'source_unchanged': True})
        status.update(status='completed', feature_cells_matched=len(comparisons), indexer_verified=args.source == 'indexer')
    except (ValueError, OSError, KeyError, AssertionError) as exc:
        status['reason'] = str(exc) if not isinstance(exc, (KeyError, AssertionError)) else 'Input/schema/statistics verification failed'
        print('Controlled replay blocked: ' + status['reason'])
    dump(out / 'run_status.json', status)
    dump(out / 'output_manifest.json', {p.name: sha256(p) for p in sorted(out.iterdir()) if p.is_file()})
    print(json.dumps(status))
    return 0 if status['status'] == 'completed' else 2
