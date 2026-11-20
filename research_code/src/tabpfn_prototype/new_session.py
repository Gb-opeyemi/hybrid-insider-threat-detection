"""TabPFN inference on a verified completed capture; shared feature definitions."""
import hashlib
import pandas as pd
from pathlib import Path
from scripts.integration.receive_ml_prediction import canonical, completed_session_id
from ..controlled_replay.new_session import extract_completed
from ..prediction_publisher import verified_completed_session
from . import artifacts
from .common import code_hashes, identity, manifest, output, read, seal, sha, write


def source_capture(root, source):
    source = Path(source).resolve()
    if (source / 'acquisition.json').exists():
        from .acquisition import verified_capture
        return verified_capture(root, source)
    events, source_sha = verified_completed_session(source, root)
    plan = read(source / 'request.json')
    if plan['availability_delay_seconds'] != 300:
        raise ValueError('Local hybrid prototype requires the original fixed 300-second cutoff')
    return source, plan, events[0], source_sha


def infer(root, source, out, job_id, *, model_context=None):
    root = Path(root).resolve(); out = output(root, out)
    status = {'status': 'blocked', 'selected_model': 'tabpfn', 'alerts_published': False,
              'models_retrained': False, 'test_partition_accessed': False}
    phase = 'source_verification'
    try:
        code_before = code_hashes(root)
        source, plan, original, source_sha = source_capture(root, source)
        phase = 'fitted_model_restoration'
        names, imputer, info, model = model_context or artifacts.restore(root)
        current = artifacts.frozen(root)[2]
        cached = dict(info); cached.pop('restoration_device', None)
        if cached != current: raise ValueError('Cached model contract changed')
        phase = 'shared_feature_extraction' if original is None else 'shared_feature_parity'
        raw, audit = extract_completed(source / 'retrieved_events.jsonl', plan, names)
        if audit['status'] != 'eligible' or (original is not None and raw != read(source / 'raw_features.json')):
            raise ValueError('Shared extraction does not reproduce the verified source features')
        transformed = imputer.transform(pd.DataFrame([raw], columns=names).astype(float))
        inputs = dict(zip(names, transformed[0].tolist()))
        if original is not None:
            saved_inputs = read(source / 'result.json')['model_inputs']
            if inputs != saved_inputs:
                raise ValueError('Imputed features differ from original completed-session inputs')
        else:
            allowed = {h.casefold() for h in read(source / 'acquisition.json')['allowed_hosts']}
            if not audit['accepted_behavior_hosts'] or not {h.casefold() for h in audit['accepted_behavior_hosts']} <= allowed:
                raise ValueError('Completion/telemetry host mismatch')
        phase = 'prediction'
        label, probabilities = artifacts.predict(model, pd.DataFrame(transformed, columns=names))
        result = {
            'schema_version': 1, 'event_type': 'thesis_tabpfn_prediction', 'mode': 'completed_session_test',
            'selected_model': 'tabpfn', 'job_id': job_id, 'synthetic': False,
            'source': 'fresh_authenticated_wazuh_archives' if original is None else 'local_replay_of_verified_indexer_capture',
            'session_id': completed_session_id(plan['username'], plan['actual_start'], plan['actual_end']),
            'username': plan['username'], 'activity_start': plan['actual_start'], 'activity_end': plan['actual_end'],
            **{k: plan[k] for k in ('observation_start', 'observation_end', 'prediction_cutoff')},
            **{k: info[k] for k in ('model', 'model_artifact', 'model_sha256', 'checkpoint_sha256')},
            'feature_schema_sha256': hashlib.sha256(canonical(names).encode()).hexdigest(),
            'classification': 'malicious' if label else 'benign',
            'benign_probability': probabilities[0], 'malicious_probability': probabilities[1],
            'prediction_score': probabilities[label], 'model_inputs': inputs,
            'missing_features_imputed': audit['missing_features'],
            'telemetry_completeness': audit['telemetry_completeness'],
            'telemetry_availability': audit['telemetry_availability'], 'alerts_published': False,
        }
        result['prediction_id'] = identity(result)
        write(out / 'request.json', plan)
        write(out / 'raw_features.json', raw)
        write(out / 'validation.json', audit)
        write(out / 'result.json', result)
        write(out / 'provenance.json', {
            'selected_model': 'tabpfn', 'job_id': job_id, 'source_session_dir': str(source),
            'source_manifest_sha256': source_sha, 'capture_sha256': sha(source / 'retrieved_events.jsonl'),
            'code_sha256': code_before, 'model_verification': info,
            'imputation': 'Frozen training-only median transform; no scaling or fit',
            'raw_feature_cells_matched': len(names) if original is not None else None,
            'imputed_feature_cells_matched': len(names) if original is not None else None,
            'capture_kind': 'fresh' if original is None else 'preserved',
            'labels_used_as_predictors': False, 'original_dataset_rows_read': False,
        })
        # Recheck immutable sources and weights after inference, too.
        if source_capture(root, source)[3] != source_sha:
            raise ValueError('Original source changed during inference')
        artifacts.frozen(root)
        if code_hashes(root) != code_before: raise ValueError('Prototype code changed during inference')
        status.update(status='completed', prediction_id=result['prediction_id'],
                      classification=result['classification'], malicious_probability=result['malicious_probability'])
    except (ValueError, OSError, KeyError, TypeError, AssertionError) as exc:
        status.update(failing_stage=phase, exception_type=type(exc).__name__, reason='TabPFN artifact, source or inference verification failed; no fallback.')
    write(out / 'run_status.json', status); seal(out)
    if status['status'] != 'completed': raise ValueError(status['reason'])
    return result


def verified_inference(root, run):
    root = Path(root).resolve(); run = Path(run).resolve()
    if not run.is_relative_to(root / 'data/experiments/tabpfn_prototype'):
        raise ValueError('Use a separate TabPFN experiment directory')
    manifest(run, {'request.json', 'result.json', 'validation.json', 'raw_features.json', 'provenance.json', 'run_status.json'})
    provenance, result, status = [read(run / (n + '.json')) for n in ('provenance', 'result', 'run_status')]
    if (status.get('status') != 'completed' or provenance.get('selected_model') != 'tabpfn'
            or result.get('selected_model') != 'tabpfn' or result.get('model') != 'TabPFN'
            or status.get('selected_model') != 'tabpfn'
            or any(status.get(k) is not False for k in ('models_retrained', 'test_partition_accessed', 'alerts_published'))
            or type(result.get('schema_version')) is not int or result['schema_version'] != 1
            or result.get('event_type') != 'thesis_tabpfn_prediction'
            or result.get('mode') != 'completed_session_test' or result.get('synthetic') is not False
            or result.get('source') not in {'local_replay_of_verified_indexer_capture', 'fresh_authenticated_wazuh_archives'}
            or provenance.get('labels_used_as_predictors') is not False
            or provenance.get('original_dataset_rows_read') is not False
            or result.get('alerts_published') is not False):
        raise ValueError('Verified unpublished TabPFN inference required')
    names, imputer, info, _ = artifacts.frozen(root)  # Does not restore/predict the classifier.
    if provenance['code_sha256'] != code_hashes(root): raise ValueError('TabPFN code provenance changed')
    expected_info = dict(provenance['model_verification']); expected_info.pop('restoration_device', None)
    if expected_info != info: raise ValueError('TabPFN model provenance changed')
    source, plan, original, source_sha = source_capture(root, provenance['source_session_dir'])
    if (provenance.get('capture_kind') != ('fresh' if original is None else 'preserved')
            or provenance.get('raw_feature_cells_matched') != (None if original is None else len(names))
            or provenance.get('imputed_feature_cells_matched') != (None if original is None else len(names))):
        raise ValueError('Feature verification provenance changed')
    if result['source'] != ('fresh_authenticated_wazuh_archives' if original is None else 'local_replay_of_verified_indexer_capture'):
        raise ValueError('Inference source kind changed')
    if (source_sha != provenance['source_manifest_sha256']
            or sha(source / 'retrieved_events.jsonl') != provenance['capture_sha256']
            or plan != read(run / 'request.json') or result['job_id'] != provenance['job_id']):
        raise ValueError('TabPFN source/session binding changed')
    raw, audit = extract_completed(source / 'retrieved_events.jsonl', plan, names)
    if raw != read(run / 'raw_features.json') or audit != read(run / 'validation.json') or audit['status'] != 'eligible':
        raise ValueError('Saved TabPFN features/attribution differ from shared extraction')
    if original is None:
        allowed = {h.casefold() for h in read(source / 'acquisition.json')['allowed_hosts']}
        if not audit['accepted_behavior_hosts'] or not {h.casefold() for h in audit['accepted_behavior_hosts']} <= allowed:
            raise ValueError('Completion/telemetry host mismatch')
    transformed = imputer.transform(pd.DataFrame([raw], columns=names).astype(float))
    if (list(result['model_inputs']) != names or result['model_inputs'] != dict(zip(names, transformed[0].tolist()))
            or result['missing_features_imputed'] != audit['missing_features']
            or result['telemetry_completeness'] != audit['telemetry_completeness']
            or result['telemetry_availability'] != audit['telemetry_availability']):
        raise ValueError('Saved TabPFN inputs/completeness changed')
    for key in ('model', 'model_artifact', 'model_sha256', 'checkpoint_sha256'):
        if result[key] != info[key]: raise ValueError('Wrong model in TabPFN result')
    for key in ('observation_start', 'observation_end', 'prediction_cutoff'):
        if result[key] != plan[key]: raise ValueError('TabPFN cutoff/window changed')
    if (result['activity_start'] != plan['actual_start'] or result['activity_end'] != plan['actual_end']
            or result['username'] != plan['username']
            or result['session_id'] != completed_session_id(plan['username'], plan['actual_start'], plan['actual_end'])
            or result['feature_schema_sha256'] != hashlib.sha256(canonical(names).encode()).hexdigest()
            or result['prediction_id'] != identity(result)):
        raise ValueError('TabPFN identity/schema mismatch')
    import math
    scores = [result[k] for k in ('malicious_probability', 'benign_probability', 'prediction_score')]
    if any(type(p) not in (int, float) or not math.isfinite(p) or not 0 <= p <= 1 for p in scores):
        raise ValueError('Invalid TabPFN probabilities')
    if result['classification'] not in {'benign', 'malicious'} or abs(sum(scores[:2]) - 1) > 1e-6:
        raise ValueError('Invalid TabPFN classification/probability sum')
    expected = result['malicious_probability'] if result['classification'] == 'malicious' else result['benign_probability']
    if abs(result['prediction_score'] - expected) > 1e-9:
        raise ValueError('TabPFN prediction score disagrees')
    if any(status.get(k) != result[k] for k in ('prediction_id', 'classification', 'malicious_probability')):
        raise ValueError('TabPFN status and result disagree')
    return result, plan, audit, source
