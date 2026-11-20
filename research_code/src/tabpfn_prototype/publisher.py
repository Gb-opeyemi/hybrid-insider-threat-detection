"""Local-only TabPFN publication contract and preparation. Sending is disabled."""
from pathlib import Path
from scripts.integration.tabpfn_contract import FIELDS, validate
from .common import code_hashes, identity, manifest, output, read, seal, sha, write
from .hybrid_session import reverify
from .new_session import verified_inference


def verified_hybrid(root, run):
    run = Path(run).resolve()
    if not run.is_relative_to(Path(root).resolve() / 'data/experiments/tabpfn_prototype'):
        raise ValueError('Use a separate TabPFN hybrid directory')
    values = manifest(run, {'hybrid_result.json', 'provenance.json', 'run_status.json'})
    provenance, result = read(run / 'provenance.json'), read(run / 'hybrid_result.json')
    if (read(run / 'run_status.json')['status'] != 'completed_dry_run'
            or provenance['selected_model'] != 'tabpfn' or provenance['code_sha256'] != code_hashes(root)):
        raise ValueError('Verified TabPFN hybrid provenance required')
    inference = Path(provenance['inference_dir'])
    prediction, _, _, _ = verified_inference(root, inference)
    if sha(inference / 'output_manifest.json') != provenance['inference_manifest_sha256']:
        raise ValueError('TabPFN inference manifest changed')
    regenerated, evidence_source = reverify(root, inference, provenance['alert_source']['source_dir'])
    if regenerated != result or evidence_source != provenance['alert_source']:
        raise ValueError('TabPFN hybrid result differs from independent evidence verification')
    evidence = result['wazuh_evidence']; completeness = prediction['telemetry_completeness']
    event = {
        **{k: prediction[k] for k in ('schema_version', 'selected_model', 'synthetic', 'session_id', 'username',
            'activity_start', 'activity_end', 'observation_start', 'observation_end', 'prediction_cutoff',
            'model', 'model_artifact', 'model_sha256', 'checkpoint_sha256', 'feature_schema_sha256',
            'benign_probability', 'prediction_score')},
        'event_type': 'thesis_tabpfn_hybrid_priority', 'mode': 'completed_session_tabpfn_hybrid', 'historical_replay': True,
        'source_results_sha256': values['hybrid_result.json'], 'ml_prediction_id': prediction['prediction_id'],
        **{k: result[k] for k in ('ml_classification', 'ml_malicious_probability', 'wazuh_detected', 'wazuh_evidence_verified',
            'wazuh_evidence_status', 'hybrid_priority', 'investigation_required', 'fusion_policy_version', 'fusion_adapter')},
        'matched_rule_ids': ','.join(evidence['matched_rule_ids']), 'verified_matching_alerts': len(evidence['matched']),
        'unresolved_alert_count': len(evidence['unresolved']),
        'unresolved_rule_ids': ','.join(sorted({r['rule_id'] for r in evidence['unresolved']})),
        'unresolved_evidence_reasons': ','.join(sorted({r['reason'] for r in evidence['unresolved']})),
        'telemetry_completeness_status': completeness['status'], 'telemetry_review_required': True,
        'telemetry_missing_features': ','.join(prediction['missing_features_imputed']),
    }
    event['prediction_id'] = identity(event)
    validate(event)
    manifest(run, set(values))
    return event


def prepare(root, run, out):
    event = verified_hybrid(root, run)
    out = output(root, out)
    write(out / 'hybrid_payload.json', event)
    write(out / 'preparation.json', {'status': 'prepared_locally', 'selected_model': 'tabpfn',
        'hybrid_dir': str(Path(run).resolve()), 'hybrid_manifest_sha256': sha(Path(run) / 'output_manifest.json'),
        'prediction_id': event['prediction_id'], 'network_used': False, 'publication_enabled': False})
    seal(out)
    return event


def verify_prepared(root, run):
    run = Path(run)
    manifest(run, {'hybrid_payload.json', 'preparation.json'})
    info = read(run / 'preparation.json')
    if info['network_used'] is not False or info['publication_enabled'] is not False:
        raise ValueError('Local-only preparation required')
    source = Path(info['hybrid_dir'])
    if sha(source / 'output_manifest.json') != info['hybrid_manifest_sha256']:
        raise ValueError('Prepared source manifest changed')
    expected = verified_hybrid(root, source)
    if expected != read(run / 'hybrid_payload.json') or info['prediction_id'] != expected['prediction_id']:
        raise ValueError('Prepared TabPFN payload changed')
    return expected


def send(*args, **kwargs):
    raise PermissionError('TabPFN publication is disabled in this local development release')
