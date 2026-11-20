"""Reuse the existing Wazuh evidence matcher and policy, with TabPFN naming."""
from pathlib import Path
from ..controlled_replay.hybrid_session import RULE_FILES, alert_query, match_alerts, verified_event_context
from ..prediction_publisher import verified_completed_session
from ..hybrid_priority import fuse_hybrid_priority
from .common import code_hashes, manifest, output, read, seal, sha, write
from .new_session import verified_inference


def saved_alerts(root, source, plan, capture_sha):
    source = Path(source).resolve()
    if (source / 'alert_acquisition.json').exists():
        from .alert_capture import verify_source
        rule_hashes = verify_source(root, source, plan, capture_sha)
    else:
        if not source.is_relative_to(Path(root).resolve() / 'data/experiments/hybrid_session_phase1'):
            raise ValueError('Use a preserved operational alert capture')
        manifest(source, {'provenance.json', 'retrieved_alerts.jsonl', 'alert_retrieval_audit.json', 'run_status.json'})
        provenance = read(source / 'provenance.json')
        rf_source = Path(provenance['source_session_dir']).resolve()
        _, digest = verified_completed_session(rf_source, root)
        if (digest != provenance['session_manifest_sha256'] or read(rf_source / 'request.json') != plan
                or sha(rf_source / 'retrieved_events.jsonl') != capture_sha
                or provenance['operational_source'] != 'actual_indexer_alerts; no retrospective baseline substitution'):
            raise ValueError('Alert source is not bound to this exact session/capture')
        for path in (Path(root) / 'src/controlled_replay/hybrid_session.py', Path(root) / 'src/hybrid_priority.py'):
            if provenance['code_sha256'].get(str(path)) != sha(path): raise ValueError('Alert source code provenance changed')
        rule_hashes = {str(Path(root) / 'data/wazuh/etc/rules' / n): sha(Path(root) / 'data/wazuh/etc/rules' / n) for n in RULE_FILES}
        if provenance['frozen_rule_files_sha256'] != rule_hashes: raise ValueError('Frozen Wazuh rule hashes changed')
    audit = read(source / 'alert_retrieval_audit.json')
    if (audit.get('status') != 'query_verified' or audit.get('complete_scroll') is not True
            or audit.get('certificate_verification_required') is not True or audit.get('hostname_verification') is not True):
        raise ValueError('Complete TLS-verified saved alert query required')
    kinds = {r.get('data.win.system.systemTime') for r in audit.get('mapping_field_types', [])}
    if not kinds or not kinds <= {'keyword', 'date', 'date_nanos'} or ('keyword' in kinds and len(kinds) > 1):
        raise ValueError('Inconsistent saved alert mapping')
    if audit['query'] != alert_query(plan, 'keyword' if kinds == {'keyword'} else 'date'):
        raise ValueError('Saved Wazuh query does not match original cutoff/window')
    from scripts.integration.receive_ml_prediction import strict_json
    rows = [strict_json(line) for line in (source / 'retrieved_alerts.jsonl').read_text().splitlines()]
    if type(audit.get('documents')) is not int or audit['documents'] != len(rows): raise ValueError('Alert count mismatch')
    ids = [(r['index'], r['document_id']) for r in rows]
    if len(set(ids)) != len(ids): raise ValueError('Duplicate alert document identity')
    return rows, {'source_dir': str(source), 'manifest_sha256': sha(source / 'output_manifest.json'),
                  'frozen_rule_files_sha256': rule_hashes, 'query': audit['query'], 'documents': len(rows)}


def combine(prediction, evidence):
    decision = fuse_hybrid_priority(int(prediction['classification'] == 'malicious'),
        evidence['wazuh_detected'], wazuh_evidence_verified=evidence['wazuh_evidence_verified']).to_dict()
    decision['ml_detected'] = decision.pop('rf_detected')
    return {
        'mode': 'completed_session_tabpfn_hybrid_dry_run', 'dry_run': True, 'alerts_published': False,
        **{k: prediction[k] for k in ('selected_model', 'model', 'job_id', 'session_id', 'username',
            'activity_start', 'activity_end', 'observation_start', 'observation_end', 'prediction_cutoff',
            'model_sha256', 'checkpoint_sha256', 'telemetry_completeness')},
        'ml_prediction_id': prediction['prediction_id'], 'ml_classification': prediction['classification'],
        'ml_malicious_probability': prediction['malicious_probability'],
        'fusion_adapter': 'tabpfn_to_existing_binary_policy_v1',
        **decision, 'wazuh_evidence_status': evidence['evidence_status'], 'wazuh_evidence': evidence,
        'matched_wazuh_rule_ids': evidence.get('matched_rule_ids', []),
        'investigation_required': bool(decision['review_required']),
    }


def reverify(root, inference, alert_source):
    prediction, plan, validation, capture_source = verified_inference(root, inference)
    rows, provenance = saved_alerts(root, alert_source, plan, sha(capture_source / 'retrieved_events.jsonl'))
    index, digests = verified_event_context(capture_source / 'retrieved_events.jsonl', plan, validation['accepted_behavior_hosts'])
    evidence = match_alerts(rows, plan, index, digests, validation['accepted_behavior_hosts'])
    return combine(prediction, evidence), provenance


def run(root, inference, alert_source, out):
    out = output(root, out)
    status = {'status': 'blocked', 'selected_model': 'tabpfn', 'dry_run': True, 'alerts_published': False}
    try:
        result, source = reverify(root, inference, alert_source)
        write(out / 'hybrid_result.json', result)
        write(out / 'provenance.json', {'selected_model': 'tabpfn', 'inference_dir': str(Path(inference).resolve()),
            'inference_manifest_sha256': sha(Path(inference) / 'output_manifest.json'),
            'alert_source': source, 'code_sha256': code_hashes(root),
            'operational_source': ('fresh_authenticated_wazuh_alerts' if (Path(alert_source) / 'alert_acquisition.json').exists()
                                   else 'local_replay_of_verified_indexer_capture')})
        status.update(status='completed_dry_run', hybrid_priority=result['hybrid_priority'],
                      wazuh_evidence_status=result['wazuh_evidence_status'])
    except (ValueError, OSError, KeyError, TypeError, AssertionError) as exc:
        status.update(exception_type=type(exc).__name__, reason='Wazuh provenance/query/attribution unavailable; no negative inferred.')
        write(out / 'hybrid_result.json', {'selected_model': 'tabpfn', 'wazuh_detected': None,
            'wazuh_evidence_verified': False, 'wazuh_evidence_status': 'query_failed_or_unavailable',
            'hybrid_priority': 'Evidence Unavailable', 'investigation_required': True, 'alerts_published': False})
    write(out / 'run_status.json', status); seal(out)
    if status['status'] != 'completed_dry_run': raise ValueError(status['reason'])
    return result
