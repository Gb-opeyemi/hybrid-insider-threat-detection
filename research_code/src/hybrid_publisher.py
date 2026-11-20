"""Explicit, manually invoked publication of verified operational hybrid results."""
import argparse
import hashlib
from pathlib import Path

from scripts.integration.receive_ml_prediction import canonical, prediction_id, strict_json, validate_hybrid
from .prediction_publisher import sha, write, verified_completed_session, _ssh_send
from .controlled_replay.hybrid_session import (RULE_FILES, alert_query, verified_event_context,
                                             match_alerts, hybrid_result)
from .hybrid_priority import FUSION_POLICY_VERSION


def check_manifest(run, name, required):
    manifest = strict_json((run / name).read_text())
    if not isinstance(manifest, dict) or not required <= manifest.keys():
        raise ValueError('Required verification artifacts absent')
    for filename, digest in manifest.items():
        path = (run / filename).resolve()
        if path.parent != run.resolve() or sha(path) != digest:
            raise ValueError('Publication source integrity failure')
    return manifest


def verified_hybrid(run, root=None):
    """Reverify RF and operational evidence; never promote a saved priority alone."""
    root = (root or Path.cwd()).resolve(); run = run.resolve()
    if not run.is_relative_to(root / 'data/experiments/hybrid_session_phase1'):
        raise ValueError('Use a preserved operational hybrid experiment directory')
    manifest = check_manifest(run, 'output_manifest.json', {'run_status.json', 'hybrid_result.json',
        'provenance.json', 'retrieved_alerts.jsonl', 'alert_retrieval_audit.json'})
    def read(name): return strict_json((run / (name + '.json')).read_text())
    status, result, provenance, retrieval = (read(n) for n in (
        'run_status', 'hybrid_result', 'provenance', 'alert_retrieval_audit'))
    if (status.get('status') != 'completed_dry_run' or status.get('dry_run') is not True
            or status.get('alerts_published') is not False or status.get('test_partition_accessed') is not False
            or result.get('mode') != 'completed_session_hybrid_dry_run'
            or result.get('dry_run') is not True or result.get('alerts_published') is not False):
        raise ValueError('Completed unpublished operational hybrid dry-run required')
    if (result.get('wazuh_evidence_verified') is not True or type(result.get('wazuh_detected')) is not int
            or result['wazuh_detected'] != 1 or result.get('wazuh_evidence_status') != 'verified_positive'
            or result.get('fusion_policy_version') != FUSION_POLICY_VERSION):
        raise ValueError('Verified positive Wazuh evidence and current fusion policy required')
    if provenance.get('operational_source') != 'actual_indexer_alerts; no retrospective baseline substitution':
        raise ValueError('Actual authenticated operational alert evidence required')
    source = Path(provenance['source_session_dir']).resolve()
    rf_events, source_manifest_sha = verified_completed_session(source, root)
    rf = rf_events[0]
    if source_manifest_sha != provenance['session_manifest_sha256']:
        raise ValueError('Underlying RF manifest changed')
    expected_code = [root / 'src/controlled_replay/hybrid_session.py', root / 'src/hybrid_priority.py']
    for path in expected_code:
        if provenance['code_sha256'].get(str(path)) != sha(path):
            raise ValueError('Hybrid extraction/fusion code provenance mismatch')
    for filename in RULE_FILES:
        path = root / 'data/wazuh/etc/rules' / filename
        if provenance['frozen_rule_files_sha256'].get(str(path)) != sha(path):
            raise ValueError('Frozen rule provenance mismatch')
    plan = strict_json((source / 'request.json').read_text())
    validation = strict_json((source / 'validation.json').read_text())
    if (retrieval.get('status') != 'query_verified' or retrieval.get('complete_scroll') is not True
            or retrieval.get('certificate_verification_required') is not True
            or retrieval.get('hostname_verification') is not True):
        raise ValueError('Complete TLS-verified operational alert query required')
    kinds = {r.get('data.win.system.systemTime') for r in retrieval.get('mapping_field_types', [])}
    if not kinds or not kinds <= {'keyword', 'date', 'date_nanos'} or ('keyword' in kinds and len(kinds) > 1):
        raise ValueError('Recorded alert mapping evidence missing/inconsistent')
    kind = 'keyword' if kinds == {'keyword'} else 'date'
    if retrieval['query'] != alert_query(plan, kind):
        raise ValueError('Recorded alert query differs from the verified session query')
    rows = [strict_json(line) for line in (run / 'retrieved_alerts.jsonl').read_text().splitlines()]
    if type(retrieval.get('documents')) is not int or retrieval['documents'] != len(rows):
        raise ValueError('Alert capture count mismatch')
    identities = [(r['index'], r['document_id']) for r in rows]
    if len(set(identities)) != len(identities): raise ValueError('Repeated alert document identity')
    index, digests = verified_event_context(source / 'retrieved_events.jsonl', plan, validation['accepted_behavior_hosts'])
    evidence = match_alerts(rows, plan, index, digests, validation['accepted_behavior_hosts'])
    regenerated = hybrid_result(rf, evidence)
    if regenerated != result:
        raise ValueError('Saved hybrid result differs from independently reverified session evidence/fusion')
    if (status.get('hybrid_priority') != result['hybrid_priority']
            or status.get('investigation_required') != result['investigation_required']
            or status.get('wazuh_evidence_status') != result['wazuh_evidence_status']):
        raise ValueError('Hybrid status/result disagreement')
    event = {'schema_version': 1, 'event_type': 'thesis_hybrid_priority', 'mode': 'completed_session_hybrid',
        'historical_replay': True, 'synthetic': False,
        **{k: rf[k] for k in ('session_id', 'session_id_source', 'username', 'activity_start', 'activity_end',
            'observation_start', 'observation_end', 'prediction_cutoff', 'model', 'model_artifact', 'model_sha256',
            'telemetry_completeness_status', 'telemetry_review_required', 'telemetry_missing_features')},
        'source_results_sha256': manifest['hybrid_result.json'], 'rf_prediction_id': rf['prediction_id'],
        'rf_classification': result['rf_classification'], 'rf_malicious_probability': result['rf_malicious_probability'],
        'wazuh_detected': result['wazuh_detected'], 'wazuh_evidence_verified': result['wazuh_evidence_verified'],
        'wazuh_evidence_status': result['wazuh_evidence_status'],
        'matched_rule_ids': ','.join(evidence['matched_rule_ids']), 'verified_matching_alerts': len(evidence['matched']),
        'unresolved_alert_count': len(evidence['unresolved']),
        'unresolved_rule_ids': ','.join(sorted({r['rule_id'] for r in evidence['unresolved']})),
        'unresolved_evidence_reasons': ','.join(sorted({r['reason'] for r in evidence['unresolved']})),
        'hybrid_priority': result['hybrid_priority'], 'investigation_required': result['investigation_required'],
        'fusion_policy_version': result['fusion_policy_version']}
    event['prediction_id'] = prediction_id(event)
    validate_hybrid(event)
    # Detect source changes during preparation, without rewriting either run.
    if check_manifest(run, 'output_manifest.json', set(manifest)) != manifest:
        raise ValueError('Hybrid manifest changed during verification')
    check_manifest(source, 'output_manifest.json', {'result.json', 'provenance.json', 'retrieved_events.jsonl'})
    if sha(source / 'output_manifest.json') != source_manifest_sha:
        raise ValueError('RF manifest changed during hybrid verification')
    return event, sha(run / 'output_manifest.json')


def synthetic_hybrid(high=True):
    from .prediction_publisher import synthetic_completed
    rf = synthetic_completed('malicious' if high else 'benign')
    event = {'schema_version': 1, 'event_type': 'thesis_hybrid_priority', 'mode': 'completed_session_hybrid',
        'historical_replay': True, 'synthetic': True,
        **{k: rf[k] for k in ('session_id', 'session_id_source', 'username', 'activity_start', 'activity_end',
            'observation_start', 'observation_end', 'prediction_cutoff', 'model', 'model_artifact', 'model_sha256',
            'telemetry_completeness_status', 'telemetry_review_required', 'telemetry_missing_features')},
        'source_results_sha256': '0'*64, 'rf_prediction_id': rf['prediction_id'],
        'rf_classification': rf['classification'], 'rf_malicious_probability': rf['malicious_probability'],
        'wazuh_detected': 1, 'wazuh_evidence_verified': True, 'wazuh_evidence_status': 'verified_positive',
        'matched_rule_ids': '100100', 'verified_matching_alerts': 1, 'unresolved_alert_count': 1,
        'unresolved_rule_ids': '100301', 'unresolved_evidence_reasons': 'watcher_summary_host_window_identity_contract_unverified',
        'hybrid_priority': 'High Priority' if high else 'Needs Review', 'investigation_required': True,
        'fusion_policy_version': FUSION_POLICY_VERSION}
    event['prediction_id'] = prediction_id(event)
    return validate_hybrid(event)


def verify_prepared(prepared):
    check_manifest(prepared, 'manifest.json', {'hybrid_payload.json', 'preparation.json',
        'synthetic_high_priority.json', 'synthetic_needs_review.json'})
    receipt = strict_json((prepared / 'preparation.json').read_text())
    if receipt.get('status') != 'prepared_locally' or receipt.get('network_used') is not False:
        raise ValueError('Verified local preparation required')
    event, digest = verified_hybrid(Path(receipt['hybrid_run']))
    if digest != receipt['hybrid_manifest_sha256'] or event != strict_json((prepared / 'hybrid_payload.json').read_text()):
        raise ValueError('Prepared hybrid payload/source mismatch')
    for name, high in [('high_priority', True), ('needs_review', False)]:
        if strict_json((prepared / f'synthetic_{name}.json').read_text()) != synthetic_hybrid(high):
            raise ValueError('Synthetic preparation changed')
    return event


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prepare = sub.add_parser('prepare', help='Verify and prepare locally; never sends')
    prepare.add_argument('--hybrid-dir', type=Path, required=True)
    prepare.add_argument('--output-dir', type=Path, required=True)
    send = sub.add_parser('send', help='Explicit manual SSH publication; rechecks all provenance')
    send.add_argument('--prepared-dir', type=Path, required=True)
    send.add_argument('--ssh-host', required=True)
    send.add_argument('--synthetic', choices=('high_priority', 'needs_review'))
    send.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    out = args.output_dir.resolve()
    if not out.is_relative_to(Path.cwd().resolve() / 'data/experiments') or out.exists():
        parser.error('Use a fresh ignored data/experiments/ output directory')
    out.mkdir(parents=True, exist_ok=False)
    receipt = {'action': args.action, 'status': 'blocked', 'remote_submissions': []}
    stage = 'hybrid_source_verification' if args.action == 'prepare' else 'prepared_source_verification'
    try:
        if args.action == 'prepare':
            event, digest = verified_hybrid(args.hybrid_dir)
            stage = 'local_preparation_output'
            write(out / 'hybrid_payload.json', event)
            write(out / 'synthetic_high_priority.json', synthetic_hybrid(True))
            write(out / 'synthetic_needs_review.json', synthetic_hybrid(False))
            receipt.update(status='prepared_locally', network_used=False, hybrid_run=str(args.hybrid_dir.resolve()),
                           hybrid_manifest_sha256=digest, prediction_id=event['prediction_id'])
            write(out / 'preparation.json', receipt)
        else:
            event = verify_prepared(args.prepared_dir.resolve())
            if args.synthetic: event = synthetic_hybrid(args.synthetic == 'high_priority')
            stage = 'ssh_publication'
            ack = _ssh_send(event, args.ssh_host, validate_hybrid)
            receipt.update(status='acknowledged', remote_submissions=[ack], synthetic=event['synthetic'],
                           payload_sha256=hashlib.sha256(canonical(event).encode()).hexdigest())
        write(out / 'receipt.json', receipt)
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
        receipt['reason'] = 'Hybrid source/provenance/schema verification or receiver/SSH acknowledgement failed; no raw event or credential details printed.'
        receipt.update(failed_stage=stage, exception_type=type(exc).__name__)
        write(out / 'receipt.json', receipt)
    write(out / 'manifest.json', {p.name: sha(p) for p in sorted(out.iterdir()) if p.is_file()})
    print(canonical(receipt))
    return 0 if receipt['status'] != 'blocked' else 2


if __name__ == '__main__': raise SystemExit(main())
