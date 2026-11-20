"""Independent operational alert acquisition using the preserved Wazuh matcher."""
import json
import os
from pathlib import Path
from ..controlled_replay.hybrid_session import AlertClient, fetch_alerts, RULE_FILES
from .common import code_hashes, manifest, output, read, seal, sha, write
from .new_session import verified_inference


def rule_hashes(root):
    return {str(Path(root) / 'data/wazuh/etc/rules' / n): sha(Path(root) / 'data/wazuh/etc/rules' / n) for n in RULE_FILES}


def capture(root, inference, out, client=None):
    _, plan, _, source = verified_inference(root, inference)
    out = output(root, out); audit = {'status': 'failed', 'stage': 'client_initialization'}
    try:
        client = client or AlertClient(os.environ['WAZUH_INDEXER_URL'], os.environ['WAZUH_ALERT_INDEX_PATTERN'],
            os.environ['WAZUH_INDEXER_USERNAME'], os.environ['WAZUH_INDEXER_PASSWORD'],
            ca_file=os.environ['WAZUH_INDEXER_CA_CERT'], tls_profile=os.environ.get('WAZUH_INDEXER_TLS_PROFILE', 'strict'))
        rows, audit = fetch_alerts(client, plan, diagnostics=audit)
        with (out / 'retrieved_alerts.jsonl').open('x') as handle:
            for row in rows: handle.write(json.dumps(row) + '\n')
        write(out / 'alert_acquisition.json', {'selected_model': 'tabpfn',
            'source': 'fresh_authenticated_wazuh_alerts', 'inference_dir': str(Path(inference).resolve()),
            'inference_manifest_sha256': sha(Path(inference) / 'output_manifest.json'),
            'capture_sha256': sha(source / 'retrieved_events.jsonl'), 'code_sha256': code_hashes(root),
            'frozen_rule_files_sha256': rule_hashes(root), 'alerts_published': False})
    except (OSError, ValueError, KeyError, TypeError) as exc:
        audit.update(status='failed', exception_type=type(exc).__name__,
                     reason='Operational alert acquisition unavailable; no negative inferred.')
        write(out / 'alert_retrieval_audit.json', audit); seal(out)
        raise ValueError('Wazuh alert query unavailable; inspect stage audit') from None
    write(out / 'alert_retrieval_audit.json', audit); seal(out)
    return out


def verify_source(root, source, plan, capture_sha):
    source = Path(source).resolve()
    if not source.is_relative_to(Path(root).resolve() / 'data/experiments/tabpfn_prototype'):
        raise ValueError('Separate TabPFN alert capture required')
    manifest(source, {'alert_acquisition.json', 'retrieved_alerts.jsonl', 'alert_retrieval_audit.json'})
    info = read(source / 'alert_acquisition.json')
    _, actual_plan, _, events = verified_inference(root, info['inference_dir'])
    if (info['selected_model'] != 'tabpfn' or info['source'] != 'fresh_authenticated_wazuh_alerts'
            or info['alerts_published'] is not False or info['code_sha256'] != code_hashes(root)
            or info['inference_manifest_sha256'] != sha(Path(info['inference_dir']) / 'output_manifest.json')
            or actual_plan != plan or info['capture_sha256'] != capture_sha
            or sha(events / 'retrieved_events.jsonl') != capture_sha
            or info['frozen_rule_files_sha256'] != rule_hashes(root)):
        raise ValueError('Independent alert acquisition provenance changed')
    return info['frozen_rule_files_sha256']
