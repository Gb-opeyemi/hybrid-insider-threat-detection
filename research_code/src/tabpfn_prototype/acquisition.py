"""Fresh read-only acquisition for shadow jobs. No RF inference or dataset rows."""
import json
from pathlib import Path
from ..controlled_replay.new_session import request_window, new_data_boundary, check_competing_windows
from ..controlled_replay.indexer import search_query, event_time_filter, validate_mapping, validate_envelope
from ..session_orchestrator import record, timestamp, digest
from ..wazuh_completion_feed import client_from_environment
from .common import code_hashes, manifest, output, read, seal, sha, write


def make_plan(root, completion, windows, now):
    record(completion, completion['feed_id'])
    if completion['status'] != 'Completed': raise ValueError('Verified successful completion required')
    plan = request_window(completion['username'], completion['start'], completion['end'],
                          new_data_boundary(Path(root)), now=now, availability_delay_seconds=300)
    check_competing_windows(plan, windows, now=now)
    return plan


def capture(root, completion, windows, aliases, out, now, client=None):
    plan = make_plan(root, completion, windows, now)  # Wait before any network/model work.
    out = output(root, out)
    try:
        client = client or client_from_environment()
        audit = client.capture(timestamp(plan['evidence_start']), timestamp(plan['prediction_cutoff']),
                               out / 'retrieved_events.jsonl', event_start=timestamp(plan['new_data_boundary']))
        write(out / 'request.json', plan)
        write(out / 'retrieval_audit.json', audit)
        write(out / 'acquisition.json', {'schema_version': 1, 'selected_model': 'tabpfn',
            'source': 'fresh_authenticated_wazuh_archives', 'completion': completion,
            'completion_sha256': digest(completion), 'competing_windows': windows,
            'allowed_hosts': aliases, 'capture_sha256': sha(out / 'retrieved_events.jsonl'),
            'code_sha256': code_hashes(root), 'captured_at': now.isoformat(),
            'original_dataset_rows_read': False, 'alerts_published': False})
        write(out / 'run_status.json', {'status': 'captured', 'alerts_published': False})
    except (ValueError, OSError, KeyError, TypeError) as exc:
        write(out / 'run_status.json', {'status': 'blocked', 'stage': 'archive_acquisition',
            'exception_type': type(exc).__name__, 'reason': 'Archive retrieval or validation failed; no fallback.',
            'alerts_published': False})
        seal(out)
        raise ValueError('Archive acquisition failed; inspect sanitized stage status') from None
    seal(out)
    verified_capture(root, out)
    return out


def verified_capture(root, source):
    source = Path(source).resolve()
    if not source.is_relative_to(Path(root).resolve() / 'data/experiments/tabpfn_prototype'):
        raise ValueError('Separate TabPFN capture required')
    manifest(source, {'request.json', 'retrieved_events.jsonl', 'retrieval_audit.json', 'acquisition.json', 'run_status.json'})
    info, plan, audit = [read(source / (name + '.json')) for name in ('acquisition', 'request', 'retrieval_audit')]
    if (info['selected_model'] != 'tabpfn' or info['source'] != 'fresh_authenticated_wazuh_archives'
            or info['schema_version'] != 1 or info['original_dataset_rows_read'] is not False
            or info['alerts_published'] is not False or info['completion_sha256'] != digest(info['completion'])
            or info['capture_sha256'] != sha(source / 'retrieved_events.jsonl')
            or info['code_sha256'] != code_hashes(root) or not info['allowed_hosts']
            or any(not isinstance(h, str) or not h for h in info['allowed_hosts'])
            or read(source / 'run_status.json')['status'] != 'captured'):
        raise ValueError('Fresh capture provenance changed')
    expected = make_plan(root, info['completion'], info['competing_windows'], timestamp(info['captured_at']))
    if expected != plan: raise ValueError('Fresh acquisition window/cutoff changed')
    kind = validate_mapping(audit['indices_mapping'])
    query = search_query(timestamp(plan['evidence_start']), timestamp(plan['prediction_cutoff']), kind)
    query['bool']['filter'][1] = event_time_filter(kind, plan['prediction_cutoff'], plan['new_data_boundary'])
    if (audit.get('source') != 'wazuh_indexer' or audit.get('complete_scroll') is not True
            or audit.get('certificate_verification_required') is not True or audit.get('hostname_verification') is not True
            or audit['query'] != query or audit['availability_cutoff'] != plan['prediction_cutoff']
            or audit['receipt_start'] != plan['evidence_start'] or audit['event_time_lower_bound'] != plan['new_data_boundary']
            or audit.get('missing_or_unparseable_system_time_in_receipt_interval') != 0):
        raise ValueError('Complete cutoff-bounded TLS archive query required')
    count = 0
    with (source / 'retrieved_events.jsonl').open() as handle:
        for line in handle:
            event = validate_envelope(json.loads(line), timestamp(plan['evidence_start']), timestamp(plan['prediction_cutoff']))
            if event.time() < timestamp(plan['new_data_boundary']): raise ValueError('Original dataset event refused')
            count += 1
    if type(audit['retrieved_documents']) is not int or count != audit['retrieved_documents'] or not count:
        raise ValueError('Fresh capture count mismatch')
    return source, plan, None, sha(source / 'output_manifest.json')
