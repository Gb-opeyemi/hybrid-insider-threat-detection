"""Opt-in, read-only operational Wazuh evidence + preserved RF priority fusion."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from urllib.parse import quote
import xml.etree.ElementTree as ET

from .. import features as ref
from ..hybrid_priority import fuse_hybrid_priority
from ..prediction_publisher import verified_completed_session, sha, write, canonical
from .indexer import IndexerClient, RetrievalError, validate_mapping, event_time_filter, check_page

RULE_FILES = ('thesis_insider_rules.xml', 'thesis_m02_rules.xml', 'thesis_m03_rules.xml',
              'thesis_m04_rules.xml', 'thesis_m05_rules.xml')
RULE_IDS = ('100100', '100101', '100200', '100201', '100301', '100401', '100501')
WINDOWS_RULES = {'100100': (ref.SECURITY, '5145'), '100101': (ref.SECURITY, '5145'),
                 '100200': (ref.SECURITY, '4625'), '100201': (ref.SECURITY, '4625'),
                 '100501': (ref.SYSMON, '1')}


def safe_failure(stage, exc):
    """Classify trusted client error patterns; never serialize arbitrary exceptions."""
    message = str(exc)
    failure_stage = stage
    explanation = 'Unexpected client/schema error; inspect this stage locally. Raw exception and server contents omitted.'
    result = {'request_stage': stage, 'exception_type': type(exc).__name__}
    http = re.match(r'^Indexer HTTP ([0-9]{3});', message) if isinstance(exc, RetrievalError) else None
    if http:
        code = int(http.group(1)); result['http_status'] = code
        failure_stage = {401: 'authentication', 403: 'authorization', 404: 'index_discovery'}.get(code, stage)
        explanation = {401: 'Indexer rejected authentication; check the existing local credential variables.',
                       403: 'Indexer denied this read operation; check alert-index read/search permissions.',
                       404: 'Requested index/endpoint was not found; check alert index discovery/retention.',
                       400: 'Indexer rejected the request; inspect query/mapping compatibility at this stage.'}.get(
                           code, 'Indexer returned an HTTP error; raw response omitted.')
    elif isinstance(exc, RetrievalError) and message.startswith('TLS certificate verification failed:'):
        failure_stage = 'tls_connection'
        explanation = ('Certificate validation failed because the CA lacks key usage. The existing private CA previously required the explicitly selected legacy_ca profile; strict remains the default.'
                       if 'key usage' in message.casefold() else
                       'TLS certificate verification failed; check CA trust, validity and hostname. Do not disable verification.')
    elif isinstance(exc, RetrievalError) and 'connection refused or timed out' in message:
        failure_stage = 'connection'
        explanation = 'Connection refused/timed out; check the existing SSH tunnel and endpoint.'
    elif isinstance(exc, RetrievalError) and 'connection/TLS' in message:
        failure_stage = 'connection_or_tls'
        explanation = 'Transport/TLS/JSON failure; the shared client omits raw transport and server details.'
    elif stage == 'client_initialization' and isinstance(exc, OSError):
        failure_stage = 'ca_certificate_loading'
        explanation = 'Could not load the local CA file or initialise TLS; check file readability and certificate format.'
    elif stage in {'mapping_validation', 'rule_mapping_validation'}:
        explanation = 'Alert mapping does not meet the existing timestamp/channel/rule-ID contract; inspect the reported field types. No fallback mapping was selected.'
    elif stage in {'search_response_validation', 'count_response_validation', 'pagination', 'pagination_validation'}:
        explanation = 'Partial, timed-out, malformed, oversized or inconsistent alert results refused; no negative decision inferred.'
    elif stage == 'session_attribution':
        explanation = 'Session-evidence attribution failed; no matching criteria were relaxed.'
    elif stage == 'hybrid_result_serialization':
        explanation = 'Hybrid result is not valid JSON; output metadata must contain JSON-compatible values. RF verification is a separate earlier stage.'
    result.update(failing_stage=failure_stage, explanation=explanation)
    return result


class AlertDiagnosticError(RetrievalError):
    """The safe details are held in the audit, never in raw server text."""


class AlertClient(IndexerClient):
    """Explicit alert-source adapter; reuse only the existing read-only TLS transport.

    Original archive client/capture validation remains unchanged. Inherited request
    permits only mappings, search/count and ephemeral scroll cleanup for this index.
    """
    def __init__(self, url, pattern, username, password, ca_file, **kwargs):
        if not re.fullmatch(r'wazuh-alerts-[a-zA-Z0-9.*_-]+', pattern):
            raise ValueError('An explicit wazuh-alerts-* pattern is required')
        super().__init__(url, pattern.replace('wazuh-alerts-', 'wazuh-archives-', 1),
                         username, password, ca_file, **kwargs)
        self.pattern = pattern


def alert_query(plan, clock_kind):
    # Retrieve all custom summaries received during the evidence interval, not
    # merely Windows-channel documents. Unknown summary schemas must stay visible.
    windows = event_time_filter(clock_kind, plan['observation_end'], plan['observation_start'])
    return {'bool': {'filter': [
        {'terms': {'rule.id': list(RULE_IDS)}},
        {'range': {'timestamp': {'gte': plan['evidence_start'], 'lte': plan['prediction_cutoff']}}},
        {'bool': {'should': [windows, {'terms': {'rule.id': ['100301', '100401']}},
                            {'bool': {'must_not': [{'exists': {'field': 'data.win.system.systemTime'}}]}}],
                  'minimum_should_match': 1}},
    ]}}


def fetch_alerts(client, plan, maximum=10000, *, diagnostics=None, check_access_only=False):
    audit = diagnostics if diagnostics is not None else {}
    audit.update(index_pattern=client.pattern, tls_profile=client.tls_profile,
                 certificate_verification_required=True, hostname_verification=True,
                 network_attempted=False, completed_stages=[])
    base = '/' + quote(client.pattern, safe='*.-_')
    stage, scroll = 'mapping_request', None
    rows, seen = [], set()
    try:
        audit['network_attempted'] = True
        mapping = client.request('GET', base + '/_mapping')
        audit['completed_stages'].append(stage)
        stage = 'mapping_validation'
        from .indexer import mapping_type
        audit['mapping_field_types'] = [
            {field: mapping_type(info.get('mappings', {}).get('properties', {}), field)
             for field in ('timestamp', 'data.win.system.systemTime', 'data.win.system.channel', 'rule.id')}
            for info in mapping.values()]
        kind = validate_mapping(mapping)
        audit['completed_stages'].append(stage)
        stage = 'rule_mapping_validation'
        for info in mapping.values():
            if info.get('mappings', {}).get('properties', {}).get('rule', {}).get('properties', {}).get('id', {}).get('type') != 'keyword':
                raise RetrievalError('Expected keyword rule.id mapping; no automatic field substitution')
        audit['completed_stages'].append(stage)
        query = alert_query(plan, kind); audit['query'] = query
        if check_access_only:
            stage = 'alert_count_query'
            counted = client.request('POST', base + '/_count', {'query': query})
            audit['completed_stages'].append(stage)
            stage = 'count_response_validation'
            if (counted.get('_shards', {}).get('failed') != 0 or counted.get('_shards', {}).get('total', 0) < 1
                    or type(counted.get('count')) is not int or counted['count'] < 0):
                raise RetrievalError('Partial/invalid count response')
            audit['completed_stages'].append(stage)
            audit.update(status='access_verified', matching_custom_rule_documents=counted['count'],
                         event_documents_downloaded=0, complete_scroll=False,
                         note='Mapping and bounded count access verified; pagination and session attribution not tested.')
            return [], audit
        stage = 'alert_search'
        page = client.request('POST', base + '/_search?scroll=2m&allow_partial_search_results=false',
                              {'size': 500, 'sort': ['_doc'], 'track_total_hits': True, '_source': True, 'query': query})
        scroll = page.get('_scroll_id'); audit['completed_stages'].append(stage)
        stage = 'search_response_validation'
        check_page(page)
        total = page.get('hits', {}).get('total', {})
        if total.get('relation') != 'eq' or type(total.get('value')) is not int or not 0 <= total['value'] <= maximum:
            raise RetrievalError('Exact bounded alert count required; no truncated decision')
        while True:
            hits = check_page(page)
            if not hits: break
            for hit in hits:
                key = (hit.get('_index'), hit.get('_id'))
                if not all(key) or key in seen: raise RetrievalError('Missing/repeated alert document identity')
                seen.add(key)
                rows.append({'index': key[0], 'document_id': key[1], 'source': hit['_source']})
            if len(rows) > total['value']: raise RetrievalError('Inconsistent alert pagination')
            if len(rows) == total['value']: break
            if not scroll: raise RetrievalError('Missing alert scroll context')
            stage = 'pagination'
            page = client.request('POST', '/_search/scroll', {'scroll': '2m', 'scroll_id': scroll})
            scroll = page.get('_scroll_id', scroll)
            stage = 'pagination_validation'
        if len(rows) != total['value']: raise RetrievalError('Incomplete alert retrieval')
        audit['completed_stages'].append(stage)
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
        audit.update(status='failed', error=safe_failure(stage, exc))
        raise AlertDiagnosticError('Alert retrieval failed; see sanitised retrieval audit') from None
    finally:
        if scroll:
            try:
                client.request('DELETE', '/_search/scroll', {'scroll_id': [scroll]})
            except (ValueError, OSError, KeyError, TypeError) as exc:
                cleanup_error = safe_failure('scroll_cleanup', exc)
                if 'error' in audit:
                    audit['cleanup_error'] = cleanup_error
                else:
                    audit.update(status='failed', error=cleanup_error)
                    raise AlertDiagnosticError('Scroll cleanup failed; see sanitised retrieval audit') from None
    rows.sort(key=lambda r: (r['index'], r['document_id']))
    audit.update(status='query_verified', documents=len(rows), complete_scroll=True)
    return rows, audit


def verified_event_context(capture, plan, accepted_hosts):
    """Use the unchanged reference account/process policy, not bare-name matching."""
    base = plan['username'].rsplit('\\', 1)[-1]
    index = ref.EvidenceIndex({base})
    stats, errors = Counter(), []
    cutoff = ref.timestamp(plan['prediction_cutoff'])
    for event in ref.events([capture], stats, errors):
        if event.available() > cutoff: raise ValueError('RF capture contains future evidence')
        index.inspect(event)
    if errors: raise ValueError('Unreadable RF evidence capture')
    hosts = {h.casefold() for h in accepted_hosts}
    digests = set()
    matcher = ref.Matcher([ref.Window('selected', base, ref.timestamp(plan['actual_start']),
                                     ref.timestamp(plan['actual_end']), 'preserved_request')], 2)
    for event in ref.events([capture], Counter(), errors):
        if (event.host not in hosts or not matcher.candidates(base, event.time())
                or not ref.timestamp(plan['actual_start']) <= event.available() <= cutoff): continue
        user, _ = index.identity(event)
        if user != base: continue
        if '\\' in plan['username']:
            known = index.domain_first[base].get(plan['username'].rsplit('\\', 1)[0])
            if known is None or known > event.available(): continue
        if not ref.is_artifact(event): digests.add(event.digest())
    if errors: raise ValueError('Unreadable RF evidence capture')
    return index, digests


def match_alerts(rows, plan, index, session_digests, accepted_hosts):
    """A positive needs an exact session event plus causal identity/host evidence.

    Empty or incomplete alert coverage never establishes a negative. Watcher
    summaries lack a verified host/window contract in the available frozen XML;
    preserve them as unresolved rather than inventing one from receipt time.
    """
    matched, unresolved, rejected = [], [], []
    seen = set()
    base = plan['username'].rsplit('\\', 1)[-1]
    hosts = {h.casefold() for h in accepted_hosts}
    lo, hi, cutoff = [ref.timestamp(plan[k]) for k in ('observation_start', 'observation_end', 'prediction_cutoff')]
    for record in sorted(rows, key=lambda r: (r['index'], r['document_id'])):
        source = record['source']; rid = str(source.get('rule', {}).get('id', ''))
        item = {'rule_id': rid, 'index': record['index'], 'document_id': record['document_id']}
        if rid not in RULE_IDS:
            rejected.append({**item, 'reason': 'not_an_M01_M05_rule'}); continue
        try:
            receipt = ref.timestamp(source.get('timestamp'))
            if not ref.timestamp(plan['evidence_start']) <= receipt <= cutoff:
                rejected.append({**item, 'reason': 'outside_availability_interval'}); continue
            win = source.get('data', {}).get('win', {})
            if rid not in WINDOWS_RULES:
                unresolved.append({**item, 'reason': 'watcher_summary_host_window_identity_contract_unverified',
                                   'data_fields': sorted(source.get('data', {})), 'receipt_utc': ref.iso(receipt)})
                continue
            event = ref.Event(win['system'], win.get('eventdata', {}), source)
            item.update(host=event.host, event_time=ref.iso(event.time()), receipt_time=ref.iso(receipt),
                        event_record_id=event.system.get('eventRecordID'))
            if event.host not in hosts or not lo <= event.time() <= hi or event.available() > cutoff:
                rejected.append({**item, 'reason': 'wrong_host_or_time'}); continue
            if (event.provider, event.eid) != WINDOWS_RULES[rid]:
                unresolved.append({**item, 'reason': 'unexpected_rule_event_schema'}); continue
            user, identity_source = index.identity(event)
            if user != base:
                rejected.append({**item, 'reason': 'wrong_or_unresolved_account'}); continue
            if '\\' in plan['username']:
                known = index.domain_first[base].get(plan['username'].rsplit('\\', 1)[0])
                if known is None or known > event.available():
                    unresolved.append({**item, 'reason': 'namespace_not_verified_as_of_alert'}); continue
            digest = event.digest()
            if digest not in session_digests:
                unresolved.append({**item, 'reason': 'no_exact_verified_session_event'}); continue
            if (rid, digest) in seen: continue
            seen.add((rid, digest))
            matched.append({**item, 'event_digest': digest.hex(), 'identity_source': identity_source,
                            'attribution_scope': 'verified_session_trigger_event; rule_correlation_history_may_precede_session'})
        except (KeyError, ValueError, TypeError, AttributeError):
            unresolved.append({**item, 'reason': 'missing_or_invalid_alert_timestamps_or_schema'})
    return {'wazuh_detected': 1 if matched else None, 'wazuh_evidence_verified': bool(matched),
            'evidence_status': 'verified_positive' if matched else 'unavailable',
            'matched_rule_ids': sorted({m['rule_id'] for m in matched}),
            'matched': matched, 'unresolved': unresolved, 'rejected': rejected,
            'negative_decision_verified': False,
            'coverage_note': 'Search completeness is not proof of rule deployment, watcher execution, collection health, retention or a negative M01-M05 decision.'}


def hybrid_result(event, evidence):
    decision = fuse_hybrid_priority(int(event['classification'] == 'malicious'), evidence['wazuh_detected'],
                                   wazuh_evidence_verified=evidence['wazuh_evidence_verified'])
    return {'mode': 'completed_session_hybrid_dry_run', 'dry_run': True, 'alerts_published': False,
            'session_id': event['session_id'], 'session_id_source': event['session_id_source'],
            'username': event['username'], 'rf_classification': event['classification'],
            'rf_malicious_probability': event['malicious_probability'],
            'rf_prediction_id': event['prediction_id'], 'rf_model_sha256': event['model_sha256'],
            'activity_start': event['activity_start'], 'activity_end': event['activity_end'],
            'observation_start': event['observation_start'], 'observation_end': event['observation_end'],
            'prediction_cutoff': event['prediction_cutoff'],
            'telemetry_completeness_status': event['telemetry_completeness_status'],
            'telemetry_review_required': event['telemetry_review_required'],
            'telemetry_missing_features': event['telemetry_missing_features'],
            'matched_wazuh_rule_ids': evidence.get('matched_rule_ids', []),
            'wazuh_evidence_status': evidence.get('evidence_status', 'verified' if evidence['wazuh_evidence_verified'] else 'unavailable'),
            'wazuh_evidence': evidence, **decision.to_dict(),
            'investigation_required': bool(decision.review_required)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--check-access', action='store_true',
                        help='Mappings and session-bounded count only; downloads no alert events and performs no fusion')
    args = parser.parse_args(argv)
    root = Path.cwd().resolve(); out = args.output_dir.resolve()
    if not out.is_relative_to(root / 'data/experiments') or out.exists():
        parser.error('Use a fresh ignored data/experiments/ output directory')
    out.mkdir(parents=True, exist_ok=False)
    status = {'status': 'blocked', 'dry_run': True, 'alerts_published': False, 'test_partition_accessed': False}
    phase = 'rf_verification'
    try:
        events, manifest_sha = verified_completed_session(args.session_dir, root)
        phase = 'session_metadata'
        event = events[0]; run = args.session_dir.resolve()
        source_manifest = json.loads((run / 'output_manifest.json').read_text())
        plan = json.loads((run / 'request.json').read_text())
        validation = json.loads((run / 'validation.json').read_text())
        rule_hashes = {}
        phase = 'rule_provenance'
        for name in RULE_FILES:
            path = root / 'data/wazuh/etc/rules' / name
            rule_hashes[str(path)] = sha(path)
            # Verify the inspected frozen definitions, never substitute evaluation decisions.
            ET.parse(path)
        if not args.check_access:
            phase = 'session_context'
            index, digests = verified_event_context(run / 'retrieved_events.jsonl', plan,
                                                    validation['accepted_behavior_hosts'])
        retrieval = {'status': 'unavailable', 'tls_profile': os.environ.get('WAZUH_INDEXER_TLS_PROFILE', 'strict'),
                     'network_attempted': False}
        stage = 'environment_validation'
        try:
            required_env = ('WAZUH_INDEXER_URL', 'WAZUH_INDEXER_USERNAME',
                            'WAZUH_INDEXER_PASSWORD', 'WAZUH_INDEXER_CA_CERT')
            missing_env = [name for name in required_env if not os.environ.get(name)]
            if missing_env:
                retrieval.update(status='configuration_missing', missing_environment_variables=missing_env,
                             network_attempted=False,
                             reason='Run in the existing authenticated Mac terminal, or export the existing indexer settings there. No new connection is required.')
                raise ValueError('Existing indexer environment is not loaded')
            stage = 'client_initialization'
            client = AlertClient(os.environ['WAZUH_INDEXER_URL'],
                os.environ.get('WAZUH_ALERT_INDEX_PATTERN', 'wazuh-alerts-*'),
                os.environ['WAZUH_INDEXER_USERNAME'], os.environ['WAZUH_INDEXER_PASSWORD'],
                os.environ['WAZUH_INDEXER_CA_CERT'], tls_profile=os.environ.get('WAZUH_INDEXER_TLS_PROFILE', 'strict'))
            rows, retrieval = fetch_alerts(client, plan, diagnostics=retrieval, check_access_only=args.check_access)
            if not args.check_access:
                stage = 'alert_capture_output'
                with (out / 'retrieved_alerts.jsonl').open('x') as handle:
                    for row in rows: handle.write(json.dumps(row) + '\n')
                stage = 'session_attribution'
                evidence = match_alerts(rows, plan, index, digests, validation['accepted_behavior_hosts'])
                retrieval['completed_stages'].append(stage)
                retrieval['session_attribution'] = {
                    'evidence_status': evidence['evidence_status'],
                    'matched_alerts': len(evidence['matched']),
                    'unresolved_alerts': len(evidence['unresolved']),
                    'rejected_alerts': len(evidence['rejected']),
                    'unresolved_reasons': dict(Counter(r['reason'] for r in evidence['unresolved'])),
                    'rejected_reasons': dict(Counter(r['reason'] for r in evidence['rejected'])),
                }
        except (ValueError, OSError, KeyError, TypeError) as exc:
            if 'error' not in retrieval:
                retrieval['error'] = safe_failure(stage, exc)
            if retrieval.get('status') != 'configuration_missing': retrieval['status'] = 'failed'
            evidence = {'wazuh_detected': None, 'wazuh_evidence_verified': False,
                        'evidence_status': 'query_failed_or_unavailable', 'matched_rule_ids': [],
                        'reason': 'Read-only alert query unavailable/failed; no negative decision inferred. Credentials/server response omitted.'}
            if retrieval.get('status') == 'configuration_missing':
                evidence.update(evidence_status='configuration_missing',
                                missing_environment_variables=retrieval['missing_environment_variables'],
                                reason=retrieval['reason'])
            evidence['diagnostic'] = retrieval['error']
        phase = 'source_integrity_recheck'
        if sha(run / 'output_manifest.json') != manifest_sha:
            raise ValueError('Preserved session manifest changed during dry-run')
        for name, digest in source_manifest.items():
            path = (run / name).resolve()
            if path.parent != run or sha(path) != digest:
                raise ValueError('Preserved RF evidence changed during dry-run')
        if any(sha(Path(path)) != digest for path, digest in rule_hashes.items()):
            raise ValueError('Frozen rule files changed during dry-run')
        phase = 'output_provenance'
        provenance = {'session_manifest_sha256': manifest_sha,
              'source_session_dir': str(run), 'frozen_rule_files_sha256': rule_hashes,
              'code_sha256': {str(p): sha(p) for p in (Path(__file__), root / 'src/hybrid_priority.py')},
              'operational_source': 'actual_indexer_alerts; no retrospective baseline substitution',
              'generated_at_utc': datetime.now(timezone.utc).isoformat()}
        write(out / 'alert_retrieval_audit.json', retrieval)
        write(out / 'provenance.json', provenance)
        if args.check_access:
            status.update(status='access_verified' if retrieval['status'] == 'access_verified' else 'access_check_failed',
                          event_documents_downloaded=0)
        else:
            phase = 'hybrid_fusion'
            result = hybrid_result(event, evidence)
            phase = 'hybrid_result_serialization'
            # Validate before opening the output; do not leave an empty result
            # if an unexpected metadata type cannot be serialized.
            canonical(result)
            phase = 'hybrid_result_output'
            write(out / 'hybrid_result.json', result)
            status.update(status='completed_dry_run', hybrid_priority=result['hybrid_priority'],
                          investigation_required=result['investigation_required'], wazuh_evidence_status=evidence['evidence_status'])
            if 'session_attribution' in retrieval:
                status['wazuh_attribution_summary'] = retrieval['session_attribution']
        if 'error' in retrieval:
            status['wazuh_failure'] = retrieval['error']
    except (ValueError, OSError, KeyError, TypeError, ET.ParseError) as exc:
        status['reason'] = phase + ' failed; no hybrid result produced.'
        status['failure'] = safe_failure(phase, exc)
    write(out / 'run_status.json', status)
    write(out / 'output_manifest.json', {p.name: sha(p) for p in sorted(out.iterdir()) if p.is_file()})
    print(json.dumps(status, indent=2))
    return 0 if status['status'] in {'completed_dry_run', 'access_verified'} else 2


if __name__ == '__main__':
    raise SystemExit(main())
