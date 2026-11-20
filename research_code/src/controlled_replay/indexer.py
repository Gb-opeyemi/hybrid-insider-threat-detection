"""Read-only Wazuh archive search with complete scroll pagination and TLS."""
from __future__ import annotations

import base64
import json
import re
import ssl
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import (HTTPRedirectHandler, HTTPSHandler, ProxyHandler,
                            Request, build_opener)

from .. import features as ref


class RetrievalError(ValueError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RetrievalError("Indexer redirects are forbidden")


def tls_context(ca_file: str | None, profile: str = 'strict') -> ssl.SSLContext:
    """Explicit legacy CA-format compatibility; never disable chain/host checks.

    Python 3.13 enables additional RFC 5280 conformance checks by default.
    Legacy mode opts out of that flag only, for existing private CAs lacking
    extensions required by strict mode. It is a validation-policy relaxation,
    not equivalent security to strict mode, and must be explicitly selected.
    """
    if profile not in {'strict', 'legacy_ca'}:
        raise ValueError('WAZUH_INDEXER_TLS_PROFILE must be strict or legacy_ca')
    context = ssl.create_default_context(cafile=ca_file)
    if profile == 'legacy_ca':
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    else:
        context.verify_flags |= ssl.VERIFY_X509_STRICT
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise ValueError('Certificate-chain and hostname verification are mandatory')
    return context


TIME_FIELD = 'data.win.system.systemTime'
PARSE_TIME = "java.time.Instant.parse(doc[params.field].value).truncatedTo(java.time.temporal.ChronoUnit.MICROS)"


def event_time_filter(kind: str, upper: str, lower: str | None = None) -> dict:
    """Parse keyword clocks; never use lexicographic date ranges.

    Truncation to microseconds matches the existing Python timestamp parser.
    This query-time script reads doc values; it does not write index mappings.
    """
    if kind == 'date':
        return {'range': {TIME_FIELD: {'lte': upper, **({'gte': lower} if lower else {})}}}
    if kind != 'keyword':
        raise RetrievalError('Unsupported Windows timestamp mapping')
    return {'script': {'script': {'lang': 'painless', 'params': {'field': TIME_FIELD, 'upper': upper, 'lower': lower},
        'source': "if (doc[params.field].size() != 1) return false; try { def t = " + PARSE_TIME + "; "
                  "return t.compareTo(java.time.Instant.parse(params.upper)) <= 0 && "
                  "(params.lower == null || t.compareTo(java.time.Instant.parse(params.lower)) >= 0); "
                  "} catch (Exception e) { return false; }"}}}


def invalid_time_query(query: dict, kind: str) -> dict:
    filters = [query['bool']['filter'][0], query['bool']['filter'][2]]
    if kind == 'date':
        return {'bool': {'filter': filters, 'must_not': [{'exists': {'field': TIME_FIELD}}]}}
    return {'bool': {'filter': filters + [{'script': {'script': {'lang': 'painless',
        'params': {'field': TIME_FIELD}, 'source':
        "if (doc[params.field].size() != 1) return true; try { def t = " + PARSE_TIME +
        "; return false; } catch (Exception e) { return true; }"}}}]}}


def search_query(start: datetime, cutoff: datetime, time_kind: str = 'date') -> dict:
    """Background evidence is needed before the session, but never after cutoff."""
    if start >= cutoff:
        raise ValueError("Invalid evidence interval")
    return {"bool": {"filter": [
        {"range": {"timestamp": {"gte": ref.iso(start), "lte": ref.iso(cutoff)}}},
        event_time_filter(time_kind, ref.iso(cutoff)),
        {"terms": {"data.win.system.channel": ["Security", "Microsoft-Windows-Sysmon/Operational"]}},
    ]}}


def validate_envelope(source: dict, start: datetime, cutoff: datetime) -> ref.Event:
    try:
        win = source["data"]["win"]
        system, payload = win["system"], win.get("eventdata", {})
        if not isinstance(system, dict) or not isinstance(payload, dict):
            raise ValueError
        e = ref.Event(system, payload, source)
        if not start <= ref.timestamp(source["timestamp"]) <= cutoff or e.available() > cutoff:
            raise ValueError
        if not e.host or not e.system.get("eventRecordID") or not ref.supported_families(e):
            raise ValueError
        return e
    except (KeyError, TypeError, ValueError, AttributeError):
        raise RetrievalError("Invalid, unsupported or out-of-cutoff Windows source document") from None


def mapping_type(properties: dict, path: str) -> str | None:
    node = {"properties": properties}
    for part in path.split('.'):
        node = node.get("properties", {}).get(part, {})
    return node.get("type")


def validate_mapping(mapping: dict) -> str:
    if not isinstance(mapping, dict) or not mapping:
        raise RetrievalError("No archive indices available")
    clock_types = set()
    for index in mapping.values():
        props = index.get("mappings", {}).get("properties", {})
        if mapping_type(props, 'timestamp') not in {'date', 'date_nanos'}:
            raise RetrievalError('Expected date mapping for timestamp; inspect actual mapping')
        clock = mapping_type(props, TIME_FIELD)
        if clock not in {'date', 'date_nanos', 'keyword'}:
            raise RetrievalError('Expected date or keyword Windows systemTime mapping')
        clock_types.add('date' if clock in {'date', 'date_nanos'} else clock)
        if mapping_type(props, "data.win.system.channel") != "keyword":
            raise RetrievalError("Expected keyword channel mapping; no automatic field substitution")
    if len(clock_types) != 1:
        raise RetrievalError('Mixed date/keyword clocks require separate reviewed queries')
    return next(iter(clock_types))


def check_page(page: dict) -> list[dict]:
    if page.get("timed_out") is not False or page.get("_shards", {}).get("failed") != 0:
        raise RetrievalError("Partial/timed-out search refused")
    shards = page.get("_shards", {})
    if not isinstance(shards.get("total"), int) or shards["total"] < 1:
        raise RetrievalError("No searchable archive shards")
    hits = page.get("hits", {}).get("hits")
    if not isinstance(hits, list):
        raise RetrievalError("Malformed search response")
    return hits


class IndexerClient:
    """Only mappings, count, search and ephemeral search-context endpoints."""
    def __init__(self, url: str, pattern: str, username: str, password: str,
                 ca_file: str | None = None, page_size: int = 1000, tls_profile: str = 'strict'):
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("Provide an HTTPS indexer origin without credentials/path/query")
        if not re.fullmatch(r"wazuh-archives-[a-zA-Z0-9.*_-]+", pattern):
            raise ValueError("An explicit wazuh-archives-* pattern is required; alerts are insufficient")
        if not username or not password or not 1 <= page_size <= 10000:
            raise ValueError("Read-only credentials and a valid page size are required")
        self.url, self.pattern, self.page_size = url.rstrip('/'), pattern, page_size
        self.auth = 'Basic ' + base64.b64encode(f'{username}:{password}'.encode()).decode()
        self.tls_profile = tls_profile
        self.opener = build_opener(ProxyHandler({}), NoRedirect(),
                                  HTTPSHandler(context=tls_context(ca_file, tls_profile)))
        self.audit = {}

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        base = '/' + quote(self.pattern, safe='*.-_')
        allowed = ((method == "GET" and path in {base + '/_mapping', base + '/_mapping?filter_path=*.mappings.properties.timestamp,*.mappings.properties.data.properties.win.properties.system'}) or
                   (method == "POST" and path in {base + '/_count',
                       base + '/_search?allow_partial_search_results=false',
                       base + '/_search?scroll=2m&allow_partial_search_results=false', '/_search/scroll'}) or
                   (method == "DELETE" and path == '/_search/scroll'))
        if not allowed:
            raise RetrievalError("Non-search operation forbidden")
        req = Request(self.url + path, data=None if body is None else json.dumps(body).encode(),
                      headers={"Authorization": self.auth, "Content-Type": "application/json"}, method=method)
        try:
            with self.opener.open(req, timeout=120) as response:
                result = json.load(response)
            if not isinstance(result, dict):
                raise RetrievalError("Invalid indexer JSON")
            return result
        except HTTPError as e:
            raise RetrievalError(f"Indexer HTTP {e.code}; inspect endpoint, TLS, archive retention and read permissions") from None
        except URLError as e:
            if isinstance(e.reason, ssl.SSLCertVerificationError):
                raise RetrievalError('TLS certificate verification failed: ' + e.reason.verify_message) from None
            if isinstance(e.reason, (ConnectionRefusedError, TimeoutError)):
                raise RetrievalError('Indexer connection refused or timed out; check SSH tunnel and endpoint') from None
            raise RetrievalError('Indexer connection/TLS failure (' + type(e.reason).__name__ + '); credentials omitted') from None
        except (OSError, json.JSONDecodeError, UnicodeError):
            raise RetrievalError("Indexer connection/TLS/JSON failure; credentials and server response omitted") from None

    def capture(self, start: datetime, cutoff: datetime, output, *, event_start: datetime | None = None) -> dict:
        base = '/' + quote(self.pattern, safe='*.-_')
        mapping = self.request('GET', base + '/_mapping')
        time_kind = validate_mapping(mapping)
        query = search_query(start, cutoff, time_kind)
        if event_start is not None:
            if event_start > cutoff:
                raise ValueError('Event-time lower bound is after cutoff')
            query['bool']['filter'][1] = event_time_filter(time_kind, ref.iso(cutoff), ref.iso(event_start))
        # Missing Windows event clocks in the bounded receipt interval must not
        # disappear silently behind the systemTime query filter.
        missing_query = invalid_time_query(query, time_kind)
        missing = self.request('POST', base + '/_count', {'query': missing_query})
        if missing.get('_shards', {}).get('failed') != 0 or missing.get('count') != 0:
            raise RetrievalError("Missing/unparseable Windows timestamps or partial timestamp audit")
        page = self.request('POST', base + '/_search?scroll=2m&allow_partial_search_results=false',
            {'size': self.page_size, 'sort': ['_doc'], 'track_total_hits': True, '_source': True, 'query': query})
        scroll = page.get('_scroll_id')
        count = 0
        doc_ids = set()
        try:
            total = page.get('hits', {}).get('total', {})
            if not isinstance(total, dict) or total.get('relation') != 'eq' or not isinstance(total.get('value'), int) or total['value'] <= 0:
                raise RetrievalError("Exact nonempty archive result count required")
            with output.open('x', encoding='utf-8') as handle:
                while True:
                    hits = check_page(page)
                    if not hits:
                        break
                    for hit in hits:
                        key = (hit.get('_index'), hit.get('_id'))
                        if not all(isinstance(k, str) and k for k in key) or key in doc_ids:
                            raise RetrievalError("Missing/repeated indexer hit identity; pagination refused")
                        doc_ids.add(key)
                        source = hit.get('_source')
                        validate_envelope(source, start, cutoff)
                        handle.write(json.dumps(source, separators=(',', ':')) + '\n')
                        count += 1
                    if count > total['value'] or not scroll:
                        raise RetrievalError("Incomplete or inconsistent scroll pagination")
                    page = self.request('POST', '/_search/scroll', {'scroll': '2m', 'scroll_id': scroll})
                    scroll = page.get('_scroll_id', scroll)
            if count != total['value']:
                raise RetrievalError("Scroll result count mismatch")
        finally:
            if scroll:
                # Frees search resources only; does not delete indexed documents.
                self.request('DELETE', '/_search/scroll', {'scroll_id': [scroll]})
        self.audit = {'source': 'wazuh_indexer', 'query': query, 'index_pattern': self.pattern,
            'tls_profile': self.tls_profile, 'certificate_verification_required': True, 'hostname_verification': True,
            'windows_timestamp_mapping': time_kind,
            'timestamp_query_policy': 'Keyword clocks parsed as Instant and truncated to reference microseconds; no string date ordering',
            'indices_mapping': mapping, 'retrieved_documents': count, 'complete_scroll': True,
            'receipt_start': ref.iso(start), 'availability_cutoff': ref.iso(cutoff),
            'missing_system_time_in_receipt_interval': 0,
            'missing_or_unparseable_system_time_in_receipt_interval': 0,
            'limitation': 'Documents lacking receipt timestamps cannot be temporally audited; exact feature parity is mandatory.'}
        if event_start is not None:
            self.audit['event_time_lower_bound'] = ref.iso(event_start)
        return self.audit
