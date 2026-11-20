"""Read dedicated Windows lifecycle events through the existing TLS indexer client.

Only completion-source metadata is handled here. Detector evidence cutoffs remain
inside the unchanged RF/hybrid commands, even if a trigger arrives much later.
"""
from __future__ import annotations
import json
import os
from datetime import timedelta
from urllib.parse import quote
from .session_orchestrator import FIELDS, digest, iso, record, timestamp
from .controlled_replay.indexer import IndexerClient, RetrievalError, check_page, mapping_type

PAYLOAD = FIELDS | {'event_type', 'source_status'}
EVENT_TYPE = 'controlled_session_lifecycle'


def client_from_environment():
    names=('WAZUH_INDEXER_URL','WAZUH_INDEXER_INDEX_PATTERN','WAZUH_INDEXER_USERNAME',
           'WAZUH_INDEXER_PASSWORD','WAZUH_INDEXER_CA_CERT')
    if any(not os.environ.get(k) for k in names): raise ValueError('Existing indexer environment missing')
    return IndexerClient(*(os.environ[k] for k in names[:4]),ca_file=os.environ[names[4]],
                         tls_profile=os.environ.get('WAZUH_INDEXER_TLS_PROFILE','strict'))


def completion_query(cfg, armed_at, now):
    # Receipt filtering selects ONLY dedicated lifecycle documents. No Windows
    # Security/Sysmon data or original experiment partition is queried here.
    return {'bool':{'filter':[
        {'term':{'data.thesis_session.event_type':EVENT_TYPE}},
        {'term':{'data.thesis_session.feed_id':cfg['feed_id']}},
        {'term':{'agent.id':cfg['completion_agent_id']}},
        {'term':{'location':cfg['completion_location']}},
        {'range':{'timestamp':{'gte':iso(timestamp(armed_at)-timedelta(seconds=300)),'lte':iso(now)}}}
    ]}}


def normalize(source, cfg, armed_at, now):
    if (source.get('agent',{}).get('id') != cfg['completion_agent_id']
            or source.get('location') != cfg['completion_location']):
        raise ValueError('Completion source agent/location mismatch')
    receipt=timestamp(source['timestamp'])
    if not timestamp(armed_at)-timedelta(seconds=300) <= receipt <= now:
        raise ValueError('Completion receipt outside query interval')
    value=source['data']['thesis_session']
    # Wazuh's decoded data can omit an empty string that still exists in full_log.
    # Accept only the observed Started/end omission, with original-JSON proof.
    # This does not supply an execution end time or make a terminal event eligible.
    if (isinstance(value,dict) and set(value)==PAYLOAD-{'end'}
            and value.get('status')=='Started' and value.get('source_status')=='Started'):
        def unique_pairs(pairs):
            result={}
            for key, item in pairs:
                if key in result: raise ValueError('Duplicate original lifecycle JSON key')
                result[key]=item
            return result
        try:
            original=json.loads(source['full_log'],object_pairs_hook=unique_pairs)
            raw=original['thesis_session']
            proved=(isinstance(original,dict) and set(original)=={'thesis_session'}
                    and isinstance(raw,dict) and set(raw)==PAYLOAD and raw['end']==''
                    and all(raw[k]==value[k] for k in value))
        except (ValueError,KeyError,TypeError):
            proved=False
        if not proved: raise ValueError('Started empty end omission lacks matching original JSON proof')
        value={**value,'end':''}
    if not isinstance(value,dict) or set(value)!=PAYLOAD or value['event_type']!=EVENT_TYPE:
        raise ValueError('Unexpected lifecycle payload')
    if value['schema_version'] not in ('1',1) or isinstance(value['schema_version'],bool):
        raise ValueError('Unexpected lifecycle version')
    statuses={'Started':'Started','completed':'Completed','failed':'Failed','audit_not_verified':'Failed'}
    if value.get('source_status') not in statuses or value['status']!=statuses[value['source_status']]:
        raise ValueError('Runner outcome/lifecycle mismatch')
    item={k:value[k] for k in FIELDS}; item['schema_version']=1
    if item['status']=='Started':
        if item['end'] != '': raise ValueError('Started end must be empty')
        item['end']=None
    record(item,cfg['feed_id'])
    return item


def fetch(client,cfg,armed_at,now,maximum=10000,diagnostics=None):
    base='/' + quote(client.pattern,safe='*.-_')
    query=completion_query(cfg,armed_at,now)
    audit=diagnostics if diagnostics is not None else {}
    audit.update({'source':'authenticated_wazuh_archives','query':query,'index_pattern':client.pattern,
           'certificate_verification_required':True,'hostname_verification':True,
           'tls_profile':client.tls_profile,'complete_scroll':False,'stage':'mapping_request'})
    mapping=client.request('GET',base+'/_mapping')
    audit['stage']='mapping_validation'
    if not mapping: raise RetrievalError('No archive mappings available')
    for info in mapping.values():
        props=info.get('mappings',{}).get('properties',{})
        if mapping_type(props,'timestamp') not in {'date','date_nanos'}:
            raise RetrievalError('Completion receipt mapping must be date')
        for field in ('agent.id','location'):
            if mapping_type(props,field)!='keyword': raise RetrievalError('Completion envelope keyword mapping required')
        # Before the first lifecycle event, these fields may legitimately be absent.
        for field in ('data.thesis_session.feed_id','data.thesis_session.event_type'):
            kind=mapping_type(props,field)
            if kind is not None and kind!='keyword': raise RetrievalError('Completion payload keyword mapping required')
    audit['stage']='completion_search'
    page=client.request('POST',base+'/_search?scroll=2m&allow_partial_search_results=false',
        {'size':500,'sort':['_doc'],'track_total_hits':True,'query':query,'_source':['timestamp','agent.id','location','data.thesis_session','full_log']})
    scroll=page.get('_scroll_id'); rows=[]; seen=set()
    try:
        audit['stage']='completion_page_validation'
        check_page(page)
        total=page.get('hits',{}).get('total',{})
        if total.get('relation')!='eq' or type(total.get('value')) is not int or not 0<=total['value']<=maximum:
            raise RetrievalError('Exact bounded completion count required')
        while True:
            hits=check_page(page)
            for hit in hits:
                key=(hit.get('_index'),hit.get('_id'))
                if not all(isinstance(k,str) and k for k in key) or key in seen:
                    raise RetrievalError('Repeated/missing completion document identity')
                seen.add(key)
                audit['stage']='completion_attribution_and_schema'
                source=hit['_source']; item=normalize(source,cfg,armed_at,now)
                rows.append({'index':key[0],'document_id':key[1],'receipt':source['timestamp'],
                             'source_status':source['data']['thesis_session']['source_status'],'record':item})
            if len(rows)>total['value']: raise RetrievalError('Completion count grew beyond exact result')
            if len(rows)==total['value']: break
            if not hits or not scroll: raise RetrievalError('Incomplete completion pagination')
            audit['stage']='completion_pagination'
            page=client.request('POST','/_search/scroll',{'scroll':'2m','scroll_id':scroll})
            scroll=page.get('_scroll_id',scroll)
    finally:
        if scroll: client.request('DELETE','/_search/scroll',{'scroll_id':[scroll]})
    audit.update(status='query_verified',documents=len(rows),complete_scroll=True)
    return rows,audit


def snapshot(service,client=None):
    """Persist complete lifecycle provenance; tolerate reordered identical deliveries."""
    armed_at=service.meta('armed_at')
    if not armed_at: raise ValueError('Initialize before querying completion events')
    audit={'stage':'client_initialization'}
    try:
        rows,audit=fetch(client or client_from_environment(),service.cfg,armed_at,service.clock(),diagnostics=audit)
    except (ValueError,OSError,KeyError,TypeError) as exc:
        if audit.get('stage')=='completion_attribution_and_schema':
            # Fixed validation messages only; never include arbitrary field values.
            safe_checks={'Completion source agent/location mismatch','Completion receipt outside query interval',
                         'Unexpected lifecycle payload','Unexpected lifecycle version','Runner outcome/lifecycle mismatch',
                         'Started end must be empty','Started empty end omission lacks matching original JSON proof',
                         'Qualified Windows account required','Host required','Invalid activity interval','Untrusted completion feed'}
            audit['validation_check']=str(exc) if str(exc) in safe_checks else 'Malformed required field or timestamp; value omitted'
        audit.update(status='failed',exception_type=type(exc).__name__,
                     reason='Completion connection/mapping/query/schema verification failed; credentials and event contents omitted')
        with service.db:
            service.db.execute('INSERT INTO completion_queries(at,audit) VALUES(?,?)',(iso(service.clock()),json.dumps(audit)))
        raise
    starts,terminals={},{}
    terminal_statuses={}
    with service.db:
        for row in rows:
            item=row['record']; key=(row['index'],row['document_id']); payload=json.dumps(row,sort_keys=True)
            old=service.db.execute('SELECT payload FROM completion_documents WHERE index_name=? AND document_id=?',key).fetchone()
            if old and old[0]!=payload: raise ValueError('Previously indexed completion evidence changed')
            service.db.execute('INSERT OR IGNORE INTO completion_documents VALUES(?,?,?)',(*key,payload))
        for stored in service.db.execute('SELECT payload FROM completion_documents'):
            item=json.loads(stored[0])['record']
            target=starts if item['status']=='Started' else terminals; sid=item['session_id']
            if sid in target and digest(target[sid])!=digest(item): raise ValueError('Conflicting lifecycle evidence for same session')
            if item['status'] != 'Started':
                source_status=json.loads(stored[0])['source_status']
                if sid in terminal_statuses and terminal_statuses[sid] != source_status:
                    raise ValueError('Conflicting runner terminal outcomes')
                terminal_statuses[sid]=source_status
            target[sid]=item
        pending=[]
        for sid,value in terminals.items():
            if sid not in starts:
                pending.append(sid); continue
            if any(starts[sid][k]!=value[k] for k in ('feed_id','session_id','username','host','start')):
                raise ValueError('Started/terminal lifecycle identity mismatch')
        # Terminal-before-start ingestion is unresolved, not a completed job.
        # Block all jobs until the snapshot is coherent; do not miss an overlap.
        audit['terminal_records_missing_start']=pending
        service.db.execute('INSERT INTO completion_queries(at,audit) VALUES(?,?)',(iso(service.clock()),json.dumps(audit)))
    if pending: raise ValueError('Terminal lifecycle events arrived before their start evidence; retry next poll')
    service.runner_terminal_statuses=terminal_statuses
    return starts,terminals
