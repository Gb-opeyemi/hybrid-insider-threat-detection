"""Synthetic source-provenance, runner integration and fixed-cutoff regression tests."""
import copy
from datetime import datetime,timedelta,timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4
from src.session_orchestrator import Orchestrator, iso, config_file
from src.wazuh_completion_feed import fetch, normalize, snapshot, completion_query
from scripts.operational.prepare_windows_completion_runner import integrate

UTC=timezone.utc


class Client:
    pattern='wazuh-archives-*'; tls_profile='legacy_ca'
    def __init__(self,hits): self.hits=hits; self.calls=[]; self.fail=False; self.partial=False
    def request(self,method,path,body=None):
        self.calls.append((method,path,body))
        if self.fail: raise OSError('SENSITIVE_SERVER_ERROR')
        if method=='GET':
            return {'wazuh-archives-synthetic':{'mappings':{'properties':{
                'timestamp':{'type':'date'},'agent':{'properties':{'id':{'type':'keyword'}}},
                'location':{'type':'keyword'},'data':{'properties':{'thesis_session':{'properties':{
                'feed_id':{'type':'keyword'},'event_type':{'type':'keyword'}}}}}}}}}
        if method=='DELETE': return {'succeeded':True}
        return {'timed_out':False,'_shards':{'failed':1 if self.partial else 0,'total':1},
                '_scroll_id':'synthetic','hits':{'total':{'relation':'eq','value':len(self.hits)},'hits':self.hits}}


class FeedTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        self.now=datetime(2030,1,1,tzinfo=UTC); self.feed_id=str(uuid4()); self.sid=str(uuid4())
        self.cfg={'root':str(self.root),'completion_source':'wazuh','completion_agent_id':'007',
          'completion_location':r'C:\ProgramData\ThesisHybrid\session_lifecycle.jsonl','feed_id':self.feed_id,
          'state_dir':str(self.root/'data/experiments/operational_service/wazuh'),'dry_run':True,
          'enable_publication':False,'ssh_host':'thesis-ml-manager','host_aliases':{'SOURCE':['source.example.invalid']},
          'max_attempts':3,'retry_seconds':1}
        self.service=Orchestrator(self.cfg,lambda:self.now,runner=lambda *args:None)
        self.service.initialize(); self.armed=self.service.meta('armed_at'); self.now+=timedelta(seconds=400)
    def tearDown(self): self.service.close(); self.tmp.cleanup()
    def hit(self,status='Started',sid=None):
        item={'schema_version':'1','event_type':'controlled_session_lifecycle','feed_id':self.feed_id,
          'session_id':sid or self.sid,'username':'EXAMPLE\\selected.user','host':'SOURCE',
          'start':'2030-01-01T00:00:01.1234567Z','end':'' if status=='Started' else '2030-01-01T00:00:11.1234567Z',
          'status':'Started' if status=='Started' else ('Completed' if status=='completed' else 'Failed'),
          'source_status':status}
        return {'_index':'wazuh-archives-synthetic','_id':str(uuid4()),'_source':{'agent':{'id':'007'},
                'location':self.cfg['completion_location'],'timestamp':iso(self.now-timedelta(seconds=1)),
                'data':{'thesis_session':item}}}
    def test_selected_smb_identity_and_exact_boundaries(self):
        hit=self.hit('completed'); item=normalize(hit['_source'],self.cfg,self.armed,self.now)
        self.assertEqual(item['username'],'EXAMPLE\\selected.user')
        self.assertEqual(item['start'],'2030-01-01T00:00:01.1234567Z'); self.assertEqual(item['status'],'Completed')
    def test_wrong_agent_location_feed_account_or_label_rejected(self):
        for mutate in (lambda h:h['_source']['agent'].update(id='999'),
                       lambda h:h['_source'].update(location='elsewhere'),
                       lambda h:h['_source']['data']['thesis_session'].update(feed_id=str(uuid4())),
                       lambda h:h['_source']['data']['thesis_session'].update(username='Administrator'),
                       lambda h:h['_source']['data']['thesis_session'].update(scenario_ground_truth='Suspicious')):
            hit=self.hit('completed'); mutate(hit)
            with self.assertRaises(ValueError): normalize(hit['_source'],self.cfg,self.armed,self.now)
    def test_terminal_before_start_blocks_then_recovers(self):
        terminal=self.hit('completed'); client=Client([terminal])
        with self.assertRaises(ValueError): snapshot(self.service,client)
        self.assertEqual(self.service.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],0)
        client.hits=[terminal,self.hit()]; starts,terminals=snapshot(self.service,client)
        self.assertIn(self.sid,starts); self.assertIn(self.sid,terminals)
    def test_replayed_identical_events_deduplicate_and_conflicts_fail(self):
        a,b=self.hit(),self.hit('completed'); snapshot(self.service,Client([a,b]))
        duplicate=copy.deepcopy(a); duplicate['_id']=str(uuid4())
        starts,ends=snapshot(self.service,Client([a,b,duplicate])); self.assertEqual(len(starts),1)
        conflict=copy.deepcopy(b); conflict['_id']=str(uuid4()); conflict['_source']['data']['thesis_session']['end']='2030-01-01T00:00:12Z'
        with self.assertRaises(ValueError): snapshot(self.service,Client([conflict]))
    def test_query_failed_or_partial_never_looks_empty(self):
        client=Client([]); client.partial=True
        with self.assertRaises(ValueError): snapshot(self.service,client)
        client.partial=False; client.fail=True
        with self.assertRaises(OSError): snapshot(self.service,client)
        audit=self.service.db.execute('SELECT audit FROM completion_queries ORDER BY seq DESC').fetchone()[0]
        self.assertIn('mapping_request',audit); self.assertNotIn('SENSITIVE_SERVER_ERROR',audit)
    def test_empty_feed_is_valid_not_negative_detection(self):
        rows,audit=fetch(Client([]),self.cfg,self.armed,self.now)
        self.assertEqual(rows,[]); self.assertTrue(audit['complete_scroll'])
        self.assertNotIn('wazuh_detected',audit)
    def test_audit_not_verified_does_not_queue_rf(self):
        hits=[self.hit(),self.hit('audit_not_verified')]
        with patch('src.wazuh_completion_feed.client_from_environment',return_value=Client(hits)):
            self.service.tick()
        job=self.service.db.execute('SELECT * FROM jobs').fetchone()
        self.assertEqual(job['status'],'audit_not_verified'); self.assertEqual(job['stage'],'rf')
    def test_trigger_can_arrive_after_cutoff_without_extending_rf_cutoff(self):
        hits=[self.hit(),self.hit('completed')]; calls=[]
        self.service.runner=lambda stage,value,out,job,windows:calls.append((stage,value))
        with patch('src.wazuh_completion_feed.client_from_environment',return_value=Client(hits)):
            self.service.tick()
        self.assertEqual(calls[0][1]['end'],'2030-01-01T00:00:11.1234567Z')
        self.assertEqual(calls[0][0],'rf')
        client=Client(hits); query=completion_query(self.cfg,self.armed,self.now)
        self.assertEqual(query['bool']['filter'][2],{'term':{'agent.id':'007'}})
    def test_no_inference_before_end_plus_300(self):
        self.now=datetime(2030,1,1,0,5,11,tzinfo=UTC); hits=[self.hit(),self.hit('completed')]; calls=[]
        self.service.runner=lambda *args:calls.append(args)
        with patch('src.wazuh_completion_feed.client_from_environment',return_value=Client(hits)):
            self.service.tick()
        self.assertEqual(calls,[])
    def test_historical_newly_forwarded_records_excluded(self):
        hits=[self.hit(),self.hit('completed')]
        for h in hits: h['_source']['data']['thesis_session']['start']='2029-12-31T23:59:01Z'
        with patch('src.wazuh_completion_feed.client_from_environment',return_value=Client(hits)): self.service.tick()
        self.assertEqual(self.service.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],0)
    def test_wazuh_omitted_empty_started_end_requires_matching_raw_proof(self):
        import json
        hit=self.hit(); source=hit['_source']
        source['full_log']=json.dumps({'thesis_session':dict(source['data']['thesis_session'])})
        del source['data']['thesis_session']['end']
        normalized=normalize(source,self.cfg,self.armed,self.now)
        self.assertIsNone(normalized['end']); self.assertEqual(normalized['status'],'Started')
        self.assertNotIn('end',source['data']['thesis_session'])  # input stays immutable
        rows,_=fetch(Client([hit]),self.cfg,self.armed,self.now)
        self.assertIsNone(rows[0]['record']['end'])
    def test_empty_end_recovery_refuses_missing_malformed_or_conflicting_proof(self):
        import json
        for proof in (None, 'invalid json', json.dumps({'thesis_session':{'end':''}})):
            hit=self.hit(); del hit['_source']['data']['thesis_session']['end']
            if proof is not None: hit['_source']['full_log']=proof
            with self.assertRaises(ValueError): normalize(hit['_source'],self.cfg,self.armed,self.now)
        for field,value in (('end','2030-01-01T00:00:12Z'),('username','EXAMPLE\\different.user'),('host','OTHER'),('session_id',str(uuid4()))):
            hit=self.hit(); raw=dict(hit['_source']['data']['thesis_session']); raw[field]=value
            hit['_source']['full_log']=json.dumps({'thesis_session':raw})
            del hit['_source']['data']['thesis_session']['end']
            with self.assertRaises(ValueError): normalize(hit['_source'],self.cfg,self.armed,self.now)
    def test_terminal_end_is_never_recovered_from_original_log(self):
        import json
        for status in ('completed','failed','audit_not_verified'):
            hit=self.hit(status); raw=dict(hit['_source']['data']['thesis_session'])
            hit['_source']['full_log']=json.dumps({'thesis_session':raw})
            del hit['_source']['data']['thesis_session']['end']
            with self.assertRaises(ValueError): normalize(hit['_source'],self.cfg,self.armed,self.now)
    def test_omitted_end_recovery_does_not_bypass_agent_location_or_feed(self):
        import json
        for key in ('agent','location','feed'):
            hit=self.hit(); source=hit['_source']; raw=dict(source['data']['thesis_session'])
            if key=='feed':
                raw['feed_id']=str(uuid4()); source['data']['thesis_session']['feed_id']=raw['feed_id']
            source['full_log']=json.dumps({'thesis_session':raw}); del source['data']['thesis_session']['end']
            if key=='agent': source['agent']['id']='999'
            if key=='location': source['location']='untrusted'
            with self.assertRaises(ValueError): normalize(source,self.cfg,self.armed,self.now)
    def test_duplicate_raw_keys_do_not_prove_empty_end(self):
        import json
        hit=self.hit(); raw=json.dumps({'thesis_session':dict(hit['_source']['data']['thesis_session'])})
        hit['_source']['full_log']=raw.replace('"end": ""','"end": "", "end": ""')
        del hit['_source']['data']['thesis_session']['end']
        with self.assertRaises(ValueError): normalize(hit['_source'],self.cfg,self.armed,self.now)

    def test_config_supports_wazuh_without_directory(self):
        import json
        path=self.root/'cfg.json'; path.write_text(json.dumps(self.cfg)); cfg=config_file(path)
        self.assertEqual(cfg['completion_source'],'wazuh'); self.assertNotIn('feed_dir',cfg)
    def test_runner_patch_is_opt_in_and_reference_unchanged(self):
        root=Path(__file__).resolve().parents[1]; original=root/'scripts/windows_reference/Invoke-CompletedSession.ps1'
        before=original.read_bytes(); text=original.read_text(encoding='utf-8-sig'); result=integrate(text)
        self.assertEqual(original.read_bytes(),before)
        self.assertIn("[string]$CompletionFeedID = ''",result)
        self.assertIn('-Username $record.simulated_username',result)
        self.assertIn('-End $record.activity_end -SourceStatus $record.status',result)
        self.assertEqual(result.count('$ended = [datetime]::UtcNow'),1)
        with self.assertRaises(ValueError): integrate(result)


if __name__=='__main__': unittest.main()
