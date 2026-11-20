"""Phase 3 uses temporary logs, synthetic payloads and mocked SSH only."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
import plistlib
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
from src.hybrid_publisher import synthetic_hybrid as rf_fixture
from src.model_aware_publication import send_verified, verify_delivery
from src.model_aware_service import require_legacy_unloaded
from scripts.integration.guarded_receiver import receive
from scripts.integration.model_publication_contract import make_claim
from scripts.integration import receive_ml_prediction as legacy
from test_tabpfn_prototype import event as tab_fixture


def qualified(value):
    value['username']='EXAMPLE\\synthetic.user'
    value['session_id']=legacy.completed_session_id(value['username'],value['activity_start'],value['activity_end'])
    if value['model']=='TabPFN':
        from scripts.integration.tabpfn_contract import identity
        value['prediction_id']=identity(value)
    else:
        value['rf_prediction_id']=legacy.prediction_id({**value,'event_type':'thesis_ml_prediction','mode':'controlled_replay'})
        value['prediction_id']=legacy.prediction_id(value)
    return value


def synthetic_hybrid(*args):return qualified(rf_fixture(*args))
def tab_event():return qualified(tab_fixture())


def completion(event):
    return {'status':'Completed','session_id':'00000000-0000-0000-0000-000000000001',
            'username':event['username'],'start':event['activity_start'],'end':event['activity_end']}


def claim(event,model):
    return make_claim(model,'00000000-0000-0000-0000-000000000001',event['username'],event['activity_start'],event['activity_end'])


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.paths=[self.root/n for n in ('rf.jsonl','tp.jsonl','owners.jsonl','guard.lock')]
        for p in self.paths:p.touch()
    def recv(self,value,mode='model_aware'):return receive(value,*self.paths,mode=mode)
    def test_rf_claim_publish_duplicate_without_changing_payload(self):
        value=synthetic_hybrid();owner=claim(value,'random_forest')
        self.assertEqual(self.recv(owner)['status'],'written')
        self.assertEqual(self.recv(value)['status'],'written')
        before=self.paths[0].read_bytes()
        self.assertEqual(self.recv(owner)['status'],'duplicate')
        self.assertEqual(self.recv(value)['status'],'duplicate')
        self.assertEqual(self.paths[0].read_bytes(),before)
        self.assertEqual(self.paths[1].read_bytes(),b'')
    def test_tab_claim_publish_and_correct_separate_ledger(self):
        value=tab_event();self.recv(claim(value,'tabpfn'));self.recv(value)
        self.assertEqual(self.paths[0].read_bytes(),b'')
        saved=json.loads(self.paths[1].read_text());self.assertEqual(saved['model'],'TabPFN')
        self.assertFalse(any(k.startswith('rf_') for k in saved))
    def test_unclaimed_legacy_entry_cannot_preempt_selected_tabpfn(self):
        with self.assertRaises(ValueError):self.recv(synthetic_hybrid())
        self.recv(claim(tab_event(),'tabpfn'))
        with self.assertRaises(ValueError):self.recv(synthetic_hybrid())
        self.assertEqual(self.recv(tab_event())['status'],'written')
    def test_cross_model_claim_conflicts_in_both_orders(self):
        for first,second in [('random_forest','tabpfn'),('tabpfn','random_forest')]:
            for p in self.paths:p.write_bytes(b'')
            self.recv(claim(synthetic_hybrid(),first))
            with self.assertRaises(ValueError):self.recv(claim(synthetic_hybrid(),second))
    def test_concurrent_claims_have_one_owner(self):
        def submit(model):
            try:return self.recv(claim(synthetic_hybrid(),model))['status']
            except ValueError:return 'rejected'
        with ThreadPoolExecutor(max_workers=2) as pool:result=list(pool.map(submit,['random_forest','tabpfn']))
        self.assertEqual(sorted(result),['rejected','written']);self.assertEqual(len(self.paths[2].read_text().splitlines()),1)
    def test_concurrent_same_payload_has_one_append(self):
        value=tab_event();self.recv(claim(value,'tabpfn'))
        with ThreadPoolExecutor(max_workers=2) as pool:result=list(pool.map(self.recv,[value,value]))
        self.assertEqual(sorted(r['status'] for r in result),['duplicate','written'])
        self.assertEqual(len(self.paths[1].read_text().splitlines()),1)
    def test_original_rf_history_is_read_only_for_duplicate_and_cross_model(self):
        value=synthetic_hybrid();legacy.receive(value,self.paths[0]);before=self.paths[0].read_bytes()
        self.assertEqual(self.recv(value)['status'],'duplicate')
        with self.assertRaises(ValueError):self.recv(claim(tab_event(),'tabpfn'))
        self.assertEqual(self.paths[0].read_bytes(),before)
    def test_no_history_backfill_claim_for_already_published_rf(self):
        legacy.receive(synthetic_hybrid(),self.paths[0])
        with self.assertRaises(ValueError):self.recv(claim(synthetic_hybrid(),'random_forest'))
    def test_equivalent_utc_spelling_cannot_bypass_cross_model_guard(self):
        value=synthetic_hybrid();legacy.receive(value,self.paths[0])
        tab=tab_event()
        for name in ('activity_start','activity_end'):
            tab[name]=tab[name].replace('Z','.000000Z') if '.' not in tab[name] else tab[name]
        tab['session_id']=legacy.completed_session_id(tab['username'],tab['activity_start'],tab['activity_end'])
        with self.assertRaises(ValueError):self.recv(claim(tab,'tabpfn'))

    def test_corrupt_or_missing_history_fails_closed(self):
        self.paths[0].write_bytes(b'broken')
        with self.assertRaises(ValueError):self.recv(claim(tab_event(),'tabpfn'))
        self.paths[0].unlink()
        with self.assertRaises(OSError):self.recv(claim(tab_event(),'tabpfn'))
        self.assertEqual(self.paths[2].read_bytes(),b'')
    def test_tampering_invalid_evidence_and_conflicting_ids_rejected(self):
        value=tab_event();self.recv(claim(value,'tabpfn'));self.recv(value)
        for change in ({'source_results_sha256':'f'*64},{'wazuh_evidence_verified':False},
                       {'wazuh_detected':None},{'hybrid_priority':'Low Risk'},{'rf_classification':'malicious'}):
            with self.subTest(change=change),self.assertRaises(ValueError):self.recv({**value,**change})
    def test_claim_mutation_or_other_job_cannot_reassign_session(self):
        value=claim(tab_event(),'tabpfn');self.recv(value)
        other=make_claim('tabpfn','00000000-0000-0000-0000-000000000002',value['username'],value['activity_start'],value['activity_end'])
        with self.assertRaises(ValueError):self.recv(other)
        with self.assertRaises(ValueError):self.recv({**value,'selected_model':'random_forest'})
    def test_rollback_accepts_original_rf_but_never_second_model(self):
        value=tab_event();self.recv(claim(value,'tabpfn'));self.recv(value)
        with self.assertRaises(ValueError):self.recv(synthetic_hybrid(),'legacy_rf')
        different=synthetic_hybrid(False)
        self.assertEqual(self.recv(different,'legacy_rf')['status'],'written')
        self.assertEqual(self.recv(different,'legacy_rf')['status'],'duplicate')
    def test_rollback_blocks_unpublished_tab_claim(self):
        self.recv(claim(tab_event(),'tabpfn'))
        with self.assertRaises(ValueError):self.recv(tab_event(),'legacy_rf')
    def test_bad_ownership_history_and_hardlinks_refused(self):
        self.paths[2].write_bytes(b'broken\n')
        with self.assertRaises(ValueError):self.recv(claim(tab_event(),'tabpfn'))
        self.paths[2].unlink();__import__('os').link(self.paths[1],self.paths[2])
        with self.assertRaises(ValueError):self.recv(claim(tab_event(),'tabpfn'))


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.value=tab_event();self.job='00000000-0000-0000-0000-000000000001'
    def test_verified_publication_and_delivery_provenance(self):
        out=self.root/'data/experiments/send'
        def ssh(event,host,validator):validator(event);return {'status':'written','prediction_id':event['prediction_id'],'guard_version':1}
        with patch('src.model_aware_publication.verified',return_value=self.value),patch('src.model_aware_publication.code_contract',return_value={'test':'hash'}),patch('src.model_aware_publication._ssh_send',side_effect=ssh) as send:
            send_verified(self.root,'prepared','tabpfn',self.job,'existing-alias',out,enabled=True,completion=completion(self.value))
            verify_delivery(self.root,out,'prepared','tabpfn',self.job,completion=completion(self.value))
            self.assertEqual(send.call_count,2)
            with self.assertRaises(ValueError):verify_delivery(self.root,out,'prepared','random_forest',self.job,completion=completion(self.value))
    def test_wrong_completion_or_missing_binding_rejected_before_ssh(self):
        other=completion(self.value);other['end']='2026-01-01T11:59:00Z'
        with patch('src.model_aware_publication.verified',return_value=self.value),patch('src.model_aware_publication._ssh_send') as network:
            for evidence in (None,other):
                with self.assertRaises(ValueError):
                    send_verified(self.root,'prepared','tabpfn',self.job,'alias',self.root/'data/experiments/out',enabled=True,completion=evidence)
            network.assert_not_called()

    def test_disabled_publication_rejects_before_network(self):
        with patch('src.model_aware_publication._ssh_send') as send:
            with self.assertRaises(PermissionError):send_verified(self.root,'prepared','tabpfn',self.job,'alias',self.root/'out')
            send.assert_not_called()
    def test_receiver_failure_retry_uses_same_claim_and_event(self):
        calls=[]
        def ssh(event,*args):
            calls.append(event)
            if len(calls)==2:raise ValueError('SECRET_REMOTE_FAILURE')
            return {'status':'duplicate' if len(calls)>2 else 'written','prediction_id':event['prediction_id'],'guard_version':1}
        with patch('src.model_aware_publication.verified',return_value=self.value),patch('src.model_aware_publication.code_contract',return_value={}),patch('src.model_aware_publication._ssh_send',side_effect=ssh):
            one=self.root/'data/experiments/one';two=self.root/'data/experiments/two'
            with self.assertRaises(ValueError):send_verified(self.root,'prepared','tabpfn',self.job,'alias',one,enabled=True,completion=completion(self.value))
            send_verified(self.root,'prepared','tabpfn',self.job,'alias',two,enabled=True,completion=completion(self.value))
            self.assertEqual(calls[:2],calls[2:]);self.assertNotIn('SECRET',str(json.loads((one/'receipt.json').read_text())))
    def test_old_receiver_ack_cannot_authorise_publication(self):
        with patch('src.model_aware_publication.verified',return_value=self.value),patch('src.model_aware_publication.code_contract',return_value={}),patch('src.model_aware_publication._ssh_send',return_value={'status':'written','prediction_id':'x'}) as send:
            with self.assertRaises(ValueError):send_verified(self.root,'prepared','tabpfn',self.job,'alias',self.root/'data/experiments/out',enabled=True,completion=completion(self.value))
            self.assertEqual(send.call_count,1)


class GuardedTransportIntegrationTests(unittest.TestCase):
    def test_real_ssh_adapter_guard_and_model_specific_gates_without_network(self):
        from src.prediction_publisher import _ssh_send
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);paths=[root/name for name in ('rf','tp','owners','lock')]
            for path in paths:path.touch()
            mode=['model_aware']
            def ssh(command,**kwargs):
                self.assertIn('StrictHostKeyChecking=yes',command)
                self.assertIn('BatchMode=yes',command)
                self.assertIn('ClearAllForwardings=yes',command)
                try:
                    ack=receive(legacy.strict_json(kwargs['input']),*paths,mode=mode[0])
                    return SimpleNamespace(returncode=0,stdout=json.dumps(ack),stderr='')
                except ValueError:
                    return SimpleNamespace(returncode=2,stdout='{}',stderr='SECRET_REJECTION')
            def prepared(root,source,model):return tab_event() if model=='tabpfn' else synthetic_hybrid()
            with patch('src.model_aware_publication.verified',side_effect=prepared), \
                    patch('src.model_aware_publication.code_contract',return_value={}), \
                    patch('src.prediction_publisher.subprocess.run',side_effect=ssh) as transport:
                job='00000000-0000-0000-0000-000000000001'
                for name in ('first','retry'):
                    out=root/'data/experiments'/name
                    receipt=send_verified(root,'prepared','tabpfn',job,'existing-alias',out,enabled=True,completion=completion(tab_event()))
                    verify_delivery(root,out,'prepared','tabpfn',job,completion=completion(tab_event()))
                self.assertEqual(receipt['remote_submissions'][0]['status'],'duplicate')
                self.assertEqual(len(paths[1].read_text().splitlines()),1)
                with self.assertRaises(ValueError):
                    send_verified(root,'prepared','random_forest',job,'existing-alias',root/'data/experiments/conflict',enabled=True,completion=completion(synthetic_hybrid()))
                self.assertEqual(paths[0].read_bytes(),b'')
                mode[0]='legacy_rf'
                rf=synthetic_hybrid(False)
                self.assertEqual(_ssh_send(rf,'existing-alias',legacy.validate_hybrid)['status'],'written')
                self.assertEqual(_ssh_send(rf,'existing-alias',legacy.validate_hybrid)['status'],'duplicate')


class DeploymentContractTests(unittest.TestCase):
    def test_legacy_scheduler_loaded_or_unverifiable_blocks(self):
        for code,stdout in [(0,'123\t0\torg.thesis.hybrid-sessions\n'),(1,'')]:
            with patch('src.model_aware_service.subprocess.run',return_value=SimpleNamespace(returncode=code,stdout=stdout)):
                with self.assertRaises(ValueError):require_legacy_unloaded('org.thesis.hybrid-sessions')
        with patch('src.model_aware_service.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout='PID Status Label\n')):
            require_legacy_unloaded('org.thesis.hybrid-sessions')
    def test_plist_does_not_override_dotenv_or_contain_credentials(self):
        root=Path(__file__).resolve().parents[1];p=plistlib.loads((root/'config/launchd/org.thesis.hybrid-model-aware.plist').read_bytes())
        self.assertTrue(p['Disabled']);self.assertNotIn('EnvironmentVariables',p);self.assertEqual(p['StartInterval'],30)
        self.assertIn('src.model_aware_service',p['ProgramArguments'])
    def test_dashboard_rules_are_model_specific_with_no_local_collision(self):
        root=Path(__file__).resolve().parents[1];path=root/'config/tabpfn_hybrid_priority_rules.xml'
        rules=ET.parse(path).getroot();ids={r.attrib['id'] for r in rules.findall('rule')}
        self.assertEqual(ids,{'110520','110521','110522'})
        for other in (root/'config').glob('*rules.xml'):
            if other==path:continue
            old={r.attrib['id'] for r in ET.parse(other).iter('rule')};self.assertFalse(ids & old)
        value=tab_event();base=rules.find('rule')
        for field in base.findall('field'):
            import re
            actual=value[field.attrib['name']]
            text=str(actual).lower() if type(actual) is bool else str(actual)
            self.assertRegex(text,field.text)
        for description in rules.iter('description'):self.assertNotIn('RF=',description.text)
