"""Isolated scheduler tests. Never load launchd, SSH, models or real Wazuh."""
from contextlib import ExitStack, redirect_stdout
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
from src.model_selection import Selection
from src.model_aware_orchestrator import Router
from src.model_aware_service import main
from src.session_orchestrator import Orchestrator
from test_session_orchestrator import Harness

RF=Selection('random_forest','dotenv');TAB=Selection('tabpfn','dotenv')


class RouterTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.h=Harness(self.tmp.name);self.h.service.close()
        self.original=Path(self.h.cfg['state_dir'])/'state.sqlite3';self.before=self.original.read_bytes()
        self.cfg={**self.h.cfg,'state_dir':str(self.h.root/'data/experiments/operational_service/model_aware/router'),
                  'dry_run':False,'enable_publication':True}
        self.tab=self.h.root/'data/experiments/tabpfn_prototype/model_aware/worker'
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch('src.model_aware_orchestrator.model_contract',side_effect=lambda root,model:{'selected_model':model}))
        self.stack.enter_context(patch('src.model_aware_orchestrator.code_contract',return_value={'test':'code'}))
        self.stack.enter_context(patch('src.tabpfn_prototype.automatic.artifacts.frozen',return_value=([],None,{'selected_model':'tabpfn'},None)))
        self.stack.enter_context(patch.object(Orchestrator,'command',side_effect=lambda stage,value,out,job,windows:self.h.run(stage,value,out,job,windows)))
        self.publish=[];self.fail_send=False
        self.stack.enter_context(patch('src.model_aware_orchestrator.send_verified',side_effect=self.send))
        self.stack.enter_context(patch('src.model_aware_orchestrator.verify_delivery',side_effect=self.delivery))
        self.stack.enter_context(patch('src.model_aware_orchestrator.Shadow.process_shadow',autospec=True,side_effect=self.tab_process))
        self.service=Router(self.cfg,self.tab,now=lambda:self.h.now);self.service.initialize()
        self.addCleanup(lambda:self.service.close())
    def send(self,root,prepared,model,job,host,out,enabled,completion):
        self.publish.append((model,job));out.mkdir(parents=True)
        if self.fail_send:raise ValueError('failed transport')
        (out/'receipt.json').write_text(json.dumps({'status':'acknowledged','remote_submissions':[{'status':'written'}]}))
    def delivery(self,root,out,*args,**kwargs):
        receipt=json.loads((Path(out)/'receipt.json').read_text())
        if receipt['status']!='acknowledged':raise ValueError('bad ack')
        return receipt
    def tab_process(self,worker,sid,*args):
        result={'hybrid_priority':'High Priority','wazuh_evidence_verified':True,'unresolved_alert_count':1,
                'telemetry_completeness':{'status':'unverified'}}
        if self.h.unknown:
            result.update(hybrid_priority='Evidence Unavailable',wazuh_evidence_verified=False,wazuh_detected=None)
        with worker.db:worker.update(sid,status='investigation_required' if self.h.unknown else 'prepared_not_published',prepared=str(worker.base/'prepared'),hybrid=str(worker.base/'hybrid'),result=json.dumps(result))
    def job(self,v):return dict(self.service.db.execute('SELECT * FROM jobs WHERE id=?',(v['session_id'],)).fetchone())
    def polls(self,selection,n=6):
        for _ in range(n):self.service.tick_selected(selection);self.h.advance(2)
    def test_rf_uses_original_processing_and_guarded_send(self):
        value=self.h.add();self.h.advance();self.polls(RF)
        self.assertEqual(self.job(value)['status'],'published')
        self.assertEqual([c for c in self.h.calls],['rf','hybrid','prepare'])
        self.assertEqual(self.publish,[('random_forest',value['session_id'])])
        self.assertEqual(self.original.read_bytes(),self.before)
    def test_switch_across_sessions_pins_each_choice(self):
        first=self.h.add();self.h.advance(100);self.service.tick_selected(RF)
        self.h.advance(300);self.polls(TAB)
        self.assertEqual(self.publish,[('random_forest',first['session_id'])])
        second=self.h.add();self.h.advance();self.polls(TAB)
        self.assertEqual(self.publish[-1],('tabpfn',second['session_id']))
        self.assertEqual(self.service.route(first['session_id'])['selected_model'],'random_forest')
        self.assertEqual(self.service.route(second['session_id'])['selected_model'],'tabpfn')
        self.assertIsNone(self.job(second)['rf']);self.assertEqual(self.original.read_bytes(),self.before)
    def test_restart_does_not_switch_or_repeat_completed_job(self):
        value=self.h.add();self.h.advance(100);self.service.tick_selected(TAB)
        self.service.close();self.service=Router(self.cfg,self.tab,now=lambda:self.h.now)
        self.h.advance();self.polls(RF);self.polls(RF)
        self.assertEqual(self.publish,[('tabpfn',value['session_id'])])
        self.assertEqual(self.job(value)['status'],'published')
    def test_publication_failure_is_bounded_and_does_not_reinfer(self):
        self.fail_send=True;value=self.h.add();self.h.advance();self.polls(RF,12)
        self.assertEqual(self.job(value)['status'],'failed')
        self.assertEqual(len(self.publish),3);self.assertEqual(self.h.calls.count('rf'),1)
        self.assertIsNone(self.job(value)['ack'])
    def test_failed_ack_retry_and_model_switch_retain_job(self):
        self.fail_send=True;value=self.h.add();self.h.advance();self.polls(RF,4)
        self.fail_send=False;self.polls(TAB,3)
        self.assertEqual(self.job(value)['status'],'published')
        self.assertEqual([m for m,_ in self.publish],['random_forest','random_forest'])
    def test_unknown_evidence_never_publishes(self):
        self.h.unknown=True;value=self.h.add();self.h.advance();self.polls(RF)
        self.assertEqual(self.job(value)['status'],'investigation_required');self.assertEqual(self.publish,[])
    def test_tabpfn_unknown_evidence_is_terminal_and_not_published(self):
        self.h.unknown=True;value=self.h.add();self.h.advance();self.polls(TAB)
        self.assertEqual(self.job(value)['status'],'investigation_required');self.assertEqual(self.publish,[])
        self.assertIn('Evidence Unavailable',self.job(value)['result'])

    def test_dry_run_holds_payload_and_does_not_release_old_work(self):
        self.cfg.update(dry_run=True,enable_publication=False)
        value=self.h.add();self.h.advance();self.polls(RF)
        self.assertEqual(self.job(value)['status'],'prepared_not_published');self.assertEqual(self.publish,[])
        self.cfg.update(dry_run=False,enable_publication=True);self.polls(TAB)
        self.assertEqual(self.publish,[])
    def test_missing_pin_is_terminal_not_fallback(self):
        value=self.h.add();self.h.advance(100);self.service.tick_selected(TAB)
        with self.service.db:self.service.db.execute('DELETE FROM routes')
        self.h.advance();self.polls(RF,1)
        self.assertEqual(self.job(value)['status'],'investigation_required');self.assertEqual(self.publish,[])
    def test_original_store_cannot_be_adopted(self):
        with self.assertRaises(ValueError):Router(self.h.cfg,self.tab)


class ScheduledSelectionTests(unittest.TestCase):
    def test_dotenv_overrides_inherited_selector_and_missing_defaults_rf(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);cfg={'root':str(root)};out=io.StringIO()
            with patch('src.model_aware_service.configuration',return_value=(cfg,root/'tab',root/'connection','label')),patch.dict(os.environ,{'THESIS_HYBRID_MODEL':'random_forest'}),redirect_stdout(out):
                (root/'.env').write_text('THESIS_HYBRID_MODEL=tabpfn\n')
                self.assertEqual(main(['--config','unused','selection']),0)
                self.assertEqual(json.loads(out.getvalue())['selected_model'],'tabpfn')
                out.seek(0);out.truncate(0);(root/'.env').unlink()
                self.assertEqual(main(['--config','unused','selection']),0)
                self.assertEqual(json.loads(out.getvalue())['selected_model'],'random_forest')
    def test_invalid_dotenv_fails_clearly_without_state_or_connection(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'.env').write_text('THESIS_HYBRID_MODEL=typo\n');out=io.StringIO()
            with patch('src.model_aware_service.configuration',return_value=({'root':str(root)},None,None,None)),patch('src.model_aware_service.Router') as router,redirect_stdout(out):
                self.assertEqual(main(['--config','unused','once']),2);router.assert_not_called()
            self.assertIn('random_forest or tabpfn',out.getvalue())
