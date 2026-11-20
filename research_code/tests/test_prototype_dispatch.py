"""New local dispatcher uses frozen job selection, never the running service."""
import io
import json
import os
from contextlib import redirect_stdout, chdir
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from src.hybrid_prototype import main
from src.tabpfn_prototype.common import sha


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()
        self.source=self.root/'data/experiments/new_completed_sessions/source'
        self.alerts=self.root/'data/experiments/hybrid_session_phase1/alerts'
        for folder in (self.source,self.alerts):
            folder.mkdir(parents=True);(folder/'output_manifest.json').write_text('{}')
        model=self.root/'models/random_forest_baseline.joblib';model.parent.mkdir();model.write_bytes(b'synthetic')
        self.event={'session_id':'synthetic','model_artifact':'models/random_forest_baseline.joblib','model_sha256':sha(model)}
        (self.alerts/'provenance.json').write_text(json.dumps({'source_session_dir':str(self.source)}))

    def test_default_rf_dispatch_and_resume_ignores_changed_environment(self):
        job=self.root/'data/experiments/rf_selected_prototype/job'
        payload={**self.event,'prediction_id':'synthetic'}
        def prepare(args):
            job.joinpath('preparation').mkdir();return 0
        with chdir(self.root), patch.dict(os.environ,{},clear=True), redirect_stdout(io.StringIO()), \
                patch('src.tabpfn_prototype.new_session.source_capture',return_value=(self.source,{},self.event,sha(self.source/'output_manifest.json'))), \
                patch('src.prediction_publisher.verified_completed_session',return_value=([self.event],'hash')), \
                patch('src.hybrid_publisher.verified_hybrid',return_value=(payload,'hash')), \
                patch('src.hybrid_publisher.verify_prepared',return_value=payload), \
                patch('src.hybrid_publisher.main',side_effect=prepare) as rf_prepare, \
                patch('src.tabpfn_prototype.new_session.infer') as tab:
            self.assertEqual(main(['run','--session-dir',str(self.source),'--alert-source-dir',str(self.alerts),'--output-dir',str(job)]),0)
            provenance=json.loads((job/'execution_provenance.json').read_text())
            self.assertEqual(provenance['selected_model'],'random_forest')
            os.environ['THESIS_HYBRID_MODEL']='tabpfn'
            (self.root/'.env').write_text('THESIS_HYBRID_MODEL=invalid')
            self.assertEqual(main(['resume','--job-dir',str(job)]),0)
            rf_prepare.assert_called_once();tab.assert_not_called()

    def test_invalid_selector_blocks_before_source_or_job(self):
        with chdir(self.root), patch.dict(os.environ,{'THESIS_HYBRID_MODEL':'invalid'}), redirect_stdout(io.StringIO()), \
                patch('src.tabpfn_prototype.new_session.source_capture') as source:
            out=self.root/'data/experiments/tabpfn_prototype/job'
            self.assertEqual(main(['run','--session-dir',str(self.source),'--alert-source-dir',str(self.alerts),'--output-dir',str(out)]),2)
            self.assertFalse(out.exists());source.assert_not_called()

    def test_tabpfn_failure_never_falls_back_to_rf(self):
        from src.prototype_jobs import Job
        from src.model_selection import Selection
        folder=self.root/'data/experiments/tabpfn_prototype/job'
        record={'root':str(self.root),'source_session_dir':str(self.source),'alert_source_dir':str(self.alerts),
            'source_manifest_sha256':sha(self.source/'output_manifest.json'),
            'alert_manifest_sha256':sha(self.alerts/'output_manifest.json'),
            'model_contract':{**{k:self.event[k] for k in ('model_artifact','model_sha256')},'checkpoint_sha256':'test'}}
        job=Job.create(folder,Selection('tabpfn','environment'),record);job.close()
        with chdir(self.root), redirect_stdout(io.StringIO()), \
                patch('src.tabpfn_prototype.artifacts.frozen',return_value=([],None,{'checkpoint_sha256':'test'},None)), \
                patch('src.tabpfn_prototype.new_session.infer',side_effect=ValueError('synthetic failure')), \
                patch('src.hybrid_publisher.main') as rf:
            self.assertEqual(main(['resume','--job-dir',str(folder)]),2)
            rf.assert_not_called()
        job=Job(folder)
        try:self.assertEqual(job.read()[0]['selected_model'],'tabpfn')
        finally:job.close()
