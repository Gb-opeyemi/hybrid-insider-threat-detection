"""Selector/job tests are isolated from the real .env, Keychain and RF state."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from src.model_selection import Selection, select_model
from src.prototype_jobs import Job


class ModelSelectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_rf_default_and_env_override(self):
        self.assertEqual(select_model(self.root, {}).model, 'random_forest')
        self.assertEqual(select_model(self.root, {'THESIS_HYBRID_MODEL':'tabpfn'}), Selection('tabpfn', 'environment'))

    def test_invalid_and_blank_do_not_fall_back(self):
        for value in ('', 'RF', 'TabPFN', ' tabpfn', 'tabpfn ', 'unknown', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                select_model(self.root, {'THESIS_HYBRID_MODEL':value})

    def test_dotenv_only_reads_selector_without_environment_mutation(self):
        (self.root / '.env').write_text('UNRELATED_SECRET=not-loaded\nexport THESIS_HYBRID_MODEL="tabpfn" # local\n')
        env = {}
        self.assertEqual(select_model(self.root, env), Selection('tabpfn', 'dotenv'))
        self.assertEqual(env, {})
        self.assertEqual(select_model(self.root, {}, load_dotenv=False).model, 'random_forest')

    def test_environment_precedes_even_invalid_dotenv(self):
        (self.root / '.env').write_text('THESIS_HYBRID_MODEL=invalid\n')
        self.assertEqual(select_model(self.root, {'THESIS_HYBRID_MODEL':'random_forest'}).model, 'random_forest')

    def test_dotenv_duplicate_interpolation_and_malformed_rejected(self):
        for text in ('THESIS_HYBRID_MODEL=tabpfn\nTHESIS_HYBRID_MODEL=random_forest',
                     'THESIS_HYBRID_MODEL=${MODEL}', 'THESIS_HYBRID_MODEL="tabpfn',
                     'THESIS_HYBRID_MODEL="tabpfn" garbage'):
            (self.root / '.env').write_text(text)
            with self.subTest(text=text), self.assertRaises(ValueError): select_model(self.root, {})

    def test_dotenv_symlink_rejected(self):
        target = self.root / 'other'; target.write_text('THESIS_HYBRID_MODEL=tabpfn')
        (self.root / '.env').symlink_to(target)
        with self.assertRaises(ValueError): select_model(self.root, {})

    def test_restart_pins_model_despite_environment_change(self):
        folder = self.root / 'new_job'
        job = Job.create(folder, Selection('tabpfn', 'environment'), {'session_id':'synthetic'})
        job.update(status='inference_running'); job.close()
        with patch.dict(os.environ, {'THESIS_HYBRID_MODEL':'random_forest'}):
            reopened = Job(folder)
            try:
                self.assertEqual(reopened.read()[0]['selected_model'], 'tabpfn')
                self.assertEqual(reopened.read()[1]['status'], 'inference_running')
            finally: reopened.close()

    def test_tampered_pinned_model_rejected(self):
        job = Job.create(self.root / 'job', Selection('random_forest', 'default'), {})
        try:
            with job.db: job.db.execute("UPDATE execution SET selected_model='tabpfn'")
            with self.assertRaises(ValueError): job.read()
        finally: job.close()

    def test_existing_job_never_overwritten(self):
        folder = self.root / 'job'; job = Job.create(folder, Selection('random_forest', 'default'), {})
        job.close()
        before = (folder / 'execution.sqlite3').read_bytes()
        with self.assertRaises(FileExistsError): Job.create(folder, Selection('tabpfn', 'environment'), {})
        self.assertEqual(before, (folder / 'execution.sqlite3').read_bytes())
