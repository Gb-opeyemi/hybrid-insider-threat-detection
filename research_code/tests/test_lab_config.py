"""Portable lab settings and literal destination matching; synthetic evidence only."""
from pathlib import Path
import re
import tempfile
import unittest
import xml.etree.ElementTree as ET
import pandas as pd
from src.lab_config import load_lab_config, validate_lab_config
from src.wazuh_session_detection import detect_wazuh_sessions
from scripts.integration.render_m05_rule import render

ROOT = Path(__file__).resolve().parents[1]


class LabConfigTests(unittest.TestCase):
    def setUp(self):
        self.config = load_lab_config(ROOT / 'config/lab.example.json')

    def test_invalid_config_and_missing_file_fail_closed(self):
        for change in ({'account_domains': []}, {'m05_destination': 'invalid'},
                       {'monitored_computer_prefix': ''}):
            with self.assertRaises(ValueError):
                validate_lab_config({**self.config, **change})
        with self.assertRaises(FileNotFoundError):
            load_lab_config(ROOT / 'missing.local.json')

    def test_rendered_rule_has_literal_dots_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'rule.xml'
            render(ROOT / 'config/lab.example.json', ROOT / 'wazuh/rules/thesis_m05_rules.xml', output)
            pattern = ET.parse(output).find('.//field[@name="win.eventdata.commandLine"]').text
            self.assertTrue(re.search(pattern, 'sftp ' + self.config['m05_destination']))
            self.assertFalse(re.search(pattern, 'sftp ' + self.config['m05_destination'].replace('.', 'x')))
            with self.assertRaises(ValueError):
                render(ROOT / 'config/lab.example.json', ROOT / 'wazuh/rules/thesis_m05_rules.xml', output)

    def test_offline_baseline_uses_literal_destination(self):
        start = pd.Timestamp('2030-01-01T00:00:00Z')
        row = dict(SessionID='synthetic', EventID=1, SeverityValue='INFORMATION',
            ResolvedUsername='example.user', AvailableTimeUTC=(start + pd.Timedelta(seconds=1)).isoformat(),
            Computer='LAB-SERVER.example.invalid', EventChannel='Microsoft-Windows-Sysmon/Operational',
            EventRecordID='1', TargetUsername='', ObjectName='', AccessMask='', Provider='Microsoft-Windows-Sysmon',
            Image=r'C:\Windows\sftp.exe', CommandLine='sftp ' + self.config['m05_destination'], EventTimeUTC=start.isoformat())
        sessions = pd.DataFrame([{'SessionID': 'synthetic'}])
        cutoffs = pd.DataFrame([{'SessionID': 'synthetic', 'PredictionCutoffUTC': (start + pd.Timedelta(seconds=30)).isoformat()}])
        with tempfile.TemporaryDirectory() as directory:
            result = detect_wazuh_sessions(sessions, pd.DataFrame([row]), cutoffs, archive_root=directory, lab_config=self.config)
            self.assertEqual(result.loc[0, 'M05_Detected_0s'], 1)
            row['CommandLine'] = row['CommandLine'].replace('.', 'x')
            result = detect_wazuh_sessions(sessions, pd.DataFrame([row]), cutoffs, archive_root=directory, lab_config=self.config)
            self.assertEqual(result.loc[0, 'M05_Detected_0s'], 0)

    def test_full_synthetic_rule_baseline(self):
        from test_wazuh_session_detection import test_original_rule_behaviour
        with tempfile.TemporaryDirectory() as directory:
            test_original_rule_behaviour(Path(directory))
