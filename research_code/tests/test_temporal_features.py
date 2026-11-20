"""Regression tests: observations after the cutoff cannot change earlier X."""

import unittest
import test_features as fixtures
from src.features import FEATURES, MODEL_INPUTS, SYSMON, verified_anchors
from pathlib import Path


event, ground, ledger = fixtures.event, fixtures.ground, fixtures.ledger


class TemporalFeatureTests(unittest.TestCase):
    # Reuse only synthetic fixtures and the existing source-format helpers.
    setUp = fixtures.FeatureTests.setUp
    write = fixtures.FeatureTests.write
    run_extract = fixtures.FeatureTests.run_extract
    def assert_values_equal(self, first, second):
        self.assertEqual({k: first[k] for k in FEATURES}, {k: second[k] for k in FEATURES})
        self.assertEqual(first["FeatureMLTrainingEligible"], second["FeatureMLTrainingEligible"])

    def test_future_domain_conflict_cannot_rewrite_earlier_identity(self):
        before, _ = self.run_extract([event()])
        future = event(at="2026-01-01T10:02:00Z", record="later")
        future["data"]["win"]["eventdata"]["subjectDomainName"] = "OTHER"
        after, _ = self.run_extract([event(), future])
        self.assert_values_equal(before[0], after[0])

    def test_future_collection_support_cannot_fill_earlier_missing_features(self):
        before, _ = self.run_extract([event()])
        future = event("3", SYSMON, "2026-01-01T10:02:00Z", "later",
                       {"user": "EXAMPLE\\other.user", "image": "ssh.exe", "destinationPort": "22"})
        after, _ = self.run_extract([event(), future])
        self.assertEqual(before[0]["network_connection_count"], "")
        self.assert_values_equal(before[0], after[0])

    def test_future_process_identity_does_not_backfill_network_actor(self):
        created = event("1", SYSMON, "2026-01-01T10:00:01Z", "create",
                        {"processGuid": "guid", "image": "ssh.exe"})
        connection = event("3", SYSMON, "2026-01-01T10:00:12Z", "net",
                           {"processGuid": "guid", "image": "ssh.exe", "destinationIp": "192.0.2.1", "destinationPort": "22", "initiated": "true"})
        future = event("11", SYSMON, "2026-01-01T10:02:00Z", "file",
                       {"processGuid": "guid", "image": "ssh.exe", "user": "EXAMPLE\\example.user", "targetFilename": "C:\\future.txt"})
        before, _ = self.run_extract([event(), created, connection])
        after, _ = self.run_extract([future, event(), connection, created])
        self.assertEqual(before[0]["network_connection_count"], 0)
        self.assert_values_equal(before[0], after[0])

    def test_late_ingestion_does_not_change_counts_or_eligibility(self):
        before, _ = self.run_extract([event()])
        late = event(record="late")
        late["timestamp"] = "2026-01-01T10:02:00Z"
        after, _ = self.run_extract([event(), late])
        self.assertEqual(after[0]["LateArrivingArchiveCandidates"], 1)
        self.assert_values_equal(before[0], after[0])

    def test_late_duplicate_read_first_does_not_suppress_on_time_event(self):
        on_time = event()
        late = {**on_time, "timestamp": "2026-01-01T10:02:00Z"}
        rows, _ = self.run_extract([late, on_time])
        self.assertEqual(rows[0]["windows_event_count"], 1)
        self.assertEqual(rows[0]["UniqueMatchedArchiveEvents"], 1)

    def test_late_received_family_does_not_establish_collection_availability(self):
        before, _ = self.run_extract([event()])
        late = event("3", SYSMON, "2026-01-01T10:00:05Z", "late-network",
                     {"user": "EXAMPLE\\other.user", "image": "ssh.exe"})
        late["timestamp"] = "2026-01-01T10:02:00Z"
        after, _ = self.run_extract([late, event()])
        self.assert_values_equal(before[0], after[0])

    def test_late_received_creation_cannot_supply_earlier_network_identity(self):
        created = event("1", SYSMON, "2026-01-01T10:00:01Z", "create",
                        {"processGuid": "guid", "image": "ssh.exe", "user": "EXAMPLE\\example.user"})
        created["timestamp"] = "2026-01-01T10:02:00Z"
        connection = event("3", SYSMON, "2026-01-01T10:00:12Z", "net",
                           {"processGuid": "guid", "image": "ssh.exe", "destinationPort": "22", "initiated": "true"})
        rows, _ = self.run_extract([created, event(), connection])
        self.assertEqual(rows[0]["network_connection_count"], 0)

    def test_late_received_process_end_cannot_reject_earlier_network_identity(self):
        created = event("1", SYSMON, "2026-01-01T10:00:01Z", "create",
                        {"processGuid": "guid", "image": "ssh.exe", "user": "EXAMPLE\\example.user"})
        connection = event("3", SYSMON, "2026-01-01T10:00:12Z", "net",
                           {"processGuid": "guid", "image": "ssh.exe", "destinationPort": "22", "initiated": "true", "destinationIp": "192.0.2.1"})
        ended = event("5", SYSMON, "2026-01-01T10:00:08Z", "end", {"processGuid": "guid"})
        ended["timestamp"] = "2026-01-01T10:02:00Z"
        before, _ = self.run_extract([created, event(), connection])
        after, _ = self.run_extract([ended, connection, event(), created])
        self.assertEqual(after[0]["network_connection_count"], 1)
        self.assert_values_equal(before[0], after[0])

    def test_prediction_cutoff_is_observation_end(self):
        rows, _ = self.run_extract([event()], padding=2)
        self.assertEqual(rows[0]["PredictionCutoffUTC"], rows[0]["ObservationEndUTC"])

    def test_worker_outcomes_are_never_static_identity_configuration(self):
        row = ground(scenario="M05")
        row.update(ActualExecutionTimestampSource="m05_worker_started", M05ResultFile="never-read.json")
        self.assertEqual(verified_anchors([row], Path("nonexistent")), {})

    def test_domain_alias_requires_same_sid_evidence_known_before_receipt(self):
        first = event(at="2026-01-01T09:00:00Z", record="short-domain")
        second = event(at="2026-01-01T09:01:00Z", record="dns-domain")
        sid = "S-1-5-21-100-200-300-1234"
        first["data"]["win"]["eventdata"]["subjectUserSid"] = sid
        second["data"]["win"]["eventdata"].update(subjectDomainName="EXAMPLE.LOCAL", subjectUserSid=sid)
        rows, _ = self.run_extract([event(), second, first])
        self.assertEqual(rows[0]["windows_event_count"], 1)
        second["data"]["win"]["eventdata"]["subjectUserSid"] = "S-1-5-21-100-200-400-1234"
        rows, _ = self.run_extract([event(), second, first])
        self.assertEqual(rows[0]["windows_event_count"], "")

    def test_protected_resource_is_diagnostic_not_model_input(self):
        self.assertIn("protected_resource_event_count", FEATURES)
        self.assertNotIn("protected_resource_event_count", MODEL_INPUTS)
        self.assertNotIn("sysmon_file_delete_count", MODEL_INPUTS)
        self.assertIn("smb_denied_count", MODEL_INPUTS)
