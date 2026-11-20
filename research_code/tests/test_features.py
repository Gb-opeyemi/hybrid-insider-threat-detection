"""Behavioral extraction tests using synthetic Windows telemetry only."""

import csv
import gzip
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone, timedelta
from pathlib import Path

from src.features import (
    FEATURES, META_FIELDS, SECURITY, SYSMON, Event, EvidenceIndex, Window, Matcher,
    audit_failure, events, extract, main, normalized_identity, normalized_path, resource_path, select_files, session_windows, timestamp,
)
from collections import Counter
from src.ground_truth import LEDGER_FIELDS, SCHEDULE_FIELDS, OUTPUT_FIELDS, main as ground_truth_main


def moment(text="2026-01-01T10:00:10Z"):
    return timestamp(text)


def ground(sid="session-a", user="example.user", scenario="N01"):
    return {"SessionID": sid, "Username": user, "ScenarioID": scenario,
            "ActualExecutionUTC": "2026-01-01T10:00:00Z",
            "ActualExecutionTimestampSource": "ledger_started_initiation",
            "MLTrainingEligible": "true", "ExtendedCohortEligible": "true",
            "Original14DayCohortEligible": "true"}


def ledger(sid="session-a"):
    return [{"SessionID": sid, "Status": status, "ExecutionUTC": instant, "Detail": detail}
            for status, instant, detail in [
                ("Started", "2026-01-01T10:00:00Z", "Session execution initiated"),
                ("Completed", "2026-01-01T10:01:00Z", "Actions: 2"),
            ]]


def event(eid="5145", provider=SECURITY, at="2026-01-01T10:00:10.123456789Z", record="1", data=None):
    if data is None:
        data = {"subjectUserName": "example.user", "subjectDomainName": "EXAMPLE",
                "objectType": "File", "shareName": "\\\\*\\RestrictedResearch",
                "shareLocalPath": "C:\\RestrictedResearch", "relativeTargetName": "synthetic.txt",
                "accessMask": "0x1", "subjectLogonId": "0x123"}
    return {"timestamp": (timestamp(at) + timedelta(seconds=1)).isoformat(), "id": "envelope-" + record,
            "data": {"win": {"system": {
                "providerName": provider, "channel": "Security" if provider == SECURITY else "Microsoft-Windows-Sysmon/Operational",
                "computer": "host.example.invalid", "eventID": eid, "eventRecordID": record,
                "systemTime": at, "keywords": "0x8020000000000000", "severityValue": "AUDIT_SUCCESS",
            }, "eventdata": data}}}


def wrapped(item):
    win = item["data"]["win"]
    return Event(win["system"], win["eventdata"], item)


class FeatureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, items, name="archive.json", compressed=False):
        path = self.root / name
        text = "".join(json.dumps(item) + "\n" for item in items)
        if compressed:
            with gzip.open(path, "wt", encoding="utf-8") as handle:
                handle.write(text)
        else:
            path.write_text(text, encoding="utf-8")
        return path

    def run_extract(self, items, rows=None, entries=None, alerts=None, padding=0, anchors=None):
        path = self.write(items)
        alert_paths = [self.write(alerts, "alerts.json")] if alerts is not None else []
        with redirect_stdout(io.StringIO()):
            return extract(rows or [ground()], entries or ledger(), [path], alert_paths,
                           moment("2026-01-01T00:00:00Z"), moment("2026-01-02T00:00:00Z"), padding,
                           identity_anchors=anchors)

    def test_nanosecond_time_and_incomplete_timestamps(self):
        self.assertEqual(timestamp("2026-01-01T10:00:10.123456789Z").microsecond, 123456)
        self.assertEqual(timestamp("2026-01-01T11:00:10+0100"), moment())
        for value in [None, "2026-01-01", "2026-01-01T10:00:00", "broken"]:
            with self.assertRaises(ValueError):
                timestamp(value)

    def test_smb_success_is_not_denial_and_paths_are_distinct(self):
        items = [event(), event(record="2")]
        items[1]["data"]["win"]["system"].update(keywords="0x8010000000000000", severityValue="AUDIT_FAILURE")
        rows, _ = self.run_extract(items)
        row = rows[0]
        self.assertEqual(row["smb_access_check_count"], 2)
        self.assertEqual(row["smb_denied_count"], 1)
        self.assertEqual(row["distinct_smb_paths"], 1)
        self.assertEqual(row["protected_resource_event_count"], 2)
        self.assertEqual(row["unique_action_signatures"], 1)

    def test_conflicting_or_missing_denial_fields_blank_denial_feature(self):
        item = event()
        item["data"]["win"]["system"].update(keywords="0x8010000000000000", severityValue="AUDIT_SUCCESS")
        self.assertIsNone(audit_failure(wrapped(item)))
        rows, _ = self.run_extract([item])
        self.assertEqual(rows[0]["smb_denied_count"], "")

    def test_duplicate_events_distinct_from_raw_counts_and_alerts(self):
        item = event()
        alert = {**item, "rule": {"id": "synthetic-rule", "description": "ignored"}}
        second = {**alert, "id": "another-alert", "rule": {"id": "another-rule"}}
        rows, report = self.run_extract([item, item], alerts=[alert, alert, second])
        row = rows[0]
        self.assertEqual(row["RawMatchedArchiveRecords"], 2)
        self.assertEqual(row["UniqueMatchedArchiveEvents"], 1)
        self.assertEqual(row["DuplicateMatchedArchiveRecords"], 1)
        self.assertEqual(row["windows_event_count"], 1)
        self.assertEqual(row["WazuhAlertRecordCount"], 2)
        self.assertEqual(row["WazuhDistinctAlertedEventCount"], 1)
        self.assertEqual(report["streams"]["archives"]["counts"]["duplicate_windows_records"], 1)

    def test_record_id_reuse_at_different_times_is_not_deduplicated(self):
        rows, _ = self.run_extract([event(), event(at="2026-01-01T10:00:11Z")])
        self.assertEqual(rows[0]["windows_event_count"], 2)

    def test_identity_and_overlap_ambiguity_never_first_match(self):
        rows, report = self.run_extract([event()], rows=[ground(), ground("session-b")],
                                        entries=ledger() + ledger("session-b"))
        self.assertTrue(all(row["AmbiguousArchiveCandidates"] == 1 for row in rows))
        self.assertTrue(all(row["windows_event_count"] == "" for row in rows))
        self.assertTrue(all(row["FeatureMLTrainingEligible"] == "false" for row in rows))
        self.assertEqual(report["streams"]["archives"]["counts"]["ambiguous_events"], 1)

    def test_windows_for_different_users_do_not_compete(self):
        rows, _ = self.run_extract([event()], rows=[ground(), ground("session-b", "other.user")],
                                   entries=ledger() + ledger("session-b"))
        self.assertEqual(rows[0]["windows_event_count"], 1)
        self.assertEqual(rows[1]["windows_event_count"], "")

    def test_window_uses_handler_return_not_later_reconciliation(self):
        entries = ledger()
        entries[1].update(Status="InvokedUnverified", Detail="Handler returned; scenario outcome requires validation.")
        entries.append({"SessionID": "session-a", "Status": "Completed", "ExecutionUTC": "2026-01-03T10:00:00Z", "Detail": "Reconciled: Handler result: Completed"})
        windows, _ = session_windows([ground()], entries, 0)
        self.assertEqual(windows[0].end, moment("2026-01-01T10:01:00Z"))

    def test_unknown_end_not_inferred_from_schedule_or_late_reconciliation(self):
        entries = ledger()
        entries[1]["Detail"] = "Reconciled: Handler result: Completed"
        windows, _ = session_windows([ground()], entries, 0)
        self.assertIsNone(windows[0].end)
        self.assertTrue(windows[0].issue)

    def test_worker_interval_preserves_late_recovery(self):
        row = ground(scenario="M05")
        row.update(ActualExecutionUTC="2026-01-03T10:00:00Z", ActualExecutionTimestampSource="m05_worker_started",
                   M05EndedUTC="2026-01-03T10:00:30Z", Original14DayCohortEligible="false")
        rows, report = self.run_extract([event(at="2026-01-03T10:00:10Z")], rows=[row])
        self.assertEqual(rows[0]["windows_event_count"], 1)
        self.assertEqual(rows[0]["FeatureExtendedCohortEligible"], "true")
        self.assertEqual(rows[0]["FeatureOriginal14DayCohortEligible"], "false")
        self.assertEqual(report["streams"]["archives"]["counts"]["attributed_outside_original_period"], 1)

    def test_padding_is_explicit_and_configurable(self):
        item = event(at="2026-01-01T09:59:59Z")
        strict, _ = self.run_extract([item], padding=0)
        padded, _ = self.run_extract([item], padding=2)
        self.assertEqual(strict[0]["windows_event_count"], "")
        self.assertEqual(padded[0]["windows_event_count"], 1)
        self.assertEqual(padded[0]["PaddingOnlyArchiveEvents"], 1)

    def test_unknown_eventtime_does_not_fallback_to_manager(self):
        item = event()
        del item["data"]["win"]["system"]["systemTime"]
        rows, report = self.run_extract([item])
        self.assertEqual(rows[0]["UniqueMatchedArchiveEvents"], 0)
        # An unplaceable later record must not contaminate every earlier session.
        self.assertEqual(rows[0]["UnknownTimestampArchiveCandidates"], 0)
        self.assertEqual(report["streams"]["archives"]["counts"]["unknown_event_time"], 1)

    def test_clock_disagreement_is_audited_without_inferred_time_shift(self):
        item = event()
        item["timestamp"] = "2026-01-01T02:00:10Z"
        rows, report = self.run_extract([item])
        self.assertEqual(rows[0]["ClockDisagreementArchiveEvents"], 1)
        self.assertIn("clock_reference_unreliable_excluded", rows[0]["FeatureReviewReasons"])
        self.assertEqual(rows[0]["FeatureMLTrainingEligible"], "false")
        self.assertEqual(rows[0]["windows_event_count"], 1)
        clocks = report["streams"]["archives"]["host_clock_audit"]
        self.assertEqual(clocks["host.example.invalid"]["over_300s_absolute"], 1)

    def test_auth_target_not_subject_and_nameless_target_unmatched(self):
        data = {"subjectUserName": "example.user", "subjectDomainName": "EXAMPLE",
                "targetUserName": "other.user", "targetDomainName": "EXAMPLE"}
        rows, _ = self.run_extract([event("4625", data=data)])
        self.assertEqual(rows[0]["UniqueMatchedArchiveEvents"], 0)
        data["targetUserName"] = "example.user"
        rows, _ = self.run_extract([event("4625", data=data)], anchors={"example.user": {r"example\example.user"}})
        self.assertEqual(rows[0]["failed_logon_count"], 1)
        del data["targetUserName"]
        rows, _ = self.run_extract([event("4625", data=data)])
        self.assertEqual(rows[0]["UniqueMatchedArchiveEvents"], 0)

    def test_domain_conflicts_are_not_merged(self):
        first, second = event(), event(record="2")
        second["data"]["win"]["eventdata"]["subjectDomainName"] = "OTHER"
        rows, _ = self.run_extract([first, second])
        self.assertEqual(rows[0]["UniqueMatchedArchiveEvents"], 0)

    def test_verified_namespace_anchor_accepts_only_exact_domain(self):
        first, second = event(), event(record="2")
        second["data"]["win"]["eventdata"]["subjectDomainName"] = "OTHER"
        rows, report = self.run_extract([first, second], anchors={"example.user": {"example\\example.user"}})
        self.assertEqual(rows[0]["UniqueMatchedArchiveEvents"], 1)
        self.assertEqual(rows[0]["windows_event_count"], 1)
        self.assertEqual(report["verified_identity_anchors"]["example.user"], ["example\\example.user"])

    def test_doubled_decoded_identity_separators_are_not_new_domains(self):
        self.assertEqual(normalized_identity(r"EXAMPLE\\example.user"), r"example\example.user")
        item = event("1", SYSMON, data={"user": r"EXAMPLE\\example.user", "image": r"C:\\sftp.exe", "processGuid": "guid"})
        rows, _ = self.run_extract([item], anchors={"example.user": {r"example\example.user"}})
        self.assertEqual(rows[0]["sftp_process_count"], 1)

    def test_doubled_native_share_path_matches_object_path(self):
        self.assertEqual(normalized_path(r"\\??\\C:\\Research\\file.txt"), r"c:\research\file.txt")
        self.assertEqual(normalized_path(r"\\host\\share\\file.txt"), r"\\host\share\file.txt")
        smb = event()
        smb["data"]["win"]["eventdata"].update(shareLocalPath=r"\\??\\C:\\RestrictedResearch", relativeTargetName=r"\\synthetic.txt")
        file = event("4663", record="2", data={"subjectUserName": "example.user", "subjectDomainName": "EXAMPLE",
                                                "objectType": "File", "objectName": r"C:\\RestrictedResearch\\synthetic.txt", "accessMask": "0x1"})
        rows, _ = self.run_extract([smb, file])
        self.assertEqual(rows[0]["distinct_file_paths"], 1)
        smb["data"]["win"]["eventdata"]["relativeTargetName"] = r"\\"
        self.assertEqual(resource_path(wrapped(smb)), r"c:\restrictedresearch")

    def test_process_guid_links_missing_user_network_to_sftp_parent(self):
        common = {"user": "EXAMPLE\\example.user"}
        parent = event("1", SYSMON, "2026-01-01T10:00:01Z", "1", {**common, "processGuid": "parent", "image": "C:\\Tools\\sftp.exe"})
        child = event("1", SYSMON, "2026-01-01T10:00:02Z", "2", {**common, "processGuid": "child", "parentProcessGuid": "parent", "image": "C:\\Tools\\ssh.exe"})
        connection = event("3", SYSMON, "2026-01-01T10:00:03Z", "3", {"processGuid": "child", "image": "C:\\Tools\\ssh.exe", "destinationIp": "192.0.2.1", "destinationPort": "22", "initiated": "true"})
        # Deliberately unsorted source records require the indexing pass.
        rows, _ = self.run_extract([connection, child, parent])
        row = rows[0]
        self.assertEqual(row["sftp_process_count"], 1)
        self.assertEqual(row["ssh_process_count"], 1)
        self.assertEqual(row["sftp_network_connection_count"], 1)
        self.assertEqual(row["ssh_port22_connection_count"], 1)
        self.assertEqual(row["IdentityLinkedArchiveEvents"], 1)

    def test_process_link_is_host_scoped_and_cannot_use_future_creation(self):
        created = event("1", SYSMON, "2026-01-01T10:00:10Z", "1", {"user": "EXAMPLE\\example.user", "processGuid": "guid", "image": "ssh.exe"})
        before = event("3", SYSMON, "2026-01-01T10:00:01Z", "2", {"processGuid": "guid", "image": "ssh.exe"})
        other_host = event("3", SYSMON, "2026-01-01T10:00:11Z", "3", {"processGuid": "guid", "image": "ssh.exe"})
        other_host["data"]["win"]["system"]["computer"] = "other.example.invalid"
        rows, _ = self.run_extract([created, before, other_host])
        self.assertEqual(rows[0]["UniqueMatchedArchiveEvents"], 1)

    def test_delete_right_distinct_from_deletion_record_and_file_path(self):
        access = event("4663", data={"subjectUserName": "example.user", "objectType": "File",
                                    "objectName": "C:\\RestrictedResearch\\synthetic.txt", "accessMask": "0x10001"})
        deleted = event("4660", record="2", data={"subjectUserName": "example.user", "handleId": "0x1"})
        rows, _ = self.run_extract([access, deleted])
        self.assertEqual(rows[0]["delete_access_count"], 1)
        self.assertEqual(rows[0]["object_deletion_event_count"], 1)
        self.assertEqual(rows[0]["file_read_access_count"], 1)
        self.assertEqual(rows[0]["distinct_file_paths"], 1)
        self.assertEqual(resource_path(wrapped(deleted)), "")

    def test_missing_access_mask_is_blank_not_zero(self):
        access = event("4663", data={"subjectUserName": "example.user", "objectType": "File", "objectName": "C:\\example.txt"})
        rows, _ = self.run_extract([access])
        self.assertEqual(rows[0]["file_access_count"], 1)
        self.assertEqual(rows[0]["delete_access_count"], "")

    def test_no_family_support_is_missing_not_zero(self):
        rows, _ = self.run_extract([event()])
        self.assertEqual(rows[0]["smb_denied_count"], 0)
        self.assertEqual(rows[0]["sftp_process_count"], "")
        self.assertEqual(rows[0]["Observed_process"], "false")

    def test_orchestration_paths_excluded_from_predictors(self):
        item = event()
        item["data"]["win"]["eventdata"].update(shareName="\\\\*\\M05Queue", shareLocalPath="C:\\M05Queue")
        rows, _ = self.run_extract([item])
        self.assertEqual(rows[0]["OrchestrationArchiveEvents"], 1)
        self.assertEqual(rows[0]["windows_event_count"], "")

    def test_failed_execution_never_feature_training_eligible(self):
        row = ground()
        row.update(MLTrainingEligible="false", ExtendedCohortEligible="false", Original14DayCohortEligible="false")
        rows, _ = self.run_extract([event()], rows=[row])
        self.assertEqual(rows[0]["FeatureMLTrainingEligible"], "false")
        self.assertEqual(rows[0]["windows_event_count"], 1)

    def test_labels_scenarios_rule_ids_and_outcomes_are_not_predictors(self):
        first, _ = self.run_extract([event()])
        changed = ground(scenario="M04")
        changed.update(GroundTruthLabel="1", FinalExecutionStatus="Failed")
        item = event()
        item["rule"] = {"id": "M05-label-shortcut", "level": 15}
        second, _ = self.run_extract([item], rows=[changed])
        self.assertEqual({k: first[0][k] for k in FEATURES}, {k: second[0][k] for k in FEATURES})
        self.assertFalse(set(FEATURES) & set(META_FIELDS))

    def test_wrong_provider_id_collision_is_not_a_security_event(self):
        item = event(provider="Other-Provider")
        rows, _ = self.run_extract([item])
        self.assertEqual(rows[0]["UniqueMatchedArchiveEvents"], 0)

    def test_gzip_active_and_byte_identical_files_selection(self):
        folder = self.root / "logs/archives/2026/Jan"
        folder.mkdir(parents=True)
        active = self.root / "logs/archives/archives.json"
        content = json.dumps(event()) + "\n"
        active.write_text(content)
        (folder / "dated.json").write_text(content)
        with gzip.open(folder / "dated.json.gz", "wt") as handle:
            handle.write(content)
        selected, manifest = select_files(self.root, "archives")
        self.assertEqual(len(selected), 2)  # Compressed content deduplicates at event level.
        self.assertEqual(sum(item["duplicate_of"] is not None for item in manifest), 1)
        stats, errors = Counter(), []
        self.assertEqual(len(list(events(selected, stats, errors))), 2)
        self.assertFalse(errors)

    def test_malformed_json_and_truncated_gzip_are_explicit_errors(self):
        bad = self.root / "bad.json"
        bad.write_text("{bad}\n")
        zipped = self.write([event()], "truncated.json.gz", compressed=True)
        zipped.write_bytes(zipped.read_bytes()[:-8])
        stats, errors = Counter(), []
        list(events([bad, zipped], stats, errors))
        self.assertEqual(stats["malformed_json"], 1)
        self.assertEqual(stats["unreadable_files"], 1)

    def test_integrity_error_blocks_all_feature_cohorts(self):
        path = self.write([event()])
        with path.open("a") as handle:
            handle.write("bad-json\n")
        with redirect_stdout(io.StringIO()):
            rows, report = extract([ground()], ledger(), [path], [],
                                   moment("2026-01-01T00:00:00Z"), moment("2026-01-02T00:00:00Z"))
        self.assertEqual(report["validation_status"], "errors")
        self.assertEqual(rows[0]["FeatureMLTrainingEligible"], "false")

    def test_matcher_inclusive_endpoints_and_invalid_windows(self):
        valid = Window("a", "user", moment("2026-01-01T10:00:00Z"), moment("2026-01-01T10:01:00Z"))
        matcher = Matcher([valid, Window("b", "user")], 0)
        self.assertEqual([w.sid for w in matcher.candidates("user", valid.end)], ["a"])
        self.assertFalse(matcher.candidates("user", moment("2026-01-01T10:01:01Z")))

    def test_cli_refuses_existing_outputs_and_original_data_destinations(self):
        output = self.root / "outputs"
        output.mkdir()
        (output / "session_features.csv").write_text("preserve")
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["--output-dir", str(output)])
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["--output-dir", "data/wazuh/forbidden"])

    def test_cli_reproducibility_join_schema_and_source_immutability(self):
        source = self.root / "source"
        source.mkdir()
        (source / "M05Results").mkdir()
        plan = dict(zip(SCHEDULE_FIELDS, ["session-a", "1", "10:00:00", "N01", "0",
                                          "example.user", "Researcher", "2", "0", "1", "2", "Pending"]))
        entries = [{**item, "ScheduledUTC": "2026-01-01T10:00:00Z", "ScenarioID": "N01",
                    "Username": "example.user"} for item in ledger()]
        for name, fields, records in [("dataset_schedule_v3.csv", SCHEDULE_FIELDS, [plan]),
                                      ("execution_ledger.csv", LEDGER_FIELDS, entries)]:
            with (source / name).open("w", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerows(records)
        gt_output = self.root / "ground"
        with redirect_stdout(io.StringIO()):
            self.assertEqual(ground_truth_main(["--input-dir", str(source), "--output-dir", str(gt_output),
                                               "--start-date", "2026-01-01", "--end-date", "2026-01-02"]), 0)
        wazuh = self.root / "wazuh"
        archive = wazuh / "logs/archives"
        archive.mkdir(parents=True)
        (archive / "archives.json").write_text(json.dumps(event()) + "\n")
        protected_files = {path: path.read_bytes() for directory in [source, gt_output, wazuh]
                           for path in directory.rglob("*") if path.is_file()}
        base_args = ["--ground-truth", str(gt_output / "session_ground_truth.csv"),
                     "--ground-truth-report", str(gt_output / "validation_report.json"),
                     "--source-dir", str(source), "--wazuh-dir", str(wazuh)]
        first, second = self.root / "features-one", self.root / "features-two"
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(base_args + ["--output-dir", str(first)]), 0)
            self.assertEqual(main(base_args + ["--output-dir", str(second)]), 0)
        for path in first.iterdir():
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())
        self.assertTrue(all(path.read_bytes() == value for path, value in protected_files.items()))
        with (first / "ml_dataset.csv").open() as handle:
            merged = list(csv.DictReader(handle))
        with (gt_output / "session_ground_truth.csv").open() as handle:
            original = list(csv.DictReader(handle))
        self.assertEqual([{key: row[key] for key in OUTPUT_FIELDS} for row in merged], original)
        schema = json.loads((first / "feature_schema.json").read_text())
        self.assertEqual(schema["candidate_predictive_columns"], FEATURES)
        self.assertTrue(set(schema["predictive_columns"]) <= set(FEATURES))
        self.assertIn("sysmon_file_delete_count", schema["unavailable_predictive_columns"])
        self.assertNotIn("WazuhAlertRecordCount", schema["predictive_columns"])
        self.assertEqual(merged[0]["WazuhAlertRecordCount"], "")


if __name__ == "__main__":
    unittest.main()
