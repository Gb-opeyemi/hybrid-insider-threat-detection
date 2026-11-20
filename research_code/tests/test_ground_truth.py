"""Synthetic fixtures only. Run: python3 -m unittest discover -s tests -v."""

import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path

from src.ground_truth import (
    LEDGER_FIELDS, SCHEDULE_FIELDS, build_dataset, main, parse_utc, same_account,
    validate_m05,
)


class GroundTruthTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        (self.inputs / "M05Results").mkdir()
        self.schedule = []
        self.ledger = []

    def add_session(self, sid="synthetic-1", scenario="N01", status="Completed"):
        self.schedule.append(dict(zip(SCHEDULE_FIELDS, [
            sid, "1", "10:00:00", scenario, "1" if scenario.startswith("M") else "0",
            "example.user", "Researcher", "2", "0", "1", "2", "Pending",
        ])))
        for state, timestamp in [("Started", "2026-01-01T10:01:00.1234567Z"),
                                 (status, "2026-01-01T10:02:00Z")]:
            self.ledger.append(dict(zip(LEDGER_FIELDS, [
                sid, "2026-01-01T10:00:00.0000000Z", scenario, "example.user",
                timestamp, state, 'Synthetic detail, with "quoted" text',
            ])))

    def result(self, sid="synthetic-1", status="Completed"):
        success = status == "Completed"
        return {
            "SessionID": sid, "Scenario": "M05", "ExecutedBy": "EXAMPLE\\example.user",
            "SourceFiles": ["synthetic-a.txt", "synthetic-b.txt"] if success else [],
            "Destination": "transfer.example.invalid", "StartedUTC": "2026-01-01T10:01:01Z",
            "EndedUTC": "2026-01-01T10:01:59Z", "Status": status,
            "FilesRequested": 2 if success else 0, "FilesTransferred": 2 if success else 0,
            "SourceBytes": 20 if success else 0, "TransferPerformed": success,
            "ValidationStatus": "PendingWazuhVerification", "ErrorMessage": "",
        }

    def write_result(self, result, name="result.json"):
        (self.inputs / "M05Results" / name).write_text(json.dumps(result), encoding="utf-8-sig")

    def write_tables(self):
        for name, fields, rows in [("dataset_schedule_v3.csv", SCHEDULE_FIELDS, self.schedule),
                                   ("execution_ledger.csv", LEDGER_FIELDS, self.ledger)]:
            with (self.inputs / name).open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerows(rows)

    def build(self):
        self.write_tables()
        return build_dataset(self.inputs, date(2026, 1, 1), date(2026, 1, 2))

    def test_completed_benign_bom_quoting_and_timestamp_provenance(self):
        self.add_session()
        rows, report = self.build()
        self.assertEqual(report["validation_status"], "passed")
        row = rows[0]
        self.assertEqual(row["GroundTruthLabel"], "0")
        self.assertEqual(row["ActualExecutionUTC"], "2026-01-01T10:01:00.1234567Z")
        self.assertNotEqual(row["ActualExecutionUTC"], row["ScheduledUTC"])
        self.assertEqual(row["ActualExecutionTimestampSource"], "ledger_started_initiation")
        self.assertIn('"quoted"', row["FinalLedgerDetail"])
        self.assertEqual(row["Original14DayCohortEligible"], "true")

    def test_final_status_uses_append_order_not_sorted_time(self):
        self.add_session()
        self.ledger.append({**self.ledger[-1], "ExecutionUTC": "2026-01-01T10:00:01Z", "Status": "Failed"})
        rows, report = self.build()
        self.assertEqual(rows[0]["FinalExecutionStatus"], "Failed")
        self.assertEqual(rows[0]["FinalLedgerRow"], 4)
        self.assertIn("ledger_time_order", report["issue_counts"])

    def test_failed_remains_identifiable_without_assigned_label(self):
        self.add_session(status="Failed")
        rows, report = self.build()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["IntendedLabel"], "0")
        self.assertEqual(rows[0]["GroundTruthLabel"], "")
        self.assertEqual(rows[0]["MLTrainingEligible"], "false")
        self.assertEqual(report["integrity_checks"]["failed_executions"], 1)

    def test_late_m05_kept_in_extended_and_ml_but_not_original(self):
        self.add_session(scenario="M05")
        self.ledger[-1]["ExecutionUTC"] = "2026-01-03T10:02:00Z"
        result = self.result()
        result["StartedUTC"] = "2026-01-03T10:01:00Z"
        result["EndedUTC"] = "2026-01-03T10:01:59Z"
        self.write_result(result)
        rows, report = self.build()
        row = rows[0]
        self.assertEqual(row["LateRecovery"], "true")
        self.assertEqual(row["ActualExecutionUTC"], result["StartedUTC"])
        self.assertEqual(row["MLTrainingEligible"], "true")
        self.assertEqual(row["ExtendedCohortEligible"], "true")
        self.assertEqual(row["Original14DayCohortEligible"], "false")
        self.assertEqual(row["M05ValidationStatus"], "PendingWazuhVerification")
        self.assertEqual(report["cohorts"]["extended"]["total"], 1)

    def test_unknown_actual_time_never_filled_from_schedule_or_final(self):
        self.add_session()
        self.ledger.pop(0)
        rows, report = self.build()
        self.assertEqual(rows[0]["ActualExecutionUTC"], "")
        self.assertEqual(rows[0]["ActualExecutionTimestampStatus"], "unknown")
        self.assertEqual(rows[0]["LateRecovery"], "unknown")
        self.assertEqual(rows[0]["Original14DayCohortEligible"], "false")
        self.assertEqual(report["integrity_checks"]["unknown_actual_execution_times"], 1)

    def test_missing_and_incomplete_ledger_sessions(self):
        self.add_session("missing")
        self.ledger.clear()
        self.add_session("incomplete", status="Queued")
        rows, report = self.build()
        self.assertEqual([x["FinalExecutionStatus"] for x in rows], ["Missing", "Queued"])
        self.assertTrue(all(x["MLTrainingEligible"] == "false" for x in rows))
        self.assertEqual(report["integrity_checks"]["incomplete_executions"], 2)

    def test_duplicate_schedule_id_blocked_and_reported(self):
        self.add_session()
        self.schedule.append(dict(self.schedule[0]))
        rows, report = self.build()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["MLTrainingEligible"], "false")
        self.assertEqual(report["integrity_checks"]["duplicate_schedule_ids"], 1)

    def test_repeated_lifecycle_is_expected_but_exact_duplicates_block(self):
        self.add_session()
        _, report = self.build()
        self.assertEqual(report["source_counts"]["ledger_repeated_ids"], 1)
        self.assertEqual(report["integrity_checks"]["duplicate_ledger_rows"], 0)
        self.ledger.append(dict(self.ledger[-1]))
        rows, report = self.build()
        self.assertEqual(report["integrity_checks"]["duplicate_ledger_rows"], 1)
        self.assertEqual(rows[0]["MLTrainingEligible"], "false")

    def test_label_and_ledger_consistency(self):
        self.add_session(scenario="M01")
        self.schedule[0]["IntendedLabel"] = "0"
        self.ledger[-1].update(ScenarioID="N01", Username="different.user",
                               ScheduledUTC="2026-01-01T11:00:00Z")
        rows, report = self.build()
        for code in ["inconsistent_intended_label", "ledger_scenario_mismatch",
                     "ledger_identity_mismatch", "ledger_scheduled_time_mismatch"]:
            self.assertIn(code, report["issue_counts"])
        self.assertEqual(rows[0]["GroundTruthLabel"], "")

    def test_unknown_status_and_orphan_ledger(self):
        self.add_session()
        self.ledger.append({**self.ledger[-1], "SessionID": "orphan", "Status": "Unexpected"})
        _, report = self.build()
        self.assertIn("unknown_ledger_status", report["issue_counts"])
        self.assertEqual(report["integrity_checks"]["orphan_ledger_ids"], 1)
        self.assertEqual(report["validation_status"], "errors")

    def test_m05_missing_duplicate_and_unmatched_results(self):
        self.add_session(scenario="M05")
        rows, report = self.build()
        self.assertEqual(rows[0]["M05TransferValidation"], "missing")
        self.assertEqual(report["integrity_checks"]["missing_m05_results"], 1)
        self.write_result(self.result(), "a.json")
        self.write_result(self.result(), "b.json")
        self.write_result(self.result("synthetic-pilot", "Failed"), "pilot.json")
        rows, report = self.build()
        self.assertEqual(rows[0]["M05TransferValidation"], "ambiguous")
        self.assertEqual(rows[0]["MLTrainingEligible"], "false")
        self.assertEqual(report["integrity_checks"]["duplicate_m05_ids"], 1)
        self.assertEqual(report["source_counts"]["m05_unmatched_unique_ids"], 1)

    def test_zero_file_failed_result_is_not_success(self):
        self.add_session(scenario="M05", status="Failed")
        self.write_result(self.result(status="Failed"))
        rows, _ = self.build()
        self.assertEqual(rows[0]["M05TransferValidation"], "worker_failed")
        self.assertEqual(rows[0]["MLTrainingEligible"], "false")
        result = self.result(status="Failed")
        result["Status"] = "Completed"
        self.assertIn("m05_success_evidence", validate_m05(result))

    def test_m05_worker_status_and_identity_conflicts(self):
        self.add_session(scenario="M05")
        result = self.result(status="Failed")
        result["ExecutedBy"] = "EXAMPLE\\other.user"
        self.write_result(result)
        rows, report = self.build()
        self.assertIn("m05_ledger_status_mismatch", report["issue_counts"])
        self.assertIn("m05_identity_mismatch", report["issue_counts"])
        self.assertEqual(rows[0]["MLTrainingEligible"], "false")

    def test_strict_m05_types_counts_and_time_order(self):
        for key, value, code in [
            ("FilesRequested", True, "m05_count_type_or_range"),
            ("FilesTransferred", -1, "m05_count_type_or_range"),
            ("TransferPerformed", "true", "m05_transfer_boolean_type"),
            ("SourceFiles", [None], "m05_source_files_type"),
            ("EndedUTC", "2026-01-01T09:00:00Z", "m05_time_order"),
            ("StartedUTC", "not-a-time", "m05_timestamp"),
            ("FilesTransferred", 3, "m05_file_counts"),
        ]:
            with self.subTest(key=key, value=value):
                result = self.result()
                result[key] = value
                self.assertIn(code, validate_m05(result))

    def test_bad_json_and_invalid_schema_reported(self):
        self.add_session()
        (self.inputs / "M05Results" / "bad.json").write_text('{"SessionID":"a","SessionID":"b"}')
        self.write_result({"SessionID": "unmatched"}, "schema.json")
        _, report = self.build()
        self.assertIn("malformed_m05_json", report["issue_counts"])
        self.assertIn("m05_schema", report["issue_counts"])

    def test_schedule_invalid_date_parameters(self):
        for key, value in [("SimulationDay", "0"), ("FileCount", "-1"),
                           ("TimeOfDayUTC", "25:00:00"), ("MinDelaySeconds", "99")]:
            with self.subTest(key=key):
                self.schedule.clear()
                self.ledger.clear()
                self.add_session()
                self.schedule[0][key] = value
                rows, report = self.build()
                self.assertIn("invalid_schedule_parameters", report["issue_counts"])
                self.assertEqual(rows[0]["MLTrainingEligible"], "false")

    def test_utc_precision_and_account_mapping(self):
        self.assertEqual(parse_utc("2026-01-01T00:00:00.1234567Z").microsecond, 123456)
        for value in ["2026-01-01T00:00:00", "2026-01-01T00:00:00+01:00", "bad"]:
            with self.assertRaises(ValueError):
                parse_utc(value)
        self.assertTrue(same_account("EXAMPLE\\Example.User", "example.user"))
        self.assertFalse(same_account("ONE\\example.user", "TWO\\example.user"))

    def cli_args(self, output):
        return ["--input-dir", str(self.inputs), "--output-dir", str(output),
                "--start-date", "2026-01-01", "--end-date", "2026-01-02"]

    def run_cli(self, output):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return main(self.cli_args(output))

    def test_cli_reproducible_exports_and_no_overwrite_or_source_changes(self):
        self.add_session()
        self.write_tables()
        before = {p: p.read_bytes() for p in self.inputs.rglob("*") if p.is_file()}
        first, second = self.root / "first", self.root / "second"
        self.assertEqual(self.run_cli(first), 0)
        self.assertEqual(self.run_cli(second), 0)
        for path in first.iterdir():
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())
        self.assertEqual(before, {p: p.read_bytes() for p in self.inputs.rglob("*") if p.is_file()})
        with self.assertRaises(SystemExit):
            self.run_cli(first)
        with self.assertRaises(SystemExit):
            self.run_cli(self.inputs / "bad-output")

    def test_cli_fatal_schema_has_report_without_master(self):
        self.add_session()
        self.write_tables()
        (self.inputs / "dataset_schedule_v3.csv").write_text("wrong,header\na,b\n")
        output = self.root / "fatal"
        self.assertEqual(self.run_cli(output), 1)
        self.assertFalse((output / "session_ground_truth.csv").exists())
        report = json.loads((output / "validation_report.json").read_text())
        self.assertEqual(report["validation_status"], "fatal")

    def test_cli_row_errors_return_nonzero_with_ineligible_audit_master(self):
        self.add_session()
        self.schedule[0]["IntendedLabel"] = "1"
        self.write_tables()
        output = self.root / "errors"
        self.assertEqual(self.run_cli(output), 1)
        with (output / "session_ground_truth.csv").open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["MLTrainingEligible"], "false")
        self.assertFalse((output / "RUN_INCOMPLETE").exists())

    def test_invalid_m05_nested_types_cannot_crash_report(self):
        self.add_session(scenario="M05")
        result = self.result()
        result["ValidationStatus"] = ["bad"]
        result["Status"] = {"bad": "type"}
        self.write_result(result)
        rows, report = self.build()
        self.assertEqual(report["validation_status"], "errors")
        self.assertEqual(rows[0]["MLTrainingEligible"], "false")

    def test_malformed_csv_width_is_fatal(self):
        self.add_session()
        self.write_tables()
        path = self.inputs / "execution_ledger.csv"
        path.write_text(path.read_text(encoding="utf-8-sig") + "too,few,fields\n")
        with self.assertRaises(ValueError):
            build_dataset(self.inputs, date(2026, 1, 1), date(2026, 1, 2))


if __name__ == "__main__":
    unittest.main()
