"""Validate execution evidence and prepare provisional session ground truth.

Run from the repository root with ``python3 -m src.ground_truth --help``.
Only the schedule, ledger, and M05 results are read; Wazuh is not validated here.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import platform
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any

POLICY_VERSION = "execution-ground-truth-v1"
SCHEDULE_FIELDS = (
    "SessionID SimulationDay TimeOfDayUTC ScenarioID IntendedLabel Username Role "
    "FileCount FailedLogins MinDelaySeconds MaxDelaySeconds ExecutionStatus"
).split()
LEDGER_FIELDS = (
    "SessionID ScheduledUTC ScenarioID Username ExecutionUTC Status Detail"
).split()
M05_STRINGS = (
    "SessionID Scenario ExecutedBy Destination StartedUTC EndedUTC Status "
    "ValidationStatus ErrorMessage"
).split()
M05_COUNTS = "FilesRequested FilesTransferred SourceBytes".split()
M05_FIELDS = M05_STRINGS + M05_COUNTS + ["SourceFiles", "TransferPerformed"]
SCENARIO_LABELS = {**{f"N{i:02}": "0" for i in range(1, 8)},
                   **{f"M{i:02}": "1" for i in range(1, 6)}}
STATUSES = {"Started", "Queued", "InvokedUnverified", "Completed", "Failed"}
OUTPUT_FIELDS = (
    "SessionID SimulationDay ScenarioID IntendedLabel Username Role "
    "ScheduledUTC ScheduleTimeOfDayUTC LedgerScheduledUTC ScheduleExecutionStatus ScheduleRow "
    "ActualExecutionUTC ActualExecutionTimestampSource ActualExecutionTimestampStatus "
    "FinalExecutionStatus FirstLedgerExecutionUTC FinalLedgerExecutionUTC "
    "FirstLedgerRow FinalLedgerRow LedgerRowCount LedgerTransitions FinalLedgerDetail "
    "M05ResultFile M05Status M05StartedUTC M05EndedUTC M05FilesRequested "
    "M05FilesTransferred M05SourceBytes M05TransferPerformed M05TransferValidation "
    "M05ValidationStatus LateRecovery LateRecoveryStatus "
    "Original14DayCohortEligible ExtendedCohortEligible MLTrainingEligible "
    "GroundTruthLabel LabelBasis TelemetryVerificationStatus "
    "ReviewRequired ReviewReasons MLExclusionReasons OriginalCohortExclusionReasons"
).split()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_utc(value: str) -> datetime:
    """Require an explicit zero UTC offset. Raw precision is retained in outputs.

    datetime truncates fractional seconds beyond six digits for comparisons.
    This pipeline compares dates/order, not sub-microsecond durations.
    """
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|\+00:00|\+0000)", value
    ):
        raise ValueError("Expected an explicit UTC ISO timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() != timedelta(0):
        raise ValueError("Timestamp must be UTC")
    return parsed


def account(value: str) -> str:
    """Compare account names case-insensitively, retaining raw identities elsewhere.

    A domain-qualified/unqualified pair may match; two explicit different domains
    must not match. UPN-to-domain mappings are deliberately not guessed.
    """
    return value.casefold()


def same_account(left: str, right: str) -> bool:
    left, right = account(left), account(right)
    if "\\" in left and "\\" in right:
        return left == right
    return left.rsplit("\\", 1)[-1] == right.rsplit("\\", 1)[-1]


def read_csv(path: Path, fields: list[str]) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle, strict=True)
        if reader.fieldnames != fields:
            raise ValueError(f"{path.name}: unexpected header; expected {fields}")
        rows = list(reader)
    if not rows:
        raise ValueError(f"{path.name}: empty table")
    if any(None in row or any(value is None for value in row.values()) for row in rows):
        raise ValueError(f"{path.name}: malformed CSV row width")
    return rows


def json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def validate_m05(result: Any) -> list[str]:
    """Structural and semantic validation, independent of ledger success."""
    if not isinstance(result, dict) or set(result) != set(M05_FIELDS):
        return ["m05_schema"]
    errors = []
    if any(type(result[k]) is not str for k in M05_STRINGS):
        return ["m05_string_type"]
    if any(not result[k].strip() for k in M05_STRINGS if k != "ErrorMessage"):
        errors.append("m05_empty_required_field")
    if any(type(result[k]) is not int or result[k] < 0 for k in M05_COUNTS):
        return errors + ["m05_count_type_or_range"]
    files = result["SourceFiles"]
    if not isinstance(files, list) or any(not isinstance(x, str) or not x.strip() for x in files):
        return errors + ["m05_source_files_type"]
    if type(result["TransferPerformed"]) is not bool:
        return errors + ["m05_transfer_boolean_type"]
    if result["Scenario"] != "M05":
        errors.append("m05_scenario")
    try:
        if parse_utc(result["StartedUTC"]) > parse_utc(result["EndedUTC"]):
            errors.append("m05_time_order")
    except ValueError:
        errors.append("m05_timestamp")
    requested, transferred = result["FilesRequested"], result["FilesTransferred"]
    if requested != len(files) or transferred > requested or len(set(files)) != len(files):
        errors.append("m05_file_counts")
    if result["Status"] == "Completed":
        if not (requested > 0 and transferred == requested
                and result["TransferPerformed"] and result["SourceBytes"] > 0
                and not result["ErrorMessage"]):
            errors.append("m05_success_evidence")
    elif result["Status"] == "Failed":
        # Partial transfers remain failure evidence, never training successes.
        if result["TransferPerformed"] != (transferred > 0):
            errors.append("m05_failure_transfer_conflict")
    else:
        errors.append("m05_unknown_status")
    return errors


def build_dataset(input_dir: Path, start: date, end: date) -> tuple[list[dict], dict]:
    """Return master rows and a local, detailed report; never mutate inputs."""
    issues: list[dict] = []
    blocks: dict[str, set[str]] = defaultdict(set)
    reviews: dict[str, set[str]] = defaultdict(set)

    def issue(code: str, *, sid: str = "", severity: str = "error",
              source: str = "", row: int | None = None, blocking: bool = True) -> None:
        issues.append({"code": code, "severity": severity, "SessionID": sid,
                       "source": source, "row": row})
        if sid:
            reviews[sid].add(code)
            if blocking:
                blocks[sid].add(code)

    schedule = read_csv(input_dir / "dataset_schedule_v3.csv", SCHEDULE_FIELDS)
    ledger = read_csv(input_dir / "execution_ledger.csv", LEDGER_FIELDS)
    m05_dir = input_dir / "M05Results"
    if not m05_dir.is_dir():
        raise ValueError("Missing M05Results directory")
    schedule_groups: dict[str, list[tuple[int, dict]]] = defaultdict(list)
    history: dict[str, list[tuple[int, dict]]] = defaultdict(list)
    result_groups: dict[str, list[tuple[Path, dict, list[str]]]] = defaultdict(list)
    planned_times: dict[str, str] = {}
    for number, row in enumerate(schedule, 2):
        sid = row["SessionID"]
        if not sid.strip():
            issue("missing_schedule_session_id", source="schedule", row=number)
            raise ValueError("Schedule row has no SessionID; cannot produce session-level master")
        schedule_groups[sid].append((number, row))
        if any(not row[k].strip() for k in SCHEDULE_FIELDS):
            issue("empty_schedule_field", sid=sid, source="schedule", row=number)
        scenario = row["ScenarioID"]
        if scenario not in SCENARIO_LABELS:
            issue("unknown_scenario", sid=sid, source="schedule", row=number)
        elif row["IntendedLabel"] != SCENARIO_LABELS[scenario]:
            issue("inconsistent_intended_label", sid=sid, source="schedule", row=number)
        try:
            numbers = {key: int(row[key]) for key in ["SimulationDay", "FileCount", "FailedLogins",
                                                     "MinDelaySeconds", "MaxDelaySeconds"]}
            if any(not re.fullmatch(r"\d+", row[k]) for k in numbers):
                raise ValueError("Non-integer schedule field")
            if not 1 <= numbers["SimulationDay"] <= (end - start).days + 1:
                raise ValueError("Day outside configured window")
            if numbers["MinDelaySeconds"] > numbers["MaxDelaySeconds"]:
                raise ValueError("Reversed delay range")
            if not re.fullmatch(r"\d{2}:\d{2}:\d{2}", row["TimeOfDayUTC"]):
                raise ValueError("Invalid time")
            scheduled = datetime.combine(start + timedelta(days=numbers["SimulationDay"] - 1),
                                         time.fromisoformat(row["TimeOfDayUTC"]), timezone.utc)
            planned_times[sid] = scheduled.isoformat().replace("+00:00", "Z")
        except ValueError:
            issue("invalid_schedule_parameters", sid=sid, source="schedule", row=number)
    for sid, group in schedule_groups.items():
        if len(group) > 1:
            issue("duplicate_schedule_session_id", sid=sid, source="schedule")

    seen_ledger: set[tuple[str, ...]] = set()
    for number, row in enumerate(ledger, 2):
        sid = row["SessionID"]
        history[sid].append((number, row))
        if not sid.strip() or sid not in schedule_groups:
            issue("orphan_ledger_session", sid=sid, source="ledger", row=number)
        signature = tuple(row[k] for k in LEDGER_FIELDS)
        if signature in seen_ledger:
            issue("duplicate_ledger_row", sid=sid, source="ledger", row=number)
        seen_ledger.add(signature)
        if row["Status"] not in STATUSES:
            issue("unknown_ledger_status", sid=sid, source="ledger", row=number)
        try:
            parse_utc(row["ExecutionUTC"])
            scheduled = parse_utc(row["ScheduledUTC"])
            if sid in planned_times and scheduled != parse_utc(planned_times[sid]):
                issue("ledger_scheduled_time_mismatch", sid=sid, source="ledger", row=number)
        except ValueError:
            issue("invalid_ledger_timestamp", sid=sid, source="ledger", row=number)
        if sid in schedule_groups:
            plan = schedule_groups[sid][0][1]
            if row["ScenarioID"] != plan["ScenarioID"]:
                issue("ledger_scenario_mismatch", sid=sid, source="ledger", row=number)
            if not same_account(row["Username"], plan["Username"]) or not row["Username"].strip():
                issue("ledger_identity_mismatch", sid=sid, source="ledger", row=number)

    for path in sorted(m05_dir.glob("*.json")):
        source = f"M05Results/{path.name}"
        try:
            result = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=json_object)
        except (ValueError, UnicodeError):
            issue("malformed_m05_json", source=source)
            continue
        errors = validate_m05(result)
        sid = result.get("SessionID") if isinstance(result, dict) else None
        if not isinstance(sid, str) or not sid.strip():
            issue("missing_m05_session_id", source=source)
            continue
        result_groups[sid].append((path, result, errors))
        for code in errors:
            issue(code, sid=sid, source=source)
        if sid not in schedule_groups:
            issue("unmatched_m05_result", sid=sid, severity="warning", source=source, blocking=False)
        elif schedule_groups[sid][0][1]["ScenarioID"] != "M05":
            issue("m05_result_for_other_scenario", sid=sid, source=source)
    for sid, group in result_groups.items():
        if len(group) > 1:
            issue("duplicate_m05_session_id", sid=sid, source="M05Results")

    lower = datetime.combine(start, time.min, timezone.utc)
    upper = datetime.combine(end + timedelta(days=1), time.min, timezone.utc)
    output = []
    for sid, planned_rows in schedule_groups.items():
        number, plan = planned_rows[0]  # Ambiguous duplicates are blocked, never treated as resolved.
        entries = history.get(sid, [])
        final = entries[-1][1] if entries else {}
        status = final.get("Status", "Missing")
        if not entries:
            issue("missing_ledger_session", sid=sid, source="ledger")
        elif status not in {"Completed", "Failed"}:
            issue("incomplete_execution", sid=sid, source="ledger")
        times = []
        for _, entry in entries:
            try:
                times.append(parse_utc(entry["ExecutionUTC"]))
            except ValueError:
                pass  # Already reported; do not invent a replacement timestamp.
        if any(a > b for a, b in zip(times, times[1:])):
            issue("ledger_time_order", sid=sid, source="ledger")
        starts = [x for _, x in entries if x["Status"] == "Started"]
        actual, actual_source = "", ""
        if len(starts) == 1:
            try:
                parse_utc(starts[0]["ExecutionUTC"])
                actual, actual_source = starts[0]["ExecutionUTC"], "ledger_started_initiation"
            except ValueError:
                pass
        elif len(starts) > 1:
            issue("multiple_execution_starts", sid=sid, source="ledger")
        result: dict = {}
        m05_validation, result_file = "not_applicable", ""
        if plan["ScenarioID"] == "M05":
            group = result_groups.get(sid, [])
            # A ledger start may precede queued worker execution by days. For M05
            # use only a uniquely identified, valid worker interval as actual time.
            actual, actual_source = "", ""
            if not group:
                issue("missing_m05_result", sid=sid, source="M05Results")
                m05_validation = "missing"
            elif len(group) > 1:
                m05_validation = "ambiguous"
            else:
                path, result, errors = group[0]
                result_file = f"M05Results/{path.name}"
                m05_validation = "invalid" if errors else (
                    "worker_success" if result["Status"] == "Completed" else "worker_failed")
                if not errors:
                    actual, actual_source = result["StartedUTC"], "m05_worker_started"
                    if not same_account(result["ExecutedBy"], plan["Username"]):
                        issue("m05_identity_mismatch", sid=sid, source=result_file)
                    if result["Status"] != status:
                        issue("m05_ledger_status_mismatch", sid=sid, source=result_file)
                    if entries:
                        try:
                            if parse_utc(result["EndedUTC"]) > parse_utc(final["ExecutionUTC"]):
                                issue("m05_result_after_final_ledger", sid=sid, source=result_file)
                            if len(starts) == 1 and parse_utc(actual) < parse_utc(starts[0]["ExecutionUTC"]):
                                issue("m05_worker_before_ledger_start", sid=sid, source=result_file)
                        except ValueError:
                            pass
                if result.get("ValidationStatus") == "PendingWazuhVerification":
                    issue("m05_wazuh_verification_pending", sid=sid, severity="warning",
                          source=result_file, blocking=False)
        if not actual:
            issue("actual_execution_time_unknown", sid=sid, severity="warning",
                  source="execution_evidence", blocking=False)
        late: bool | None = None
        within = False
        if actual:
            timestamp = parse_utc(actual)
            late, within = timestamp >= upper, lower <= timestamp < upper
            if late:
                issue("late_recovery", sid=sid, severity="warning", source=actual_source, blocking=False)
            elif not within:
                issue("execution_before_collection", sid=sid, severity="warning",
                      source=actual_source, blocking=False)
        reasons = set(blocks[sid])
        if status != "Completed":
            reasons.add("execution_failed" if status == "Failed" else "execution_not_completed")
        if plan["ScenarioID"] == "M05" and m05_validation != "worker_success":
            reasons.add("m05_worker_success_not_validated")
        eligible = not reasons
        cohort_reasons = set(reasons)
        if not actual:
            cohort_reasons.add("actual_execution_time_unknown")
        elif not within:
            cohort_reasons.add("actual_execution_outside_original_window")
        original = not cohort_reasons
        record = {k: "" for k in OUTPUT_FIELDS}
        record.update({k: plan[k] for k in ["SessionID", "SimulationDay", "ScenarioID",
                                          "IntendedLabel", "Username", "Role"]})
        record.update({
            "ScheduledUTC": planned_times.get(sid, ""),
            "ScheduleTimeOfDayUTC": plan["TimeOfDayUTC"],
            "LedgerScheduledUTC": final.get("ScheduledUTC", ""),
            "ScheduleExecutionStatus": plan["ExecutionStatus"], "ScheduleRow": number,
            "ActualExecutionUTC": actual, "ActualExecutionTimestampSource": actual_source,
            "ActualExecutionTimestampStatus": "evidenced" if actual else "unknown",
            "FinalExecutionStatus": status,
            "FirstLedgerExecutionUTC": entries[0][1]["ExecutionUTC"] if entries else "",
            "FinalLedgerExecutionUTC": final.get("ExecutionUTC", ""),
            "FirstLedgerRow": entries[0][0] if entries else "",
            "FinalLedgerRow": entries[-1][0] if entries else "",
            "LedgerRowCount": len(entries),
            "LedgerTransitions": "|".join(entry["Status"] for _, entry in entries),
            "FinalLedgerDetail": final.get("Detail", ""),
            "M05ResultFile": result_file, "M05TransferValidation": m05_validation,
            "LateRecovery": "unknown" if late is None else str(late).lower(),
            "LateRecoveryStatus": "unknown" if late is None else ("late" if late else "not_late"),
            "Original14DayCohortEligible": str(original).lower(),
            "ExtendedCohortEligible": str(eligible).lower(),
            "MLTrainingEligible": str(eligible).lower(),
            "GroundTruthLabel": plan["IntendedLabel"] if eligible else "",
            "LabelBasis": ("intended_label_with_completed_execution_and_worker_success"
                           if eligible and plan["ScenarioID"] == "M05" else
                           "intended_label_with_completed_execution" if eligible else "unassigned"),
            "TelemetryVerificationStatus": "not_assessed",
            "ReviewRequired": str(bool(reviews[sid]) or status == "Failed").lower(),
            "ReviewReasons": "|".join(sorted(reviews[sid] | ({"execution_failed"} if status == "Failed" else set()))),
            "MLExclusionReasons": "|".join(sorted(reasons)),
            "OriginalCohortExclusionReasons": "|".join(sorted(cohort_reasons)),
        })
        for key in ["Status", "StartedUTC", "EndedUTC", "FilesRequested", "FilesTransferred",
                    "SourceBytes", "TransferPerformed", "ValidationStatus"]:
            value = result.get(key, "")
            record[f"M05{key}"] = str(value).lower() if type(value) is bool else value
        output.append(record)

    def counts(rows: list[dict]) -> dict:
        return {"total": len(rows),
                "intended_labels": dict(sorted(Counter(x["IntendedLabel"] for x in rows).items())),
                "execution_statuses": dict(sorted(Counter(x["FinalExecutionStatus"] for x in rows).items())),
                "assigned_labels": dict(sorted(Counter(x["GroundTruthLabel"] or "unassigned" for x in rows).items()))}

    matched_m05 = [sid for sid in result_groups if sid in schedule_groups
                   and schedule_groups[sid][0][1]["ScenarioID"] == "M05"]
    report = {
        "policy_version": POLICY_VERSION,
        "validation_status": "errors" if any(x["severity"] == "error" for x in issues) else "passed_with_warnings" if issues else "passed",
        "scope": "schedule, ledger and M05 worker results only; no Wazuh telemetry validation or feature engineering",
        "label_policy": "Provisional execution-based labels, not independently verified attack outcomes. IntendedLabel is always preserved; GroundTruthLabel is blank for ineligible sessions. All telemetry verification remains not_assessed.",
        "cohort_policy": {
            "start_utc_inclusive": lower.isoformat(), "end_utc_exclusive": upper.isoformat(),
            "ml_training": "Completed, no blocking source inconsistencies, and (for M05) a validated positive worker transfer. Late recovery is allowed. Eligibility is provisional pending later telemetry/feature review.",
            "extended": "Same filter as MLTrainingEligible; no original-window restriction.",
            "original_14_day": "Extended eligibility plus evidenced execution start within the configured UTC window. Unknown execution times require review and are excluded only from this strict cohort.",
            "timestamp_policy": "M05 uses unique valid worker StartedUTC. Other scenarios use unique ledger Started ExecutionUTC (execution initiation, not proof of action time). Never substitute scheduled time. Final ledger time is reporting/reconciliation time.",
            "late_recovery": "Evidenced execution start on or after the exclusive window end. Unknown time remains unknown. No permanent removal from the master or extended cohort.",
            "failed_sessions": "Retained in master; blank GroundTruthLabel and false ML/extended/original eligibility. Failure is not a benign label.",
            "duplicate_schedule": "One master row per unique ID using the first source row for display only; all repeated IDs are blocked and reported. No ambiguous duplicate is eligible.",
        },
        "summary": counts(output),
        "source_counts": {"schedule_rows": len(schedule), "schedule_unique_ids": len(schedule_groups),
                          "schedule_execution_statuses": dict(sorted(Counter(x["ExecutionStatus"] for x in schedule).items())),
                          "ledger_rows": len(ledger), "ledger_unique_ids": len(history),
                          "ledger_repeated_ids": sum(len(v) > 1 for v in history.values()),
                          "ledger_raw_statuses": dict(sorted(Counter(x["Status"] for x in ledger).items())),
                          "m05_files": len(list(m05_dir.glob("*.json"))),
                          "m05_matched_unique_ids": len(matched_m05),
                          "m05_unmatched_unique_ids": len(set(result_groups) - set(schedule_groups))},
        "integrity_checks": {
            "duplicate_schedule_ids": sum(len(v) > 1 for v in schedule_groups.values()),
            "duplicate_m05_ids": sum(len(v) > 1 for v in result_groups.values()),
            "duplicate_ledger_rows": sum(x["code"] == "duplicate_ledger_row" for x in issues),
            "missing_ledger_sessions": sum(sid not in history for sid in schedule_groups),
            "missing_m05_results": sum(plan[0][1]["ScenarioID"] == "M05" and sid not in result_groups
                                       for sid, plan in schedule_groups.items()),
            "orphan_ledger_ids": len(set(history) - set(schedule_groups)),
            "inconsistent_intended_labels": sum(x["code"] == "inconsistent_intended_label" for x in issues),
            "ledger_scenario_mismatches": sum(x["code"] == "ledger_scenario_mismatch" for x in issues),
            "ledger_identity_mismatches": sum(x["code"] == "ledger_identity_mismatch" for x in issues),
            "ledger_scheduled_time_mismatches": sum(x["code"] == "ledger_scheduled_time_mismatch" for x in issues),
            "m05_ledger_status_mismatches": sum(x["code"] == "m05_ledger_status_mismatch" for x in issues),
            "incomplete_executions": sum(x["FinalExecutionStatus"] not in {"Completed", "Failed"} for x in output),
            "failed_executions": sum(x["FinalExecutionStatus"] == "Failed" for x in output),
            "unknown_actual_execution_times": sum(not x["ActualExecutionUTC"] for x in output),
            "late_recoveries": sum(x["LateRecovery"] == "true" for x in output),
        },
        "cohorts": {
            "original_14_day": counts([x for x in output if x["Original14DayCohortEligible"] == "true"]),
            "extended": counts([x for x in output if x["ExtendedCohortEligible"] == "true"]),
            "ml_training": counts([x for x in output if x["MLTrainingEligible"] == "true"]),
        },
        "scenarios": {scenario: counts([x for x in output if x["ScenarioID"] == scenario])
                      for scenario in sorted({x["ScenarioID"] for x in output})},
        "m05": {"transfer_validation": dict(sorted(Counter(x["M05TransferValidation"] for x in output if x["ScenarioID"] == "M05").items())),
                "all_result_statuses": dict(sorted(Counter(str(result.get("Status", "missing")) for group in result_groups.values() for _, result, _ in group).items())),
                "result_audit": [{"SessionID": sid, "file": f"M05Results/{path.name}",
                                  "matched_scheduled_m05": sid in matched_m05,
                                  "worker_status": result.get("Status"),
                                  "transfer_performed": result.get("TransferPerformed"),
                                  "validation_errors": errors}
                                 for sid, group in sorted(result_groups.items()) for path, result, errors in group],
                "worker_validation_status": dict(sorted(Counter(str(result.get("ValidationStatus", "missing")) for group in result_groups.values() for _, result, _ in group).items()))},
        "issue_counts": dict(sorted(Counter(x["code"] for x in issues).items())),
        "issues": issues,
        "limitations": [
            "Completed handler status is not independent proof of scenario success.",
            "M05 transfer validation uses worker self-report; Wazuh verification is separate and pending.",
            "Repeated ledger SessionIDs are expected lifecycle history, not duplicate scheduled sessions.",
            "Schedule ExecutionStatus is preserved but not authoritative; all final statuses follow ledger append order.",
            "No full Wazuh integrity, coverage, event attribution or rule-performance assessment is performed.",
            "Timestamp strings preserve seven fractional digits; Python comparisons truncate beyond microseconds.",
            "Day 12 was previously used for M01 tuning and cannot serve as untouched evaluation data.",
        ],
    }
    return output, report


def inventory(input_dir: Path) -> dict:
    paths = [input_dir / name for name in ["dataset_schedule_v3.csv", "execution_ledger.csv"]]
    paths.extend(sorted((input_dir / "M05Results").glob("*.json")))
    return {str(path.relative_to(input_dir)): {"bytes": path.stat().st_size, "sha256": sha256(path)}
            for path in paths}


def git_metadata() -> dict:
    repository = Path(__file__).resolve().parents[1]
    try:
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository, capture_output=True, text=True, check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=repository, capture_output=True, text=True, check=True).stdout
        return {"revision": revision, "dirty": bool(dirty)}
    except (OSError, subprocess.CalledProcessError):
        return {"revision": None, "dirty": None}


def csv_text(rows: list[dict]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=OUTPUT_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=Path("data/ground_truth"))
    parser.add_argument("--output-dir", type=Path, default=Path("data/processed"),
                        help="Must be a new directory; existing outputs are never overwritten")
    parser.add_argument("--start-date", type=date.fromisoformat, required=True, help="UTC date of SimulationDay 1")
    parser.add_argument("--end-date", type=date.fromisoformat, required=True, help="Inclusive final UTC date")
    args = parser.parse_args(argv)
    input_dir, output_dir = args.input_dir.resolve(), args.output_dir.resolve()
    if args.end_date < args.start_date:
        parser.error("end-date must not precede start-date")
    if output_dir == input_dir or input_dir in output_dir.parents or output_dir in input_dir.parents:
        parser.error("Input and output directories must not overlap")
    repository = Path(__file__).resolve().parents[1]
    for name in ["raw", "ground_truth", "wazuh"]:
        protected = repository / "data" / name
        if output_dir == protected or protected in output_dir.parents:
            parser.error("Output directory must not be inside an original-data directory")
    if output_dir.exists():
        parser.error("Output directory already exists; choose a new directory")
    try:
        before = inventory(input_dir)
        rows, report = build_dataset(input_dir, args.start_date, args.end_date)
        if before != inventory(input_dir):
            raise ValueError("Source inventory changed during validation; output refused")
    except (ValueError, OSError, csv.Error) as exc:
        # Schema/acquisition failure cannot produce a meaningful session master.
        output_dir.mkdir(parents=True, exist_ok=False)
        (output_dir / "validation_report.json").write_text(json.dumps({
            "validation_status": "fatal", "error": str(exc), "master_exported": False,
            "policy_version": POLICY_VERSION,
        }, indent=2) + "\n", encoding="utf-8")
        print("Validation failed; see validation_report.json (no session master exported).", file=sys.stderr)
        return 1
    report["reproducibility"] = {
        "python": platform.python_version(), "git": git_metadata(),
        "input_hashes": before, "input_directory": str(input_dir),
        "implementation_sha256": sha256(Path(__file__)),
        "configuration": {"start_date": args.start_date.isoformat(), "end_date": args.end_date.isoformat()},
    }
    output_dir.mkdir(parents=True, exist_ok=False)
    marker = output_dir / "RUN_INCOMPLETE"
    marker.write_text("Outputs are incomplete until validation_report.json is finalized.\n", encoding="utf-8")
    exports = {
        "session_ground_truth.csv": rows,
        "cohort_original_14day.csv": [x for x in rows if x["Original14DayCohortEligible"] == "true"],
        "cohort_extended.csv": [x for x in rows if x["ExtendedCohortEligible"] == "true"],
    }
    for name, selected in exports.items():
        path = output_dir / name
        temporary = path.with_suffix(".tmp")
        temporary.write_text(csv_text(selected), encoding="utf-8", newline="")
        temporary.replace(path)
    report["output_sha256"] = {name: sha256(output_dir / name) for name in exports}
    temporary = output_dir / "validation_report.tmp"
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output_dir / "validation_report.json")
    marker.unlink()
    print(json.dumps({"validation_status": report["validation_status"], "summary": report["summary"],
                      "cohorts": report["cohorts"], "issue_counts": report["issue_counts"]}, indent=2))
    return 1 if report["validation_status"] == "errors" else 0


if __name__ == "__main__":
    sys.exit(main())
