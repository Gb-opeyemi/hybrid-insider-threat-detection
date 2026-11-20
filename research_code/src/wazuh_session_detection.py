"""Notebook 08's frozen M01-M05 session-level Wazuh baseline, extracted once.

Origin: notebooks/08_wazuh_rule_based_detection.ipynb (cells 8-10, 13-14,
16-17, 21, 23-24, 25-27, 29-30). The unused *delayed fixed-bin*
M03 analysis (cells 18-20) is intentionally NOT the final baseline.

Pure inference: no labels, model fitting, Wazuh configuration changes,
network access or output-file writes. Model prediction cutoffs come from the
existing session_prediction_cutoffs.csv. Detection is a retrospective
approximation of the Wazuh rules, as in Notebook 08, not a live alert query.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from pathlib import Path
import gzip
import json
import re

from .lab_config import load_lab_config, validate_lab_config

import pandas as pd

M05_EXTRA_DELAY_SECONDS = (0, 3, 5, 10)
RULE_COLUMNS = (
    "M01_Detected", "M02_Detected", "M03_Detected",
    "M04_Detected", "M05_Detected_0s",
)
COMBINED_COLUMN = "Wazuh_Detected_M05delay_0s"


def _require_columns(df: pd.DataFrame, columns: set[str], name: str) -> None:
    missing = sorted(columns - set(df.columns))
    if missing:
        raise ValueError(f"{name}: missing columns: {missing}")


def _times(series: pd.Series, name: str) -> pd.Series:
    """Parse the mixed ISO-8601 UTC timestamps used by Notebook 08."""
    result = pd.to_datetime(series, format="mixed", utc=True, errors="raise")
    if result.isna().any():
        raise ValueError(f"{name}: missing timestamps")
    return result


def _repeated_indices(frame: pd.DataFrame, key_column: str, threshold: int = 3):
    """Original Notebook 08 60-second availability-time correlation."""
    recent_by_user = defaultdict(deque)
    chosen = []
    for idx, event in frame.sort_values("AvailableTimeUTC").iterrows():
        user = event[key_column]
        time = event["AvailableTimeUTC"]
        if pd.isna(user) or pd.isna(time):
            continue
        recent = recent_by_user[user]
        while recent and time - recent[0] > pd.Timedelta(seconds=60):
            recent.popleft()
        recent.append(time)
        if len(recent) >= threshold:
            chosen.append(idx)
    return chosen


def _event_key(computer, channel, record_id):
    """Notebook 08 M02's archived-event join key (host/channel/record)."""
    return (
        str(computer).split(".")[0].strip().upper(),
        str(channel).strip().lower(),
        str(record_id).strip().removesuffix(".0"),
    )


def _recover_m02_substatus(m02_events: pd.DataFrame, archive_root: Path):
    """Notebook 08's 4625 subStatus recovery from archived Windows events.

    Fail closed when archived evidence is missing instead of silently treating
    all unknown 4625 events as incorrect-password negatives.
    """
    if m02_events.empty:
        return pd.Series(dtype="object", index=m02_events.index)
    archive_files = sorted(Path(archive_root).rglob("ossec-archive-*.json.gz"))
    if not archive_files:
        raise FileNotFoundError(
            f"No ossec-archive-*.json.gz files in {archive_root}; "
            "cannot recover 4625 subStatus"
        )
    keys = [
        _event_key(computer, channel, record_id)
        for computer, channel, record_id in zip(
            m02_events["Computer"], m02_events["EventChannel"],
            m02_events["EventRecordID"]
        )
    ]
    target_keys = set(keys)
    lookup = {}
    for filepath in archive_files:
        with gzip.open(filepath, "rt", encoding="utf-8") as handle:
            for line in handle:
                if "4625" not in line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                win = record.get("data", {}).get("win", {})
                system = win.get("system", {})
                if str(system.get("eventID")) != "4625":
                    continue
                key = _event_key(
                    system.get("computer"), system.get("channel"),
                    system.get("eventRecordID")
                )
                if key in target_keys:
                    lookup[key] = win.get("eventdata", {}).get("subStatus")
        if len(lookup) == len(target_keys):
            break
    missing = target_keys - {key for key, value in lookup.items() if pd.notna(value)}
    if missing:
        raise ValueError(
            f"M02: cannot recover subStatus for {len(missing)} archived "
            "event keys. Do not score incomplete 4625 coverage as benign."
        )
    return pd.Series([lookup[k] for k in keys], index=m02_events.index)


def _rolling_distinct_first_crossings(
    activity: pd.DataFrame, *, threshold: int, label: str
) -> pd.DataFrame:
    """Notebook 08's M03/M04 rolling 5-minute distinct-path detectors.

    This is the SAME window loop for both cases, with the original triggering
    inequalities expressed as first crossing of 31 (M03) or 5 (M04).
    """
    stream = activity[["SessionID", "UserKey", "FilePath", "AvailableTimeUTC"]].copy()
    stream["AvailableTimeUTC"] = _times(stream["AvailableTimeUTC"], label)
    stream["FileKey"] = (
        stream["FilePath"].astype("string").str.strip().str.lower()
    )
    stream = (
        stream.dropna(
            subset=["SessionID", "UserKey", "FileKey", "AvailableTimeUTC"]
        ).sort_values("AvailableTimeUTC")
    )
    user_events = defaultdict(deque)
    user_file_counts = defaultdict(Counter)
    detections = []
    window_duration = pd.Timedelta(minutes=5)
    for event in stream.itertuples(index=False):
        user = event.UserKey
        path = event.FileKey
        timestamp = event.AvailableTimeUTC
        recent = user_events[user]
        file_counts = user_file_counts[user]
        while recent and timestamp - recent[0][0] > window_duration:
            old_time, old_path = recent.popleft()
            file_counts[old_path] -= 1
            if file_counts[old_path] == 0:
                del file_counts[old_path]
        previous = len(file_counts)
        recent.append((timestamp, path))
        file_counts[path] += 1
        current = len(file_counts)
        if previous < threshold <= current:
            detections.append({
                "SessionID": event.SessionID,
                "UserKey": user,
                "DetectionReadyUTC": timestamp,
                "DistinctFiles": current,
            })
    return pd.DataFrame(
        detections,
        columns=["SessionID", "UserKey", "DetectionReadyUTC", "DistinctFiles"],
    )


def detect_wazuh_sessions(
    sessions: pd.DataFrame,
    attributed_events: pd.DataFrame,
    cutoffs: pd.DataFrame,
    *,
    archive_root: str | Path,
    require_event_coverage: bool = True,
    lab_config: dict | None = None,
) -> pd.DataFrame:
    """Return Notebook 08's frozen session-level M01-M05 predictions.

    `sessions`: SessionID and optional Partition. Labels are NOT accepted or
    consulted by the detection logic. All detection choices were fixed in 08.
    `attributed_events`: unchanged wazuh_attributed_events_filtered.csv.
    `cutoffs`: unchanged session_prediction_cutoffs.csv.
    `archive_root`: original `data/wazuh/logs/archives` folder for M02.
    `lab_config`: configured host/file-root/destination; defaults to local/example config.
    Restore the acquisition lab settings before claiming historical parity.

    Call once with train+validation to prove parity against saved 08 outputs,
    and then with test sessions. Never modify rules based on test labels.
    """
    lab = validate_lab_config(lab_config) if lab_config is not None else load_lab_config()
    _require_columns(sessions, {"SessionID"}, "sessions")
    _require_columns(cutoffs, {"SessionID", "PredictionCutoffUTC"}, "cutoffs")
    event_columns = {
        "SessionID", "EventID", "SeverityValue", "ResolvedUsername",
        "AvailableTimeUTC", "Computer", "EventChannel", "EventRecordID",
        "TargetUsername", "ObjectName", "AccessMask", "Provider", "Image",
        "CommandLine", "EventTimeUTC",
    }
    _require_columns(attributed_events, event_columns, "attributed_events")

    if sessions["SessionID"].isna().any():
        raise ValueError("sessions contain missing SessionIDs")
    session_ids = sessions["SessionID"].astype(str)
    if session_ids.duplicated().any():
        raise ValueError("sessions must have unique, non-null SessionIDs")
    out = sessions[[c for c in ("SessionID", "Partition") if c in sessions]].copy()
    out["SessionID"] = out["SessionID"].astype(str)
    ids = set(out["SessionID"])
    # Filter BEFORE processing to reproduce Notebook 08's independent dev split.
    events = attributed_events.loc[
        attributed_events["SessionID"].astype(str).isin(ids)
    ].copy()
    events["SessionID"] = events["SessionID"].astype(str)
    if require_event_coverage:
        missing_event_ids = ids - set(events["SessionID"])
        if missing_event_ids:
            raise ValueError(
                f"No attributed events for {len(missing_event_ids)} sessions. "
                "Check full-partition event coverage; missing is not benign."
            )
    cutoff_small = cutoffs[["SessionID", "PredictionCutoffUTC"]].copy()
    cutoff_small["SessionID"] = cutoff_small["SessionID"].astype(str)
    if cutoff_small["SessionID"].duplicated().any():
        raise ValueError("Duplicate session IDs in cutoff table")
    cutoff_small = cutoff_small.loc[cutoff_small["SessionID"].isin(ids)].copy()
    if set(cutoff_small["SessionID"]) != ids:
        raise ValueError("Cutoff table does not cover all requested sessions")
    cutoff_small["PredictionCutoffUTC"] = _times(
        cutoff_small["PredictionCutoffUTC"], "PredictionCutoffUTC"
    )
    event_ids = pd.to_numeric(events["EventID"], errors="coerce")

    # M01: Notebook 08 cells 8-10 (5145 AUDIT_FAILURE, per-user >=3 in 60s).
    m01 = events.loc[event_ids.eq(5145) &
        events["SeverityValue"].astype("string").str.strip().str.upper().eq("AUDIT_FAILURE")
    ].copy()
    m01 = m01.merge(cutoff_small, on="SessionID", how="left", validate="many_to_one")
    m01["AvailableTimeUTC"] = _times(m01["AvailableTimeUTC"], "M01 availability")
    m01 = m01.loc[m01["AvailableTimeUTC"] <= m01["PredictionCutoffUTC"]].copy()
    m01["UserKey"] = (
        m01["ResolvedUsername"].astype("string").str.strip().str.lower()
    )
    repeated_m01 = m01.loc[_repeated_indices(m01, "UserKey")]
    out["Rule_100100"] = out["SessionID"].isin(m01["SessionID"]).astype(int)
    out["Rule_100101"] = out["SessionID"].isin(repeated_m01["SessionID"]).astype(int)
    out["M01_Detected"] = out[["Rule_100100", "Rule_100101"]].max(axis=1)

    # M02: Notebook 08 cells 13-14, 16; archive subStatus is authoritative.
    m02 = events.loc[event_ids.eq(4625)].copy()
    m02["SubStatus"] = _recover_m02_substatus(m02, Path(archive_root))
    m02 = m02.loc[m02["SubStatus"].astype("string").str.lower().eq("0xc000006a")].copy()
    m02 = m02.merge(cutoff_small, on="SessionID", how="left", validate="many_to_one")
    m02["AvailableTimeUTC"] = _times(m02["AvailableTimeUTC"], "M02 availability")
    m02 = m02.loc[m02["AvailableTimeUTC"] <= m02["PredictionCutoffUTC"]].copy()
    m02["UserKey"] = (
        m02["TargetUsername"].astype("string").str.strip().str.lower()
    )
    repeated_m02 = m02.loc[_repeated_indices(m02, "UserKey")]
    out["Rule_100200"] = out["SessionID"].isin(m02["SessionID"]).astype(int)
    out["Rule_100201"] = out["SessionID"].isin(repeated_m02["SessionID"]).astype(int)
    out["M02_Detected"] = out[["Rule_100200", "Rule_100201"]].max(axis=1)

    # M03/M04: Notebook 08 cells 17, 21, 23-24. 4663 on the configured host,
    # under the configured monitored file root. Do NOT use the slower fixed-bin M03.
    file_events = events.loc[event_ids.eq(4663)].copy()
    file_events = file_events.loc[
        file_events["Computer"].astype("string").str.upper().str.startswith(lab["monitored_computer_prefix"].upper())
    ].copy()
    file_events["FilePath"] = (
        file_events["ObjectName"].astype("string")
        .str.replace("/", "\\", regex=False)
        .str.replace(r"\\+", r"\\", regex=True)
    )
    file_events = file_events.loc[
        file_events["FilePath"].str.contains(re.escape(lab["monitored_file_root"].rstrip("\\/")+"\\"), case=False, regex=True, na=False)
    ].copy()
    file_events["UserKey"] = (
        file_events["ResolvedUsername"].astype("string").str.strip().str.lower()
    )
    m03_alerts = _rolling_distinct_first_crossings(file_events, threshold=31, label="M03")
    m03_alerts = m03_alerts.merge(cutoff_small, on="SessionID", how="left", validate="many_to_one")
    m03_timely_ids = set(m03_alerts.loc[
        m03_alerts["DetectionReadyUTC"] <= m03_alerts["PredictionCutoffUTC"], "SessionID"
    ])
    out["Rule_100301_Realtime"] = out["SessionID"].isin(m03_timely_ids).astype(int)
    out["M03_Detected"] = out["Rule_100301_Realtime"]

    m04 = file_events.loc[
        file_events["AccessMask"].astype("string").str.strip().str.lower().eq("0x10000")
    ].copy()
    m04_alerts = _rolling_distinct_first_crossings(m04, threshold=5, label="M04")
    m04_alerts = m04_alerts.merge(cutoff_small, on="SessionID", how="left", validate="many_to_one")
    m04_timely_ids = set(m04_alerts.loc[
        m04_alerts["DetectionReadyUTC"] <= m04_alerts["PredictionCutoffUTC"], "SessionID"
    ])
    out["Rule_100401"] = out["SessionID"].isin(m04_timely_ids).astype(int)
    out["M04_Detected"] = out["Rule_100401"]

    # M05: Notebook 08 cells 25-27, 29. Sysmon process 1 and unchanged SFTP target.
    m05 = events.loc[
        event_ids.eq(1) & events["Provider"].astype("string").str.contains("Sysmon", case=False, na=False)
    ].copy()
    m05 = m05.loc[
        m05["Image"].fillna("").astype(str).str.contains(r"\\sftp\.exe$", case=False, regex=True)
        & m05["CommandLine"].fillna("").astype(str).str.contains(
            lab["m05_destination"], case=False, regex=False
        )
    ].copy()
    m05 = m05.merge(cutoff_small, on="SessionID", how="left", validate="many_to_one")
    m05["EventTimeUTC"] = _times(m05["EventTimeUTC"], "M05 event time")
    m05["AvailableTimeUTC"] = _times(m05["AvailableTimeUTC"], "M05 availability")
    m05["DetectionReadyUTC"] = m05[["EventTimeUTC", "AvailableTimeUTC"]].max(axis=1)
    for delay in M05_EXTRA_DELAY_SECONDS:
        detection_time = m05["DetectionReadyUTC"] + pd.Timedelta(seconds=delay)
        timely_ids = set(m05.loc[detection_time <= m05["PredictionCutoffUTC"], "SessionID"])
        out[f"M05_Detected_{delay}s"] = out["SessionID"].isin(timely_ids).astype(int)
    out["Rule_100501"] = out["M05_Detected_0s"]

    # Notebook 08 cell 30: five-rule OR, zero-delay M05 primary baseline.
    for delay in M05_EXTRA_DELAY_SECONDS:
        out[f"Wazuh_Detected_M05delay_{delay}s"] = out[
            ["M01_Detected", "M02_Detected", "M03_Detected", "M04_Detected", f"M05_Detected_{delay}s"]
        ].max(axis=1)
    if out[COMBINED_COLUMN].isna().any() or out["SessionID"].duplicated().any():
        raise AssertionError("Incomplete or duplicated Wazuh results")
    return out


def assert_dev_parity(reconstructed: pd.DataFrame, saved: pd.DataFrame) -> None:
    """Require bit-for-bit session-level parity with Notebook 08's frozen CSV."""
    _require_columns(reconstructed, {"SessionID", COMBINED_COLUMN}, "reconstructed")
    _require_columns(saved, {"SessionID", COMBINED_COLUMN}, "saved")
    columns = [
        "M01_Detected", "M02_Detected", "M03_Detected", "M04_Detected",
        *[f"M05_Detected_{d}s" for d in M05_EXTRA_DELAY_SECONDS],
        *[f"Wazuh_Detected_M05delay_{d}s" for d in M05_EXTRA_DELAY_SECONDS],
    ]
    _require_columns(reconstructed, set(columns), "reconstructed")
    _require_columns(saved, set(columns), "saved")
    a = reconstructed.copy()
    b = saved.copy()
    for df in (a, b):
        df["SessionID"] = df["SessionID"].astype(str)
        if df["SessionID"].duplicated().any():
            raise ValueError("Duplicate SessionID in parity comparison")
    if set(a["SessionID"]) != set(b["SessionID"]):
        raise AssertionError("Notebook 08 session coverage differs from extracted detector")
    a = a.set_index("SessionID").sort_index()
    b = b.set_index("SessionID").sort_index()
    differences = {}
    for col in columns:
        actual = pd.to_numeric(a[col], errors="raise").astype(int)
        expected = pd.to_numeric(b[col], errors="raise").astype(int)
        mismatch = actual.ne(expected)
        if mismatch.any():
            differences[col] = int(mismatch.sum())
    if differences:
        raise AssertionError(f"Notebook 08 parity failure: {differences}")
