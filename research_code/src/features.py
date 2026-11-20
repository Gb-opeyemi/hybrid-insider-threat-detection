"""Evidence-based Windows session features; standard library only, no training."""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import ntpath
import platform
import re
import sys
import tempfile
from bisect import bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .ground_truth import (
    OUTPUT_FIELDS, LEDGER_FIELDS, build_dataset, csv_text, git_metadata,
    json_object, parse_utc, read_csv, sha256,
)

VERSION = "windows-session-features-v2-causal"
SECURITY = "Microsoft-Windows-Security-Auditing"
SYSMON = "Microsoft-Windows-Sysmon"
SFTP_IMAGES = {"sftp.exe", "psftp.exe", "winscp.exe", "winscp.com"}
ARTIFACT_COMPONENTS = {"m05queue", "m05results", "schedulerstate", "dataset2026"}

# Each predictor has a collection family and a literal, reviewable definition.
DICTIONARY = {
    "windows_event_count": ("windows", "Deduplicated, uniquely attributed Security/Sysmon events after orchestration exclusions."),
    "unique_action_signatures": ("windows", "Distinct host/provider/event/actor/resource/operation/process/logon/endpoint signatures, excluding record ID and timestamp. A repeated signature is NOT proof of one physical action."),
    "failed_logon_count": ("auth", "Security 4625 with target identity matched to this session; never use the subject/caller as the failed account."),
    "successful_logon_count": ("auth", "Security 4624 with target identity matched to this session."),
    "credential_validation_failure_count": ("credential", "Security 4776 with a nonzero hexadecimal status and target identity."),
    "smb_access_check_count": ("smb", "Security 5145 access checks, success or failure."),
    "smb_denied_count": ("smb", "5145 with Audit Failure keyword bit (or AUDIT_FAILURE when bit absent); ID/description alone never proves denial. Share-level denials only."),
    "distinct_file_paths": ("file", "Distinct (host, normalized path) on 5145, 4663, or Sysmon 11/23/26. ShareLocalPath + RelativeTargetName is preferred over UNC share identity; registry objects excluded."),
    "distinct_smb_paths": ("smb", "Distinct (host, normalized path) among 5145 events."),
    "file_access_count": ("file_access", "Security 4663 with ObjectType=File; count access-right-use events, not files or confirmed deletions."),
    "file_read_access_count": ("file_access", "File-object 4663 with AccessMask bit 0x1 set."),
    "file_write_access_count": ("file_access", "File-object 4663 with AccessMask bit 0x2 or 0x4 set."),
    "delete_access_count": ("file_access", "File-object 4663 with DELETE bit 0x10000 set; does not alone prove a completed deletion."),
    "object_deletion_event_count": ("deletion", "Security 4660 deletion events. No filename is invented; object may be file or another audited object."),
    "sysmon_file_delete_count": ("sysmon_delete", "Sysmon 23 or 26 file deletion records."),
    "file_create_event_count": ("file_create", "Sysmon 11 file creation records."),
    "protected_resource_event_count": ("file", "File/path events with a normalized path component starting with a configured protected prefix (default restricted). No path text is exported as a predictor."),
    "process_create_count": ("process", "Sysmon 1 process creation records."),
    "distinct_process_guids": ("process", "Distinct (host, ProcessGuid) among attributed Sysmon 1 records."),
    "sftp_process_count": ("process", "Sysmon 1 whose Image basename is sftp.exe, psftp.exe, winscp.exe, or winscp.com."),
    "ssh_process_count": ("process", "Sysmon 1 whose Image basename is ssh.exe; SSH alone is not proof of SFTP."),
    "scp_process_count": ("process", "Sysmon 1 whose Image basename is scp.exe or pscp.exe; SCP is separate from SFTP."),
    "network_connection_count": ("network", "Sysmon 3 network connection records, not bytes transferred."),
    "ssh_port22_connection_count": ("network", "Sysmon 3 with DestinationPort=22 and Initiated=true; protocol/port is not proof of SFTP."),
    "sftp_network_connection_count": ("network", "Sysmon 3 for an SFTP image or an ssh.exe child of an SFTP process, linked on host+ProcessGuid with verified process lifetime."),
    "distinct_network_destinations": ("network", "Distinct destination IPs in attributed Sysmon 3; no actual IPs are predictor columns."),
}
FEATURES = list(DICTIONARY)
MODEL_INPUTS = [name for name in FEATURES if name not in {
    "protected_resource_event_count", "sysmon_file_delete_count"}]
FAMILIES = sorted({value[0] for value in DICTIONARY.values()})
META_FIELDS = (
    "SessionID WindowStartUTC WindowEndUTC ObservationStartUTC ObservationEndUTC PredictionCutoffUTC "
    "WindowSource WindowStatus RawMatchedArchiveRecords UniqueMatchedArchiveEvents "
    "DuplicateMatchedArchiveRecords AmbiguousArchiveCandidates PaddingOnlyArchiveEvents "
    "IdentityLinkedArchiveEvents UnknownTimestampArchiveCandidates OrchestrationArchiveEvents ClockDisagreementArchiveEvents "
    "WazuhAlertRecordCount WazuhDistinctAlertedEventCount AmbiguousAlertCandidates "
    "TelemetryStatus MissingFeatureCount LateArrivingArchiveCandidates ClockPolicyStatus PriorOverlapExclusion FeatureMLTrainingEligible "
    "FeatureOriginal14DayCohortEligible FeatureExtendedCohortEligible FeatureReviewReasons"
).split() + [f"Observed_{family}" for family in FAMILIES]


def timestamp(value: Any) -> datetime:
    """Parse Windows 100-ns strings or offset-aware Wazuh timestamps, without guessing."""
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})", value
    ):
        raise ValueError("Incomplete or timezone-less timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def iso(value: datetime | None) -> str:
    return value.isoformat().replace("+00:00", "Z") if value else ""


def integer(value: Any) -> int | None:
    try:
        return int(value, 0) if isinstance(value, str) else value if type(value) is int else None
    except ValueError:
        return None


def normalized_path(value: str) -> str:
    value = value.replace("/", "\\").casefold()
    unc = value.startswith("\\\\")
    # Wazuh's Windows payload can retain doubled literal separators after JSON
    # decoding. Normalize separators without interpreting arbitrary escapes.
    value = re.sub(r"\\+", lambda _: "\\", value)
    if value.startswith("\\??\\"):
        value = value[4:]
    elif value.startswith("\\?\\"):
        value = value[3:]
    elif unc and value.startswith("\\"):
        value = "\\" + value
    return ntpath.normpath(value)


def normalized_identity(value: str) -> str:
    return re.sub(r"\\+", lambda _: "\\", value).casefold()


def resource_path(event: "Event") -> str:
    data = event.data
    if event.provider == SECURITY and event.eid == "5145":
        base = data.get("shareLocalPath") or data.get("shareName")
        relative = data.get("relativeTargetName")
        if isinstance(base, str) and isinstance(relative, str) and relative:
            return normalized_path(ntpath.join(normalized_path(base), relative.lstrip("\\/")))
        return ""
    if event.provider == SECURITY and event.eid == "4663" and data.get("objectType", "").casefold() == "file":
        value = data.get("objectName")
    elif event.provider == SYSMON and event.eid in {"11", "23", "26"}:
        value = data.get("targetFilename")
    else:
        return ""
    return normalized_path(value) if isinstance(value, str) and value else ""


def direct_identity(event: "Event") -> str:
    data = event.data
    if event.provider == SYSMON:
        value = data.get("user", "")
    elif event.provider == SECURITY:
        prefix = "target" if event.eid in {"4624", "4625", "4776", "4768", "4769"} else "subject"
        value = data.get(prefix + "UserName", "")
        domain = data.get(prefix + "DomainName", "")
        if isinstance(value, str) and value and isinstance(domain, str) and domain and "\\" not in value:
            value = domain + "\\" + value
    else:
        return ""
    return normalized_identity(value) if isinstance(value, str) and value not in {"", "-"} else ""


@dataclass
class Event:
    system: dict
    data: dict
    envelope: dict

    @property
    def provider(self) -> str:
        return str(self.system.get("providerName", ""))

    @property
    def eid(self) -> str:
        return str(self.system.get("eventID", ""))

    @property
    def host(self) -> str:
        value = self.system.get("computer", "")
        return value.casefold() if isinstance(value, str) else ""

    @property
    def image(self) -> str:
        return ntpath.basename(str(self.data.get("image", ""))).casefold()

    def time(self) -> datetime:
        return timestamp(self.system.get("systemTime"))

    def available(self) -> datetime:
        # Both clocks must place the observation no later than the decision.
        # This does NOT normalize clock steps; affected sessions are quarantined.
        return max(self.time(), timestamp(self.envelope.get("timestamp")))

    def digest(self) -> bytes:
        # Ignore envelope/rule/ingestion fields; retain time + full payload to
        # distinguish record-ID resets and genuinely different Windows events.
        content = [self.host, self.provider, self.system.get("channel"), self.eid,
                   self.system.get("eventRecordID"), self.system.get("systemTime"), self.data]
        return hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":")).encode()).digest()


def select_files(root: Path, kind: str) -> tuple[list[Path], list[dict]]:
    paths = sorted(p for p in (root / "logs" / kind).rglob("*")
                   if p.is_file() and p.name.endswith((".json", ".json.gz")))
    seen: dict[str, Path] = {}
    chosen, manifest = [], []
    for path in paths:
        digest = sha256(path)
        prior = seen.get(digest)
        manifest.append({"path": str(path.relative_to(root)), "bytes": path.stat().st_size,
                         "sha256": digest, "duplicate_of": str(prior.relative_to(root)) if prior else None})
        if not prior:
            seen[digest] = path
            chosen.append(path)
    return chosen, manifest


def events(paths: list[Path], stats: Counter, errors: list[dict]) -> Iterator[Event]:
    for path in paths:
        try:
            opener = gzip.open if path.suffix == ".gz" else open
            with opener(path, "rt", encoding="utf-8-sig") as handle:
                for number, line in enumerate(handle, 1):
                    stats["input_records"] += 1
                    try:
                        # Full payload inspection does not execute full_log or commandLine.
                        item = json.loads(line)
                        if not isinstance(item, dict):
                            raise ValueError("Top-level event is not an object")
                    except ValueError:
                        stats["malformed_json"] += 1
                        if len(errors) < 100:
                            errors.append({"file": str(path), "record": number, "code": "malformed_json"})
                        continue
                    data = item.get("data")
                    win = data.get("win") if isinstance(data, dict) else None
                    system = win.get("system") if isinstance(win, dict) else None
                    if not isinstance(system, dict):
                        stats["non_windows_records"] += 1
                        continue
                    payload = win.get("eventdata", {})
                    if not isinstance(payload, dict):
                        stats["malformed_eventdata"] += 1
                        continue
                    stats["windows_records"] += 1
                    yield Event(system, payload, item)
        except (OSError, EOFError, UnicodeError) as exc:
            stats["unreadable_files"] += 1
            errors.append({"file": str(path), "code": "unreadable_file", "error": type(exc).__name__})


def supported_families(event: Event) -> set[str]:
    if event.provider == SECURITY and event.system.get("channel") == "Security":
        result = {"windows"}
        if event.eid in {"4624", "4625"}:
            result.add("auth")
        if event.eid == "4776" and integer(event.data.get("status")) is not None:
            result.add("credential")
        if event.eid == "5145":
            result.update({"smb", "file"})
        if event.eid == "4663" and event.data.get("objectType", "").casefold() == "file":
            result.update({"file_access", "file"})
        if event.eid == "4660":
            result.add("deletion")
        return result
    if event.provider == SYSMON and event.system.get("channel") == "Microsoft-Windows-Sysmon/Operational":
        result = {"windows"}
        result.update({"1": {"process"}, "3": {"network"}, "11": {"file_create", "file"},
                       "23": {"sysmon_delete", "file"}, "26": {"sysmon_delete", "file"}}.get(event.eid, set()))
        return result
    return set()


@dataclass
class Process:
    identities: set[str] = field(default_factory=set)
    starts: set[datetime] = field(default_factory=set)
    ends: set[datetime] = field(default_factory=set)
    images: set[str] = field(default_factory=set)
    parents: set[str] = field(default_factory=set)


class EvidenceIndex:
    """Timestamped evidence queried as-of receipt of an event, never globally.

    Whole-acquisition schema/domain summaries are diagnostic only. Model values
    query first-known collection support and process observations by availability.
    """
    def __init__(self, users: set[str], identity_anchors: dict[str, set[str]] | None = None):
        self.users = users
        self.anchors = identity_anchors or {}  # Independently fixed configuration only.
        self.domains: dict[str, set[str]] = defaultdict(set)
        self.domain_first: dict[str, dict[str, datetime]] = defaultdict(dict)
        self.namespace_sids: dict[str, dict[str, dict[str, datetime]]] = defaultdict(lambda: defaultdict(dict))
        self.process_history: dict[tuple[str, str], list[tuple]] = defaultdict(list)
        self.support: dict[tuple[str, str], dict[str, datetime]] = defaultdict(dict)
        self.schema: dict[str, set[str]] = defaultdict(set)
        self.event_counts: Counter = Counter()

    def inspect(self, event: Event) -> None:
        key = event.provider + "|" + event.eid
        self.event_counts[key] += 1
        self.schema[key].update(event.data)
        identity = direct_identity(event)
        base = identity.rsplit("\\", 1)[-1]
        try:
            moment, ready = event.time(), event.available()
        except ValueError:
            return  # Incomplete receipt/event times cannot establish causal evidence.
        # An unsuccessful target-account attempt does not establish a namespace.
        establishes_identity = not (event.provider == SECURITY and (
            event.eid == "4625" or event.eid == "4776" and integer(event.data.get("status")) != 0))
        if base in self.users and "\\" in identity and establishes_identity:
            domain = identity.rsplit("\\", 1)[0]
            self.domains[base].add(domain)  # Report only; resolve_name uses domain_first.
            prior = self.domain_first[base].get(domain)
            self.domain_first[base][domain] = min(prior, ready) if prior else ready
            if event.provider == SECURITY:
                prefix = "target" if event.eid in {"4624", "4776", "4768", "4769"} else "subject"
                sid = event.data.get(prefix + "UserSid", "")
                if isinstance(sid, str) and sid.startswith("S-1-5-21-"):
                    previous = self.namespace_sids[base][domain].get(sid)
                    self.namespace_sids[base][domain][sid] = min(previous, ready) if previous else ready
        if event.host:
            support = self.support[(event.host, moment.date().isoformat())]
            for family in supported_families(event):
                support[family] = min(support.get(family, ready), ready)
        if event.provider == SYSMON and event.host and event.data.get("processGuid"):
            if identity or event.eid in {"1", "5"}:
                self.process_history[(event.host, str(event.data["processGuid"]).casefold())].append(
                    (ready, moment, event.eid, identity, event.image,
                     str(event.data.get("parentProcessGuid", "")).casefold()))

    def resolve_name(self, identity: str, cutoff: datetime) -> str:
        base = identity.rsplit("\\", 1)[-1]
        if base not in self.users:
            return ""
        anchors = self.anchors.get(base, set())
        if anchors:
            return base if len(anchors) == 1 and ("\\" not in identity or identity in anchors) else ""
        domains = {domain for domain, ready in self.domain_first[base].items() if ready <= cutoff}
        if len(domains) > 1:
            # A DNS name and NetBIOS name are aliases only with exact, positive
            # Security SID evidence already available by this event's receipt.
            sid_sets = [{sid for sid, ready in self.namespace_sids[base][domain].items() if ready <= cutoff}
                        for domain in domains]
            if any(not values for values in sid_sets) or len(set().union(*sid_sets)) != 1:
                return ""
        if "\\" in identity and identity.rsplit("\\", 1)[0] not in domains:
            return ""
        return base

    def process(self, event: Event, guid: str | None = None) -> Process | None:
        guid = guid if guid is not None else str(event.data.get("processGuid", "")).casefold()
        try:
            moment, cutoff = event.time(), event.available()
        except ValueError:
            return None
        process = Process()
        for ready, when, eid, identity, image, parent in self.process_history.get((event.host, guid), []):
            if ready > cutoff:
                continue
            if identity:
                process.identities.add(identity)
            if eid == "1" and when <= moment:
                process.starts.add(when)
                process.images.add(image)
                process.parents.add(parent)
            if eid == "5":
                process.ends.add(when)
        if len(process.starts) != 1 or len(process.identities) != 1 or len(process.images) != 1:
            return None
        if process.ends and moment > min(process.ends):
            return None
        return process

    def identity(self, event: Event) -> tuple[str, str]:
        try:
            cutoff = event.available()
        except ValueError:
            return "", "unresolved"
        direct = direct_identity(event)
        if direct:
            return self.resolve_name(direct, cutoff), "direct"
        if event.provider == SYSMON:
            process = self.process(event)
            if process:
                return self.resolve_name(next(iter(process.identities)), cutoff), "host_process_guid"
        return "", "unresolved"

    def families_before(self, locations: set[tuple[str, str]], cutoff: datetime) -> set[str]:
        return {family for location in locations for family, ready in self.support[location].items()
                if ready <= cutoff}

    def sftp_network(self, event: Event) -> bool:
        if event.image in SFTP_IMAGES:
            return True
        if event.image != "ssh.exe":
            return False
        process = self.process(event)
        if not process or len(process.parents) != 1:
            return False
        parent = self.process(event, next(iter(process.parents)))
        return bool(parent and next(iter(parent.images)) in SFTP_IMAGES)


@dataclass
class Window:
    sid: str
    user: str
    start: datetime | None = None
    end: datetime | None = None
    source: str = ""
    issue: str = ""


def session_windows(rows: list[dict], ledger: list[dict], padding: float) -> tuple[list[Window], "Matcher"]:
    history: dict[str, list[dict]] = defaultdict(list)
    for entry in ledger:
        history[entry["SessionID"]].append(entry)
    windows = []
    for row in rows:
        window = Window(row["SessionID"], row["Username"].casefold().rsplit("\\", 1)[-1])
        try:
            start = parse_utc(row["ActualExecutionUTC"])
            if row["ActualExecutionTimestampSource"] == "m05_worker_started":
                end = parse_utc(row["M05EndedUTC"])
                source = "worker_interval"
            elif row["ActualExecutionTimestampSource"] == "ledger_started_initiation":
                entries = history[row["SessionID"]]
                starts = [i for i, entry in enumerate(entries) if entry["Status"] == "Started"]
                if len(starts) != 1 or parse_utc(entries[starts[0]]["ExecutionUTC"]) != start:
                    raise ValueError("Unverified ledger start")
                after = entries[starts[0] + 1:]
                returned = next((entry for entry in after if entry["Status"] in {"Completed", "Failed", "InvokedUnverified"}
                                 and not entry["Detail"].startswith("Reconciled:")), None)
                if returned is None:
                    raise ValueError("No immediate handler return")
                end, source = parse_utc(returned["ExecutionUTC"]), "ledger_start_to_handler_return"
            else:
                raise ValueError("Unknown actual start source")
            if end < start:
                raise ValueError("Reversed execution interval")
            window.start, window.end, window.source = start, end, source
        except (ValueError, KeyError):
            window.issue = "unverified_execution_interval"
        windows.append(window)
    return windows, Matcher(windows, padding)


class Matcher:
    def __init__(self, windows: list[Window], padding: float):
        self.padding = timedelta(seconds=padding)
        self.by_user: dict[str, list[Window]] = defaultdict(list)
        for window in windows:
            if window.start is not None and window.end is not None:
                self.by_user[window.user].append(window)
        self.starts = {}
        self.max_span = {}
        for user, group in self.by_user.items():
            group.sort(key=lambda w: (w.start, w.sid))
            self.starts[user] = [window.start - self.padding for window in group]
            self.max_span[user] = max((window.end - window.start + 2 * self.padding for window in group))

    def candidates(self, user: str, moment: datetime) -> list[Window]:
        group = self.by_user.get(user, [])
        if not group:
            return []
        right = bisect_right(self.starts[user], moment)
        left = bisect_right(self.starts[user], moment - self.max_span[user])
        return [window for window in group[max(0, left - 1):right]
                if window.start - self.padding <= moment <= window.end + self.padding]


@dataclass
class Accumulator:
    counts: Counter = field(default_factory=Counter)
    values: dict[str, set] = field(default_factory=lambda: defaultdict(set))
    bad: set[str] = field(default_factory=set)
    locations: set[tuple[str, str]] = field(default_factory=set)
    raw: int = 0
    unique: int = 0
    ambiguous: int = 0
    linked: int = 0
    padding: int = 0
    unknown_time: int = 0
    artifacts: int = 0
    alerts: int = 0
    alerted_events: set[bytes] = field(default_factory=set)
    ambiguous_alerts: int = 0
    clock_disagreements: int = 0
    late: int = 0
    used: set = field(default_factory=set)


def audit_failure(event: Event) -> bool | None:
    keywords = integer(event.system.get("keywords"))
    failure = bool(keywords & 0x0010000000000000) if keywords is not None else False
    success = bool(keywords & 0x0020000000000000) if keywords is not None else False
    severity = event.system.get("severityValue")
    if failure and not success and severity != "AUDIT_SUCCESS":
        return True
    if success and not failure and severity != "AUDIT_FAILURE":
        return False
    if not (failure or success):
        return True if severity == "AUDIT_FAILURE" else False if severity == "AUDIT_SUCCESS" else None
    return None


def is_artifact(event: Event) -> bool:
    # Do not let session UUID/result/queue churn become an easy scenario shortcut.
    values = [resource_path(event), event.data.get("targetFilename", ""), event.data.get("objectName", ""),
              event.data.get("shareName", "")]
    return any(any(part in ARTIFACT_COMPONENTS for part in re.split(r"[\\/]", value.casefold()))
               for value in values if isinstance(value, str))


def add_features(acc: Accumulator, event: Event, user: str, index: EvidenceIndex,
                 protected_prefixes: list[str]) -> None:
    data = event.data
    path = resource_path(event)
    hostpath = (event.host, path)
    acc.counts["windows_event_count"] += 1
    signature = (event.host, event.provider, event.eid, user, path, str(data.get("accessMask", "")),
                 str(data.get("handleId", "")), str(data.get("subjectLogonId", data.get("logonId", ""))),
                 str(data.get("processGuid", data.get("processId", ""))), event.image,
                 str(data.get("destinationIp", "")), str(data.get("destinationPort", "")))
    acc.values["unique_action_signatures"].add(signature)
    if path:
        acc.values["distinct_file_paths"].add(hostpath)
        if any(part.startswith(tuple(protected_prefixes)) for part in path.split("\\")):
            acc.counts["protected_resource_event_count"] += 1
    families = supported_families(event)
    if "file" in families and not path:
        acc.bad.update({"distinct_file_paths", "protected_resource_event_count"})
    if event.provider == SECURITY:
        if event.eid == "4625":
            acc.counts["failed_logon_count"] += 1
        if event.eid == "4624":
            acc.counts["successful_logon_count"] += 1
        if event.eid == "4776":
            status = integer(data.get("status"))
            if status is None:
                acc.bad.add("credential_validation_failure_count")
            elif status != 0:
                acc.counts["credential_validation_failure_count"] += 1
        if event.eid == "5145":
            acc.counts["smb_access_check_count"] += 1
            denied = audit_failure(event)
            if denied is None:
                acc.bad.add("smb_denied_count")
            elif denied:
                acc.counts["smb_denied_count"] += 1
            if path:
                acc.values["distinct_smb_paths"].add(hostpath)
            else:
                acc.bad.add("distinct_smb_paths")
        if event.eid == "4663" and data.get("objectType", "").casefold() == "file":
            acc.counts["file_access_count"] += 1
            mask = integer(data.get("accessMask"))
            if mask is None:
                acc.bad.update({"file_read_access_count", "file_write_access_count", "delete_access_count"})
            else:
                for name, bits in [("file_read_access_count", 1), ("file_write_access_count", 6), ("delete_access_count", 0x10000)]:
                    acc.counts[name] += bool(mask & bits)
        if event.eid == "4660":
            acc.counts["object_deletion_event_count"] += 1
    if event.provider == SYSMON:
        if event.eid == "11":
            acc.counts["file_create_event_count"] += 1
        if event.eid in {"23", "26"}:
            acc.counts["sysmon_file_delete_count"] += 1
        if event.eid == "1":
            acc.counts["process_create_count"] += 1
            if data.get("processGuid"):
                acc.values["distinct_process_guids"].add((event.host, str(data["processGuid"]).casefold()))
            else:
                acc.bad.add("distinct_process_guids")
            if not event.image:
                acc.bad.update({"sftp_process_count", "ssh_process_count", "scp_process_count"})
            acc.counts["sftp_process_count"] += event.image in SFTP_IMAGES
            acc.counts["ssh_process_count"] += event.image == "ssh.exe"
            acc.counts["scp_process_count"] += event.image in {"scp.exe", "pscp.exe"}
        if event.eid == "3":
            acc.counts["network_connection_count"] += 1
            if not data.get("destinationIp"):
                acc.bad.add("distinct_network_destinations")
            else:
                acc.values["distinct_network_destinations"].add(str(data["destinationIp"]))
            if integer(data.get("destinationPort")) is None or str(data.get("initiated", "")).lower() not in {"true", "false"}:
                acc.bad.add("ssh_port22_connection_count")
            elif integer(data["destinationPort"]) == 22 and str(data["initiated"]).lower() == "true":
                acc.counts["ssh_port22_connection_count"] += 1
            if not event.image:
                acc.bad.add("sftp_network_connection_count")
            elif index.sftp_network(event):
                acc.counts["sftp_network_connection_count"] += 1


def extract(rows: list[dict], ledger: list[dict], archive_paths: list[Path], alert_paths: list[Path],
            start: datetime, end: datetime, padding: float = 2,
            protected_prefixes: list[str] | None = None,
            identity_anchors: dict[str, set[str]] | None = None,
            prior_clock_ids: set[str] | None = None,
            prior_overlap_ids: set[str] | None = None) -> tuple[list[dict], dict]:
    protected_prefixes = protected_prefixes or ["restricted"]
    users = {row["Username"].casefold().rsplit("\\", 1)[-1] for row in rows}
    index = EvidenceIndex(users, identity_anchors)
    prior_clock_ids = prior_clock_ids or set()
    prior_overlap_ids = prior_overlap_ids or set()
    index_stats: Counter = Counter()
    errors: list[dict] = []
    print("Indexing timestamped identity and collection evidence (as-of queries only)...", flush=True)
    for event in events(archive_paths, index_stats, errors):
        index.inspect(event)
    windows, matcher = session_windows(rows, ledger, padding)
    by_sid = {window.sid: window for window in windows}
    accumulators = {row["SessionID"]: Accumulator() for row in rows}
    stats_by_kind = {}
    for kind, paths in [("archives", archive_paths), ("alerts", alert_paths)]:
        print(f"Attributing {kind} (ambiguous candidates are not assigned)...", flush=True)
        stats: Counter = Counter()
        seen: set[bytes] = set()
        clock = {"count": 0, "sum_seconds": 0.0, "min_seconds": None, "max_seconds": None}
        host_clocks: dict[str, dict] = {}
        for event in events(paths, stats, errors):
            digest = event.digest()
            if kind == "alerts":
                # Distinct Wazuh envelopes are distinct alert records, even for
                # the same Windows event. Rule IDs never enter predictors.
                alert_identity = [event.envelope.get("id"), event.envelope.get("timestamp"),
                                  event.envelope.get("rule", {}), digest.hex()]
                unique_key = hashlib.sha256(json.dumps(alert_identity, sort_keys=True).encode()).digest()
            else:
                unique_key = digest
            duplicate = unique_key in seen
            if duplicate:
                stats["duplicate_windows_records"] += 1
            else:
                seen.add(unique_key)
                stats["unique_windows_records"] += 1
            user, identity_source = index.identity(event)
            try:
                moment = event.time()
            except ValueError:
                stats["unknown_event_time"] += 1
                continue
            try:
                ready = event.available()
            except ValueError:
                stats["unknown_availability_time"] += 1
                continue
            clock_delta = None
            if not duplicate:
                stats["inside_original_period" if start <= moment < end else "outside_original_period"] += 1
                if event.envelope.get("timestamp"):
                    try:
                        delta = (timestamp(event.envelope["timestamp"]) - moment).total_seconds()
                        clock_delta = delta
                        clock["count"] += 1
                        clock["sum_seconds"] += delta
                        clock["min_seconds"] = delta if clock["min_seconds"] is None else min(clock["min_seconds"], delta)
                        clock["max_seconds"] = delta if clock["max_seconds"] is None else max(clock["max_seconds"], delta)
                        host_clock = host_clocks.setdefault(event.host, {"count": 0, "min_seconds": delta,
                                                                       "max_seconds": delta, "over_300s_absolute": 0})
                        host_clock["count"] += 1
                        host_clock["min_seconds"] = min(host_clock["min_seconds"], delta)
                        host_clock["max_seconds"] = max(host_clock["max_seconds"], delta)
                        host_clock["over_300s_absolute"] += abs(delta) > 300
                    except ValueError:
                        stats["invalid_manager_time"] += 1
            if not supported_families(event):
                stats["unsupported_provider_channel"] += not duplicate
                continue
            if not event.host:
                stats["missing_host"] += not duplicate
                continue
            if not user:
                stats["identity_unresolved_or_not_simulation_user"] += not duplicate
                continue
            candidates = [w for w in matcher.candidates(user, moment) if w.start <= ready]
            if not candidates:
                stats["outside_all_user_windows"] += not duplicate
                continue
            available_candidates = [w for w in candidates if ready <= w.end + timedelta(seconds=padding)]
            for candidate in candidates:
                if candidate not in available_candidates and kind == "archives":
                    accumulators[candidate.sid].late += 1  # Does not affect earlier decisions.
            if not available_candidates:
                stats["received_after_prediction_cutoff"] += 1
                continue
            if len(candidates) > 1:
                stats["ambiguous_events"] += not duplicate
                if not duplicate:
                    for window in available_candidates:
                        acc = accumulators[window.sid]
                        if kind == "archives":
                            acc.ambiguous += 1
                        else:
                            acc.ambiguous_alerts += 1
                continue
            window = candidates[0]
            acc = accumulators[window.sid]
            if kind == "archives":
                acc.raw += 1
            use_key = (kind, unique_key)
            if use_key in acc.used:
                continue
            acc.used.add(use_key)
            stats["uniquely_attributed"] += 1
            if not start <= moment < end:
                stats["attributed_outside_original_period"] += 1
            if kind == "alerts":
                acc.alerts += 1
                acc.alerted_events.add(digest)
                continue
            acc.unique += 1
            acc.clock_disagreements += clock_delta is not None and abs(clock_delta) > 300
            acc.locations.add((event.host, moment.date().isoformat()))
            if identity_source == "host_process_guid":
                acc.linked += 1
            if not window.start <= moment <= window.end:
                acc.padding += 1
            if is_artifact(event):
                acc.artifacts += 1
                stats["orchestration_excluded"] += 1
                continue
            add_features(acc, event, user, index, protected_prefixes)
        clock["mean_seconds"] = clock.pop("sum_seconds") / clock["count"] if clock["count"] else None
        stats_by_kind[kind] = {"counts": dict(sorted(stats.items())), "manager_minus_windows_clock": clock,
                               "host_clock_audit": dict(sorted(host_clocks.items()))}
    integrity_errors = any(index_stats[key] or any(stats_by_kind[kind]["counts"].get(key, 0) for kind in stats_by_kind)
                           for key in ["malformed_json", "malformed_eventdata", "unreadable_files"])
    output = []
    for ground in rows:
        sid = ground["SessionID"]
        window, acc = by_sid[sid], accumulators[sid]
        cutoff = window.end + timedelta(seconds=padding) if window.end else None
        observed = index.families_before(acc.locations, cutoff) if cutoff else set()
        reasons = []
        if window.issue:
            reasons.append(window.issue)
        if not acc.counts["windows_event_count"]:
            reasons.append("no_attributed_behavioral_events")
        if acc.ambiguous or sid in prior_overlap_ids:
            reasons.append("ambiguous_candidate_events_excluded")
        if acc.unknown_time:
            reasons.append("same_account_events_with_unknown_timestamp")
        if acc.clock_disagreements or sid in prior_clock_ids:
            reasons.append("clock_reference_unreliable_excluded")
        if integrity_errors:
            reasons.append("telemetry_integrity_errors")
        values = {name: (len(acc.values[name]) if name in acc.values else acc.counts[name])
                  if DICTIONARY[name][0] in observed and acc.counts["windows_event_count"] and name not in acc.bad else ""
                  for name in FEATURES}
        missing = sum(value == "" for value in values.values())
        if missing:
            reasons.append("missing_predictors_require_review")
        feature_eligible = (ground["MLTrainingEligible"] == "true" and bool(acc.counts["windows_event_count"])
                            and not window.issue and not acc.ambiguous and sid not in prior_overlap_ids
                            and not acc.clock_disagreements and sid not in prior_clock_ids and not integrity_errors)
        record = {
            "SessionID": sid, "WindowStartUTC": iso(window.start), "WindowEndUTC": iso(window.end),
            "ObservationStartUTC": iso(window.start - timedelta(seconds=padding)) if window.start else "",
            "ObservationEndUTC": iso(window.end + timedelta(seconds=padding)) if window.end else "",
            "PredictionCutoffUTC": iso(cutoff),
            "WindowSource": window.source, "WindowStatus": "verified" if not window.issue else "unknown",
            "RawMatchedArchiveRecords": acc.raw, "UniqueMatchedArchiveEvents": acc.unique,
            "DuplicateMatchedArchiveRecords": acc.raw - acc.unique,
            "AmbiguousArchiveCandidates": acc.ambiguous, "PaddingOnlyArchiveEvents": acc.padding,
            "IdentityLinkedArchiveEvents": acc.linked, "UnknownTimestampArchiveCandidates": acc.unknown_time,
            "OrchestrationArchiveEvents": acc.artifacts,
            "ClockDisagreementArchiveEvents": acc.clock_disagreements,
            "WazuhAlertRecordCount": acc.alerts if alert_paths else "",
            "WazuhDistinctAlertedEventCount": len(acc.alerted_events) if alert_paths else "",
            "AmbiguousAlertCandidates": acc.ambiguous_alerts,
            "TelemetryStatus": "observed" if acc.counts["windows_event_count"] else "no_unambiguous_behavioral_events",
            "MissingFeatureCount": missing, "FeatureMLTrainingEligible": str(feature_eligible).lower(),
            "LateArrivingArchiveCandidates": acc.late,
            "ClockPolicyStatus": "excluded_unreliable_reference" if acc.clock_disagreements or sid in prior_clock_ids else "no_large_disagreement_observed",
            "PriorOverlapExclusion": str(sid in prior_overlap_ids).lower(),
            "FeatureExtendedCohortEligible": str(feature_eligible and ground["ExtendedCohortEligible"] == "true").lower(),
            "FeatureOriginal14DayCohortEligible": str(feature_eligible and ground["Original14DayCohortEligible"] == "true").lower(),
            "FeatureReviewReasons": "|".join(reasons),
            **{f"Observed_{family}": str(family in observed).lower() for family in FAMILIES}, **values,
        }
        output.append(record)
    summary = {}
    by_scenario = defaultdict(list)
    for ground, record in zip(rows, output):
        by_scenario[ground["ScenarioID"]].append(record)
    for scenario, group in sorted(by_scenario.items()):
        summary[scenario] = {
            "sessions": len(group), "sessions_with_behavioral_events": sum(x["TelemetryStatus"] == "observed" for x in group),
            "sessions_with_ambiguous_events": sum(x["AmbiguousArchiveCandidates"] > 0 for x in group),
            "feature_ml_eligible": sum(x["FeatureMLTrainingEligible"] == "true" for x in group),
            "unique_archive_events": sum(x["UniqueMatchedArchiveEvents"] for x in group),
            "missing_feature_rates": {name: round(sum(x[name] == "" for x in group) / len(group), 6) for name in FEATURES},
            "positive_feature_sessions": {name: sum(x[name] != "" and x[name] > 0 for x in group) for name in FEATURES},
            "feature_totals": {name: sum(x[name] for x in group if x[name] != "") for name in FEATURES},
        }
    report = {
        "version": VERSION, "validation_status": "errors" if integrity_errors else "completed_with_limitations",
        "index_counts": dict(sorted(index_stats.items())), "streams": stats_by_kind,
        "schema_event_counts": dict(sorted(index.event_counts.items())),
        "schema_eventdata_fields": {k: sorted(v) for k, v in sorted(index.schema.items())},
        "identity_policy": "Qualified schedule names only may be static anchors; worker results never establish static identity. Otherwise namespaces and process identity/lifetime evidence must be available by the attributed event's receipt. Multiple namespaces may map to a simulation account only when positive Security events establish the same unique domain-account SID in every namespace, already available as-of receipt. Failed target-authentication attempts do not establish namespace identity. No future observations, PID-only or scenario matching.",
        "identity_domain_evidence": {user: sorted(index.domains[user]) for user in sorted(users)},
        "verified_identity_anchors": {user: sorted(values) for user, values in sorted(index.anchors.items())},
        "window_policy": {"padding_seconds": padding, "bounds": "inclusive",
                          "non_worker": "unique ledger Started to first non-reconciled Completed/Failed/InvokedUnverified handler return",
                          "worker": "verified worker StartedUTC to EndedUTC; no lifecycle status is a predictor",
                          "ambiguity": "exclude event from ALL overlapping same-user sessions; do not resolve by first match",
                          "clock": "Windows systemTime only, explicit timezone required; no manager-time substitution or fitted clock shift"},
        "missing_policy": "Blank means missing. Host/day collection evidence must be received AND generated no later than PredictionCutoffUTC, on an observed session host/day. No later-in-day lookahead. Support is not proof of uninterrupted auditing. Unknown-time records remain global diagnostics, never assigned to every earlier session. No imputation here.",
        "feature_eligibility_policy": "Ground-truth ML eligibility AND valid window AND behavioral telemetry AND no ambiguous candidates, unknown same-account timestamps, or stream-integrity errors. Missing individual families require review/imputation design later, but do not alone remove the record. Original/extended ground-truth flags remain unchanged.",
        "protected_prefixes": protected_prefixes, "excluded_orchestration_components": sorted(ARTIFACT_COMPONENTS),
        "clock_review_policy": "No inferred normalization: prior nine clock-review sessions and any causally observed large clock disagreement are retained but experiment-ineligible. Prior six overlap exclusions remain separate. Source clock-change events do not establish shared UTC receipt/cutoff comparability.",
        "causal_policy": "PredictionCutoffUTC = ObservationEndUTC. max(Windows systemTime, Wazuh ingestion timestamp) must be <= cutoff. Index queries are even stricter: only evidence available by the attributed event's own receipt. Later duplicates, names, process ends and collection records cannot change earlier features. Offline experiment session boundaries are external annotations, not deployment features.",
        "prior_clock_review_exclusions": sorted(prior_clock_ids),
        "prior_overlap_review_exclusions": sorted(prior_overlap_ids),
        "total_sessions": len(rows), "unknown_windows": sum(bool(w.issue) for w in windows),
        "feature_ml_eligible": sum(x["FeatureMLTrainingEligible"] == "true" for x in output),
        "feature_original_cohort": sum(x["FeatureOriginal14DayCohortEligible"] == "true" for x in output),
        "feature_extended_cohort": sum(x["FeatureExtendedCohortEligible"] == "true" for x in output),
        "scenario_coverage": summary, "errors": errors,
        "limitations": [
            "User plus execution interval is temporal attribution, not causal proof; unrelated same-account activity may remain.",
            "Host/day family support does not prove uninterrupted telemetry or auditing configuration; zero is an observed count, not proof of no activity.",
            "Action signatures are distinct observed operation descriptions, not a ground-truth count of physical actions.",
            "Port 22 or ssh.exe alone does not prove SFTP; no network byte counts are inferred.",
            "Wazuh alert counts are contextual baseline metadata, excluded from default behavioral predictors.",
            "M05 worker success and pending Wazuh verification are not changed by feature extraction.",
            "Session boundaries depend on experimental execution evidence; deployment would need an independent windowing policy.",
            "Day 12 was already used for M01 tuning; these cohort flags are not independent train/test partitions.",
        ],
    }
    return output, report


def write_csv(path: Path, fields: list[str], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def verified_anchors(rows: list[dict], source_dir: Path) -> dict[str, set[str]]:
    """Only predeclared qualified schedule accounts; never future worker results."""
    anchors: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        identity = normalized_identity(row["Username"])
        base = identity.rsplit("\\", 1)[-1]
        if "\\" in identity:
            anchors[base].add(identity)
    return dict(anchors)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", type=Path, default=Path("data/processed/session_ground_truth.csv"))
    parser.add_argument("--ground-truth-report", type=Path, default=Path("data/processed/validation_report.json"))
    parser.add_argument("--source-dir", type=Path, default=Path("data/ground_truth"))
    parser.add_argument("--wazuh-dir", type=Path, default=Path("data/wazuh"))
    parser.add_argument("--output-dir", type=Path, default=Path("data/processed"))
    parser.add_argument("--padding-seconds", type=float, default=2.0)
    parser.add_argument("--review-baseline", type=Path,
                        help="Preserved pre-fix master containing fixed clock/overlap review exclusions")
    parser.add_argument("--protected-prefix", action="append", default=None,
                        help="Case-insensitive path-component prefix; repeatable; default restricted")
    args = parser.parse_args(argv)
    names = ["session_features.csv", "ml_dataset.csv", "feature_validation_report.json", "feature_schema.json"]
    output_dir = args.output_dir.resolve()
    if not 0 <= args.padding_seconds <= 60:
        parser.error("Padding must be finite and between 0 and 60 seconds")
    prefixes = args.protected_prefix or ["restricted"]
    if any(not prefix.strip() for prefix in prefixes):
        parser.error("Protected prefixes must not be empty")
    protected = [args.source_dir.resolve(), args.wazuh_dir.resolve(), Path(__file__).resolve().parents[1] / "data/raw"]
    if any(output_dir == path or path in output_dir.parents or output_dir in path.parents for path in protected):
        parser.error("Output must not overlap original source directories")
    if any((output_dir / name).exists() for name in names):
        parser.error("Feature outputs already exist; choose a new --output-dir (existing ground-truth files are allowed)")
    if args.ground_truth.resolve() in [output_dir / name for name in names] or args.ground_truth_report.resolve() in [output_dir / name for name in names]:
        parser.error("Output must not replace ground truth inputs")
    try:
        validation = json.loads(args.ground_truth_report.read_text(encoding="utf-8"))
        if validation["validation_status"] not in {"passed", "passed_with_warnings"}:
            raise ValueError("Ground truth did not pass validation")
        if sha256(args.ground_truth) != validation["output_sha256"]["session_ground_truth.csv"]:
            raise ValueError("Ground truth hash disagrees with its validation report")
        config = validation["reproducibility"]["configuration"]
        start = datetime.fromisoformat(config["start_date"]).replace(tzinfo=timezone.utc)
        end = datetime.fromisoformat(config["end_date"]).replace(tzinfo=timezone.utc) + timedelta(days=1)
        rebuilt, _ = build_dataset(args.source_dir, start.date(), (end - timedelta(days=1)).date())
        if args.ground_truth.read_bytes() != csv_text(rebuilt).encode():
            raise ValueError("Ground truth cannot be reproduced from current source evidence")
        source_manifest = {}
        for relative, source in validation["reproducibility"]["input_hashes"].items():
            path = args.source_dir / relative
            if sha256(path) != source["sha256"]:
                raise ValueError("Ground truth source hash mismatch")
            source_manifest[str(path.resolve())] = source["sha256"]
        rows = read_csv(args.ground_truth, OUTPUT_FIELDS)
        prior_clock_ids, prior_overlap_ids = set(), set()
        if args.review_baseline:
            with args.review_baseline.open(encoding="utf-8-sig", newline="") as handle:
                baseline = list(csv.DictReader(handle))
            if {r["SessionID"] for r in baseline} != {r["SessionID"] for r in rows}:
                raise ValueError("Review baseline does not cover the same scheduled sessions")
            prior_clock_ids = {r["SessionID"] for r in baseline if int(r["ClockDisagreementArchiveEvents"])}
            prior_overlap_ids = {r["SessionID"] for r in baseline if int(r["AmbiguousArchiveCandidates"])}
            source_manifest[str(args.review_baseline.resolve())] = sha256(args.review_baseline)
        if len({row["SessionID"] for row in rows}) != len(rows):
            raise ValueError("Duplicate master SessionID")
        ledger = read_csv(args.source_dir / "execution_ledger.csv", LEDGER_FIELDS)
        source_manifest[str(args.ground_truth.resolve())] = sha256(args.ground_truth)
        source_manifest[str(args.ground_truth_report.resolve())] = sha256(args.ground_truth_report)
        archive_paths, archive_manifest = select_files(args.wazuh_dir, "archives")
        alert_paths, alert_manifest = select_files(args.wazuh_dir, "alerts")
        if not archive_paths:
            raise ValueError("No archive JSON/JSON.GZ files found")
        for item in archive_manifest + alert_manifest:
            source_manifest[str((args.wazuh_dir / item["path"]).resolve())] = item["sha256"]
        features, report = extract(rows, ledger, archive_paths, alert_paths, start, end,
                                   args.padding_seconds, [prefix.casefold() for prefix in prefixes],
                                   verified_anchors(rows, args.source_dir), prior_clock_ids, prior_overlap_ids)
        if any(sha256(Path(path)) != digest for path, digest in source_manifest.items()):
            raise ValueError("Source content changed during extraction; export refused")
        _, current_archives = select_files(args.wazuh_dir, "archives")
        _, current_alerts = select_files(args.wazuh_dir, "alerts")
        if archive_manifest != current_archives or alert_manifest != current_alerts:
            raise ValueError("Telemetry file inventory changed during extraction")
        report["files"] = {"archives": archive_manifest, "alerts": alert_manifest}
        report["reproducibility"] = {"python": platform.python_version(), "git": git_metadata(),
                                     "implementation_sha256": sha256(Path(__file__)), "input_sha256": source_manifest}
        report["alerts_available"] = bool(alert_paths)
        merged = [{**ground, **record} for ground, record in zip(rows, features)]
        schema = {
            "version": VERSION,
            "predictive_columns": MODEL_INPUTS,
            "diagnostic_only_columns": ["protected_resource_event_count", "sysmon_file_delete_count"],
            "protected_resource_exclusion": "Role-based permitted activity on a restricted resource is not unauthorized behavior; this count is diagnostic only. Validated SMB access/denial behavior remains predictive.",
            "candidate_predictive_columns": FEATURES,
            "unavailable_predictive_columns": [name for name in FEATURES if all(row[name] == "" for row in features)],
            "ground_truth_columns": OUTPUT_FIELDS,
            "metadata_columns": [key for key in META_FIELDS if key != "SessionID"],
            "join_key": "SessionID", "target_column": "GroundTruthLabel",
            "feature_dictionary": {name: {"collection_family": family, "definition": definition,
                                          "type": "nullable_nonnegative_integer"}
                                   for name, (family, definition) in DICTIONARY.items()},
            "excluded_from_predictors": "All columns not explicitly listed in predictive_columns, including alerts, rule IDs, identities, timestamps, scenario/labels, eligibility, outcomes and missingness metadata. Never select predictors merely by numeric dtype.",
        }
        output_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".feature-stage-", dir=output_dir) as temporary:
            stage = Path(temporary)
            write_csv(stage / names[0], META_FIELDS + FEATURES, features)
            write_csv(stage / names[1], OUTPUT_FIELDS + [x for x in META_FIELDS if x not in OUTPUT_FIELDS] + FEATURES, merged)
            (stage / names[3]).write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            report["output_sha256"] = {name: sha256(stage / name) for name in [names[0], names[1], names[3]]}
            (stage / names[2]).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            # Report is published last. A missing report means incomplete output.
            for name in [names[0], names[1], names[3], names[2]]:
                if (output_dir / name).exists():
                    raise ValueError("Output appeared during extraction; refusing overwrite")
                (stage / name).replace(output_dir / name)
        print(json.dumps({key: report[key] for key in ["validation_status", "total_sessions", "unknown_windows",
                                                       "feature_ml_eligible", "feature_original_cohort", "feature_extended_cohort"]}, indent=2))
        return 1 if report["validation_status"] == "errors" else 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Feature extraction failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
