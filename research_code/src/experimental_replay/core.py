"""Causal event-only rolling state; no simulation/session/label dependencies."""
from __future__ import annotations

import heapq
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .. import features as ref


def feature_values(acc: ref.Accumulator, observed: set[str], names: list[str]) -> dict:
    """Exact reference nullable-count policy, usable for interval parity too."""
    return {name: (len(acc.values[name]) if name in acc.values else acc.counts[name])
            if ref.DICTIONARY[name][0] in observed and acc.counts["windows_event_count"] and name not in acc.bad
            else None for name in names}


@dataclass
class WindowState:
    events: list = field(default_factory=list)
    counts: Counter = field(default_factory=Counter)
    values: dict = field(default_factory=lambda: defaultdict(Counter))
    bad: Counter = field(default_factory=Counter)
    locations: Counter = field(default_factory=Counter)
    clock_bad: int = 0

    def update(self, delta: ref.Accumulator, location: tuple, clock_bad: bool, direction: int):
        for name, value in delta.counts.items():
            self.counts[name] += direction * value
        for name, values in delta.values.items():
            for value in values:
                self.values[name][value] += direction
                if self.values[name][value] == 0:
                    del self.values[name][value]
        for name in delta.bad:
            self.bad[name] += direction
        self.locations[location] += direction
        if self.locations[location] == 0:
            del self.locations[location]
        self.clock_bad += direction * clock_bad

    def expire(self, lower: datetime):
        while self.events and self.events[0][0] <= lower:
            _, _, delta, location, clock_bad = heapq.heappop(self.events)
            self.update(delta, location, clock_bad, -1)

    def accumulator(self):
        return ref.Accumulator(counts=self.counts,
            values={name: set(values) for name, values in self.values.items()},
            bad={name for name, n in self.bad.items() if n > 0})


class RollingReplay:
    """Five-minute event-time windows, availability-ordered evidence updates.

    Account discovery comes from arriving identities, never a schedule. User
    basenames are routing keys only after the reference namespace/SID checks.
    State and ingestion have no SessionID, ScenarioID, Role or outcome inputs.
    """
    def __init__(self, names: list[str], seconds: int = 300):
        if len(set(names)) != len(names) or any(n not in ref.MODEL_INPUTS for n in names):
            raise ValueError("Only the behavioral allowlist may enter replay")
        self.names = names
        self.duration = timedelta(seconds=seconds)
        self.index = ref.EvidenceIndex(set())
        self.windows = defaultdict(WindowState)
        self.used = set()
        self.seen = set()
        self.stats = Counter()
        self.last_ready = None
        self.last_tick = None
        self.sequence = 0

    def ingest(self, event: ref.Event):
        self.stats["input_events"] += 1
        try:
            moment, ready = event.time(), event.available()
        except ValueError:
            self.stats["invalid_timestamp"] += 1
            return "invalid_timestamp"
        if self.last_ready is not None and ready < self.last_ready:
            raise ValueError("Events must be supplied in availability order")
        if self.last_tick is not None and ready < self.last_tick:
            raise ValueError("Cannot retroactively ingest evidence before an emitted tick")
        self.last_ready = ready
        identity = ref.direct_identity(event)
        if identity:
            self.index.users.add(identity.rsplit("\\", 1)[-1])
        self.index.inspect(event)
        digest = event.digest()
        if digest in self.seen:
            self.stats["duplicate_input"] += 1
        self.seen.add(digest)
        if not ref.supported_families(event) or not event.host:
            self.stats["unsupported_or_missing_host"] += 1
            return "unsupported_or_missing_host"
        user, source = self.index.identity(event)
        if not user:
            self.stats["identity_unresolved"] += 1
            return "identity_unresolved"
        if digest in self.used:
            return "duplicate"
        self.used.add(digest)
        delta = ref.Accumulator()
        artifact = ref.is_artifact(event)
        if not artifact:
            # Freeze the original feature contribution with evidence available
            # NOW. Later process/name evidence never recomputes this delta.
            ref.add_features(delta, event, user, self.index, ["restricted"])
        else:
            self.stats["orchestration_excluded"] += 1
        clock_bad = abs((ref.timestamp(event.envelope["timestamp"]) - moment).total_seconds()) > 300
        state = self.windows[user]
        location = (event.host, moment.date().isoformat())
        self.sequence += 1
        heapq.heappush(state.events, (moment, self.sequence, delta, location, clock_bad))
        state.update(delta, location, clock_bad, 1)
        self.stats["accepted_attributions"] += 1
        self.stats["process_linked"] += source == "host_process_guid"
        self.stats["late_received"] += ready > moment
        return "artifact" if artifact else "accepted"

    def snapshot(self, tick: datetime, user: str) -> tuple[dict, dict]:
        if self.last_ready is not None and tick < self.last_ready:
            raise ValueError("Snapshot would use future evidence")
        if self.last_tick is not None and tick < self.last_tick:
            raise ValueError("Prediction cutoffs must be monotonic")
        self.last_tick = tick
        state = self.windows[user]
        state.expire(tick - self.duration)
        observed = self.index.families_before(set(state.locations), tick)
        values = feature_values(state.accumulator(), observed, self.names)
        status = ("no_behavioral_telemetry" if not state.counts["windows_event_count"] else
                  "clock_unreliable" if state.clock_bad else "eligible")
        return values, {"Status": status, "MissingFeatures": "|".join(k for k,v in values.items() if v is None),
                        "ObservedFamilies": "|".join(sorted(observed)),
                        "WindowEventCount": state.counts["windows_event_count"],
                        "ClockDisagreementEvents": state.clock_bad}
