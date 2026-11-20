"""Deterministic operational priority fusion for a completed user session.

This module deliberately does NOT fetch Wazuh alerts, modify the stored RF
prediction, or publish messages. The caller must provide an independently
validated session-matched Wazuh M01-M05 decision.

Policy matches the *exploratory* Notebook 09 Cell E decision table:
    RF=1, Wazuh=1 -> High Priority
    RF!=Wazuh      -> Needs Review
    RF=0, Wazuh=0 -> Low Risk

When Wazuh evidence cannot be verified, assign Evidence Unavailable rather
than assuming that no rule fired. Treat this as requiring manual review.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

FUSION_POLICY_VERSION = "rf_wazuh_priority_v1_exploratory"


@dataclass(frozen=True)
class HybridDecision:
    rf_detected: int
    wazuh_detected: int | None
    wazuh_evidence_verified: bool
    hybrid_priority: str
    high_priority_alert: int
    review_required: int
    fusion_policy_version: str = FUSION_POLICY_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _binary(value: object, field: str) -> int:
    # Strict validation avoids silent truthiness of strings such as "0".
    if type(value) is bool:
        return int(value)
    if type(value) is int and value in (0, 1):
        return value
    raise ValueError(f"{field} must be integer 0/1 or bool, got {value!r}")


def fuse_hybrid_priority(
    rf_detected: bool | int,
    wazuh_detected: bool | int | None,
    *,
    wazuh_evidence_verified: bool,
) -> HybridDecision:
    """Fuse completed-session RF classification with verified Wazuh rules.

    Ground truth and RF probability are intentionally not inputs. An unknown
    Wazuh status is *not* silently interpreted as a negative rule result.
    """
    rf_flag = _binary(rf_detected, "rf_detected")
    if type(wazuh_evidence_verified) is not bool:
        raise ValueError("wazuh_evidence_verified must be bool")

    if wazuh_detected is None:
        if wazuh_evidence_verified:
            raise ValueError("Verified Wazuh evidence requires a 0/1 decision")
        return HybridDecision(
            rf_detected=rf_flag,
            wazuh_detected=None,
            wazuh_evidence_verified=False,
            hybrid_priority="Evidence Unavailable",
            high_priority_alert=0,
            review_required=1,
        )

    wazuh_flag = _binary(wazuh_detected, "wazuh_detected")
    if not wazuh_evidence_verified:
        raise ValueError(
            "Unverified Wazuh evidence must be represented by None, "
            "not by a seemingly definitive 0/1 flag"
        )

    if rf_flag == 1 and wazuh_flag == 1:
        priority = "High Priority"
    elif rf_flag != wazuh_flag:
        priority = "Needs Review"
    else:
        priority = "Low Risk"

    return HybridDecision(
        rf_detected=rf_flag,
        wazuh_detected=wazuh_flag,
        wazuh_evidence_verified=True,
        hybrid_priority=priority,
        high_priority_alert=int(priority == "High Priority"),
        review_required=int(priority != "Low Risk"),
    )
