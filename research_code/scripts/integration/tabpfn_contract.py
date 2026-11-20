"""Stdlib-only TabPFN wire schema for the undeployed receiver candidate."""
import hashlib
import math
import re
from datetime import timedelta
from .receive_ml_prediction import CUSTOM_RULE_IDS, canonical, completed_session_id, utc

FUSION_POLICY_VERSION = 'rf_wazuh_priority_v1_exploratory'

def identity(event):
    keys = ('schema_version', 'event_type', 'selected_model', 'session_id', 'activity_start',
            'activity_end', 'observation_start', 'observation_end', 'prediction_cutoff',
            'model_sha256', 'checkpoint_sha256', 'feature_schema_sha256', 'synthetic')
    return hashlib.sha256(canonical({k: event[k] for k in keys}).encode()).hexdigest()


FIELDS = set('schema_version event_type mode historical_replay synthetic selected_model prediction_id session_id username activity_start activity_end observation_start observation_end prediction_cutoff model model_artifact model_sha256 checkpoint_sha256 feature_schema_sha256 source_results_sha256 ml_prediction_id ml_classification ml_malicious_probability benign_probability prediction_score wazuh_detected wazuh_evidence_verified wazuh_evidence_status matched_rule_ids verified_matching_alerts unresolved_alert_count unresolved_rule_ids unresolved_evidence_reasons hybrid_priority investigation_required fusion_policy_version fusion_adapter telemetry_completeness_status telemetry_review_required telemetry_missing_features'.split())


def validate(event):
    if not isinstance(event, dict) or set(event) != FIELDS:
        raise ValueError('Unexpected TabPFN hybrid payload fields')
    if (type(event['schema_version']) is not int or event['schema_version'] != 1
            or event['event_type'] != 'thesis_tabpfn_hybrid_priority' or event['mode'] != 'completed_session_tabpfn_hybrid'
            or event['selected_model'] != 'tabpfn' or event['model'] != 'TabPFN'
            or event['model_artifact'] != 'models/tabpfn_baseline.tabpfn_fit'
            or event['historical_replay'] is not True or type(event['synthetic']) is not bool
            or event['fusion_policy_version'] != FUSION_POLICY_VERSION
            or event['fusion_adapter'] != 'tabpfn_to_existing_binary_policy_v1'):
        raise ValueError('Unsupported TabPFN model/schema/policy')
    user = event['username']
    if not isinstance(user, str) or not 1 <= len(user) <= 128 or any(ord(c) < 32 or ord(c) == 127 for c in user):
        raise ValueError('Invalid account identity')
    start, end = utc(event['activity_start']), utc(event['activity_end'])
    if (not start < end or utc(event['observation_start']) != start - timedelta(seconds=2)
            or utc(event['observation_end']) != end + timedelta(seconds=2)
            or utc(event['prediction_cutoff']) != end + timedelta(seconds=300)
            or event['session_id'] != completed_session_id(user, event['activity_start'], event['activity_end'])):
        raise ValueError('TabPFN activity/availability/session identity mismatch')
    for name in ('model_sha256', 'checkpoint_sha256', 'feature_schema_sha256', 'source_results_sha256', 'ml_prediction_id', 'prediction_id'):
        if not isinstance(event[name], str) or not re.fullmatch('[0-9a-f]{64}', event[name]):
            raise ValueError('Invalid TabPFN provenance digest')
    p, b, score = [event[n] for n in ('ml_malicious_probability', 'benign_probability', 'prediction_score')]
    if any(type(v) not in (int, float) or not math.isfinite(v) or not 0 <= v <= 1 for v in (p, b, score)):
        raise ValueError('Invalid TabPFN probability')
    # TabPFN returns float32 probabilities. Preserve the actual values and allow
    # their floating-point sum error; do not renormalize or change decisions.
    if (event['ml_classification'] not in {'benign', 'malicious'} or abs(p + b - 1) > 1e-6
            or abs(score - (p if event['ml_classification'] == 'malicious' else b)) > 1e-9):
        raise ValueError('Inconsistent TabPFN probabilities/classification')
    if (event['wazuh_evidence_verified'] is not True or type(event['wazuh_detected']) is not int
            or event['wazuh_detected'] != 1 or event['wazuh_evidence_status'] != 'verified_positive'
            or event['investigation_required'] is not True
            or event['hybrid_priority'] != ('High Priority' if event['ml_classification'] == 'malicious' else 'Needs Review')):
        raise ValueError('Verified positive Wazuh evidence and consistent fusion required')
    for name in ('verified_matching_alerts', 'unresolved_alert_count'):
        if type(event[name]) is not int or event[name] < (1 if name == 'verified_matching_alerts' else 0):
            raise ValueError('Invalid evidence counts')
    for name in ('matched_rule_ids', 'unresolved_rule_ids'):
        value = event[name]
        if not isinstance(value, str): raise ValueError('Flat rule IDs required')
        ids = value.split(',') if value else []
        if ids != sorted(set(ids)) or not set(ids) <= CUSTOM_RULE_IDS:
            raise ValueError('Invalid rule IDs')
    if not event['matched_rule_ids'] or len(event['matched_rule_ids'].split(',')) > event['verified_matching_alerts']:
        raise ValueError('Missing verified matching rule evidence')
    for name, bound in [('unresolved_evidence_reasons', 1024), ('telemetry_missing_features', 2048)]:
        value = event[name]
        if not isinstance(value, str) or len(value) > bound or any(ord(c) < 32 for c in value):
            raise ValueError('Invalid review metadata')
    if (bool(event['unresolved_alert_count']) != bool(event['unresolved_rule_ids'])
            or bool(event['unresolved_alert_count']) != bool(event['unresolved_evidence_reasons'])
            or event['telemetry_completeness_status'] not in {'potentially_incomplete', 'unverified'}
            or event['telemetry_review_required'] is not True):
        raise ValueError('Uncertainty must remain visible')
    if event['prediction_id'] != identity(event) or len(canonical(event).encode()) > 8064:
        raise ValueError('TabPFN payload identity/size mismatch')
    return event

