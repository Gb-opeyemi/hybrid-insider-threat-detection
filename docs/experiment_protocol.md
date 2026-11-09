# Experimental protocol (draft)

1. Preserve immutable source backups and checksums outside Git.
2. Confirm date coverage and actual event completeness, including late recovery activity.
3. Match schedule to the final ledger entry per SessionID; exclude or label separately eight failed executions.
4. Independently verify scenario outcomes (particularly M05) before assigning attack labels.
5. Build session-level telemetry features from raw archives, including events that never triggered Wazuh alerts.
6. Establish Wazuh v1 baseline, Random Forest baseline, then TabPFN; optionally Isolation Forest.
7. Use a chronological or group-aware split; never randomly split alerts from the same session across training and test.
8. Report per-scenario precision/recall/F1, false positives, failure to detect, and limitations.
9. Evaluate combined Wazuh + ML predictions without using labels or future observations as inference features.
10. Run a new, untouched validation set when possible; events already studied for M01 rule tuning cannot be called independent test data.

Record code revision, feature schema, random seed, train/test window and environment versions for every experiment.
