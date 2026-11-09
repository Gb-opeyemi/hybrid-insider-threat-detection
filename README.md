# Hybrid Insider Threat Detection

MSc Cybersecurity research prototype combining Wazuh telemetry with tabular machine-learning models for insider-threat detection in a simulated university.

## Dataset
- Simulated Windows Server 2019 and Windows 11 environment, with Wazuh 4.14.8.
- 14-day collection: 26 October to 8 November 2026.
- 1,200 scheduled sessions: 1,192 final Completed, 8 Failed, 0 Queued.
- Attack scenarios: M01 denied SMB access, M02 failed authentication, M03 high-volume file access, M04 deletion-related access, M05 SFTP exfiltration.
- Ground truth: simulation schedule, append-only execution ledger and M05 transfer result files.

## Repository layout
- scripts/backup: repeatable acquisition, packaging, checksums
- scripts/validation: session execution checks
- simulation: reviewed simulation sources (to be added)
- wazuh/rules: original and experimental rules (to be added)
- src: feature engineering, Random Forest, TabPFN, evaluation, integration (to be added)
- docs: methods, protocol and reproducibility notes (to be added)
- data: raw and generated datasets, excluded from Git

## Backups
Ubuntu: run scripts/backup/backup_wazuh.sh with optional --source, --output, --label.
Windows: run scripts/backup/backup_ground_truth.ps1, then package_ground_truth.ps1.
Check statuses with scripts/validation/check_simulation_sessions.ps1.

Raw event logs, ground truth, credentials and backup archives are not committed. The Wazuh snapshot produced a 'file changed as we read it' warning on an active archive; archive readability and SHA-256 do not establish an atomic capture. Late recovery telemetry must be distinguished from the original 14-day period.

## Research protocol
Use actual ledger outcomes and M05 results rather than scheduled labels alone. Keep sessions grouped and separate development data from a previously unseen evaluation set. The M01 rule investigation already used Day 12 events; those observations are development evidence, not independent holdout validation.
