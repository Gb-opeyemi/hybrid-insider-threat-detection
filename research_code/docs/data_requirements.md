# Data and model requirements

The code is shared without the research dataset, raw logs, saved evaluation
results or fitted models. Imputers, checkpoints, databases and credentials are
also kept separately. Access to these files depends on the researcher's release
arrangements; no public dataset download is provided.

The synthetic tests can run without these inputs. Reproducing the numerical
results requires the original data or an approved release of it, together with
the appropriate reference files.

## Local file layout

The expected locations are shown below. These folders are ignored by Git.

```text
data/ground_truth/dataset_schedule_v3.csv
data/ground_truth/execution_ledger.csv
data/ground_truth/M05Results/*.json
data/wazuh/logs/archives/                 # JSONL .json and rotated .json.gz
data/wazuh/logs/alerts/
data/wazuh/etc/rules/                    # acquisition-specific rule XML
data/processed/                        # generated reference tables/manifests
data/snapshots/pre_temporal_fix/         # immutable original finalization inputs
data/notebook_outputs/                  # notebook intermediates and ml_ready matrices
models/                                 # fitted model artifacts, if authorised
artifacts/frozen_baseline/               # verified restoration/imputation bundle
results/                                # newly generated predictions/metrics/figures
```

The schedule uses the following columns:

```text
SessionID,SimulationDay,TimeOfDayUTC,ScenarioID,IntendedLabel,Username,Role,FileCount,FailedLogins,MinDelaySeconds,MaxDelaySeconds,ExecutionStatus
```

The execution ledger uses:

```text
SessionID,ScheduledUTC,ScenarioID,Username,ExecutionUTC,Status,Detail
```

Each M05 result contains SessionID, Scenario, ExecutedBy, Destination,
SourceFiles, StartedUTC, EndedUTC, Status, ValidationStatus, ErrorMessage,
FilesRequested, FilesTransferred, SourceBytes and TransferPerformed. Windows
records contain `data.win.system` and `data.win.eventdata`.

Original files remain unchanged. Ledger row order, timezone information, event
identities and missing values must be preserved during processing. A later
reconciliation entry is not automatically the activity's execution time.

## Preprocessing and rule files

The public feature-order file lists column names, not learned training medians.
Inference requires the verified training-derived preprocessing. Medians must not
be fitted on validation, test or new-session data.

The rules used to reconstruct the baseline must match the acquisition being
examined. The M05 template contains an example destination, which must be
configured for that acquisition. The resulting detections should be checked
against the saved development results before comparison.

## Lab components

The supplied 14-day scheduler, dispatchers, handlers, reconcilers and M05 worker
are described in the [simulation guide](../simulation/original_14_day/README.md).
Their publication copies use example addresses and identities. The schedule,
historical backups and pre-upgrade executor remain private.

The [M03/M04 watchers](../scripts/wazuh_watchers/README.md) and service examples
are also included. Their installed versions, index mappings and behaviour need
to be checked in a new environment. These files do not establish a complete
historical deployment record.

Accounts, shares, permissions, audit settings and scheduled-task definitions
still need to be supplied for lab reconstruction. The separate completed-session
runner supports new controlled activity rather than regenerating the original
14-day dataset.
