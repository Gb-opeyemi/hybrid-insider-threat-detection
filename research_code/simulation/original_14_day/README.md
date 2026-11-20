# Original 14-day simulation scripts

These scripts were supplied as the Windows code used for dataset generation.
They are separate from the newer lifecycle-driven operational service. Neither
Python imports nor the notebooks install or run them automatically.

The public copies replace private server addresses with reserved documentation
addresses. The M05 worker identity is consistently represented as
`EXAMPLE\example.user` or `example.user`. Files use a UTF-8 BOM and Windows line
endings for PowerShell 5.1. Unchanged originals and their SHA-256 inventory are
retained privately. This collection alone does not establish the exact version
deployed on every simulation day.

## Script roles

| File | Purpose |
|---|---|
| `server/DatasetScheduler.ps1` | Reads the 1,200-row schedule, derives dates from 26 October 2026, selects due sessions and appends ledger entries. |
| `server/DatasetTaskRunner.ps1` | Runs the scheduler with `-RunDue -MaxSessions 20` and records its output. |
| `server/NormalActivityController.ps1` | Runs the scheduled N01-N07 benign activities. |
| `server/MaliciousDispatcher.ps1` | Routes M01-M04 to their handlers; M03 uses DatasetExecutor. |
| `server/DatasetExecutor.ps1` | Runs the file-access activity selected by the M03 dispatcher route. |
| `server/SimulationController.ps1` | An additional supplied file-access controller; inclusion does not prove that every version was deployed. |
| `server/M01Handler.ps1` | Attempts access to restricted shares. |
| `server/M02Handler.ps1` | Generates failed authentication followed by correct authentication, with an account-lockout policy check. |
| `server/M04Handler.ps1` | Runs deletion activity in the designated workspace. |
| `server/ResearchFileSelector.ps1` | Selects files from the lab's research-document hierarchy. |
| `server/M05QueueDispatcher.ps1` | Writes pending M05 jobs for the Windows 11 worker. |
| `windows11_worker/M05Worker.ps1` | Validates jobs, performs SFTP transfers and writes result JSON. |
| `server/M05ResultReconciler.ps1` | Compares scheduler and worker evidence to produce reconciliation output. |
| `server/SessionOutcomeReconciler.ps1` | Reconciles outcomes and can append changes to the execution ledger. |

The runner at `scripts/windows_reference/Invoke-CompletedSession.ps1` serves a
different purpose: new controlled tests of the operational prototype. Historical
scripts must not replace it or feed old completions into an armed service.

## Separate files and prerequisites

The schedule CSV remains private research data. Its required location is
explained in the [data guide](../../docs/data_requirements.md). No replacement
schedule or inferred labels are generated. Historical backups and
`DatasetExecutor-PreM05Upgrade.ps1` are retained privately so that earlier
versions are not confused with the main entry points. They may support a later
version audit.

The release does not contain credential XML, SSH keys, account/domain setup,
SMB share and ACL creation, source documents, task-registration definitions,
audit/Sysmon policy or the complete SFTP server setup. The
[M03/M04 watchers](../../scripts/wazuh_watchers/README.md) are supplied separately.
These scripts improve access to the method, but do not provide a complete lab
installation or prove the exact configuration used throughout the simulation.

## Environment settings

The scripts retain the original directory layout under
`C:\UniversityData\Simulation`, including `Scripts`, `Credentials`,
`Dataset2026\dataset_schedule_v3.csv`, scheduler state and result folders. They
also expect the research-document tree. Server scripts refer to one another
through the `Scripts` directory and should be installed together there. The
Windows 11 worker belongs on its separate host.

Saved credentials must be created for the Windows user and machine running the
scripts and must match the selected accounts. Group names, resource names and
file-name restrictions are part of the simulation setup.

The public examples use `198.51.100.10` for Windows/SMB and `198.51.100.20` for
the SFTP receiver. The worker checks its example identity, job username and
destination; the scheduler also restricts M05 to that worker account. These
values must be reviewed together with the schedule and M05 Wazuh rule.
The historical scripts do not load `config/lab.local.json`, so editing that file
does not update their settings.

The receiver username `m05receiver`, remote `/received` directory and SSH key
filename describe the expected setup. They are not supplied credentials.

## Execution precautions

`DatasetTaskRunner` and the scheduler's `-RunDue` option must not be used as
casual installation checks in an existing lab. The dates are fixed in the past;
with an empty ledger, many historical sessions could immediately become due.
M04 deletes files, M05 transfers documents and the reconcilers write evidence.
Any approved regeneration needs disposable synthetic files and a separate lab.
The original ledger must remain unchanged, and regenerated activity must not be
presented as the original experimental dataset.

Source and private-copy checksums were verified when these files were included.
No PowerShell execution, replay, transfer, deletion, task creation or model
training took place during that work. Windows execution remains a separate
validation step. The [prototype guide](../../docs/prototype_installation.md)
covers installation of the operational system.
