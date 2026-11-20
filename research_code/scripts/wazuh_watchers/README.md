# M03 and M04 summary watchers

The Ubuntu watchers query Wazuh archives and write JSON summaries for the M03
and M04 rules. They run separately from the Mac's completed-session ML process.
The four public Python copies replace the original agent name with `LAB-SERVER`;
the remaining executable logic is unchanged. Original files and source/copy
hashes are retained privately. Credentials, state and output logs are not included.

## Detection behaviour

| Script | Behaviour |
|---|---|
| `thesis_m03_counter.py` | Searches the last 30 minutes, groups 4663 events into fixed five-minute buckets and reports more than 30 distinct paths after bucket end + 120 seconds. |
| `thesis_m04_counter.py` | Uses the same buckets and delay, filters exact accessMask `0x10000` and reports at least five distinct paths. |
| `thesis_m03_counter_realtime.py` | Searches a trailing five-minute window and reports when a user first exceeds 30 distinct paths. Further reports are suppressed while the user stays above the threshold. |
| `thesis_m04_counter_realtime.py` | Uses the rolling approach with the exact DELETE accessMask and at least five distinct paths. |
| `thesis_detection_runner.sh` | Runs the two fixed-window scripts in sequence and returns failure if either fails. |

The queries filter the agent name, event ID 4663 and the UniversityData
object-path regular expression. Time grouping uses `@timestamp`, not Windows
`systemTime`. The installed mapping must establish what that timestamp means;
it must not be assumed to match the ML event-time or availability clocks.

Distinct-path counts come from an indexer cardinality aggregation. They are not
necessarily exact counts of file operations. DELETE access also does not prove
that a file was deleted. Queries return up to 100 username buckets and do not
explicitly reject timed-out or partial-shard responses. These limitations remain
in the supplied code.

Fixed-window scripts remember reported username/bucket IDs for 30 days. Rolling
scripts store users currently above the threshold and allow another report
after their count drops below it. Removing state can cause repeated summaries.
Appending output and saving state are separate operations, so a crash can also
cause repetition. This differs from the hybrid receiver's publication ledger.

## Service selection

| Supplied service or file | Effect |
|---|---|
| `thesis-detection.service` and timer | Runs the combined fixed-window scripts every five minutes. |
| `thesis-m03.service` and timer | Runs fixed-window M03 every five minutes unless the drop-in is installed. |
| `thesis-m03.service.d/override.conf` | Changes M03's command to the rolling script without changing its five-minute timer. |
| `thesis-m04.service` and timer | Runs rolling M04 30 seconds after activation and after each inactive interval. |

These files offer alternatives; they do not establish which was installed on
every simulation day. The combined timer and individual timers must not be
enabled together. They use different locks, so concurrent operation could write
competing summaries. Installed units and drop-ins can be reviewed with
`systemctl cat`. The selected version and timing belong in the experiment record.

## Ubuntu setup

Installation should take place in a separate test lab. The original evidence
environment and existing watcher state should remain unchanged.

Archived 4663 records must contain the expected agent, username, objectName,
accessMask and `@timestamp` fields. The regular expression needs checking against
actual file paths. Ordinary-string and raw-string versions are preserved as
supplied; their matching behaviour must be checked for the selected script.

Each watcher reads a private configuration file at `/etc/thesis-m03/indexer.json`
or `/etc/thesis-m04/indexer.json`. Both need string fields `url`, `username`,
`password` and `ca_cert`. The account needs read-only search access. Configuration
files should be root-owned with mode 0600, inside mode-0700 directories. Passwords
must remain local, outside the repository and command-line arguments.

TLS uses `ssl.create_default_context(cafile=...)`. The watchers do not inherit
the Mac client's TLS-profile settings. An incompatible certificate requires a
reviewed certificate or connection change, not disabled verification.

The directories `/var/lib/thesis-m03` and `/var/lib/thesis-m04` must exist and be
writable; fixed-window scripts do not create them. Summary files are appended at
`/var/ossec/logs/thesis_m03_detections.json` and
`/var/ossec/logs/thesis_m04_detections.json`. Wazuh must be able to read them.
Upgrades must preserve these files and existing state rather than truncate them.

The `LAB-SERVER` literal must be replaced with the verified exact `agent.name`.
These scripts do not read `config/lab.local.json` or Mac Keychain credentials.
Their Linux paths are explicit installation assumptions. Thresholds, clocks and
query behaviour must remain fixed for a historical reproduction claim.

The selected scripts belong at the `/usr/local/bin/` paths in their service
units. Files should be root-owned and not writable by simulated users. Python
files can use mode 0644 because the services invoke `/usr/bin/python3`; the shell
runner needs executable permission. Only the selected units and drop-in belong
under `/etc/systemd/system/`. The supplied services run as root and have not been
redesigned as hardened service accounts.

After a backup, merge these inputs into the manager's existing `ossec_config`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/thesis_m03_detections.json</location>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/thesis_m04_detections.json</location>
</localfile>
```

The files in `rules/` match `wazuh/rules/` byte for byte. Only one copy should be
installed, after checking rule IDs 100301 and 100401 for conflicts. Configuration
can be checked with `wazuh-analysisd -t` and synthetic summaries with
`wazuh-logtest`. A manager restart follows review of those checks.

The chosen systemd files also need validation before `systemctl daemon-reload`
and timer activation. Collection, query results and summary attribution should
be checked in the separate lab first. Syntax checks alone do not establish
runtime correctness. Copying these files into the repository did not activate
any timer or execute a watcher.

## Session attribution limits

Summary JSON contains a username, count, window start and detection ID. Rolling
versions add detection time. The records do not contain a verified account
domain, original host or simulation SessionID. A summary alone therefore cannot
establish an unambiguous completed-session detection.

The hybrid verifier keeps incomplete summaries unresolved. Their presence does
not justify a positive decision, and their absence does not prove a negative.
The [prototype installation guide](../../docs/prototype_installation.md) covers
the separate Mac inference and publication process. Its end + 300-second
availability cutoff is distinct from the watchers' five-minute windows and the
fixed-window 120-second delay.
