# Controlled-session prototype installation

The prototype connects a Windows activity runner, Wazuh collection, a Mac
processing service and an SSH alert publisher. Random Forest is the default.
TabPFN is a separate model option that requires its own verification. Processing
uses completed sessions, not continuous rolling-window predictions.

The sections below identify where each command runs. Paths and example addresses
must be replaced with the lab's actual settings. The synthetic tests passed
during release preparation, but a clean external installation has not been
independently verified. The instructions do not activate services on their own.

## 1. Required components

| Component | Included? | Additional requirement |
|---|---|---|
| Python code, tests and configuration examples | Yes | A Mac account with Python and launchd access |
| Windows activity runner and completion helper | Yes | Windows Server 2019, synthetic accounts, credential XML, SMB shares and audited files |
| Historical dataset-generation scripts | Sanitised copies | Schedule, lab setup and task definitions; see `simulation/original_14_day/README.md` |
| Wazuh agent, manager, indexer and dashboard | No | A working Wazuh lab; the research used version 4.14.8 |
| Security and Sysmon collection | Not configured by the repository | Audit policies, file/share auditing, Sysmon and event-channel collection |
| M01-M05 rules | Yes, including an M05 template | Reviewed installation and matching telemetry; M03/M04 watchers are supplied separately |
| Fitted RF and training median imputer | No | Trusted files with the required verification evidence |
| Fitted TabPFN and pretrained checkpoint | No | Matching files, dependencies and applicable access/licence terms |
| Credentials, SSH keys, certificates and private settings | No | Local configuration and authenticated connections |

Missing models, preprocessing evidence or telemetry producers block installation.
Invented medians or edited hashes cannot replace verification. Missing M03/M04
summaries also cannot establish a negative detection. The
[data guide](data_requirements.md) lists the separately supplied inputs; the code
alone cannot regenerate the whole 14-day experiment.

A new installation belongs in a separate lab. Existing deployments need backups
and a review of their settings before changes. State, logs, authorized keys and
rules must not be replaced with empty files or examples.

## 2. Mac: Python and local configuration

The commands run from the repository root containing `.publication-root`, `src/`
and `config/`. The selected Python environment should use the verified package
versions. After activation, `python` must refer to that environment.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -B -m unittest discover -s tests -q
```

`requirements-ml.txt` adds TabPFN and PyTorch when needed. The pinned versions
come from the checked Python 3.13 environment, not a complete cross-platform
lockfile. The supplied model's dependency record must agree with the installed
packages. Any mismatch needs resolution with the artifact provider before the
operational service runs; package upgrades should not be tested on that service.

```sh
mkdir -p data/experiments/operational_service/private
chmod 700 data/experiments/operational_service/private
cp -n config/operational_service_wazuh.example.json data/experiments/operational_service/private/service_wazuh.json
cp -n config/operational_connection.example.json data/experiments/operational_service/private/connection.json
cp -n config/model_aware_service.example.json data/experiments/operational_service/private/model_aware.json
cp -n config/lab.example.json config/lab.local.json
```

The copied private files need local values and mode-0600 permissions. Existing
configuration must be preserved rather than overwritten. The repository should
be writable only by trusted operators. Ignored folders can still hold sensitive
captures and state.

The [lab configuration guide](lab_configuration.md) covers non-secret domains,
hosts, paths and the literal M05 destination. Its example values must be replaced
before processing real lab data. The M05 XML can then be generated locally if needed.

## 3. Mac: saved models and preprocessing

The fitted RF prototype requires these files from a trusted artifact source:

```text
models/random_forest_baseline.joblib
artifacts/frozen_baseline/run_manifest.json
artifacts/frozen_baseline/training_median_imputer.joblib
artifacts/frozen_baseline/imputation_verification.json
artifacts/frozen_baseline/model_verification.json
```

TabPFN also requires `models/tabpfn_baseline.tabpfn_fit` and its verified local
checkpoint. Restoration uses `load_fitted_tabpfn_model` on CPU without retraining.
Automatic checkpoint downloads are blocked. The checks in
`src/tabpfn_prototype/artifacts.py` cover checkpoint location and automatic
resolution, hashes, dependencies, the 23-column order and fitted training population.

The bundle supplies the original training-only medians, feature order and model
verification. No external scaling is added. The older factory in
`src/preprocessing.py` is not a substitute, and a new session must not be used
to fit an imputer.

`artifacts/frozen_baseline/` is the default bundle directory. Another location
can be set with the process environment variable `THESIS_ARTIFACT_BUNDLE`
before Python starts. The model-selector `.env` parser does not read that setting.
The default location avoids an extra launchd environment setting. Moving files
or changing code can require a separately reviewed verification bundle; the
release has no command that creates trustworthy provenance from missing evidence.

Models trained through the notebooks need their schema, medians and provenance
reviewed and packaged before operational use. Notebook training alone does not
create this installation bundle.

## 4. Ubuntu and Mac: indexer access

On Ubuntu, first check the Windows agent connection and archive indexing:

```sh
sudo /var/ossec/bin/agent_control -l
sudo grep -n 'logall_json' /var/ossec/etc/ossec.conf
sudo grep -n -A4 -B2 'archives:' /etc/filebeat/filebeat.yml
```

The application reads non-alert events as well as `wazuh-alerts-*`. The manager
needs JSON archive logging, and Filebeat's Wazuh archives input must be enabled.
Missing settings need administrator review, a backup and validation before only
the affected services are restarted. This guide assumes Wazuh is already installed.

The Mac needs a trusted copy of the indexer's CA certificate, obtained through
an authenticated administrator channel. The indexer account needs read-only
mapping, count, search and scroll access for both index patterns. Scroll cleanup
is permitted; retrieval does not need document-write access. Credentials must
not appear in URLs or command arguments.

An existing authenticated tunnel can be reused. Otherwise, a separately
approved administrative SSH alias can forward the indexer connection:

```sh
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
  -L 127.0.0.1:9200:127.0.0.1:9200 wazuh-tunnel
```

The example forwards to Ubuntu loopback. A separate indexer host needs its actual
destination. SSH host keys must be verified through a trusted channel. This
alias and key allow forwarding; they are different from the restricted
publication connection. The tunnel runs independently of polling, and the
repository does not install a tunnel supervisor.

In the private `connection.json` created above, set the HTTPS URL, archive and
alert patterns, and absolute CA path. `strict` TLS is preferred where compatible.
`legacy_ca` relaxes an additional X.509 conformance flag for the reviewed lab CA;
it is not equivalent to strict mode. Both retain certificate-chain and hostname
verification. A hostname mismatch needs a reviewed certificate or connection
change, not `verify=False` or `curl -k`.

macOS Keychain Access stores two generic password items in the login keychain.
Both use the service name `thesis-operational-wazuh`:

| Account | Stored value |
|---|---|
| `WAZUH_INDEXER_USERNAME` | Existing indexer username |
| `WAZUH_INDEXER_PASSWORD` | Existing indexer password |

The trusted `/usr/bin/security` lookup may prompt for local access. Credentials
stay out of the plist, JSON and repository `.env`. launchd does not inherit
terminal exports, so the launcher reads Keychain. An unavailable Keychain or
tunnel blocks processing.

## 5. Windows: completion logging

The deployment copy and feed UUID are generated on the Mac:

```sh
python -B -m scripts.operational.prepare_windows_completion_runner \
  --output-dir data/experiments/operational_service/windows_bundle_01
python -c 'import uuid; print(uuid.uuid4())'
```

The UUID becomes `FEED_ID`. The two generated PowerShell files are transferred
together to `C:\ThesisScripts` through an approved administrator channel and kept
writable only by trusted administrators. The generator leaves the reference
runner unchanged and refuses an existing output directory.

The service account and host are checked in elevated Windows PowerShell 5.1:

```powershell
Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'" |
    Select-Object Name, StartName, PathName
Get-Service WazuhSvc
$env:COMPUTERNAME
```

The following fresh-installation example assumes Wazuh runs as LocalSystem and
the trusted runner runs as an administrator. It creates the restricted lifecycle log:

```powershell
$dir = 'C:\ProgramData\ThesisHybrid'
if (Test-Path -LiteralPath $dir) { throw 'Inspect existing directory and ACLs first' }
New-Item -ItemType Directory -Path $dir | Out-Null
icacls.exe $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
if ($LASTEXITCODE -ne 0) { throw 'ACL setup failed' }
New-Item -ItemType File -Path "$dir\session_lifecycle.jsonl" | Out-Null
```

Different service or runner accounts need explicit access for those accounts.
Simulated users must not have write access to the completion log. After backing
up the installed agent `ossec.conf`, merge `config/windows_completion_localfile.xml`
inside its existing `ossec_config`. The whole configuration must not be replaced.
XML validation and administrator review come before restarting `WazuhSvc` and
checking that the agent reconnects.

Security and Sysmon collection must remain enabled. The runner does not create
domain accounts, SMB shares, file SACLs, audit policy or Sysmon configuration.
The separate [M03/M04 watchers](../scripts/wazuh_watchers/README.md) also need
review before Ubuntu installation. Local audit checks do not establish full
23-feature coverage or continuous collection; the expected events must be
confirmed in Wazuh.

Saved PSCredential XML belongs under `CredentialsDir`, created by the Windows
account and machine running the script. It must contain the selected
`DOMAIN\username` and remain private. The runner checks it before activity.
`-AccountDomain`, `-LabServer`, `-SourceShare` and `-RestrictedShare` must describe
the actual lab, and both shares must belong to `LabServer`.

PowerShell can run under Administrator while SMB uses a synthetic user. Event
attribution must retain that distinction rather than assign the controller's
activity to the selected SMB account.

## 6. Mac: discovery and initial dry-run

`service_wazuh.json` needs the absolute repository root, actual agent ID with
leading zeros, `FEED_ID` and exact lifecycle log location. `host_aliases` maps
the lifecycle host to verified Security/Sysmon computer names, such as its FQDN.
Only evidence-supported aliases are acceptable; a mismatch is not a reason to
accept arbitrary hosts.

`model_aware.json` needs absolute paths for `rf_config`, `connection`,
`state_dir` and `tabpfn_state_dir`. Router and worker state use separate new
folders under `operational_service/model_aware/` and
`tabpfn_prototype/model_aware/`. An existing legacy database must not be reused.
`legacy_label` stays unchanged, and both configurations initially disable publication:

```json
"dry_run": true,
"enable_publication": false
```

The repository-root `.env` sets the model. An existing file should be edited
without replacing unrelated entries:

```dotenv
THESIS_HYBRID_MODEL=random_forest
```

The scheduled launcher reads `.env` on every poll and ignores an inherited
model-selector export. Each admitted job keeps its model choice, so a later
file edit cannot switch it halfway through processing. RF remains selected for
the first check.

Only one scheduler can own the workflow. An existing legacy service needs its
pending work reviewed and paused or drained before its LaunchAgent is unloaded.
The new launcher refuses to run while the legacy label is loaded.

From the repository root:

```sh
python -B -m src.model_aware_service --config data/experiments/operational_service/private/model_aware.json selection
python -B -m src.model_aware_service --config data/experiments/operational_service/private/model_aware.json init
python -B -m src.model_aware_service --config data/experiments/operational_service/private/model_aware.json feed-check
```

`init` sets the one-time admission boundary. Only sessions starting afterward can
enter the new queue. It neither runs inference nor publishes. State must not be
deleted or initialised again to replay older sessions.

A successful empty `feed-check` confirms query access, but not decoding of actual
Windows records. The first fresh Started/terminal pair also needs verification.
For a separately approved new controlled session, the generated runner executes
on Windows with the reviewed account, shares, paths and feed UUID:

```powershell
& 'C:\ThesisScripts\Invoke-CompletedSession.ps1' `
  -User 'example.user' -AccountDomain 'EXAMPLE' -Mode Benign `
  -LabServer 'YOUR_LAB_SERVER' `
  -SourceShare '\\YOUR_LAB_SERVER\YOUR_SOURCE_SHARE' `
  -RestrictedShare '\\YOUR_LAB_SERVER\YOUR_RESTRICTED_SHARE' `
  -CredentialsDir 'C:\YOUR_PRIVATE_CREDENTIALS_DIRECTORY' `
  -CompletionFeedID 'YOUR_FEED_UUID'
```

This command is for a new isolated test, not historical sessions or production
files. The activity is chosen before its prediction is known. Failed execution
and `audit_not_verified` are ineligible. Completion messages contain identity,
host, timestamps and status, without labels, roles, scenario IDs or activity mode.

On the Mac, repeated `once` calls advance the initial dry-run. A poll advances
ready stages rather than completing every stage immediately:

```sh
python -B -m src.model_aware_service --config data/experiments/operational_service/private/model_aware.json once
python -B -m src.model_aware_service --config data/experiments/operational_service/private/model_aware.json status
python -B -m src.model_aware_service --config data/experiments/operational_service/private/model_aware.json events
```

The saved request, retrieval and validation audits, hybrid result and timing
records show whether the run followed its original interval. Inference cannot
start before actual end + 300 seconds. The event-time window remains start -
2 seconds to end + 2 seconds, and the receipt cutoff stays at end + 300 seconds
through later polls, indexing and retries. Identity evidence is also restricted
by availability. Original seven-digit Windows timestamps are retained, while
Python comparisons use microsecond precision.

An eligible verified-positive run can reach `prepared_not_published`. A benign
run with no verified Wazuh negative may instead end in Evidence Unavailable and
investigation. Missing events are not automatically zero. Telemetry warnings
and unresolved M03 summaries remain visible. Defaults allow three attempts per
stage, 60 seconds apart; exhausted failures require investigation.

## 7. Ubuntu: receiver and dashboard rules

Receiver installation follows a successful dry-run and administrator approval.
The dedicated publication account, shown as `thesisml`, uses an SSH key and has
no sudo permission. Files are staged through a separate administrative channel.
From the staged repository root, the standard-library receiver modules are installed with:

```sh
sudo install -d -o root -g root -m 0755 /usr/local/lib/thesis-hybrid/scripts/integration
sudo install -o root -g root -m 0644 \
  scripts/integration/receive_ml_prediction.py \
  scripts/integration/receive_hybrid_candidate.py \
  scripts/integration/tabpfn_contract.py \
  scripts/integration/model_publication_contract.py \
  scripts/integration/guarded_receiver.py \
  /usr/local/lib/thesis-hybrid/scripts/integration/
sudo install -o root -g root -m 0755 scripts/integration/model_aware_receiver_entry.py \
  /usr/local/lib/thesis-hybrid/model_aware_receiver_entry.py
sudo install -d -o root -g root -m 0755 /etc/thesis-hybrid
sudo install -d -o thesisml -g thesisml -m 0700 /var/log/thesis-ml
```

Existing files and ownership need review before upgrades. The receiver depends
on the `scripts/integration/` package layout, and its code must not be writable
by the SSH account. A fresh installation needs four history/lock files. Existing
ones must be retained without truncation:

```sh
for name in predictions.jsonl tabpfn_predictions.jsonl hybrid_ownership.jsonl hybrid_guard.lock; do
  path="/var/log/thesis-ml/$name"
  if sudo test -e "$path"; then
    echo "Preserve existing file: $path"
  else
    sudo install -o thesisml -g thesisml -m 0600 /dev/null "$path"
  fi
done
sudo install -o root -g root -m 0644 config/model_aware_receiver_policy.example.json \
  /etc/thesis-hybrid/publication-policy.json
```

An existing policy needs a backup before the template is installed. The example
sets `schema_version: 1` and `mode: model_aware`. Ownership claims and both model
histories are checked under one lock. Identical retries return duplicate
acknowledgements; changed payloads and competing model claims are rejected.

The publishing key's authorized_keys entry uses this forced command:

```text
restrict,command="/usr/bin/python3 -I /usr/local/lib/thesis-hybrid/model_aware_receiver_entry.py" ssh-ed25519 YOUR_PUBLIC_KEY
```

The real public key replaces the placeholder. Unrelated authorized keys remain
unchanged, and the file needs a backup. The account's `.ssh` directory and
authorized_keys use appropriate ownership and modes 0700 and 0600. Every
publication entry point must pass through the same receiver; an old unguarded
key would bypass cross-model protection. The publication key is separate from
tunnel and administrator access.

The corresponding alias belongs in the Mac's private SSH configuration:

```sshconfig
Host thesis-ml-manager
    HostName YOUR_MANAGER_HOST
    User thesisml
    IdentityFile ~/.ssh/YOUR_PUBLICATION_PRIVATE_KEY
    IdentitiesOnly yes
    BatchMode yes
    StrictHostKeyChecking yes
```

Trusted known_hosts entries and noninteractive key access must be configured
locally. The private key stays out of the repository. The client sends a fixed
command, while the server forces execution of the receiver. An arbitrary
`ssh ... echo` check will not test this setup because the receiver expects a
validated JSON request.

Before rule installation, check IDs on Ubuntu:

```sh
sudo grep -R -nE 'id="11051[0-2]"|id="11052[0-2]"' /var/ossec/etc/rules /var/ossec/ruleset/rules
```

Any match needs review. An already installed identical thesis rule must not be
added twice; an unrelated collision blocks the proposed ID. With no conflict,
`config/phase3_hybrid_priority_rules.xml` and the optional
`config/tabpfn_hybrid_priority_rules.xml` are installed as separate root-owned,
Wazuh-readable files under `/var/ossec/etc/rules/`. M01-M05 definitions and
thresholds remain unchanged.

After backing up manager `ossec.conf`, merge `config/phase2_ml_replay_localfile.xml`
and, for TabPFN, `config/tabpfn_hybrid_localfile.xml` into its existing
`ossec_config`. These rules use the built-in JSON decoder. Both prediction files
must be readable by Wazuh; the ownership ledger must not be collected as alerts.

Before real publication, synthetic TabPFN and RF payloads can be generated on the Mac:

```sh
mkdir -p data/experiments/installation_rule_test
PYTHONPATH=tests python -B -c \
  'import json; from test_model_aware_publication import tab_event; print(json.dumps(tab_event()))' \
  > data/experiments/installation_rule_test/synthetic_tabpfn.json
PYTHONPATH=tests python -B -c \
  'import json; from test_model_aware_publication import synthetic_hybrid; print(json.dumps(synthetic_hybrid()))' \
  > data/experiments/installation_rule_test/synthetic_rf.json
```

The generated files are transferred through the administrator staging channel.
On Ubuntu, configuration and rule tests run with:

```sh
sudo /var/ossec/bin/wazuh-analysisd -t
sudo /var/ossec/bin/wazuh-logtest -l /var/log/thesis-ml/tabpfn_predictions.jsonl < synthetic_tabpfn.json
sudo /var/ossec/bin/wazuh-logtest -l /var/log/thesis-ml/predictions.jsonl < synthetic_rf.json
```

The TabPFN High Priority fixture should match 110521; Needs Review uses 110522.
RF uses 110511 and 110512 respectively. Logtest checks both synthetic records
without appending a real publication. Unit tests check receiver rejection and
duplicate handling separately; synthetic records must not be inserted into
production history.

After the installed configuration and rule tests pass, an approved manager
restart loads the collection inputs and rules. Backups remain available for rollback.

## 8. Mac: background dry-run service

The log directory `~/Library/Logs/ThesisHybrid` needs mode 0700. A private copy of
`config/launchd/org.thesis.hybrid-model-aware.plist` needs absolute paths to the
verified Python executable, repository, private `model_aware.json` and output
logs. Passwords do not belong in it.

`Disabled` becomes false only when activation is approved. The installed copy
belongs at `~/Library/LaunchAgents/org.thesis.hybrid-model-aware.plist`, mode
0600. An existing working plist must be preserved first.

```sh
plutil -lint "$HOME/Library/LaunchAgents/org.thesis.hybrid-model-aware.plist"
launchctl enable "gui/$(id -u)/org.thesis.hybrid-model-aware"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/org.thesis.hybrid-model-aware.plist"
launchctl print "gui/$(id -u)/org.thesis.hybrid-model-aware"
tail -n 50 "$HOME/Library/Logs/ThesisHybrid/model-aware.stdout.log"
tail -n 50 "$HOME/Library/Logs/ThesisHybrid/model-aware.stderr.log"
```

The LaunchAgent polls every 30 seconds under the logged-in Mac account and exits
between polls. A zero exit code does not prove successful session processing;
`status`, `events` and saved audits provide that evidence. The Mac, Keychain and
SSH tunnel must remain available.

Future sessions no longer need manual `once` calls after activation. A separately
approved new controlled session should complete the unattended dry-run before
publication is enabled.

## 9. Publication and dashboard checks

After dry-run and receiver checks pass, explicit approval allows these two fields
to change in the complete private model-aware configuration:

```json
"dry_run": false,
"enable_publication": true
```

The configuration is saved atomically between polls. Newly eligible jobs can
then claim ownership and publish. Previously held dry-run jobs remain held;
this launcher has no bulk historical-release command. State must not be reset
to release them. Unavailable evidence cannot pass the verified-positive
publication requirement.

Ownership and publication acknowledgements need matching prediction IDs and
`guard_version: 1`. A receiver acknowledgement confirms append acceptance, not
completed indexing. In Wazuh Dashboard's Discover view, select `wazuh-alerts-*`
and a time range covering publication, then search:

```text
rule.id:"110511" AND data.event_type:"thesis_hybrid_priority"
```

For TabPFN, the equivalent filter uses rule 110521 and event type
`thesis_tabpfn_hybrid_priority`. The payload's `data.session_id` can differ from
the Windows lifecycle UUID; job records link them. The displayed classification,
probability, matched rules, priority, investigation status, unresolved evidence,
telemetry completeness and timestamps should agree with the saved result.
These are historical controlled-session predictions, not new live incidents.

## 10. Model changes, stopping and recovery

TabPFN needs its fitted model, checkpoint and completed local dry-run verified
before selection. With publication disabled, `.env` can be saved atomically as
`THESIS_HYBRID_MODEL=tabpfn`. `random_forest` selects RF again. Existing jobs keep
their original model; a failed TabPFN run does not become an RF fallback. The
receiver prevents competing model publications for the same activity interval.

The scheduled service can be stopped without deleting state:

```sh
launchctl bootout "gui/$(id -u)/org.thesis.hybrid-model-aware"
launchctl disable "gui/$(id -u)/org.thesis.hybrid-model-aware"
```

Restarting uses the earlier enable/bootstrap commands, not another `init`.
Publication alone can be paused with `dry_run: true` and
`enable_publication: false`. An immediate processing stop requires unloading the
agent first; a configuration edit cannot recall an in-flight submission.

| Symptom | Evidence to check |
|---|---|
| No session discovered | Running/connected `WazuhSvc`, fresh lifecycle pair, archive indexing, correct agent/feed/location and a start after arming |
| Feed schema failure | Saved audit and original lifecycle JSON; missing terminal fields must not be filled by guessing |
| HTTPS failure | Tunnel, trusted CA, certificate hostname, TLS profile, Keychain and read-only index permissions |
| Host mismatch | Lifecycle and Security/Sysmon host values; aliases need independent evidence |
| Model or dependency failure | Artifact hashes, imputer, schema, checkpoint path and the verified package environment |
| Evidence Unavailable | Alert-query audit, clocks, original cutoff, attribution and watcher availability; absent matches are not verified negatives |
| Prepared but not published | Publication flags, held-job status, receiver policy, SSH and publication diagnostics |
| Acknowledged but absent in Discover | Log collection, loaded rules, Filebeat/indexing, index pattern and publication-time range |

A full return to a pre-existing legacy RF service requires stopping the
model-aware agent, reviewing pending ownership claims and preserving both
databases. Under an approved rollback, the receiver policy can be set to
`legacy_rf`. New TabPFN claims and writes are then blocked, while legacy RF can
publish unclaimed results.

The shared receiver and history checks remain in place. Restoring an unguarded
receiver would lose cross-model protection. The preserved legacy plist can be
restored only after competing workers have stopped. Models, ledgers, databases
and published alerts remain unchanged.

## Source files and final checks

Completion handling is implemented in
`scripts/operational/prepare_windows_completion_runner.py`,
`scripts/operational/Write-WazuhSessionLifecycle.ps1` and
`src/wazuh_completion_feed.py`. `src/model_aware_service.py` and
`src/model_aware_orchestrator.py` control processing. RF inference and evidence
checks use `src/controlled_replay/new_session.py` and
`src/controlled_replay/hybrid_session.py`; TabPFN uses `src/tabpfn_prototype/`.
Fusion is in `src/hybrid_priority.py`. Publication uses
`src/model_aware_publication.py` and `scripts/integration/guarded_receiver.py`.
The examples in this guide need review; they are not automatic installers.

A completed installation needs a recorded fresh lifecycle pair, correct cutoff
and execution time, verified feature/model provenance, Wazuh evidence result,
hybrid result, receiver acknowledgement and one indexed dashboard alert. An
unavailable-evidence case should stop for investigation. Repeated polling must
not duplicate publication, and restart must retain the job and model choice.
These checks establish operation of the prototype, not statistical detection
accuracy or proof that every expected event was collected.
