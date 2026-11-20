# Hybrid Insider-Threat Detection with Wazuh and Machine Learning

This repository contains my MSc Cybersecurity project on insider-threat detection
in a simulated university environment. The study examines how machine learning
and Wazuh rules respond to benign and malicious activity carried out by synthetic
university accounts.

The research has two parts. The first develops an original labelled activity
dataset and compares Random Forest, TabPFN and Wazuh rule-based detection. The
second demonstrates a completed-session prototype that combines a selected
model's prediction with verified Wazuh evidence and publishes eligible hybrid
priorities to the Wazuh Dashboard.

## Dataset and experiments

The laboratory used Windows Server 2019, a Windows 11 client and Wazuh 4.14.8.
The original simulation covered 14 days, from 26 October to 8 November 2026, with
1,200 scheduled sessions: 900 intended benign and 300 intended malicious. The
execution records show 1,192 completed sessions and eight failures. All accounts
and activities were synthetic.

The benign scenarios include routine document work, occasional failed logins,
legitimate intensive access and approved transfers. The malicious scenarios
cover unauthorised access, suspicious authentication, excessive file access,
mass deletion and potential SFTP exfiltration.

Session labels and execution evidence are reconciled before Windows events are
attributed to activity sessions. The final models use 23 behavioural features.
The chronological experiment uses Days 1-8 for training, Days 9-10 for validation
and Days 11-14 for testing. Learned preprocessing is fitted on training data only.
Labels, scenario IDs, usernames, roles and Wazuh decisions are excluded from
model inputs.

## How the prototype works

A Windows runner records the selected account, session ID and actual activity
times. Wazuh forwards completion records, and the Mac service waits until the
session end plus 300 seconds before processing its telemetry. Python calculates
the original session features and runs either Random Forest or TabPFN. Random
Forest is the default; each session keeps one selected model.

The saved prediction is combined with Wazuh alerts that can be verified against
the same session. Eligible results are sent through the SSH publisher and appear
in the dashboard with their probability, priority and investigation warnings.
Unavailable evidence requires investigation rather than being treated as a
negative detection.

This is a controlled completed-session demonstration. It does not make continuous
rolling-window predictions, and its operational checks are separate from the
offline model evaluation.

## Code and architecture

The shareable implementation is in **[research_code/](research_code/README.md)**.
Its README covers Python setup, notebooks, required data and prototype installation.

| Location | Contents |
|---|---|
| [Research code](research_code/README.md) | Notebooks, Python modules, tests, configuration examples and Wazuh rules |
| [Simulation scripts](research_code/simulation/original_14_day/README.md) | Scheduler, activity handlers, reconciliation scripts and Windows 11 M05 worker |
| [M03/M04 watchers](research_code/scripts/wazuh_watchers/README.md) | Summary-generation scripts and service examples |
| [System overview](research_code/docs/diagrams/thesis_system_architecture_page_1.drawio) | Simplified editable architecture diagram |
| [Full architecture](research_code/docs/diagrams/thesis_full_system_architecture.drawio) | Detailed editable system diagram |

The diagrams can be opened in diagrams.net. Older backup and validation utilities
also remain in the repository; the setup instructions for the shared code are
under `research_code/`.

## Getting started

The Python code was checked on macOS with Python 3.13. From this repository's
root, the synthetic tests can be run with:

```sh
cd research_code
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -B -m unittest discover -s tests -q
```

These tests do not require the research dataset or a live Wazuh connection.
They do not train models or publish alerts. Additional dependencies and input
files are needed for the notebooks and fitted prototype:

- [Research workflow](research_code/docs/reproduction.md)
- [Data and model requirements](research_code/docs/data_requirements.md)
- [Lab configuration](research_code/docs/lab_configuration.md)
- [Windows, Ubuntu and Mac installation](research_code/docs/prototype_installation.md)

## Scope and availability

Raw telemetry, datasets, trained models, learned imputers, checkpoints and
credentials are not included. The required files must be supplied separately
to reproduce the numerical results or run the saved models. Full lab provisioning
is also outside the release.
