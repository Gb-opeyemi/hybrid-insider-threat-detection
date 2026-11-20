# Hybrid Insider-Threat Detection with Wazuh and Machine Learning

This MSc Cybersecurity project examines insider-threat detection in a simulated
university environment. It includes an original labelled dataset of benign and
malicious Windows activity, an evaluation of Random Forest, TabPFN and Wazuh
rules, and a prototype that combines machine-learning predictions with Wazuh
evidence.

The prototype processes completed sessions. Wazuh collects the events, Python
extracts 23 behavioural features, and the selected model classifies the activity.
Verified Wazuh alerts are then used alongside that prediction to assign a hybrid
priority. Eligible results can be published to the Wazuh Dashboard. Random Forest
is the default, with TabPFN available as an alternative. Each session uses one model.

Processing starts at least five minutes after a session ends, allowing time for
events to arrive. The observation period comes from the session's recorded start
and end times. The system does not make continuous rolling-window predictions.
The offline model evaluation and the operational demonstration are assessed separately.

## Repository contents

| Folder | Contents |
|---|---|
| `notebooks/` | Exploration, dataset preparation, feature engineering, training and evaluation. Notebook 11 contains the separate RF-only SMOTE experiment. |
| `src/` | Data processing, model inference, completed-session processing and hybrid decisions. |
| `simulation/original_14_day/` | Original simulation scripts with example addresses and account names. |
| `scripts/` | Windows completion logging, M03/M04 watchers and Wazuh publication scripts. |
| `config/` and `wazuh/` | Configuration examples, feature order, experiment settings and Wazuh rules. |
| `tests/` | Automated checks using synthetic examples. |
| `docs/` | Setup guides, data requirements and editable architecture diagrams. |

The [overview diagram](docs/diagrams/thesis_system_architecture_page_1.drawio)
shows the main components. The
[full architecture](docs/diagrams/thesis_full_system_architecture.drawio) provides
more detail. Both files can be opened in diagrams.net.

## Python setup

The code was checked on macOS with Python 3.13. The requirements files record the
package versions from that environment. Installation on other systems has not
been independently checked, and the background service uses macOS launchd.

Run the following commands from the repository root, where this README, `src/`
and `notebooks/` are located. Python 3.13 must already be installed.

```sh
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

The synthetic test suite can then be run with:

```sh
python -B -m unittest discover -s tests -q
```

These checks do not require the research dataset, saved models or a live Wazuh
connection. They do not train models or publish alerts, making them a useful
first check before setting up the lab.

## Research notebooks

The dataset is supplied separately. Reproducing the experiments requires the
schedule, execution ledger, M05 results and Wazuh logs, together with the reference
files listed in [data requirements](docs/data_requirements.md). Some notebooks
compare their outputs with saved reference tables, so raw logs alone are not
enough to run the whole workflow.

The [processing guide](docs/reproduction.md) explains the order of execution.
The frozen split uses Days 1-8 for training, Days 9-10 for validation and Days
11-14 for testing. Preprocessing is fitted on training data only. The final
models use 23 behavioural features, training-derived median imputation and no
added external scaling.

Notebook 07's TabPFN sections require the additional packages below:

```sh
python -m pip install -r requirements-ml.txt
```

Notebook 11's separate SMOTE experiment requires:

```sh
python -m pip install -r requirements-smote.txt
```

Lab settings must match the supplied data. The
[configuration guide](docs/lab_configuration.md) explains the domains, hosts,
paths and transfer destination. The example values are placeholders. After these
settings and the required inputs are in place, start Jupyter from the repository root:

```sh
jupyter lab
```

Notebooks 01-09 follow the main research workflow, beginning with
`notebooks/01_data_exploration.ipynb`. Each notebook's inputs should be checked
before its cells are run. Notebook 11 is optional and follows the baseline
experiments. Saved cell outputs have been cleared.

## Hybrid prototype

The prototype requires a configured Windows/Wazuh lab. The research environment
used Windows Server 2019, a Windows 11 client and Wazuh 4.14.8 on Ubuntu, with a
Mac running the Python processing service.

The [installation guide](docs/prototype_installation.md) covers each machine's
setup, including event collection, completion logging, secure connections,
background processing and publication. The initial test runs with publication
disabled. Automatic publication is enabled only after the results have been checked.

Running the fitted prototype also requires the saved model files, training
median imputer and verification files listed in that guide. TabPFN needs its
verified local pretrained checkpoint and matching package versions. These files
are not included here. Model files should come from a trusted source; TabPFN
access and licence terms apply separately.

The model-aware service reads the model choice from a local `.env` file.
`.env.example` provides the starting setting:

```dotenv
THESIS_HYBRID_MODEL=random_forest
```

The other supported value is `tabpfn`. A change applies to newly admitted jobs;
sessions already being processed keep their recorded model choice. Selecting a
model does not enable publication. Credentials remain local, following the
installation guide's Keychain and SSH setup.

When Wazuh evidence cannot be verified, the result requires investigation.
Missing alerts are not treated as proof that the activity was benign.

## Data and lab access

Raw logs, datasets, trained models, evaluation outputs and credentials are
excluded by `.gitignore`. Without the required data and model files, the code
and synthetic tests remain available, but the thesis results and fitted
prototype cannot be reproduced.

The [simulation scripts](simulation/original_14_day/README.md) and
[M03/M04 watchers](scripts/wazuh_watchers/README.md) are included. A lab still
needs its own accounts, shares, permissions, audit settings and source documents.
The scripts do not create the entire environment or establish which version was
deployed on every simulation day. Their setup notes should be reviewed before
any execution in a separate test lab.

## Licence

A software licence has not been added. Third-party packages and TabPFN weights
have their own licence terms.
