# Research workflow

The processing code follows the original simulation period of 26 October to
8 November 2026. The frozen chronological split uses Days 1-8 for training,
Days 9-10 for validation and Days 11-14 for testing. The required data and
reference files are listed in [data requirements](data_requirements.md).
Synthetic test data supports code checks, but cannot reproduce the thesis metrics.

## Processing order

`src.ground_truth` first reconciles the schedule, append-only execution ledger
and M05 results. `src.features` then validates archived events, attributes them
to sessions and calculates the reference features using information available
by each prediction cutoff.

`src.finalize_dataset` checks the original snapshot hashes and creates the
frozen reference split. Those snapshots are required inputs, not files to
reconstruct by guessing. Notebooks 01-06 cover exploration, event processing,
feature preparation and comparison with the reference tables.

Notebook 07 trains the RF and TabPFN baselines and evaluates validation data.
Its dependencies should be installed before the notebook is opened. Notebook
08 reconstructs the standalone Wazuh baseline. Notebook 09 compares the final
results and examines exploratory hybrid prioritisation, including checks against
the saved development detections.

Notebook 11 is a separate RF-only SMOTE experiment. It scales training data for
neighbour calculations, applies SMOTE only to that data, then returns samples
to their original units before fitting a clone of the RF baseline. Validation
data remains unchanged. This does not add scaling to the frozen baseline's
prediction process, and it is not a TabPFN augmentation experiment or a fresh
independent test. Fractional or implausible synthetic event counts are examined
rather than silently rounded.

Notebook kernels should start in this repository root or `notebooks/`. The
startup cell uses `.publication-root` to avoid selecting a parent working
project. Lab settings must match the supplied events. Cells should be run in
stages after checking their inputs; saved execution outputs are not distributed.

## Features, preprocessing and exclusions

The final trained order is recorded in `config/trained_feature_order.json` and
contains 23 features. The models use Notebook 06's training-only median
imputation, without added external scaling. Labels, scenarios, usernames,
roles, execution outcomes and Wazuh decisions remain outside model inputs.

The extraction allowlist can include a feature later removed because it was
constant in training. The saved trained schema therefore determines the final
inference columns. `src/preprocessing.py` remains for the earlier reference
finalisation stage because the finaliser imports it. Its older TabPFN scaling
recipe is not the final notebook recipe and must not replace the 23-feature
model's preprocessing.

All scheduled sessions remain in the master table. Failed executions,
ambiguous attribution, clock-quality problems and late recovery retain their
separate cohort flags. Unknown telemetry is not replaced with zero, and
scheduled times do not replace actual execution evidence.

Day 12 informed M01 rule development. The retrospective holdout is therefore
not an untouched independent Wazuh or hybrid test. Repeated simulated behaviours
also limit generalisation. The already examined test set must not be used for
further tuning.

## Operational prototype

The [installation guide](prototype_installation.md) explains the setup on each
machine. The first operational checks run with publication disabled.
`src.model_aware_service` selects the model for newly admitted jobs while
preserving the five-minute availability cutoff, account and host verification,
frozen inputs and Wazuh evidence policy. This demonstration is separate from
the offline evaluation. Tests and imports do not install live services.

Restoration requires a trusted bundle containing `run_manifest.json`,
`training_median_imputer.joblib`, `imputation_verification.json` and
`model_verification.json`, plus the fitted models and verified local TabPFN
checkpoint where applicable. The bundle is not distributed. Its location is
explained in [lab configuration](lab_configuration.md).

Missing verification evidence blocks restoration. The exact historical checkpoint
identity was not independently established during the original automatic
checkpoint selection; the available records should not be described as stronger
proof than they provide.

Some required helpers retain names from earlier experiments.
`experimental_replay/core.py` and `preflight.py` provide feature and loading
functions. `receive_hybrid_candidate.py` supplies receiver-ledger helpers.
These are dependencies, even though standalone replay analysis and debugging
commands are not part of the release. Tests use shared synthetic fixtures
instead of importing an excluded diagnostic command.

## Tests and external validation

```sh
python -m unittest discover -s tests -q
```

The suite checks data processing, synthetic M01-M05 detections, configuration,
completion discovery, cutoffs, RF/TabPFN verification, fusion, publication,
duplicate prevention, recovery and timing. It also invokes the full M01-M05
function test. It does not train real models, run notebooks or contact live
Wazuh and SSH services.

A clean external deployment has not been independently verified. Windows
execution and the installed Wazuh rule engine need checks in a configured lab.
The simulation scripts and [watchers](../scripts/wazuh_watchers/README.md) are
included with their setup and version limitations, but complete lab provisioning
is not supplied. Reproducing every numerical result therefore requires more
than downloading the code and running one command.
