# Lab configuration

The public examples use placeholder domains, hosts and addresses. A local
configuration file supplies the settings for the actual lab without adding them
to Git.

Copy `config/lab.example.json` to `config/lab.local.json` and edit the copy.
The file contains account domains, the monitored computer prefix, the monitored
file root and the literal M05 `user@host` destination. It is ignored by Git and
should contain non-secret settings only.

`THESIS_LAB_CONFIG` can select another JSON file. Relative paths are resolved
inside this repository. The loader does not expand shell expressions or load
credentials. An explicitly selected file that is missing causes an error rather
than a fallback to different settings.

The examples use `EXAMPLE`, `LAB-SERVER` and reserved documentation addresses.
Actual values must be established before feature extraction or evaluation, rather
than chosen to improve test performance. Notebooks 04 and 08 and the offline
Wazuh baseline use these settings. Notebook 09 passes them to its baseline
reconstruction checks.

The detection thresholds and classification logic remain unchanged. Historical
reproduction requires the acquisition's lab settings and agreement with the
saved development predictions. The original private working code was not changed
when these public configuration options were added.

## M05 destination matching

In a regular expression, `.` matches any character. An escaped dot, `\.`, matches
an actual dot. For example, `198\.51\.100\.20` matches `198.51.100.20`; the
unescaped expression could also match `198x51x100x20`. The backslashes are matching
syntax, not part of a password or additional address.

The Python baseline searches for the configured destination as literal text with
`regex=False`. The Wazuh XML rule needs a regular expression, so the renderer uses
`re.escape()` on the same destination. This keeps both forms consistent.

The following command writes a new local rule file without installing it:

```sh
python -m scripts.integration.render_m05_rule \
  --config config/lab.local.json \
  --output data/generated_rules/thesis_m05_rules.xml
```

The generated file needs review against the original rule version and target
Wazuh installation before deployment. The M01-M04 rules are unchanged. The M05
file in `wazuh/rules/` is an example template, not evidence that its placeholder
endpoint was used in the research. It must not replace the live thesis rule as
part of a reproduction check.

## Windows and operational settings

The controlled Windows runner accepts `-AccountDomain`, `-LabServer`,
`-SourceShare`, `-RestrictedShare`, `-CredentialsDir` and `-OutputDir`. It checks
that both shares belong to the selected server. Its default address is an
example; credentials and Credential XML files must be provisioned locally.

The operational JSON and plist files also contain placeholders. Fixed receiver
paths, log paths and service labels are shared assumptions used by the client
and receiver. A different deployment layout needs a review of both sides, while
keeping the security checks in place.

The model and imputer verification bundle defaults to `artifacts/frozen_baseline/`.
An alternative location can be set through `THESIS_ARTIFACT_BUNDLE` before Python
starts. This is a process environment variable; the model-selection `.env` parser
does not load it. Fitted models remain under the ignored `models/` directory.

Hash, feature-order, dependency and checkpoint checks still apply after files
are moved. An original manifest must not be edited simply to pass verification.
Any replacement bundle needs its own reviewed evidence for the publication code.
