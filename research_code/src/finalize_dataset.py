"""Version causal datasets and the one frozen split; fit preprocessing only."""

from __future__ import annotations

import argparse
import csv
import json
import shutil
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn

from .features import FEATURES, MODEL_INPUTS, main as extract_main, timestamp, write_csv
from .ground_truth import OUTPUT_FIELDS, sha256
from .preprocessing import make_preprocessor, numeric_frame


def read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def verify_snapshots(folder: Path) -> dict[str, str]:
    expected = {}
    for line in (folder / "SHA256SUMS.txt").read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.strip().split(maxsplit=1)
        name = name.lstrip("*")
        if Path(name).name != name or name in expected:
            raise ValueError("Unexpected snapshot checksum path or duplicate")
        expected[name] = digest.lower()
    if set(expected) != {"session_features.csv", "ml_dataset.csv"}:
        raise ValueError("Snapshot checksum manifest must cover both preserved CSVs")
    if any(sha256(folder / name) != digest for name, digest in expected.items()):
        raise ValueError("Preserved snapshot checksum mismatch; nothing may be published")
    return {**expected, "SHA256SUMS.txt": sha256(folder / "SHA256SUMS.txt")}


def original_inventory(data_root: Path) -> dict:
    return {str(path): sha256(path) for name in ["raw", "ground_truth", "wazuh"]
            for path in sorted((data_root / name).rglob("*")) if path.is_file()}


def split_name(day: int, config: dict) -> str:
    for name in ["train", "validation", "test"]:
        first, last = config[f"{name}_days"]
        if first <= day <= last:
            return name
    raise ValueError("Day not covered by frozen chronological split")


def validate_split_config(config: dict) -> None:
    covered = [day for name in ["train", "validation", "test"]
               for day in range(config[f"{name}_days"][0], config[f"{name}_days"][1] + 1)]
    if covered != list(range(1, 15)):
        raise ValueError("Split must be three nonempty contiguous ordered partitions of Days 1-14")


def split_rows(rows: list[dict], config: dict) -> tuple[list[dict], dict]:
    validate_split_config(config)
    start = date.fromisoformat(config["start_date"])
    manifest = []
    for row in rows:
        name = split_name(int(row["SimulationDay"]), config)
        included = row["FeatureOriginal14DayCohortEligible"] == "true"
        reasons = []
        if row["MLTrainingEligible"] != "true":
            reasons.append("failed_or_ground_truth_ineligible")
        if row["ClockPolicyStatus"] == "excluded_unreliable_reference":
            reasons.append("clock_reference_unreliable")
        if int(row["AmbiguousArchiveCandidates"]) or row["PriorOverlapExclusion"] == "true":
            reasons.append("overlap_ambiguity")
        if row["FeatureMLTrainingEligible"] != "true" and not reasons:
            reasons.append("causal_telemetry_ineligible")
        if row["LateRecovery"] == "true":
            reasons.append("late_recovery_extended_only")
        lower_day, upper_day = config[f"{name}_days"]
        lower = timestamp((start + timedelta(days=lower_day - 1)).isoformat() + "T00:00:00Z")
        upper = timestamp((start + timedelta(days=upper_day)).isoformat() + "T00:00:00Z")
        if included and (timestamp(row["ObservationStartUTC"]) < lower or timestamp(row["PredictionCutoffUTC"]) >= upper):
            included = False
            reasons.append("observation_crosses_partition_boundary")
        manifest.append({"SessionID": row["SessionID"], "SimulationDay": row["SimulationDay"],
                         "Partition": name, "Included": str(included).lower(),
                         "ScenarioID": row["ScenarioID"], "GroundTruthLabel": row["GroundTruthLabel"],
                         "PredictionCutoffUTC": row["PredictionCutoffUTC"],
                         "ActualExecutionUTC": row["ActualExecutionUTC"],
                         "LateRecovery": row["LateRecovery"],
                         "ExclusionReasons": "|".join(reasons),
                         "Day12PriorDevelopmentEvidence": str(int(row["SimulationDay"]) == 12).lower()})
    groups = {name: [row for row, decision in zip(rows, manifest)
                     if decision["Partition"] == name and decision["Included"] == "true"]
              for name in ["train", "validation", "test"]}
    if any(not group for group in groups.values()):
        raise ValueError("A frozen partition has no eligible sessions")
    for first, second in [("train", "validation"), ("validation", "test")]:
        if max(timestamp(row["PredictionCutoffUTC"]) for row in groups[first]) >= min(timestamp(row["ObservationStartUTC"]) for row in groups[second]):
            raise ValueError("Actual observation intervals cross chronological partitions")
    return manifest, groups


def comparison(before: list[dict], after: list[dict]) -> tuple[dict, list[dict]]:
    by_id = {row["SessionID"]: row for row in before}
    if len(before) != len(after) or len({r["SessionID"] for r in after}) != len(after) or set(by_id) != {r["SessionID"] for r in after}:
        raise ValueError("Master session set/count changed")
    changes, counts = [], Counter()
    for row in after:
        prior = by_id[row["SessionID"]]
        if any(prior[key] != row[key] for key in OUTPUT_FIELDS):
            raise ValueError("Ground truth changed during causal feature regeneration")
        for key in sorted(set(row) | set(prior)):
            if prior.get(key, "") != row.get(key, ""):
                changes.append({"SessionID": row["SessionID"], "Column": key,
                                "Before": prior.get(key, ""), "After": row.get(key, "")})
                counts[key] += 1
    return {"before_rows": len(before), "after_rows": len(after), "ground_truth_changes": 0,
            "changed_cells_by_column": dict(sorted(counts.items())),
            "changed_feature_cells": sum(counts[name] for name in FEATURES)}, changes


def finalize(root: Path, version: Path, snapshots: Path, config_path: Path) -> dict:
    config = json.loads(config_path.read_text())
    validate_split_config(config)
    snapshot_hashes = verify_snapshots(snapshots)
    original = original_inventory(root.parent)
    ground_hash = sha256(root / "session_ground_truth.csv")
    before = read_csv(snapshots / "ml_dataset.csv")
    result = extract_main(["--output-dir", str(version), "--ground-truth", str(root / "session_ground_truth.csv"),
                           "--ground-truth-report", str(root / "validation_report.json"),
                           "--source-dir", str(root.parent / "ground_truth"),
                           "--wazuh-dir", str(root.parent / "wazuh"),
                           "--review-baseline", str(snapshots / "ml_dataset.csv"),
                           "--padding-seconds", str(config["padding_seconds"])])
    if result != 0:
        raise ValueError("Causal extraction did not pass; publication refused")
    rows = read_csv(version / "ml_dataset.csv")
    features = read_csv(version / "session_features.csv")
    manifest, groups = split_rows(rows, config)
    distributions = {}
    for name, group in groups.items():
        labels = Counter("Benign" if row["GroundTruthLabel"] == "0" else row["ScenarioID"] for row in group)
        distributions[name] = {"days": config[f"{name}_days"], "total": len(group),
                               **{key: labels[key] for key in ["Benign", "M01", "M02", "M03", "M04", "M05"]}}
        absent = [key for key in ["Benign", "M01", "M02", "M03", "M04", "M05"] if distributions[name][key] == 0]
        if absent:
            raise ValueError(f"Frozen {name} split lacks {absent}; document limitation, never move boundaries silently")
    for merged, feature, decision in zip(rows, features, manifest):
        for target in [merged, feature]:
            target["ExperimentPartition"] = decision["Partition"]
            target["ExperimentIncluded"] = decision["Included"]
    write_csv(version / "ml_dataset.csv", list(rows[0]), rows)
    write_csv(version / "session_features.csv", list(features[0]), features)
    write_csv(version / "split_manifest.csv", list(manifest[0]), manifest)
    for name in groups:
        selected = [row for row in manifest if row["Partition"] == name and row["Included"] == "true"]
        write_csv(version / f"{name}_manifest.csv", list(manifest[0]), selected)

    preprocessing = {}
    retained = None
    for name in ["random_forest", "tabpfn"]:
        pipeline = make_preprocessor(name)
        # This is the ONLY fit: no y, classifier, validation or test is passed.
        pipeline.fit(numeric_frame(groups["train"]))
        columns = list(pipeline.get_feature_names_out())
        if retained is not None and columns != retained:
            raise ValueError("Preprocessing recipes disagree on retained behavioral columns")
        retained = columns
        shapes = {}
        for partition, group in groups.items():
            matrix = pipeline.transform(numeric_frame(group))
            if not np.isfinite(matrix.to_numpy()).all():
                raise ValueError("Preprocessing left non-finite values")
            shapes[partition] = list(matrix.shape)
        joblib.dump(pipeline, version / f"{name}_preprocessor.joblib")
        preprocessing[name] = {"input_columns": MODEL_INPUTS, "retained_columns": columns,
                               "removed_training_constants": [x for x in MODEL_INPUTS if x not in columns],
                               "imputer_statistics": pipeline["impute"].statistics_.tolist(),
                               "scaler_mean": pipeline["scale"].mean_.tolist() if name == "tabpfn" else None,
                               "matrix_shapes": shapes, "fitted_partition": "train", "classifiers_fitted": False}
    if set(retained) & (set(OUTPUT_FIELDS) | {"protected_resource_event_count"}):
        raise ValueError("Forbidden predictor survived preprocessing")
    schema = json.loads((version / "feature_schema.json").read_text())
    schema["preprocessing_input_columns"] = MODEL_INPUTS
    schema["predictive_columns"] = retained
    schema["model_predictive_columns"] = {"random_forest": retained, "tabpfn": retained}
    schema["training_only_constant_columns"] = [name for name in MODEL_INPUTS if name not in retained]
    schema["metadata_columns"] += ["ExperimentPartition", "ExperimentIncluded"]
    (version / "feature_schema.json").write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
    (version / "preprocessing_parameters.json").write_text(json.dumps(preprocessing, indent=2, sort_keys=True) + "\n")
    shutil.copy2(config_path, version / "experiment_config.json")
    report = json.loads((version / "feature_validation_report.json").read_text())
    for name in report["output_sha256"]:
        report["output_sha256"][name] = sha256(version / name)
    report["final_predictive_columns"] = retained
    (version / "feature_validation_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    changes, cells = comparison(before, rows)
    write_csv(version / "changed_values.csv", ["SessionID", "Column", "Before", "After"], cells)
    changes["snapshots_sha256"] = snapshot_hashes
    changes["after_sha256"] = {name: sha256(version / name) for name in ["session_features.csv", "ml_dataset.csv"]}
    changes["eligibility_counts"] = {
        "before_feature_ml": sum(r["FeatureMLTrainingEligible"] == "true" for r in before),
        "after_feature_ml": sum(r["FeatureMLTrainingEligible"] == "true" for r in rows),
        "before_strict": sum(r["FeatureOriginal14DayCohortEligible"] == "true" for r in before),
        "after_strict": sum(r["FeatureOriginal14DayCohortEligible"] == "true" for r in rows)}
    (version / "before_after_comparison.json").write_text(json.dumps(changes, indent=2, sort_keys=True) + "\n")
    summary = {"version": config["version"], "status": "prepared_for_model_training_with_stated_limitations",
               "master_rows": len(rows), "ground_truth_unchanged": True, "classifiers_trained": False,
               "distributions": distributions, "predictive_columns": retained,
               "clock_excluded": sum(row["ClockPolicyStatus"] == "excluded_unreliable_reference" for row in rows),
               "prior_overlap_excluded": sum(row["PriorOverlapExclusion"] == "true" for row in rows),
               "failed_excluded": sum(row["FinalExecutionStatus"] == "Failed" for row in rows),
               "versions": {"sklearn": sklearn.__version__, "numpy": np.__version__, "pandas": pd.__version__, "joblib": joblib.__version__},
               "snapshot_checksums_intact": True, "config_sha256": sha256(config_path),
               "code_sha256": {name: sha256(Path(__file__).parent / name) for name in
                               ["features.py", "ground_truth.py", "preprocessing.py", "finalize_dataset.py"]},
               "limitations": [config["test_limitation"], "M04 support is small: no claim of production generalization.",
                               "End-of-session classification uses externally observed experimental boundaries.",
                               "Late recovery is retained in the master but outside the strict-period experiment.",
                               "Observed zeros and as-of collection support do not prove continuous auditing.",
                               "Worker outcomes remain provisional and are not automatically independently verified."]}
    if verify_snapshots(snapshots) != snapshot_hashes or sha256(root / "session_ground_truth.csv") != ground_hash:
        raise ValueError("Snapshot or original ground truth changed")
    if original_inventory(root.parent) != original:
        raise ValueError("Original telemetry/ground truth/acquisition files changed")
    summary["original_file_sha256"] = original
    summary["artifact_sha256"] = {p.name: sha256(p) for p in sorted(version.iterdir()) if p.is_file()}
    (version / "final_readiness.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    # Publish only after every validation succeeds. All prior metadata is retained.
    metadata_backup = version / "previous_metadata"
    metadata_backup.mkdir()
    names = ["session_features.csv", "ml_dataset.csv", "feature_schema.json", "feature_validation_report.json",
             "split_manifest.csv", "train_manifest.csv", "validation_manifest.csv", "test_manifest.csv"]
    for name in names:
        if (root / name).exists() and name not in {"session_features.csv", "ml_dataset.csv"}:
            shutil.copy2(root / name, metadata_backup / name)
        temporary = root / (name + ".temporal-v2.tmp")
        shutil.copy2(version / name, temporary)
        temporary.replace(root / name)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processed-dir", type=Path, default=Path("data/processed"))
    parser.add_argument("--snapshots", type=Path, default=Path("data/snapshots/pre_temporal_fix"))
    parser.add_argument("--config", type=Path, default=Path("config/experiment.json"))
    parser.add_argument("--version-dir", type=Path, default=Path("data/processed/versions/temporal-v2"))
    args = parser.parse_args(argv)
    if args.version_dir.exists():
        parser.error("Version directory exists; refusing to overwrite")
    if not args.version_dir.resolve().is_relative_to(args.processed_dir.resolve()):
        parser.error("Version outputs must remain under the processed-data directory")
    if args.version_dir.resolve().is_relative_to(args.snapshots.resolve()):
        parser.error("Snapshot directories are immutable")
    summary = finalize(args.processed_dir, args.version_dir, args.snapshots, args.config)
    print(json.dumps({key: summary[key] for key in ["status", "master_rows", "distributions", "clock_excluded",
                                                   "prior_overlap_excluded", "failed_excluded", "predictive_columns"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
