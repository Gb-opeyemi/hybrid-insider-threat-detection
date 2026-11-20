"""Read-only training-prefix access and artifact/imputation compatibility gates."""
from __future__ import annotations

import csv
import io
import json
from importlib.metadata import version
from pathlib import Path
from zipfile import ZipFile

import joblib
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer

from .. import features as reference
from ..ground_truth import sha256


def read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def training_schedule(path: Path) -> list[dict]:
    """Stop at the first Day 9 row; never traverse the held-out tail."""
    result = []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            day = int(row["SimulationDay"])
            if day > 8:
                break
            if not 1 <= day <= 8:
                raise ValueError("Schedule is not a training prefix")
            result.append(row)
    return result


def training_prefix(path: Path, needed: set[str], allowed: set[str]) -> list[dict]:
    """Only accept training-prefix rows; stop immediately after required IDs.

    Original tables are in schedule order. A foreign ID stops the read rather
    than scanning/filtering a combined master through evaluation partitions.
    """
    result, found = [], set()
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            sid = row["SessionID"]
            if sid not in allowed:
                raise ValueError(f"Non-training ID reached in {path.name}; prefix read stopped")
            if sid in needed:
                if sid in found:
                    raise ValueError("Duplicate training SessionID")
                result.append(row)
                found.add(sid)
            if found == needed:
                break
    if found != needed:
        raise ValueError("Training prefix does not cover required IDs")
    return result


def verify_inputs(root: Path, output: Path) -> tuple[list[str], list[dict], dict, SimpleImputer]:
    """Verify original notebook training transform, not the old preprocessor."""
    manifest = read_csv(root / "data/processed/train_manifest.csv")
    if any(r["Partition"] != "train" or r["Included"] != "true" or not 1 <= int(r["SimulationDay"]) <= 8
           for r in manifest):
        raise ValueError("Training manifest contains non-training records")
    needed = {r["SessionID"] for r in manifest}
    schedule = training_schedule(root / "data/ground_truth/dataset_schedule_v3.csv")
    schedule_by = {r["SessionID"]: r for r in schedule}
    allowed = set(schedule_by)
    if len(needed) != len(manifest) or not needed <= allowed:
        raise ValueError("Training manifest IDs disagree with schedule")
    raw = training_prefix(root / "data/notebook_outputs/session_features_jupyter.csv", needed, allowed)
    reference_rows = training_prefix(root / "data/processed/session_features.csv", needed, allowed)
    prepared = read_csv(root / "data/notebook_outputs/ml_ready/train_ml.csv")
    names = [k for k in prepared[0] if k not in {"SessionID", "GroundTruthLabel"}]
    if len(names) != 23 or set(names) != set(reference.MODEL_INPUTS) - {"scp_process_count"}:
        raise ValueError("Unexpected trained behavioral schema")
    if {r["SessionID"] for r in prepared} != needed:
        raise ValueError("Prepared training IDs disagree")
    for model in ["random_forest", "tabpfn"]:
        meta = json.loads((root / "results" / model / "validation_metrics.json").read_text())
        # Only training provenance/schema fields are used; no validation data.
        if meta["feature_columns"] != names or meta["training_sessions"] != len(needed):
            raise ValueError("Training metadata/schema conflict")
        if model == "tabpfn" and meta["package_version"] != version("tabpfn"):
            raise ValueError("TabPFN package version changed since fitting")
    raw_by = {r["SessionID"]: r for r in raw}
    X = pd.DataFrame([{k: float(raw_by[r["SessionID"]][k]) if raw_by[r["SessionID"]][k] != "" else np.nan
                       for k in names} for r in prepared], columns=names)
    imputer = SimpleImputer(strategy="median")
    transformed = imputer.fit_transform(X)  # Reconstruct original TRAIN-ONLY preprocessing, not a classifier fit.
    expected = np.array([[float(r[k]) for k in names] for r in prepared])
    np.testing.assert_allclose(transformed, expected, atol=1e-12, rtol=0)
    if not np.isfinite(imputer.statistics_).all():
        raise ValueError("Training median unavailable")
    joblib.dump(imputer, output / "training_median_imputer.joblib")
    config = {"feature_names": names, "training_rows": len(prepared),
              "statistics": dict(zip(names, imputer.statistics_.tolist())),
              "training_missing_counts": X.isna().sum().to_dict(),
              "prepared_training_reconstruction_max_absolute_error": float(np.abs(transformed - expected).max()),
              "scaling": "none", "missing_indicator": False,
              "source": "Notebook 06 SimpleImputer(strategy='median'), fit only on original training rows"}
    (output / "imputation_verification.json").write_text(json.dumps(config, indent=2) + "\n")
    selected = []
    ref_by = {r["SessionID"]: r for r in reference_rows}
    for scenario in ["M03", "N06"]:
        group = sorted([r for r in manifest if r["ScenarioID"] == scenario],
                       key=lambda r: (reference.timestamp(r["ActualExecutionUTC"]), r["SessionID"]))[:2]
        if len(group) != 2:
            raise ValueError("Four-session pilot unavailable")
        for row in group:
            selected.append({**row, "Username": schedule_by[row["SessionID"]]["Username"],
                             "WindowStartUTC": ref_by[row["SessionID"]]["WindowStartUTC"],
                             "WindowEndUTC": ref_by[row["SessionID"]]["WindowEndUTC"],
                             "ObservationStartUTC": ref_by[row["SessionID"]]["ObservationStartUTC"],
                             "ObservationEndUTC": ref_by[row["SessionID"]]["ObservationEndUTC"]})
    selected.sort(key=lambda r: (reference.timestamp(r["ActualExecutionUTC"]), r["SessionID"]))
    references = {r["SessionID"]: r for r in reference_rows}
    return names, selected, {"raw": raw_by, "reference": references, "prepared": prepared,
                             "allowed": allowed, "schedule": schedule_by}, imputer


def verify_models(root: Path, output: Path, names: list[str], device: str):
    """Restore the saved state with existing local weights, never download/refit."""
    from tabpfn.model_loading import load_fitted_tabpfn_model, resolve_model_path
    import tabpfn.model_loading as loading
    from tabpfn.settings import settings
    import torch

    rf_path = root / "models/random_forest_baseline.joblib"
    tab_path = root / "models/tabpfn_baseline.tabpfn_fit"
    rf = joblib.load(rf_path)
    with ZipFile(tab_path) as archive:
        params = json.loads(archive.read("init_params.json"))
        attributes = joblib.load(io.BytesIO(archive.read("fitted_attrs.joblib")))
    if params["model_path"] != "auto":
        raise ValueError("Unexpected checkpoint selection; review required")
    paths = resolve_model_path(None, "classifier", settings.tabpfn.model_version.value)[0]
    if len(paths) != 1 or not paths[0].is_file():
        raise ValueError("Matching local TabPFN checkpoint unavailable; downloads forbidden")
    checkpoint = paths[0]
    # Pin current cached resolution and hash. The original fit omitted a weight
    # hash, so historical bit-for-bit provenance is explicitly not asserted.
    report = {"dependencies": {k: version(k) for k in ["tabpfn", "torch", "scikit-learn", "numpy", "pandas", "joblib"]},
              "rf_sha256": sha256(rf_path), "tabpfn_fit_sha256": sha256(tab_path),
              "checkpoint_path": str(checkpoint), "checkpoint_sha256": sha256(checkpoint),
              "resolved_model_version": settings.tabpfn.model_version.value,
              "device": device, "tabpfn_training_samples": attributes["n_train_samples_"],
              "checkpoint_provenance_limitation": "Original fit stored model_path=auto and no checkpoint hash. Current same-version cached checkpoint is pinned; historical byte identity cannot be independently proven."}
    for obj in [rf, attributes]:
        features = obj["feature_names_in_"] if isinstance(obj, dict) else obj.feature_names_in_
        classes = obj["classes_"] if isinstance(obj, dict) else obj.classes_
        if list(features) != names or list(classes) != [0, 1]:
            raise ValueError("Model feature order or classes disagree")
    if device == "mps" and not torch.backends.mps.is_available():
        raise ValueError("Requested MPS unavailable")
    original_download = loading.download_model
    def forbid_download(*args, **kwargs):
        raise ValueError("Network checkpoint download is forbidden")
    loading.download_model = forbid_download
    try:
        tab = load_fitted_tabpfn_model(tab_path, device=device)
    finally:
        loading.download_model = original_download
    if list(tab.feature_names_in_) != names or tab.n_train_samples_ != 659:
        raise ValueError("Restored TabPFN contract disagrees")
    report["restored"] = True
    (output / "model_verification.json").write_text(json.dumps(report, indent=2) + "\n")
    return rf, tab, report
