"""Legacy train-only reference-finalization factories, not the final 23-feature
Notebook 06/07 model recipe. The latter uses no external TabPFN scaling.
No classifiers or classifier fitting live here.
"""

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_selection import VarianceThreshold
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .features import MODEL_INPUTS


def numeric_frame(rows: list[dict]) -> pd.DataFrame:
    """Only the fixed behavioral allowlist enters the numeric frame."""
    return pd.DataFrame({name: [float(row[name]) if row[name] != "" else np.nan for row in rows]
                         for name in MODEL_INPUTS})


def make_preprocessor(model: str) -> Pipeline:
    if model not in {"random_forest", "tabpfn"}:
        raise ValueError("Only the two planned preprocessing recipes are supported")
    selector = ColumnTransformer([("behavior", "passthrough", MODEL_INPUTS)],
                                 remainder="drop", verbose_feature_names_out=False)
    pipeline = Pipeline([
        ("allowlist", selector),
        ("impute", SimpleImputer(strategy="median", keep_empty_features=True)),
        ("remove_constants", VarianceThreshold(threshold=0.0)),
        ("scale", StandardScaler() if model == "tabpfn" else "passthrough"),
    ])
    return pipeline.set_output(transform="pandas")
