"""Restore the verified fitted model and median imputer, without fitting/downloads."""
from contextlib import contextmanager
from importlib.metadata import version
from pathlib import Path
import joblib
import numpy as np
from .. import features as ref
from ..controlled_replay.app import PILOT
from .common import read, sha


def frozen(root):
    root = Path(root); pilot = root / PILOT
    previous = read(pilot / 'run_manifest.json')
    paths = [pilot / name for name in ('training_median_imputer.joblib',
                                     'imputation_verification.json', 'model_verification.json')]
    for path in paths:
        if sha(path) != previous['artifacts_sha256'][path.name]:
            raise ValueError('Frozen preprocessing/model verification changed')
    info, models = read(paths[1]), read(paths[2])
    names = info['feature_names']
    if (len(names) != 23 or len(set(names)) != 23
            or set(names) != set(ref.MODEL_INPUTS) - {'scp_process_count'}
            or info['scaling'] != 'none' or info['missing_indicator'] is not False):
        raise ValueError('Frozen 23-feature preprocessing contract differs')
    model_path = root / 'models/tabpfn_baseline.tabpfn_fit'
    checkpoint = Path(models['checkpoint_path']).resolve()
    if sha(model_path) != models['tabpfn_fit_sha256'] or sha(checkpoint) != models['checkpoint_sha256']:
        raise ValueError('TabPFN artifact/checkpoint hash differs')
    for package, expected in models['dependencies'].items():
        if version(package) != expected:
            raise ValueError('Dependency version differs from verified TabPFN environment: ' + package)
    imputer = joblib.load(paths[0])
    if list(imputer.feature_names_in_) != names or imputer.strategy != 'median' or imputer.add_indicator:
        raise ValueError('Frozen median imputer contract differs')
    np.testing.assert_allclose(imputer.statistics_, [info['statistics'][n] for n in names], rtol=0, atol=0)
    fingerprints = {str(p.relative_to(root)): sha(p) for p in paths + [model_path]}
    return names, imputer, {
        'model': 'TabPFN', 'selected_model': 'tabpfn',
        'model_artifact': 'models/tabpfn_baseline.tabpfn_fit',
        'model_sha256': models['tabpfn_fit_sha256'], 'checkpoint_sha256': models['checkpoint_sha256'],
        'checkpoint_provenance_limitation': models['checkpoint_provenance_limitation'],
        'dependencies': models['dependencies'], 'frozen_artifacts_sha256': fingerprints,
    }, checkpoint


@contextmanager
def no_downloads():
    import tabpfn.model_loading as loading
    original = loading.download_model
    def blocked(*args, **kwargs):
        raise ValueError('Automatic TabPFN checkpoint downloads are forbidden')
    loading.download_model = blocked
    try: yield
    finally: loading.download_model = original


def restore(root):
    names, imputer, info, checkpoint = frozen(root)
    from tabpfn.model_loading import load_fitted_tabpfn_model, resolve_model_path
    from tabpfn.settings import settings
    resolved = resolve_model_path(None, 'classifier', settings.tabpfn.model_version.value)[0]
    if len(resolved) != 1 or Path(resolved[0]).resolve() != checkpoint:
        raise ValueError('Automatic checkpoint resolution differs from verified local checkpoint')
    with no_downloads():
        model = load_fitted_tabpfn_model(Path(root) / info['model_artifact'], device='cpu')
    if (list(model.feature_names_in_) != names or list(model.classes_) != [0, 1]
            or model.n_train_samples_ != 659):
        raise ValueError('Restored fitted TabPFN schema/classes/training population differs')
    info['restoration_device'] = 'cpu'
    return names, imputer, info, model


def predict(model, frame):
    if frame.shape != (1, 23) or not np.isfinite(frame.to_numpy()).all() or (frame < 0).any().any():
        raise ValueError('One finite nonnegative 23-feature vector required')
    with no_downloads():
        labels = np.asarray(model.predict(frame))
        probabilities = np.asarray(model.predict_proba(frame), dtype=float)
    if (labels.shape != (1,) or labels[0] not in (0, 1) or probabilities.shape != (1, 2)
            or not np.isfinite(probabilities).all() or (probabilities < 0).any()
            or (probabilities > 1).any() or not np.allclose(probabilities.sum(axis=1), 1, rtol=0, atol=1e-6)):
        raise ValueError('Invalid TabPFN prediction/classes/probabilities')
    return int(labels[0]), probabilities[0].tolist()
