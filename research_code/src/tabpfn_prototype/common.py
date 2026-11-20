"""Strict local artifact helpers, separate from the preserved RF modules."""
import hashlib
import json
from pathlib import Path
from scripts.integration.receive_ml_prediction import strict_json
from scripts.integration.tabpfn_contract import identity


def sha(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def read(path):
    return strict_json(Path(path).read_text())


def write(path, value):
    with Path(path).open('x') as handle:
        handle.write(json.dumps(value, indent=2, allow_nan=False) + '\n')


def output(root, path):
    path = Path(path).resolve()
    if not path.is_relative_to(Path(root).resolve() / 'data/experiments'):
        raise ValueError('Use a fresh ignored data/experiments output directory')
    path.mkdir(parents=True, exist_ok=False, mode=0o700)
    return path


def seal(path):
    write(path / 'output_manifest.json', {p.name: sha(p) for p in sorted(path.iterdir()) if p.is_file()})


def manifest(path, required):
    path = Path(path).resolve()
    values = read(path / 'output_manifest.json')
    if not isinstance(values, dict) or not required <= values.keys():
        raise ValueError('Required provenance artifacts missing')
    for name, digest in values.items():
        child = (path / name).resolve()
        if child.parent != path or sha(child) != digest:
            raise ValueError('Artifact integrity failure')
    return values


def code_hashes(root):
    root = Path(root)
    paths = [root / 'src/model_selection.py', root / 'src/features.py',
             root / 'src/hybrid_prototype.py', root / 'src/tabpfn_shadow_service.py',
             root / 'src/session_orchestrator.py', root / 'src/wazuh_completion_feed.py',
             root / 'src/controlled_replay/new_session.py', root / 'src/controlled_replay/indexer.py',
             root / 'src/controlled_replay/hybrid_session.py', root / 'src/hybrid_priority.py',
             root / 'scripts/integration/tabpfn_contract.py']
    paths += sorted((root / 'src/tabpfn_prototype').glob('*.py'))
    return {str(p.relative_to(root)): sha(p) for p in paths}

