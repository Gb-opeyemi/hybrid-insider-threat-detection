"""Development-only selection. Never loads credentials or edits process environment."""
from dataclasses import dataclass
import os
from pathlib import Path

MODELS = frozenset({'random_forest', 'tabpfn'})
VARIABLE = 'THESIS_HYBRID_MODEL'


@dataclass(frozen=True)
class Selection:
    model: str
    source: str


def validate_model(value):
    if not isinstance(value, str) or value not in MODELS:
        raise ValueError('THESIS_HYBRID_MODEL must be random_forest or tabpfn')
    return value


def select_model(root: Path, environ=None, *, load_dotenv=True):
    """Explicit environment > root .env > RF. Blank values fail, not fall back.

    Only this selector key is read. No interpolation, shell execution, parent
    search, credential loading or global os.environ mutation is performed.
    """
    env = os.environ if environ is None else environ
    if VARIABLE in env:
        return Selection(validate_model(env[VARIABLE]), 'environment')
    path = Path(root) / '.env'
    if load_dotenv and path.exists():
        if path.is_symlink() or path.stat().st_size > 65536:
            raise ValueError('Unsafe development .env file')
        found = []
        for line in path.read_text(encoding='utf-8-sig').splitlines():
            line = line.strip()
            if line.startswith('export '): line = line[7:].lstrip()
            key, sep, value = line.partition('=')
            if not sep or key.strip() != VARIABLE: continue
            value = value.strip()
            if value[:1] in {'"', "'"}:
                quote = value[0]
                end = value.find(quote, 1)
                if end < 0 or (value[end + 1:].strip() and not value[end + 1:].lstrip().startswith('#')):
                    raise ValueError('Malformed model selector in .env')
                value = value[1:end]
            else:
                value = value.split('#', 1)[0].strip()
            found.append(value)
        if len(found) > 1: raise ValueError('Duplicate model selector in .env')
        if found: return Selection(validate_model(found[0]), 'dotenv')
    return Selection('random_forest', 'default')
