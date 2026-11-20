"""Non-secret lab assumptions shared by notebooks and the offline Wazuh baseline."""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIELDS = {'account_domains','monitored_computer_prefix','monitored_file_root','m05_destination'}


def validate_lab_config(value):
    if not isinstance(value,dict) or set(value)!=FIELDS:
        raise ValueError('Lab config must contain exactly: '+', '.join(sorted(FIELDS)))
    domains=value['account_domains']
    if not isinstance(domains,list) or not domains or any(not isinstance(d,str) or not d.strip() or '\\' in d or any(ord(c)<32 for c in d) for d in domains):
        raise ValueError('Provide nonempty Windows domain names without account separators')
    for key in FIELDS-{'account_domains'}:
        text=value[key]
        if not isinstance(text,str) or not text.strip() or text!=text.strip() or any(ord(c)<32 for c in text):
            raise ValueError('Invalid lab setting: '+key)
    if value['m05_destination'].count('@')!=1 or any(not x or any(c.isspace() for c in x) for x in value['m05_destination'].split('@')):
        raise ValueError('M05 destination must be a literal user@host, not a regular expression')
    return {**value,'account_domains':list(domains)}


def load_lab_config(path=None):
    if path is None:
        setting=os.environ.get('THESIS_LAB_CONFIG')
        if setting is not None:
            if not setting.strip():raise ValueError('THESIS_LAB_CONFIG must name a config file')
            path=Path(setting).expanduser()
            if not path.is_absolute():path=ROOT/path
        else:
            local=ROOT/'config/lab.local.json'
            path=local if local.is_file() else ROOT/'config/lab.example.json'
    return validate_lab_config(json.loads(Path(path).read_text(encoding='utf-8-sig')))
