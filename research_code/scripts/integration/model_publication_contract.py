"""Small stdlib-only ownership protocol for the restricted SSH receiver."""
import hashlib
from uuid import UUID
from datetime import timezone
from .receive_ml_prediction import canonical, completed_session_id, utc

MODELS = {'random_forest', 'tabpfn'}
CLAIM_FIELDS = {'operation', 'schema_version', 'selected_model', 'job_id', 'session_id',
                'username', 'activity_start', 'activity_end', 'prediction_id'}


def claim_id(value):
    return hashlib.sha256(canonical({k:v for k,v in value.items() if k != 'prediction_id'}).encode()).hexdigest()


def validate_claim(value):
    if not isinstance(value, dict) or set(value) != CLAIM_FIELDS:
        raise ValueError('Unexpected ownership claim fields')
    if (value['operation'] != 'claim' or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or value['selected_model'] not in MODELS):
        raise ValueError('Unsupported ownership claim')
    UUID(value['job_id'])
    user = value['username']
    if (not isinstance(user,str) or user.count('\\') != 1 or len(user)>128
            or any(not part.strip() for part in user.split('\\')) or any(ord(c)<32 for c in user)):
        raise ValueError('Qualified account required')
    if (utc(value['activity_start']) >= utc(value['activity_end'])
            or value['session_id'] != completed_session_id(user,value['activity_start'],value['activity_end'])
            or value['prediction_id'] != claim_id(value)):
        raise ValueError('Ownership identity mismatch')
    return value


def make_claim(model, job_id, username, start, end):
    value = dict(operation='claim',schema_version=1,selected_model=model,job_id=job_id,
                 username=username,activity_start=start,activity_end=end,
                 session_id=completed_session_id(username,start,end))
    value['prediction_id'] = claim_id(value)
    return validate_claim(value)


def session_key(value):
    """Compare actual account/time identity, including equivalent UTC spellings."""
    times=[]
    for name in ('activity_start','activity_end'):
        at=utc(value[name])
        if at.tzinfo is None:raise ValueError('UTC timezone required')
        times.append(at.astimezone(timezone.utc).isoformat(timespec='microseconds'))
    return canonical([value['username'].casefold(),*times])
