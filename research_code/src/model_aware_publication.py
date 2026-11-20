"""Guarded publication alongside the unchanged RF and shadow publisher modules."""
from pathlib import Path
from scripts.integration import receive_ml_prediction as legacy
from scripts.integration.model_publication_contract import make_claim, validate_claim
from scripts.integration.tabpfn_contract import validate as validate_tabpfn
from .prediction_publisher import _ssh_send
from .session_orchestrator import digest
from .tabpfn_prototype.common import output, read, seal, sha, write


def code_contract(root):
    paths = ['src/model_aware_publication.py','src/model_aware_orchestrator.py','src/model_aware_service.py',
             'scripts/integration/model_publication_contract.py','scripts/integration/guarded_receiver.py']
    return {p:sha(Path(root)/p) for p in paths}


def verified(root, prepared, model):
    if model=='random_forest':
        from .hybrid_publisher import verify_prepared
        event=verify_prepared(Path(prepared))
        if event['model']!='Random Forest': raise ValueError('Wrong RF model identity')
        legacy.validate_hybrid(event)
    elif model=='tabpfn':
        from .tabpfn_prototype.publisher import verify_prepared
        event=verify_prepared(root,Path(prepared));validate_tabpfn(event)
    else:raise ValueError('Unsupported pinned model')
    return event


def bind_completion(event, job_id, completion):
    from .session_orchestrator import timestamp
    if (not isinstance(completion,dict) or completion.get('status')!='Completed'
            or completion.get('session_id')!=job_id
            or event['username'].casefold()!=completion['username'].casefold()
            or timestamp(event['activity_start'])!=timestamp(completion['start'])
            or timestamp(event['activity_end'])!=timestamp(completion['end'])):
        raise ValueError('Prepared publication does not belong to the pinned completion')


def send_verified(root, prepared, model, job_id, ssh_host, out, *, enabled=False, completion=None):
    if enabled is not True:raise PermissionError('Explicit publication enablement required')
    event=verified(root,prepared,model)
    bind_completion(event,job_id,completion)
    claim=make_claim(model,job_id,event['username'],event['activity_start'],event['activity_end'])
    out=output(root,out); code=code_contract(root)
    receipt={'status':'blocked','selected_model':model,'job_id':job_id,'prediction_id':event['prediction_id'],
             'remote_submissions':[],'failing_stage':'claim'}
    try:
        ack=_ssh_send(claim,ssh_host,validate_claim)
        if ack.get('guard_version')!=1:raise ValueError('Shared receiver guard acknowledgement required')
        write(out/'ownership_ack.json',ack)
        receipt['failing_stage']='prepared_reverification'
        if verified(root,prepared,model)!=event or code_contract(root)!=code:
            raise ValueError('Prepared evidence or publication code changed')
        receipt['failing_stage']='publication'
        ack=_ssh_send(event,ssh_host,validate_tabpfn if model=='tabpfn' else legacy.validate_hybrid)
        if ack.get('guard_version')!=1:raise ValueError('Shared receiver guard acknowledgement required')
        receipt.update(status='acknowledged',remote_submissions=[ack],failing_stage=None)
    except (ValueError,OSError,KeyError,TypeError) as exc:
        receipt.update(exception_type=type(exc).__name__,reason='Guarded SSH publication unverified; no raw remote error logged. Retry the same payload.')
    write(out/'receipt.json',receipt)
    write(out/'publication_provenance.json',{'selected_model':model,'job_id':job_id,'prepared_dir':str(Path(prepared).resolve()),
        'claim':claim,'completion_sha256':digest(completion),'payload_sha256':__import__('hashlib').sha256(legacy.canonical(event).encode()).hexdigest(),
        'code_sha256':code,'guard_version_required':1})
    seal(out)
    if receipt['status']!='acknowledged':raise ValueError('Guarded publication failed; inspect stage receipt')
    return receipt


def verify_delivery(root, out, prepared, model, job_id, *, completion=None):
    from .tabpfn_prototype.common import manifest
    out=Path(out)
    manifest(out,{'receipt.json','ownership_ack.json','publication_provenance.json'})
    event=verified(root,prepared,model);receipt=read(out/'receipt.json');provenance=read(out/'publication_provenance.json')
    bind_completion(event,job_id,completion)
    claim=make_claim(model,job_id,event['username'],event['activity_start'],event['activity_end'])
    if (provenance!={'selected_model':model,'job_id':job_id,'prepared_dir':str(Path(prepared).resolve()),
        'claim':claim,'completion_sha256':digest(completion),'payload_sha256':__import__('hashlib').sha256(legacy.canonical(event).encode()).hexdigest(),
        'code_sha256':code_contract(root),'guard_version_required':1}
            or receipt.get('status')!='acknowledged' or receipt.get('selected_model')!=model
            or receipt.get('job_id')!=job_id or receipt.get('prediction_id')!=event['prediction_id']
            or len(receipt.get('remote_submissions',[]))!=1):
        raise ValueError('Delivery provenance/receipt mismatch')
    for ack,identity in [(read(out/'ownership_ack.json'),claim['prediction_id']),
                         (receipt['remote_submissions'][0],event['prediction_id'])]:
        if ack.get('guard_version')!=1 or ack.get('prediction_id')!=identity or ack.get('status') not in {'written','duplicate'}:
            raise ValueError('Unverified guard acknowledgement')
    return receipt
