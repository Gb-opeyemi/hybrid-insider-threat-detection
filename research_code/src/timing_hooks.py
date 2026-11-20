"""Scoped observers of unchanged operations. No models, inputs or results altered.

Hooks exist only in the timed RF child or during one TabPFN worker call. They
are removed even on failure. Only explicitly listed call boundaries are timed.
"""
from contextlib import ExitStack, contextmanager
from functools import wraps
import subprocess
import math
from pathlib import Path
import sys
from .operational_timing import CURRENT, Collector, atomic, load, warn


def role(c, metric):
    if metric in {'model_inference','preprocessing','feature_extraction'}:
        return 'primary' if c.inference_depth else 'verification'
    if metric == 'model_loading': return 'primary' if c.stage in {'rf','inference'} else 'verification'
    if metric == 'wazuh_evidence_correlation': return 'primary' if c.stage in {'hybrid','alerts','tabpfn_hybrid'} else 'verification'
    if metric == 'hybrid_decision': return 'primary' if c.stage in {'hybrid','tabpfn_hybrid'} else 'verification'
    return 'primary'


def remember_feature_validation(result):
    """Fixed reason codes/counts only, never identities, raw events or arbitrary text."""
    c = CURRENT.get()
    if c is None or not isinstance(result,tuple) or len(result)!=2:return
    audit=result[1]
    if not isinstance(audit,dict):return
    known={'no_unambiguous_behavioral_events','requested_account_identity_unresolved',
           'requested_account_process_unresolved','requested_namespace_not_verified_as_of_event',
           'clock_disagreement_over_300s'}
    reasons=audit.get('reasons',[])
    snapshot={'status':audit.get('status') if audit.get('status') in {'eligible','blocked'} else 'unknown',
              'reasons':sorted(r for r in reasons if isinstance(r,str) and r in known),
              'other_validation_reasons_present':any(not isinstance(r,str) or r not in known for r in reasons),
              'counts':{}}
    counts=audit.get('counts',{})
    for name in ('raw_attributed','unique_attributed','clock_disagreement_over_300s'):
        value=counts.get(name)
        if type(value) is int and value>=0:snapshot['counts'][name]=value
    availability=audit.get('telemetry_availability',{})
    for name in ('behavior_receipt_minus_event_seconds_min','behavior_receipt_minus_event_seconds_median',
                 'behavior_receipt_minus_event_seconds_max'):
        value=availability.get(name)
        if type(value) in (int,float) and math.isfinite(value):snapshot[name]=value
    c.last_feature_validation=snapshot


@contextmanager
def replace(obj, name, value):
    local = name in vars(obj); original = getattr(obj, name)
    setattr(obj, name, value)
    try: yield
    finally:
        if local: setattr(obj, name, original)
        else:
            delattr(obj, name)
            if not hasattr(obj, name): setattr(obj, name, original)


class Hooks:
    def __init__(self): self.stack = ExitStack(); self.models = set(); self.model_classes = set()
    def __enter__(self):
        try:
            self.install()
        except Exception:
            self.stack.close(); warn()  # Instrumentation must not prevent original processing.
        return self
    def __exit__(self, *args): return self.stack.__exit__(*args)

    def observe(self, obj, name, metric, predicate=None, after=None):
        original = getattr(obj, name)
        @wraps(original)
        def call(*args, **kwargs):
            c = CURRENT.get()
            if c is None or (predicate and not predicate(c)): return original(*args, **kwargs)
            with c.span(metric, role(c, metric)):
                result = original(*args, **kwargs)
            if after:
                try: after(result)
                except Exception: warn()
            return result
        self.stack.enter_context(replace(obj, name, call))

    def model(self, model):
        if id(model) in self.models: return
        self.models.add(id(model))
        try:
            cls = type(model)
            if all(hasattr(cls,name) for name in ('predict','predict_proba')):
                if cls in self.model_classes: return
                self.model_classes.add(cls)
                # Do not attach closures to fitted instances (which may be pickled
                # internally by a library). Observe their class methods temporarily.
                for name in ('predict','predict_proba'):
                    self.observe(cls,name,'model_inference')
            else:
                # Supports lightweight synthetic adapters with instance-only callables.
                for name in ('predict','predict_proba'):
                    self.observe(model,name,'model_inference')
        except Exception: warn()

    def install(self):
        # All these modules are already used by the operational workflow. Importing
        # TabPFN's numerical library itself remains deferred to the original loader.
        from .controlled_replay import new_session as rf, hybrid_session as wh
        from .tabpfn_prototype import artifacts, new_session as tp, hybrid_session as th
        from .controlled_replay.indexer import IndexerClient
        from . import model_aware_publication as publication
        from sklearn.impute import SimpleImputer
        import pandas as pd
        self.observe(IndexerClient, 'capture', 'wazuh_event_retrieval')
        for module in (rf, tp):
            self.observe(module, 'extract_completed', 'feature_extraction', after=remember_feature_validation)
        self.observe(rf, 'load_model', 'model_loading', after=self.model)
        self.observe(artifacts, 'restore', 'model_loading', after=lambda value:self.model(value[3]))
        for module in (wh, th):
            self.observe(module, 'verified_event_context', 'wazuh_evidence_correlation')
            self.observe(module, 'match_alerts', 'wazuh_evidence_correlation')
            self.observe(module, 'fuse_hybrid_priority', 'hybrid_decision')
        self.observe(wh, 'fetch_alerts', 'wazuh_evidence_correlation')
        # alert_capture imports fetch_alerts by value; observe its actual call site too.
        from .tabpfn_prototype import alert_capture
        self.observe(alert_capture, 'fetch_alerts', 'wazuh_evidence_correlation')
        def prep(c):
            return c.inference_depth and not any(c.depth.get((metric,'primary')) for metric in
                                                ('model_inference','model_loading','feature_extraction'))
        self.observe(pd.DataFrame, '__init__', 'preprocessing', predicate=prep)
        self.observe(pd.DataFrame, 'astype', 'preprocessing', predicate=prep)
        self.observe(SimpleImputer, 'transform', 'preprocessing', predicate=prep)
        original = tp.infer
        @wraps(original)
        def infer(*args, **kwargs):
            c = CURRENT.get()
            if c is None: return original(*args, **kwargs)
            c.inference_depth += 1
            try: return original(*args, **kwargs)
            finally: c.inference_depth -= 1
        self.stack.enter_context(replace(tp,'infer',infer))
        original_send = publication._ssh_send
        @wraps(original_send)
        def send(value, *args, **kwargs):
            c = CURRENT.get()
            if c is None: return original_send(value,*args,**kwargs)
            metric = 'ownership_claim' if value.get('operation') == 'claim' else 'publication'
            with c.span(metric) as event:
                ack = original_send(value,*args,**kwargs)
                if metric == 'publication' and event is not None:
                    event['ack_status'] = ack.get('status') if type(ack.get('guard_version')) is int and ack['guard_version']==1 else 'unverified'
                return ack
        self.stack.enter_context(replace(publication,'_ssh_send',send))


@contextmanager
def rf_child_transport(stage, artifact):
    """Keep the original RF argument builder/timeout/security settings unchanged."""
    c = CURRENT.get()
    if c is None:
        yield; return
    original_run = subprocess.run
    modules = {'rf':'src.controlled_replay.new_session','hybrid':'src.controlled_replay.hybrid_session',
               'prepare':'src.hybrid_publisher'}
    descriptor = c.folder / 'children' / (c.attempt + '.json')
    try:
        atomic(descriptor, {'journal_dir':str(c.folder.resolve()), 'stage':stage, 'artifact':str(artifact)})
    except Exception:
        warn(); yield; return
    def run(command, *args, **kwargs):
        if (isinstance(command,list) and len(command)>=4 and command[1:3]==['-B','-m']
                and command[3]==modules[stage]):
            command = command[:3] + ['src.timed_replay_stage','--stage',stage,'--descriptor',str(descriptor),'--'] + command[4:]
        return original_run(command,*args,**kwargs)
    with replace(subprocess, 'run', run): yield


def timed_shadow_class():
    from .tabpfn_prototype.automatic import Shadow
    class TimedShadow(Shadow):
        def execute_stage(self, stage, out, job, value, windows):
            c = CURRENT.get()
            if c is None: return super().execute_stage(stage,out,job,value,windows)
            label = {'hybrid':'tabpfn_hybrid','prepare':'tabpfn_prepare'}.get(stage,stage)
            cached = stage=='inference' and self.context is not None
            with c.work(label,out):
                before = len(c.new_events)
                c.last_feature_validation=None
                # A successful feature-extraction call may return a BLOCKED audit.
                # Its caller then raises before restoration; observe that stage too.
                with c.span(None,'stage','stage_execution') as event:
                    try:
                        result = super().execute_stage(stage,out,job,value,windows)
                    except Exception as exc:
                        if event is not None and isinstance(exc,ValueError) and str(exc)=='Fresh features or completion host unverified':
                            event['validation_check']='Fresh features or completion host unverified'
                            if c.last_feature_validation is not None:
                                event['preflight_validation']=c.last_feature_validation
                        raise
                if cached and any(e['metric']=='model_inference' for e in c.new_events[before:]): c.cached_loading()
                return result
        def validate_stage(self, stage, path, job, value):
            c = CURRENT.get()
            if c is None: return super().validate_stage(stage,path,job,value)
            with c.work('verification',path): return super().validate_stage(stage,path,job,value)
    return TimedShadow
