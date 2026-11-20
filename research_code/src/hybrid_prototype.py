"""Explicit local prototype execution; model comes from environment/.env, never CLI.

The production RF LaunchAgent does not import this module. No send/activation
action exists. Resume uses the persisted model, not today's environment.
"""
import argparse
from pathlib import Path
from .model_selection import select_model
from .prototype_jobs import Job
from .tabpfn_prototype.common import read, sha, write


def execute(root, job):
    record, state = job.read()
    source, alerts = Path(record['source_session_dir']), Path(record['alert_source_dir'])
    if (sha(source / 'output_manifest.json') != record['source_manifest_sha256']
            or sha(alerts / 'output_manifest.json') != record['alert_manifest_sha256']):
        raise ValueError('Pinned source manifests changed')
    model_contract = record['model_contract']
    if sha(root / model_contract['model_artifact']) != model_contract['model_sha256']:
        raise ValueError('Pinned job model artifact changed')
    if state['status'] == 'prepared_not_published':
        if record['selected_model'] == 'random_forest':
            from .hybrid_publisher import verify_prepared
            payload = verify_prepared(job.folder / 'preparation')
        else:
            from .tabpfn_prototype.publisher import verify_prepared
            payload = verify_prepared(root, job.folder / 'preparation')
        if payload['prediction_id'] != state['prediction_id']:
            raise ValueError('Completed job prediction identity changed')
        provenance = read(job.folder / 'execution_provenance.json')
        if any(provenance.get(k) != v for k, v in record.items()):
            raise ValueError('Execution provenance and pinned job disagree')
        return state
    if state['status'] == 'investigation_required': return state
    model = record['selected_model']; folder = job.folder
    if model == 'random_forest':
        from .prediction_publisher import verified_completed_session
        from .hybrid_publisher import verified_hybrid, main as rf_publisher
        events, _ = verified_completed_session(source, root)
        payload, _ = verified_hybrid(alerts, root)
        if (payload['session_id'] != events[0]['session_id']
                or Path(read(alerts / 'provenance.json')['source_session_dir']).resolve() != source):
            raise ValueError('RF inference and hybrid sources differ')
        # Existing preparation command, not an altered RF implementation.
        preparation = folder / 'preparation'
        if not preparation.exists():
            code = rf_publisher(['prepare', '--hybrid-dir', str(alerts), '--output-dir', str(preparation)])
            if code: raise ValueError('Existing RF preparation gate refused')
        from .hybrid_publisher import verify_prepared
        verify_prepared(preparation)
        job.update(status='prepared_not_published', prediction_id=payload['prediction_id'])
    else:
        from .tabpfn_prototype import new_session, hybrid_session, publisher
        from .tabpfn_prototype.artifacts import frozen
        if frozen(root)[2]['checkpoint_sha256'] != model_contract['checkpoint_sha256']:
            raise ValueError('Pinned job checkpoint changed')
        inference = folder / 'inference'
        if not inference.exists():
            job.update(status='inference_running')
            new_session.infer(root, source, inference, record['job_id'])
        prediction, _, _, original_source = new_session.verified_inference(root, inference)
        if prediction['job_id'] != record['job_id'] or original_source != source:
            raise ValueError('Inference belongs to a different pinned execution')
        hybrid = folder / 'hybrid'
        if not hybrid.exists():
            job.update(status='hybrid_running')
            try:
                result = hybrid_session.run(root, inference, alerts, hybrid)
            except ValueError:
                if (hybrid / 'hybrid_result.json').is_file():
                    result = read(hybrid / 'hybrid_result.json')
                    if result.get('hybrid_priority') == 'Evidence Unavailable':
                        job.update(status='investigation_required', hybrid_priority='Evidence Unavailable')
                        return job.read()[1]
                raise
        else:
            result = read(hybrid / 'hybrid_result.json')
        if result.get('wazuh_evidence_verified') is not True:
            job.update(status='investigation_required', hybrid_priority='Evidence Unavailable')
            return job.read()[1]
        preparation = folder / 'preparation'
        if not preparation.exists(): publisher.prepare(root, hybrid, preparation)
        payload = publisher.verify_prepared(root, preparation)
        job.update(status='prepared_not_published', prediction_id=payload['prediction_id'],
                   hybrid_priority=payload['hybrid_priority'])
    write(folder / 'execution_provenance.json', {
        **record, 'execution_status': job.read()[1]['status'], 'alerts_published': False,
        'selection_frozen_at_job_creation': True, 'automatic_service_changed': False,
        'model_verification': {'model_sha256': payload['model_sha256'],
                               'checkpoint_sha256': payload.get('checkpoint_sha256')},
    })
    return job.read()[1]


def main(argv=None):
    import sys
    values = list(sys.argv[1:] if argv is None else argv)
    if values[:1] == ['auto']:
        from .tabpfn_shadow_service import main as shadow_main
        return shadow_main(values[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('selection', help='Show only the selected model and its source')
    run = sub.add_parser('run', help='Local capture replay and preparation only; never sends')
    run.add_argument('--session-dir', type=Path, required=True)
    run.add_argument('--alert-source-dir', type=Path, required=True)
    run.add_argument('--output-dir', type=Path, required=True)
    resume = sub.add_parser('resume', help='Resume the model pinned in an existing local job')
    resume.add_argument('--job-dir', type=Path, required=True)
    args = parser.parse_args(argv); root = Path.cwd().resolve(); job = None
    try:
        if args.action == 'selection':
            selection = select_model(root)
            print(__import__('json').dumps({'selected_model': selection.model, 'source': selection.source})); return 0
        if args.action == 'run':
            selection = select_model(root)
            folder = args.output_dir.resolve()
            expected = root / 'data/experiments' / ('tabpfn_prototype' if selection.model == 'tabpfn' else 'rf_selected_prototype')
            if not folder.is_relative_to(expected) or folder == expected:
                raise ValueError('Use a new model-specific experiment subdirectory')
            from .tabpfn_prototype.new_session import source_capture
            source, _, source_event, source_sha = source_capture(root, args.session_dir)
            if selection.model == 'tabpfn':
                from .tabpfn_prototype.artifacts import frozen
                model_info = frozen(root)[2]
                model_contract = {k: model_info[k] for k in ('model_artifact', 'model_sha256', 'checkpoint_sha256')}
            else:
                model_contract = {k: source_event[k] for k in ('model_artifact', 'model_sha256')}
            alerts = args.alert_source_dir.resolve()
            if not alerts.is_relative_to(root / 'data/experiments/hybrid_session_phase1'):
                raise ValueError('Use an existing verified operational alert capture')
            job = Job.create(folder, selection, {'root': str(root), 'source_session_dir': str(source),
                'session_id': source_event['session_id'], 'model_contract': model_contract,
                'source_manifest_sha256': source_sha, 'alert_source_dir': str(alerts),
                'alert_manifest_sha256': sha(alerts / 'output_manifest.json')})
        else:
            folder = args.job_dir.resolve()
            allowed = (root / 'data/experiments/tabpfn_prototype', root / 'data/experiments/rf_selected_prototype')
            if not any(folder.is_relative_to(p) and folder != p for p in allowed) or not (folder / 'execution.sqlite3').is_file():
                raise ValueError('Use an existing separate prototype job')
            job = Job(folder)
        if job.read()[0]['root'] != str(root): raise ValueError('Job belongs to a different project root')
        state = execute(root, job)
        print(__import__('json').dumps({'selected_model': job.read()[0]['selected_model'], **state,
                                      'alerts_published': False, 'active_service_changed': False}))
        return 0 if state['status'] == 'prepared_not_published' else 2
    except (ValueError, OSError, KeyError, TypeError, AssertionError) as exc:
        if job: job.update(status='blocked', exception_type=type(exc).__name__)
        print(__import__('json').dumps({'status': 'blocked', 'exception_type': type(exc).__name__,
            'reason': 'Local prototype verification failed; no fallback or publication. Inspect saved stage audits.',
            'alerts_published': False}))
        return 2
    finally:
        if job: job.close()


if __name__ == '__main__': raise SystemExit(main())
