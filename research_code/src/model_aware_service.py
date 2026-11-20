"""Undeployed scheduled model-aware launcher. .env is authoritative per poll."""
import argparse
import json
import os
from pathlib import Path
import subprocess
from .model_selection import select_model
from .model_aware_orchestrator import Router, configuration
from .tabpfn_shadow_service import connection_environment


def require_legacy_unloaded(label):
    # Inspect labels only. Never log the full launchctl output/environment.
    result=subprocess.run(['/bin/launchctl','list'],capture_output=True,text=True,timeout=15,check=False)
    if result.returncode!=0:raise ValueError('Cannot verify scheduler ownership; launchctl inspection failed')
    if any(line.split() and line.split()[-1]==label for line in result.stdout.splitlines()):
        raise ValueError('Legacy RF LaunchAgent is loaded; do not run competing schedulers')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('action',choices=('selection','init','once','status','events','feed-check'))
    args=parser.parse_args(argv);service=None;stage='configuration'
    os.umask(0o077)
    try:
        cfg,tab,connection,legacy_label=configuration(args.config)
        # Unlike development CLIs, ignore inherited selector exports. The scheduled
        # process rereads this project's .env each poll; absent key/file means RF.
        selection=select_model(Path(cfg['root']),environ={})
        if args.action=='selection':
            print(json.dumps({'selected_model':selection.model,'source':selection.source,
                'selection_policy':'project_dotenv_then_rf_default; inherited_selector_ignored'}));return 0
        if args.action in {'init','once','feed-check'}:
            stage='scheduler_ownership';require_legacy_unloaded(legacy_label)
        stage='router_state';service=Router(cfg,tab)
        if args.action=='init':service.initialize()
        elif args.action in {'once','feed-check'}:
            if not service.meta('armed_at'):raise ValueError('Explicitly initialize the new router; no backfill')
            stage='existing_connection'
            with connection_environment(connection):
                stage='model_aware_poll'
                if args.action=='once':service.tick_selected(selection)
                else:
                    if service.meta('binding')!=service.binding():raise ValueError('Completion binding changed')
                    service.source_snapshot()
        elif args.action=='events':
            print(json.dumps([dict(r) for r in service.db.execute('SELECT * FROM events ORDER BY seq DESC LIMIT 100')],indent=2))
        else:
            rows=[]
            for row in service.db.execute('SELECT id,status,stage,attempt,error,rf,hybrid,prepared,ack,result FROM jobs'):
                rows.append({**dict(row),'selected_model':service.route(row['id'])['selected_model']})
            print(json.dumps(rows,indent=2))
        print(json.dumps({'status':'model_aware_'+args.action+'_completed','selected_model':selection.model,
            'dry_run':cfg['dry_run'],'enable_publication':cfg['enable_publication']}));return 0
    except Exception as exc:
        if service:
            with service.db:service.log(None,stage,'failed',type(exc).__name__)
        reason='Inspect isolated service state and existing connection; raw errors and secrets omitted.'
        if stage=='configuration':reason='Validate THESIS_HYBRID_MODEL in project .env (random_forest or tabpfn) and the new service configuration.'
        if stage=='scheduler_ownership':reason='Original RF LaunchAgent must be unloaded before the new scheduler runs; ownership could not be verified.'
        print(json.dumps({'status':'blocked','stage':stage,'exception_type':type(exc).__name__,'reason':reason}));return 2
    finally:
        if service:service.close()


if __name__=='__main__':raise SystemExit(main())
