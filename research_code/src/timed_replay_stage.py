"""Opt-in RF child observer; executes the unchanged main with unchanged argv."""
import argparse
from importlib import import_module
from pathlib import Path
from .operational_timing import Collector, load, warn
from .timing_hooks import Hooks


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    stages = {'rf':'src.controlled_replay.new_session','hybrid':'src.controlled_replay.hybrid_session',
              'prepare':'src.hybrid_publisher'}
    parser.add_argument('--stage', choices=tuple(stages), required=True)
    parser.add_argument('--descriptor', type=Path, required=True)
    parser.add_argument('original_args', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    module = import_module(stages[args.stage])
    values = args.original_args[1:] if args.original_args[:1]==['--'] else args.original_args
    try:
        info = load(args.descriptor); folder = Path(info['journal_dir']).resolve()
        if (info['stage'] != args.stage or not folder.is_relative_to(
                Path.cwd().resolve() / 'data/experiments/operational_service/model_aware')):
            raise ValueError('Invalid timing descriptor')
        c = Collector(folder)
    except Exception:
        warn()
        return module.main(values)  # No prediction/publication change on timing-file failure.
    c.inference_depth = int(args.stage=='rf')
    with c.installed(), c.work(info['stage'],info['artifact']), Hooks():
        return module.main(values)


if __name__ == '__main__': raise SystemExit(main())
