"""Staged forced-command entry: install as a root-owned file, execute with -I."""
import sys
# Fixed administrator-owned installation directory; never a caller's cwd/PYTHONPATH.
sys.path.insert(0, '/usr/local/lib/thesis-hybrid')
from scripts.integration.guarded_receiver import main

if __name__ == '__main__': raise SystemExit(main())
