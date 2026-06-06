"""Week 3 — Policy Enforcer Entry Point
=======================================
This module is the Week 3 deliverable entry point.

The full Policy Enforcer implementation lives in ``src/enforcer.py``.
This file provides a thin launcher so you can run the enforcer from the
``Week3/`` directory during development, or reference it when reviewing
the Week 3 codebase in isolation.

Usage (from the project root):
    python Week3/policy_enforcer.py [--dry-run] [--once] [--unblock-all]

Or use the dedicated PowerShell launcher which handles venv activation
and admin checking:
    .\\run_enforcer.ps1 -DryRun
    .\\run_enforcer.ps1 -Once
    .\\run_enforcer.ps1

See ``src/enforcer.py`` for the full implementation, and ``README.md``
section "Run the Policy Enforcer (Week 3)" for complete usage instructions.
"""

import sys
from pathlib import Path

# Ensure the project root is on the path so src.enforcer can be imported
# regardless of which directory this script is run from.
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.enforcer import main  # noqa: E402

if __name__ == "__main__":
    main()
