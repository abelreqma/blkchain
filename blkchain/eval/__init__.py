''
from __future__ import annotations

import os

# Fully local / offline: disable deepeval telemetry and any login attempt.
os.environ.setdefault("DEEPEVAL_TELEMETRY_OPT_OUT", "YES")
os.environ.setdefault("ERROR_REPORTING", "NO")
