"""
Audit Log - append-only JSONL engagement record

Every tool invocation lands here: timestamp, argv, engagement, guard
verdict, exit code, duration. This is the evidence trail for the report.
"""

import json
import os
import time

from vantic.core import store

VANTIC_HOME = os.path.join(os.path.expanduser("~"), ".vantic")


def audit_path():
    """Per-engagement audit file (None when no engagement is active)."""
    name = store.active_engagement()
    if not name:
        return None
    d = os.path.join(store.ENGAGE_DIR, name)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "audit.jsonl")


def log(event, **fields):
    """Append one event record. Never raises."""
    try:
        path = audit_path()
        if not path:
            return
        from datetime import datetime
        rec = {"ts": datetime.now().isoformat(timespec="seconds"), "event": event}
        rec.update(fields)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
    except Exception:
        pass


def log_run(tool, argv, engagement, guard_verdict, exit_code=None, duration=None):
    log("run", tool=tool, argv=list(argv), engagement=engagement,
        guard=guard_verdict, exit_code=exit_code, duration=duration)


class run_timer:
    """Context manager that writes the run record on exit."""

    def __init__(self, tool, argv, guard_verdict="allowed"):
        self.tool = tool
        self.argv = list(argv)
        self.verdict = guard_verdict
        self.start = time.time()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        duration = round(time.time() - self.start, 2)
        code = 0
        if exc_type is SystemExit and exc.code is not None:
            code = exc.code if isinstance(exc.code, int) else 0
        elif exc_type is KeyboardInterrupt:
            code = 4
        elif exc_type is not None:
            code = 1
        log_run(self.tool, self.argv, store.active_engagement(), self.verdict,
                exit_code=code, duration=duration)
        return False
