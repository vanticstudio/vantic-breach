"""
Jobs Tool
Engagement run history: list runs, show one, inspect checkpoints

Runs are recorded automatically whenever an engagement is active.
"""

from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, kv, Colors, emit_json
)

from vantic.core import store

META = {
    "name": "jobs",
    "title": "Run History",
    "category": "ANALYSIS & REPORTING",
    "description": "Engagement run history + checkpoints",
    "risk": "safe",
    "examples": [
        "vantic jobs",
        "vantic jobs --show 12",
    ],
    "flow": [],
    "guard": {},
}


def add_arguments(parser):
    parser.add_argument('--list', action='store_true', help='List recent runs')
    parser.add_argument('--show', type=int, metavar='RUN_ID', help='Show one run')
    parser.add_argument('--limit', type=int, default=25, help='Rows to list')


def run(args):
    show = getattr(args, 'show', None)
    limit = getattr(args, 'limit', 25)

    if not store.is_active():
        print_error("No active engagement - activate one first:")
        print(f"      {Colors.CYAN}vantic engage new demo && vantic engage use demo{Colors.RESET}")
        return

    if show:
        run = store.run_get(show)
        if not run:
            print_error(f"No run #{show}")
            return
        print_header("RUN", f"#{show}")
        kv("Tool", run['tool'])
        kv("Argv", run['argv'][:70])
        kv("Started", run['started_at'])
        kv("Finished", run['finished_at'] or '(running?)')
        kv("Exit code", run['exit_code'] if run['exit_code'] is not None else '?')
        if run.get('stats'):
            kv("Stats", str(run['stats'])[:60])
        checkpoint = store.checkpoint_get(show)
        if checkpoint:
            print()
            print_subheader("CHECKPOINT")
            kv("Wordlist", checkpoint[0])
            kv("Offset", checkpoint[1])
        return

    runs = store.run_list(limit)
    if not runs:
        print_info("No runs recorded yet in this engagement")
        return

    print_header("RUN HISTORY", f"{len(runs)} most recent")
    print()
    rows = []
    for r in runs:
        code = r['exit_code']
        code_str = str(code) if code is not None else '...'
        color = (Colors.BRIGHT_GREEN if code == 0 else
                 Colors.BRIGHT_YELLOW if code == 4 else
                 Colors.BRIGHT_RED if code else Colors.DIM)
        rows.append(((str(r['id']), r['tool'], r['argv'][:44],
                      r['started_at'], code_str), color))
    print_table(["ID", "TOOL", "ARGV", "STARTED", "EXIT"], rows,
                widths=[5, 10, 46, 19, 5])
    print()
    print_info("Inspect one: vantic jobs --show <ID>")
    print_info("Diff two scans: vantic diff --run-a <ID> --run-b <ID>")

    if getattr(args, 'json', False):
        emit_json({"tool": "jobs",
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": runs})
