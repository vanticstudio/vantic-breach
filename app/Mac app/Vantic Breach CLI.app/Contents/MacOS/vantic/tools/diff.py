"""
Run Diff Tool
Compare two scan runs: new/lost ports, changed banners

Consumes two scan JSON exports (vantic scan --json) or two engagement
runs. The first consumer of the engagement store's run history.
"""

import json
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, kv, Colors, emit_json
)

META = {
    "name": "diff",
    "title": "Scan Diff",
    "category": "ANALYSIS & REPORTING",
    "description": "Compare two scan results",
    "risk": "safe",
    "examples": [
        "vantic diff --a run1.json --b run2.json",
        "vantic diff --run-a 12 --run-b 30",
    ],
    "flow": [
        ("opt", "--a", "First scan JSON", ""),
        ("opt", "--b", "Second scan JSON", ""),
    ],
    "guard": {},
}


def load_scan(path):
    """Load a scan JSON export -> {(host, port): record}."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        print_error(f"Cannot read {path}: {e}")
        return None
    if isinstance(data, dict) and 'results' in data:
        results = data['results']
    elif isinstance(data, dict) and 'ports' in data:
        results = data['ports']
    elif isinstance(data, list):
        results = data
    else:
        print_error(f"Unrecognized scan format in {path}")
        return None
    out = {}
    host = (data.get('target') if isinstance(data, dict) else None) or '?'
    for r in results:
        try:
            port = int(r.get('port', 0))
        except (TypeError, ValueError):
            continue
        state = str(r.get('status', r.get('state', ''))).upper()
        if state in ('OPEN', 'open'):
            out[(host, port)] = {'banner': (r.get('banner') or '')[:80],
                                 'service': r.get('service', '')}
    return out


def load_run(run_id):
    """Load services captured by a store run (via services table)."""
    from vantic.core import store
    run = store.run_get(run_id)
    if not run:
        print_error(f"No run #{run_id} in the active engagement")
        return None
    services = store.services_all()
    out = {}
    for s in services:
        out[(s['host'], int(s['port']))] = {'banner': (s.get('banner') or '')[:80],
                                            'service': s.get('service_name', '')}
    return out


def add_arguments(parser):
    group = parser.add_argument_group('inputs')
    group.add_argument('--a', dest='file_a', help='First scan JSON')
    group.add_argument('--b', dest='file_b', help='Second scan JSON')
    group.add_argument('--run-a', type=int, help='First engagement run id')
    group.add_argument('--run-b', type=int, help='Second engagement run id')


def run(args):
    file_a = getattr(args, 'file_a', None)
    file_b = getattr(args, 'file_b', None)
    run_a = getattr(args, 'run_a', None)
    run_b = getattr(args, 'run_b', None)

    if file_a and file_b:
        scan_a, scan_b = load_scan(file_a), load_scan(file_b)
        label_a, label_b = file_a, file_b
    elif run_a and run_b:
        scan_a, scan_b = load_run(run_a), load_run(run_b)
        label_a, label_b = f"run #{run_a}", f"run #{run_b}"
    else:
        print_error("Give --a/--b (two scan JSON files) or --run-a/--run-b")
        return

    if scan_a is None or scan_b is None:
        return

    print_header("SCAN DIFF", f"{label_a} → {label_b}")
    kv("A", f"{len(scan_a)} open ports")
    kv("B", f"{len(scan_b)} open ports")
    print()

    keys_a, keys_b = set(scan_a), set(scan_b)
    new_ports = sorted(keys_b - keys_a, key=lambda k: (k[0], k[1]))
    lost_ports = sorted(keys_a - keys_b, key=lambda k: (k[0], k[1]))
    common = keys_a & keys_b

    if new_ports:
        print_subheader("NEW PORTS", len(new_ports))
        rows = []
        for host, port in new_ports:
            info = scan_b[(host, port)]
            rows.append(((host, str(port), info['service'], info['banner'][:30]),
                         Colors.BRIGHT_RED))
            print(f"  {Colors.BRIGHT_RED}[+NEW]{Colors.RESET} {host}:{port} "
                  f"{Colors.DIM}{info['service']} {info['banner'][:40]}{Colors.RESET}")
        print()

    if lost_ports:
        print_subheader("LOST PORTS", len(lost_ports))
        for host, port in lost_ports:
            info = scan_a[(host, port)]
            print(f"  {Colors.DIM}[-GONE]{Colors.RESET} {host}:{port} "
                  f"{Colors.DIM}{info['service']}{Colors.RESET}")
        print()

    # Banner drift on common ports
    changed = []
    for key in sorted(common):
        if scan_a[key]['banner'] != scan_b[key]['banner'] and \
                (scan_a[key]['banner'] or scan_b[key]['banner']):
            changed.append((key, scan_a[key]['banner'], scan_b[key]['banner']))
    if changed:
        print_subheader("BANNER DRIFT", len(changed))
        for (host, port), before, after in changed[:15]:
            print(f"  {Colors.BRIGHT_YELLOW}[~]{Colors.RESET} {host}:{port}")
            print(f"      {Colors.DIM}was: {before[:56] or '(none)'}{Colors.RESET}")
            print(f"      {Colors.DIM}now: {after[:56] or '(none)'}{Colors.RESET}")
        print()

    if not (new_ports or lost_ports or changed):
        print_success("No differences")

    print_summary("DIFF", [
        ("New ports", len(new_ports)),
        ("Lost ports", len(lost_ports)),
        ("Banner drift", len(changed)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "diff",
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"new": [f"{h}:{p}" for h, p in new_ports],
                               "lost": [f"{h}:{p}" for h, p in lost_ports],
                               "changed": [f"{h}:{p}" for (h, p), _b, _a in changed]}})

    print_success("Diff completed")
