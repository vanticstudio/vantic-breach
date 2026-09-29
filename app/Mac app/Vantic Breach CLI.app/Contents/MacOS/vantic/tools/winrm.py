"""
WinRM Assessment Tool
HTTP(S) /wsman presence + accepted authentication planes

Read-only: one GET, parse the 401 WWW-Authenticate challenges. No auth
attempts are made.
"""

import socket
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json
)

from vantic.core import net, findings, store

META = {
    "name": "winrm",
    "title": "WinRM Assessment",
    "category": "INTERNAL / AD",
    "description": "WS-Man presence + auth planes",
    "risk": "safe",
    "examples": [
        "vantic winrm 192.168.1.10",
        "vantic winrm 10.0.0.5 --ports 5985,5986",
    ],
    "flow": [
        ("arg", "target", "Target IP or host", None),
    ],
    "guard": {"target": "host"},
}


def probe_port(target, port, use_ssl):
    """GET /wsman -> (reachable, status, auth types, server header)."""
    scheme = 'https' if use_ssl else 'http'
    try:
        resp = net.request(f"{scheme}://{target}:{port}/wsman", "GET",
                           timeout=8, follow_redirects=False, max_retries=0)
        status = resp.status
        auth = resp.header("WWW-Authenticate", "")
        server = resp.header("Server", "")
        return True, status, auth, server
    except Exception as e:
        return False, str(e), '', ''


def add_arguments(parser):
    parser.add_argument('target', help='Target IP or hostname')
    parser.add_argument('--ports', default='5985,5986',
                        help='Ports (5985=http, 5986=https)')


def run(args):
    target = args.target
    ports = []
    for p in getattr(args, 'ports', '5985,5986').split(','):
        p = p.strip()
        if p.isdigit():
            ports.append((int(p), int(p) == 5986 or int(p) == 443))

    print_header("WINRM ASSESSMENT", target)
    kv("Ports", ', '.join(str(p) for p, _ in ports))
    print()

    found_any = False
    for port, use_ssl in ports:
        label = f":{port} ({'https' if use_ssl else 'http'})"
        ok, status, auth, server = probe_port(target, port, use_ssl)
        if not ok:
            print(f"  {Colors.DIM}[·] {label:<18} unreachable{Colors.RESET}")
            continue
        found_any = True
        print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {label:<18} "
              f"{Colors.BOLD}{status}{Colors.RESET}")
        if server:
            kv("Server", server)
        if auth:
            mechs = [m.strip() for m in auth.split(',') if m.strip()]
            kv("Auth accepted", ', '.join(mechs))
            if 'Basic' in mechs and not use_ssl:
                findings.make(family="winrm-basic-http",
                              title="WinRM accepts Basic auth over plain HTTP",
                              severity="high", target=target, port=port,
                              evidence=f"WWW-Authenticate: {auth}",
                              remediation="Disable Basic or require HTTPS (5986)",
                              tool="winrm")
            if not mechs:
                print_info("No auth challenge (anonymous WS-Man?)")
        if store.is_active():
            store.record_service(target, port, "winrm",
                                f"{status} {' '.join(auth.split(','))}",
                                source_tool="winrm")
        print()

    if not found_any:
        print_warning("No WinRM listeners answered "
                      "(Enable-PSRemoting not run on the target?)")
    else:
        print_info("Presence + auth-type report only - no auth attempts were made")

    print_summary("WINRM", [("Listeners", "found" if found_any else "none")])

    if getattr(args, 'json', False):
        emit_json({"tool": "winrm", "target": target,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"ports_checked": [p for p, _ in ports]}})

    net.close_connections()
    print_success("WinRM assessment completed")
