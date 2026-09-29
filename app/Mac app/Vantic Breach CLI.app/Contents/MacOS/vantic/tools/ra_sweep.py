"""
Remote Access Sweep Tool
VNC / SSH / Telnet / TeamViewer / AnyDesk remote-access surfaces

VNC security type 1 = "no authentication" (critical). Old Windows
OpenSSH banners = version-age signal. TeamViewer/AnyDesk ports open =
third-party remote access worth flagging in the report.
"""

import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, ProgressBar, kv, Colors,
    emit_json
)

from vantic.core import findings, store

META = {
    "name": "ra_sweep",
    "title": "Remote Access Sweep",
    "category": "INTERNAL / AD",
    "description": "VNC/SSH/Telnet/TV/AnyDesk surfaces",
    "risk": "safe",
    "examples": [
        "vantic ra_sweep 192.168.1.10",
        "vantic ra_sweep 192.168.1.0/24 --vnc --ssh",
    ],
    "flow": [
        ("arg", "target", "Target IP or CIDR", None),
    ],
    "guard": {"target": "cidr"},
}


def probe_vnc(host, timeout=5):
    """RFB handshake: version exchange + security types."""
    try:
        with socket.create_connection((host, 5900), timeout=timeout) as s:
            s.settimeout(timeout)
            version = s.recv(12).decode(errors='replace').strip()
            if not version.startswith('RFB'):
                return None
            s.sendall(b"RFB 003.008\n")
            sec = s.recv(64)
            types = []
            if len(sec) >= 2 and sec[0]:
                n = sec[0]
                types = list(sec[1:1 + n])
            elif len(sec) >= 34:  # RFB 3.3: single u32 security type
                t = int.from_bytes(sec[:4], 'big')
                types = [t]
            return {'version': version, 'types': types}
    except OSError:
        return None


def probe_ssh(host, port=22, timeout=5):
    """SSH banner read."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(256).decode(errors='replace').strip()
            return banner if banner.startswith('SSH-') else None
    except OSError:
        return None


def probe_telnet(host, timeout=5):
    """Telnet banner read."""
    try:
        with socket.create_connection((host, 23), timeout=timeout) as s:
            s.settimeout(3)
            data = s.recv(256)
            # strip IAC sequences
            text = ''
            i = 0
            while i < len(data):
                if data[i] == 255 and i + 2 < len(data):
                    i += 3
                else:
                    text += chr(data[i])
                    i += 1
            return text.strip() or '(connected, silent)'
    except OSError:
        return None


def check_tcp(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            return True
    except OSError:
        return False


def add_arguments(parser):
    parser.add_argument('target', help='Target IP or CIDR')
    parser.add_argument('--vnc', action='store_true', help='VNC (5900+)')
    parser.add_argument('--ssh', action='store_true', help='SSH banner (22)')
    parser.add_argument('--telnet', action='store_true', help='Telnet banner (23)')
    parser.add_argument('--tva', action='store_true',
                        help='TeamViewer/AnyDesk port presence')
    parser.add_argument('--all', action='store_true', help='Every check')


def run(args):
    target = args.target.strip()
    if getattr(args, 'all', False):
        args.vnc = args.ssh = args.telnet = args.tva = True
    if not any([getattr(args, 'vnc', False), getattr(args, 'ssh', False),
                getattr(args, 'telnet', False), getattr(args, 'tva', False)]):
        args.vnc = args.ssh = args.telnet = args.tva = True

    hosts = [target]
    if '/' in target:
        import ipaddress
        try:
            net_obj = ipaddress.ip_network(target, strict=False)
        except ValueError:
            print_error(f"Invalid CIDR: {target}")
            return
        if net_obj.num_addresses > 256:
            print_error("Cap is /24 per sweep")
            return
        hosts = [str(ip) for ip in net_obj.hosts()]

    print_header("REMOTE ACCESS SWEEP", target)
    kv("Hosts", len(hosts))
    kv("Checks", ' '.join(filter(None, ['vnc' if args.vnc else None,
                                       'ssh' if args.ssh else None,
                                       'telnet' if args.telnet else None,
                                       'tva' if args.tva else None])))
    print()

    results = []
    work = []
    for host in hosts:
        if args.vnc:
            work.append(('vnc', host))
        if args.ssh:
            work.append(('ssh', host))
        if args.telnet:
            work.append(('telnet', host))
        if args.tva:
            work.append(('tva', host))

    def do(item):
        kind, host = item
        if kind == 'vnc':
            return kind, host, probe_vnc(host)
        if kind == 'ssh':
            return kind, host, probe_ssh(host)
        if kind == 'telnet':
            return kind, host, probe_telnet(host)
        if kind == 'tva':
            tv = check_tcp(host, 5938)
            ad = check_tcp(host, 7070)
            return kind, host, {'teamviewer': tv, 'anydesk': ad}

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(do, item): item for item in work}
        progress = ProgressBar(len(work), "ra sweep")
        for future in as_completed(futures):
            kind, host, result = future.result()
            if result:
                results.append({'kind': kind, 'host': host, 'data': result})
                progress.interrupt()
                _report(kind, host, result)
            progress.update()

    print()
    print_summary("REMOTE ACCESS", [
        ("Hosts", len(hosts)),
        ("Surfaces", len(results)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "ra_sweep", "target": target,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": results})
    print_success("Remote access sweep completed")


def _report(kind, host, result):
    if kind == 'vnc':
        types = result['types']
        type_names = {1: 'None (NO AUTH)', 2: 'VNC auth', 5: 'RA2', 6: 'Tight',
                      16: 'TLS', 17: 'VeNCrypt', 19: 'ARD', 35: 'Ultra'
                      }.items()
        names = [n for t, n in type_names if t in types] or [f"types {types}"]
        color = Colors.BRIGHT_RED if 1 in types else Colors.BRIGHT_GREEN
        print(f"  {color}[VNC]{Colors.RESET} {host:<16} {result['version']} "
              f"auth: {', '.join(names)}")
        if 1 in types:
            findings.make(family="vnc-noauth", title="VNC without authentication",
                          severity="critical", target=host, port=5900,
                          evidence=f"RFB {result['version']} offers security type 1 (None)",
                          remediation="Require VNC authentication or tunnel over SSH",
                          tool="ra_sweep")
        if store.is_active():
            store.record_service(host, 5900, "vnc", result['version'], source_tool="ra_sweep")
    elif kind == 'ssh':
        windows = 'OpenSSH_for_Windows' in result
        old = False
        import re
        m = re.search(r'OpenSSH_([0-9.]+)', result)
        if m:
            try:
                if float(m.group(1)[:4]) < 7.4:
                    old = True
            except ValueError:
                pass
        color = Colors.BRIGHT_YELLOW if (old or windows) else Colors.BRIGHT_GREEN
        print(f"  {color}[SSH]{Colors.RESET} {host:<16} {result[:60]}")
        if old:
            findings.make(family="ssh-old", title="Aged OpenSSH banner",
                          severity="medium", target=host, port=22,
                          evidence=result, remediation="Update OpenSSH",
                          tool="ra_sweep")
        if store.is_active():
            store.record_service(host, 22, "ssh", result, source_tool="ra_sweep")
    elif kind == 'telnet':
        print(f"  {Colors.BRIGHT_YELLOW}[TELNET]{Colors.RESET} {host:<16} {str(result)[:50]}")
        findings.make(family="telnet", title="Telnet service exposed",
                      severity="high", target=host, port=23,
                      evidence=str(result)[:120] or 'banner read',
                      remediation="Replace telnet with SSH",
                      tool="ra_sweep")
        if store.is_active():
            store.record_service(host, 23, "telnet", str(result), source_tool="ra_sweep")
    elif kind == 'tva':
        if result.get('teamviewer') or result.get('anydesk'):
            which = ', '.join(filter(None, ['TeamViewer(5938)' if result['teamviewer'] else None,
                                           'AnyDesk(7070)' if result['anydesk'] else None]))
            print(f"  {Colors.BRIGHT_MAGENTA}[3RD-PARTY]{Colors.RESET} {host:<16} {which}")
            findings.make(family="third-party-ra",
                         title=f"Third-party remote access detected ({which})",
                         severity="medium", target=host,
                         evidence=which,
                         remediation="Review/authorize third-party remote-access tools",
                         tool="ra_sweep")
