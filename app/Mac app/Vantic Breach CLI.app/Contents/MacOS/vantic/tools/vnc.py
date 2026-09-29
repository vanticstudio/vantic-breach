"""
VNC Tool
RFB handshake: version exchange + security types

Security type 1 (None) = unauthenticated VNC (critical finding).
"""

import socket
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json
)

from vantic.core import findings, store

META = {
    "name": "vnc",
    "title": "VNC Probe",
    "category": "SERVICES",
    "description": "RFB version + security types",
    "risk": "safe",
    "examples": [
        "vantic vnc 10.0.0.50",
        "vantic vnc 10.0.0.50 --display 1",
    ],
    "flow": [
        ("arg", "target", "Target IP", None),
        ("opt", "--display", "VNC display number (port = 5900+n)", "0"),
    ],
    "guard": {"target": "host"},
}

SECURITY_NAMES = {0: 'Invalid', 1: 'None (NO AUTH)', 2: 'VNC Authentication',
                 5: 'RA2', 6: 'RA2ne', 7: 'Tight', 8: 'Ultra', 10: 'TLS',
                 11: 'VeNCrypt', 12: 'GTK-VNC SASL', 16: 'TLS',
                 17: 'VeNCrypt', 19: 'ARD', 20: 'MSLogonII', 35: 'Ultra'}


def rfb_handshake(host, port, timeout=6):
    """Version exchange + read the server's security types."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(12)
            if not banner.startswith(b'RFB'):
                return {'error': f'not an RFB service ({banner[:8]!r})'}
            server_version = banner.decode(errors='replace').strip()
            # Reply with the same protocol generation
            major = server_version[3]
            reply = f"RFB 003.{major}08\n"[:11].encode()
            if major == '3':
                reply = b"RFB 003.008\n"
            s.sendall(reply)
            sec_data = s.recv(64)
            types = []
            if len(sec_data) >= 1 and sec_data[0]:
                n = sec_data[0]
                types = list(sec_data[1:1 + n])
            elif len(sec_data) >= 4:  # RFB 3.3: single u32
                t = int.from_bytes(sec_data[:4], 'big')
                types = [t] if t else []
            return {'version': server_version, 'types': types}
    except OSError as e:
        return {'error': str(e)}


def add_arguments(parser):
    parser.add_argument('target', help='Target IP')
    parser.add_argument('--display', type=int, default=0,
                        help='VNC display number (port = 5900 + n)')
    parser.add_argument('--port', type=int, default=None, help='Explicit port')


def run(args):
    host = args.target
    display = getattr(args, 'display', 0)
    port = getattr(args, 'port', None) or (5900 + display)

    print_header("VNC PROBE", f"{host}:{port}")
    print()

    result = rfb_handshake(host, port)
    if result.get('error'):
        print_error(f"{host}:{port} {result['error']}")
        if getattr(args, 'json', False):
            emit_json({"tool": "vnc", "target": f"{host}:{port}",
                       "started": datetime.now().isoformat(timespec='seconds'),
                       "results": {"error": result['error']}})
        return

    version = result['version']
    types = result['types']
    kv("RFB version", version, Colors.BOLD)

    if not types:
        print_warning("No security types offered (or unsupported RFB version)")
        return

    names = [SECURITY_NAMES.get(t, f'type {t}') for t in types]
    kv("Security types", ', '.join(names))

    if store.is_active():
        store.record_service(host, port, "vnc", f"{version} auth={names}",
                            source_tool="vnc")

    if 1 in types:
        print()
        print_warning("Security type 1 (None) offered - VNC WITHOUT authentication")
        findings.make(family="vnc-noauth", title="VNC without authentication",
                      severity="critical", target=f"{host}:{port}",
                      evidence=f"RFB {version} offers security type 1 (None)",
                      remediation="Enable VNC authentication or tunnel via SSH",
                      tool="vnc")
    elif 2 in types:
        print()
        print_success("VNC authentication required (type 2)")
    elif any(t in (16, 17, 19) for t in types):
        print()
        print_success("TLS-capable auth offered")
    else:
        print_info("Auth posture needs manual review: " + ', '.join(names))

    print()
    print_summary("VNC", [
        ("Version", version),
        ("Auth", "NONE" if 1 in types else "required"),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "vnc", "target": f"{host}:{port}",
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": result})

    print_success("VNC probe completed")
