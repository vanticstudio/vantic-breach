"""
Memcached Tool
TCP + UDP version/stats probes - no-auth detection and item counts
"""

import socket
import struct
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json
)

from vantic.core import findings, store

META = {
    "name": "memcache",
    "title": "Memcached Probe",
    "category": "SERVICES",
    "description": "Version/stats + no-auth detection",
    "risk": "intrusive",
    "examples": [
        "vantic memcache 10.0.0.30",
        "vantic memcache 10.0.0.30 --udp",
    ],
    "flow": [
        ("arg", "target", "Target IP", None),
        ("opt", "--port", "Port", "11211"),
    ],
    "guard": {"target": "host"},
}


def tcp_stats(host, port, timeout=5):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"version\r\n")
            version = s.recv(256).decode(errors='replace').strip()
            s.sendall(b"stats\r\n")
            data = b''
            while b'END' not in data[-16:]:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return version, data.decode(errors='replace')
    except OSError:
        return None, None


def udp_stats(host, port, timeout=4):
    """UDP mode: memcached UDP has a 8-byte header + request id framing."""
    req_id = 0x1337
    body = b"version\r\n"
    header = struct.pack('>HHHH', req_id, 0, 1, 0)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(header + body, (host, port))
            data, _ = s.recvfrom(4096)
        return data[8:].decode(errors='replace').strip(), None
    except OSError as e:
        return None, str(e)


def add_arguments(parser):
    parser.add_argument('target', help='Target IP')
    parser.add_argument('--port', type=int, default=11211)
    parser.add_argument('--udp', action='store_true', help='Probe UDP mode too')
    parser.add_argument('--timeout', type=float, default=5)


def run(args):
    host = args.target
    port = getattr(args, 'port', 11211)
    timeout = getattr(args, 'timeout', 5)

    print_header("MEMCACHED PROBE", f"{host}:{port}")
    print()

    version, stats = tcp_stats(host, port, timeout)
    udp_version, udp_err = (None, None)
    if getattr(args, 'udp', False):
        udp_version, udp_err = udp_stats(host, port, timeout)

    if not version and not udp_version:
        print_error(f"No memcached response ({udp_err or 'TCP closed'})")
        return

    if version:
        ver = version.replace('VERSION ', '').strip()
        kv("TCP version", ver or '(silent)', Colors.BOLD)
        items = 0
        for line in (stats or '').splitlines():
            if line.startswith('STAT curr_items'):
                try:
                    items = int(line.split()[2])
                except (IndexError, ValueError):
                    pass
            if line.startswith('STAT version'):
                ver = line.split()[2]
        kv("Current items", str(items))
        findings.make(family="memcache-unauth",
                      title="Unauthenticated memcached (TCP)",
                      severity="medium", target=f"{host}:{port}",
                      evidence=f"version={ver} curr_items={items}",
                      remediation="Enable SASL auth or firewall to app hosts; "
                                 "never expose to the internet (UDP amplification)",
                      tool="memcache")
        if store.is_active():
            store.record_service(host, port, "memcache", f"version {ver}",
                                source_tool="memcache")

    if udp_version:
        print_success(f"UDP also answering (version {udp_version.replace('VERSION', '').strip()})")
        findings.make(family="memcache-udp",
                      title="Memcached UDP enabled",
                      severity="low", target=f"{host}:{port}",
                      evidence="UDP version probe answered",
                      remediation="Disable UDP unless needed (amplification vector)",
                      tool="memcache")
    elif getattr(args, 'udp', False):
        print_info(f"UDP silent ({udp_err})")

    print()
    print_summary("MEMCACHED", [
        ("TCP", version or '-'),
        ("UDP", udp_version or '-'),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "memcache", "target": f"{host}:{port}",
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"tcp": version, "udp": udp_version}})

    print_success("Memcached probe completed")
