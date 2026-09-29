"""
mDNS Scanner Tool
Multicast DNS / Bonjour inventory (UDP/5353): Macs, printers, IoT

PTR queries for common service types + a passive listen window. Flags
non-corporate gear (shadow IT / flat network evidence).
"""

import socket
import struct
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, ProgressBar, kv, Colors,
    emit_json
)

from vantic.core import findings, store

META = {
    "name": "mdnsscan",
    "title": "mDNS Scanner",
    "category": "INTERNAL / AD",
    "description": "Bonjour/mDNS service inventory",
    "risk": "safe",
    "examples": [
        "vantic mdnsscan",
        "vantic mdnsscan --active --types _smb,_http,_ipp",
        "vantic mdnsscan --passive --duration 30",
    ],
    "flow": [
        ("flag", "--active", "Query common service types?"),
        ("flag", "--passive", "Listen for announcements?"),
    ],
    "guard": {},
}

MDNS_GROUP = ("224.0.0.251", 5353)

SERVICE_TYPES = [
    "_smb._tcp", "_http._tcp", "_https._tcp", "_ipp._tcp", "_ipps._tcp",
    "_printer._tcp", "_airplay._tcp", "_raop._tcp", "_ssh._tcp",
    "_rdp._tcp", "_adisk._tcp", "_afpovertcp._tcp", "_daap._tcp",
    "_googlecast._tcp", "_homekit._tcp", "_hap._tcp", "_mqtt._tcp",
    "_uscan._tcp", "_companion-link._tcp", "_services._dns-sd",
]

SHADOW_HINTS = ('googlecast', 'airplay', 'raop', 'homekit', 'hap',
               'daap', 'companion-link')


def build_query(stype):
    """A DNS PTR query packet for <service>.local."""
    qname_parts = stype.split('.') + ['local']
    qname = b''.join(bytes([len(p)]) + p.encode() for p in qname_parts if p) + b'\x00'
    header = struct.pack('>HHHHHH', 0x0000, 0x0000, 1, 0, 0, 0)
    return header + qname + struct.pack('>HH', 12, 1)  # PTR, IN


def parse_ptr_answer(data):
    """Extract PTR rdata strings from an mDNS response."""
    results = []
    if len(data) < 12:
        return results
    qdcount = struct.unpack('>H', data[4:6])[0]
    ancount = struct.unpack('>H', data[6:8])[0]
    offset = 12
    for _ in range(qdcount):
        offset = skip_name(data, offset)
        offset += 4
    for _ in range(ancount):
        offset = skip_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack('>HHIH', data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        offset += rdlen
        if rtype == 12 and rdlen > 0:  # PTR
            name = read_name(data, offset - rdlen + 1) if rdata and rdata[0] < 0x40 else ''
            # rdata is itself a (possibly compressed) name
            try:
                target = read_name_at(data, offset - rdlen)
                if target:
                    results.append(target)
            except Exception:
                pass
    return results


def skip_name(data, offset):
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0:
            return offset + 2
        offset += 1 + length
    return offset


def read_name_at(data, offset):
    """Read a possibly-compressed DNS name at offset."""
    labels = []
    jumps = 0
    while offset < len(data) and jumps < 10:
        length = data[offset]
        if length == 0:
            break
        if length & 0xC0:
            pointer = struct.unpack('>H', data[offset:offset + 2])[0] & 0x3FFF
            offset = pointer
            jumps += 1
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode('utf-8', errors='replace'))
        offset += length
    return '.'.join(labels)


def query_stype(stype, timeout=2.5):
    """One mDNS PTR query -> [instance names]."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.sendto(build_query(stype), MDNS_GROUP)
        seen = set()
        end = time.time() + timeout
        while time.time() < end:
            try:
                sock.settimeout(max(0.1, end - time.time()))
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            for target in parse_ptr_answer(data):
                seen.add((target, addr[0]))
        return sorted(seen)
    except OSError:
        return []
    finally:
        sock.close()


class PassiveListener(threading.Thread):
    def __init__(self, duration, sink):
        super().__init__(daemon=True)
        self.duration = duration
        self.sink = sink
        self.stop_event = threading.Event()

    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            sock.bind(("", 5353))
            mreq = struct.pack("4sl", socket.inet_aton(MDNS_GROUP[0]), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.settimeout(1)
            end = time.time() + self.duration
            while not self.stop_event.is_set() and time.time() < end:
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                for target in parse_ptr_answer(data):
                    self.sink((target, addr[0]))
            sock.close()
        except OSError:
            pass


def add_arguments(parser):
    parser.add_argument('--active', action='store_true', help='Query service types')
    parser.add_argument('--passive', action='store_true', help='Listen for announcements')
    parser.add_argument('--types', help=f"Service types (comma-separated, e.g. _smb._tcp)")
    parser.add_argument('--duration', type=int, default=30,
                        help='Passive listen seconds')


def run(args):
    active = getattr(args, 'active', False)
    passive = getattr(args, 'passive', False)
    duration = getattr(args, 'duration', 30)
    types_arg = getattr(args, 'types', None)
    if not active and not passive:
        active = passive = True

    types = SERVICE_TYPES
    if types_arg:
        types = [t.strip() for t in types_arg.split(',') if t.strip()]

    print_header("MDNS SCANNER", "224.0.0.251:5353")
    kv("Mode", ("active + passive" if active and passive
               else "active" if active else "passive"))
    kv("Service types", len(types))
    print()

    results = []

    if active:
        print_subheader("ACTIVE QUERIES")
        for stype in types:
            hits = query_stype(stype)
            for name, ip in hits:
                results.append({'service': stype, 'name': name, 'ip': ip})
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {stype:<22} "
                      f"{Colors.BOLD}{name[:40]}{Colors.RESET} {Colors.DIM}{ip}{Colors.RESET}")
                if store.is_active():
                    store.record_target(ip, "host", group_name="mdns")
        print()

    if passive:
        print_subheader("PASSIVE LISTEN", f"{duration}s")
        lock = threading.Lock()

        def sink(item):
            with lock:
                name, ip = item
                results.append({'service': 'announced', 'name': name, 'ip': ip})
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} "
                      f"{Colors.BOLD}{name[:44]}{Colors.RESET} {Colors.DIM}{ip}{Colors.RESET}")

        listener = PassiveListener(duration, sink)
        listener.start()
        print_info(f"Listening {duration}s - Ctrl+C to stop early")
        try:
            while listener.is_alive():
                listener.join(timeout=1.0)
        except KeyboardInterrupt:
            listener.stop_event.set()
            listener.join(timeout=2)
        print()

    # Shadow-IT detection
    shadow = [r for r in results
              if any(h in r['name'].lower() or h in r['service'].lower()
                     for h in SHADOW_HINTS)]
    if shadow:
        print_warning(f"{len(shadow)} consumer/IoT services on the corporate segment")
        findings.make(family="mdns-shadow",
                      title="Consumer/IoT devices on corporate network",
                      severity="medium",
                      evidence=", ".join(f"{r['name'].split('.')[0]} ({r['ip']})"
                                         for r in shadow[:8]),
                      remediation="Enroll, quarantine or VLAN-segment consumer devices",
                      tool="mdnsscan")

    print_summary("MDNS INVENTORY", [
        ("Services found", len(results)),
        ("Unique hosts", len({r['ip'] for r in results})),
        ("Consumer/IoT", len(shadow)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "mdnsscan",
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": results})

    print_success("mDNS scan completed")
