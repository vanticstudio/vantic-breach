"""
NetBIOS Query Tool
NBSTAT (UDP/137) node status - hostnames, logged-on users (<03>),
file servers (<20>), browser roles, MAC

Windows firewalls often block UDP/137 inbound - timeouts are reported
as their own signal, not as "no NetBIOS".
"""

import socket
import struct
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, ProgressBar, kv, Colors,
    emit_json
)

from vantic.core import findings, store

META = {
    "name": "nbtquery",
    "title": "NetBIOS Query",
    "category": "INTERNAL / AD",
    "description": "NBSTAT name tables + user leaks",
    "risk": "safe",
    "examples": [
        "vantic nbtquery 192.168.1.10",
        "vantic nbtquery 192.168.1.0/24",
    ],
    "flow": [
        ("arg", "target", "Target IP or CIDR", None),
    ],
    "guard": {"target": "cidr"},
}

NAME_TYPES = {
    0x00: "Workstation/hostname", 0x01: "Messenger browser",
    0x03: "Messenger (logged-on user)", 0x06: "RAS server",
    0x1B: "Domain master browser", 0x1D: "Master browser",
    0x1E: "Browser elections", 0x20: "File server",
    0x21: "RAS client", 0xBE: "Network monitor agent",
    0xBF: "Network monitor utility",
}


def nbstat_query(ip, timeout=2, retries=2):
    """Send an NBSTAT query; parse the name table. Returns (names, mac, err)."""
    # NBNS header: transaction id, flags=NODE_STAT (0x0010), questions=1
    # Q name = the encoded wildcard status name, scope NUL, type NBSTAT, class IN
    qname = b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00'
    packet = struct.pack('>HHHH', 0x1337, 0x0010, 1, 0) + qname + \
        struct.pack('>HH', 0x0021, 0x0001)

    for _ in range(retries + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(packet, (ip, 137))
                data, _ = s.recvfrom(2048)
            return _parse_nbstat(data), None
        except socket.timeout:
            return None, "timeout (firewalled UDP/137?)"
        except ConnectionRefusedError:
            return None, "ICMP port unreachable (closed)"
        except OSError as e:
            last = str(e)
            continue
    return None, last


def _decode_nb_name(raw):
    """First-level NetBIOS name encoding: 16 bytes -> 32 ASCII chars."""
    out = []
    for i in range(0, len(raw), 2):
        if i + 1 >= len(raw):
            break
        hi = raw[i] - ord('A')
        lo = raw[i + 1] - ord('A')
        out.append(chr((hi << 4) | lo))
    return ''.join(out)


def _parse_nbstat(data):
    """Parse an NBSTAT response into [(name, suffix, flags)] + MAC."""
    if len(data) < 12 + 1 + 34:
        return None
    offset = 12
    # skip question name (encoded + scope)
    while offset < len(data) and data[offset] != 0:
        offset += data[offset] + 1
    offset += 1
    offset += 4  # type + class
    # resource name + type + class + ttl + rdlength
    offset += 2  # RR name pointer (0xC00C)
    rtype, rclass, ttl, rdlen = struct.unpack('>HHIH', data[offset:offset + 10])
    offset += 10
    payload = data[offset:offset + rdlen]
    if len(payload) < 1:
        return None
    num_names = payload[0]
    pos = 1
    names = []
    for _ in range(num_names):
        if pos + 18 > len(payload):
            break
        raw_name = payload[pos:pos + 16]
        suffix = payload[pos + 15]
        flags = struct.unpack('<H', payload[pos + 16:pos + 18])[0]
        pos += 18
        name = _decode_nb_name(raw_name).strip()
        if name:
            names.append((name, suffix, flags))
    mac = payload[pos:pos + 6] if pos + 6 <= len(payload) else b''
    mac_str = ':'.join(f"{b:02x}" for b in mac) if len(mac) == 6 else ''
    return {'names': names, 'mac': mac_str}


def add_arguments(parser):
    parser.add_argument('target', help='Target IP or CIDR')
    parser.add_argument('--timeout', type=int, default=2, help='Per-query timeout (s)')


def run(args):
    target = args.target.strip()
    timeout = getattr(args, 'timeout', 2)

    ips = [target]
    if '/' in target:
        import ipaddress
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            print_error(f"Invalid CIDR: {target}")
            return
        if net.num_addresses > 256:
            print_error("Cap is /24 per sweep")
            return
        ips = [str(ip) for ip in net.hosts()]

    print_header("NETBIOS QUERY", target)
    kv("Hosts", len(ips))
    kv("Timeout", f"{timeout}s")
    print()

    all_results = []
    rows = []

    if len(ips) == 1:
        parsed, err = nbstat_query(ips[0], timeout)
        if parsed is None:
            print_error(f"{ips[0]}: {err}")
            if 'timeout' in (err or ''):
                print_info("UDP/137 timeouts are common - Windows firewalls block "
                           "inbound NetBIOS (itself a posture signal)")
            if getattr(args, 'json', False):
                emit_json({"tool": "nbtquery", "target": target,
                           "started": datetime.now().isoformat(timespec='seconds'),
                           "results": []})
            return
        _render(ips[0], parsed)
        all_results.append({'ip': ips[0], **parsed})
    else:
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(nbstat_query, ip, timeout): ip for ip in ips}
            progress = ProgressBar(len(ips), "NBSTAT")
            for future in as_completed(futures):
                ip = futures[future]
                parsed, err = future.result()
                if parsed:
                    _render(ip, parsed)
                    all_results.append({'ip': ip, **parsed})
                progress.update()
        print()

    if all_results:
        print_summary("NBSTAT SWEEP", [
            ("Queried", len(ips)),
            ("Answered", len(all_results)),
        ])

    if getattr(args, 'json', False):
        emit_json({"tool": "nbtquery", "target": target,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": [{'ip': r['ip'], 'mac': r['mac'],
                                'names': [{'name': n, 'suffix': s, 'flags': f}
                                          for n, s, f in r['names']]}
                               for r in all_results]})
    print_success("NetBIOS query completed")


def _render(ip, parsed):
    print_subheader(ip, f"{len(parsed['names'])} names")
    for name, suffix, flags in parsed['names']:
        role = NAME_TYPES.get(suffix, f"type 0x{suffix:02X}")
        color = Colors.BRIGHT_GREEN if suffix in (0x03, 0x1B) else Colors.DIM
        marker = '★' if suffix == 0x03 else ' '
        print(f"  {color}[+]{Colors.RESET} {marker} {Colors.BOLD}{name:<18}{Colors.RESET}"
              f"<{suffix:02X}> {role}")
        if suffix == 0x03:
            findings.make(family="nbns-user-leak",
                          title=f"Logged-on user disclosed via NetBIOS",
                          severity="low", target=ip,
                          evidence=f"name '{name}' <03> Messenger entry",
                          remediation="Disable the Messenger/NetBIOS name types",
                          tool="nbtquery")
    if parsed.get('mac'):
        print(f"  {Colors.DIM}MAC: {parsed['mac']}{Colors.RESET}")
    if store.is_active():
        store.record_target(ip, "host")
