"""
SNMP Tool
Raw BER GET walks for sysDescr/sysObjectID/sysName + community testing

Default community discovery ('public') is itself the finding. Pure
stdlib BER - no pysnmp needed.
"""

import random
import socket
import struct
import time
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json,
    resolve_wordlist, load_lines
)

from vantic.core import findings, store

META = {
    "name": "snmp",
    "title": "SNMP Probe",
    "category": "SERVICES",
    "description": "sysDescr/sysObjectID + community audit",
    "risk": "intrusive",
    "examples": [
        "vantic snmp 10.0.0.1",
        "vantic snmp 10.0.0.1 --community public --walk",
    ],
    "flow": [
        ("arg", "target", "Target IP", None),
        ("opt", "--community", "Community string", "public"),
    ],
    "guard": {"target": "host"},
}

DEFAULT_COMMUNITIES = ['public', 'private', 'community', 'snmp', 'monitor',
                       'cisco', 'read', 'vantic']

# OID branches to read
SYSTEM_OIDS = [
    ("1.3.6.1.2.1.1.1.0", "sysDescr"),
    ("1.3.6.1.2.1.1.2.0", "sysObjectID"),
    ("1.3.6.1.2.1.1.3.0", "sysUpTime"),
    ("1.3.6.1.2.1.1.4.0", "sysContact"),
    ("1.3.6.1.2.1.1.5.0", "sysName"),
    ("1.3.6.1.2.1.1.6.0", "sysLocation"),
]


# ---------- BER ----------

def ber_len(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(raw)]) + raw


def ber_encode(tag, value):
    if isinstance(value, int):
        if value == 0:
            return bytes([tag, 1, 0])
        raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        return bytes([tag]) + ber_len(len(raw)) + raw
    if isinstance(value, str):
        value = value.encode()
    if isinstance(value, bytes):
        return bytes([tag]) + ber_len(len(value)) + value
    if isinstance(value, list):
        inner = b"".join(value)
        return bytes([tag | 0x20]) + ber_len(len(inner)) + inner
    raise TypeError(value)


def encode_oid(oid):
    parts = [int(p) for p in oid.split('.')]
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p < 128:
            body += bytes([p])
        else:
            stack = []
            while p:
                stack.insert(0, (p & 0x7F) | (0x80 if stack else 0))
                p >>= 7
            body += bytes(stack)
    return ber_encode(0x06, body)


def encode_null():
    return b"\x05\x00"


def build_get(community, oid, request_id=None):
    rid = request_id or random.randint(1, 0x7FFFFFFF)
    varbind = ber_encode(0x30, [encode_oid(oid), encode_null()])
    varbinds = ber_encode(0x30, [varbind])
    pdu = ber_encode(0xA0, [ber_encode(0x02, rid), ber_encode(0x02, 0),
                            ber_encode(0x02, 0), varbinds])
    msg = ber_encode(0x30, [ber_encode(0x02, 1), ber_encode(0x04, community), pdu])
    return msg, rid


def parse_get_response(data):
    """Return (error_status, [(oid, type, value_bytes)])."""
    results = []
    error_status = 0

    def walk(seq, depth=0):
        nonlocal error_status
        if depth > 6 or not seq:
            return
        # iterate TLVs
        pos = 0
        while pos < len(seq) - 2:
            tag = seq[pos]
            l = seq[pos + 1]
            if l & 0x80:
                n = l & 0x7F
                l = int.from_bytes(seq[pos + 2:pos + 2 + n], 'big')
                pos += 2 + n
            else:
                pos += 2
            value = seq[pos:pos + l]
            pos += l
            if tag in (0x30, 0xA0, 0xA1, 0xA2) and depth < 4:
                if tag == 0xA1:  # error-status is 2nd field of GetResponse PDU
                    pass
                walk(value, depth + 1)
                # PDU fields: request-id, error-status, error-index, varbinds
            elif tag == 0x02 and depth == 2:
                try:
                    error_status = int.from_bytes(value, 'big')
                except Exception:
                    pass
            elif tag == 0x30 and depth == 3:
                # varbind: sequence(oid, value)
                pass
            elif tag == 0x06:
                results.append(('oid', value))
            elif tag in (0x04, 0x05, 0x40, 0x41, 0x42, 0x43):
                results.append((hex(tag), value))

    # top-level walk with special PDU awareness
    walk(data)
    return error_status, results


def decode_value(tag, raw):
    if tag == 'oid':
        try:
            parts = [raw[0] // 40, raw[0] % 40]
            i = 1
            while i < len(raw):
                val = 0
                while True:
                    b = raw[i]
                    val = (val << 7) | (b & 0x7F)
                    i += 1
                    if not b & 0x80:
                        break
                parts.append(val)
            return '.'.join(map(str, parts))
        except Exception:
            return raw.hex()
    if tag == '0x40':  # OCTET STRING inside varbind
        return raw.decode('utf-8', errors='replace')
    if tag == '0x41':  # INTEGER-ish? no: 0x02 is int; 0x41 is... unused here
        return str(int.from_bytes(raw, 'big'))
    if tag == '0x42':  # Counter32
        return str(int.from_bytes(raw, 'big'))
    if tag == '0x43':  # TimeTicks
        return f"{int.from_bytes(raw, 'big') // 100}s"
    if tag == '0x05' or tag == '0x04':
        return raw.decode('utf-8', errors='replace') if raw else '(empty)'
    return raw.decode('utf-8', errors='replace') if raw else ''


def snmp_get(host, community, oid, port=161, timeout=3, retries=2):
    """One GET. Returns (ok, error_status, decoded_value)."""
    pkt, rid = build_get(community, oid)
    for _ in range(retries + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(pkt, (host, port))
                data, _ = s.recvfrom(65535)
            error_status, parts = parse_get_response(data)
            for tag, raw in parts:
                if tag == 'oid':
                    continue
                return True, error_status, decode_value(tag, raw)
            return True, error_status, None
        except socket.timeout:
            continue
        except OSError:
            return False, None, None
    return False, None, None


def snmp_walk(host, community, oid, port=161, max_reps=60):
    """GETNEXT-style walk via non-repeaters? Simpler: repeated GET on
    sysORIDs - keep it a bounded sample: read ifNumber + first interfaces."""
    results = []
    # Read ifNumber + ifDescr for the first 8 interfaces
    ok, _es, count = snmp_get(host, community, "1.3.6.1.2.1.2.1.0", port)
    if not ok or count is None:
        return results
    try:
        n = int(count)
    except (TypeError, ValueError):
        return results
    for i in range(1, min(n, 8) + 1):
        ok, _es, desc = snmp_get(host, community, f"1.3.6.1.2.1.2.2.1.2.{i}", port)
        if ok and desc:
            results.append((f"ifDescr.{i}", desc))
    return results


def add_arguments(parser):
    parser.add_argument('target', help='Target IP')
    parser.add_argument('--port', type=int, default=161)
    parser.add_argument('--community', help='Community string (default: test common list)')
    parser.add_argument('--walk', action='store_true', help='Sample interface table')
    parser.add_argument('--timeout', type=float, default=3)


def run(args):
    host = args.target
    port = getattr(args, 'port', 161)
    timeout = getattr(args, 'timeout', 3)
    community_arg = getattr(args, 'community', None)

    print_header("SNMP PROBE", f"{host}:{port}")
    print()

    # Community discovery. Note: a wrong SNMPv2c community is silent (same
    # as a closed port), so the sweep must try every candidate - but with
    # single-try probes to keep a dead port's cost bounded.
    communities = [community_arg] if community_arg else DEFAULT_COMMUNITIES
    working = None
    if community_arg:
        ok, _es, val = snmp_get(host, community_arg, SYSTEM_OIDS[0][0], port, timeout)
        if ok:
            working = community_arg
    else:
        print_subheader("COMMUNITY DISCOVERY", f"{len(communities)} candidates")
        probe_timeout = min(timeout, 2.0)
        for c in communities:
            ok, _es, val = snmp_get(host, c, SYSTEM_OIDS[0][0], port,
                                    probe_timeout, retries=0)
            if ok:
                working = c
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} community "
                      f"{Colors.BOLD}{c}{Colors.RESET} works")
                break
        if not working:
            print(f"  {Colors.DIM}[·] no working community from the common list{Colors.RESET}")
        print()

    if not working:
        print_warning(f"No SNMP response on {host}:{port} "
                      f"(UDP silence = closed or filtered)")
        if getattr(args, 'json', False):
            emit_json({"tool": "snmp", "target": host, "port": port,
                       "started": datetime.now().isoformat(timespec='seconds'),
                       "results": {"error": "no response"}})
        return

    findings.make(family="snmp-default",
                  title=f"SNMP readable with '{working}' community",
                  severity="high" if working in ('public', 'private') else "medium",
                  target=host, port=port,
                  evidence=f"community '{working}' accepted",
                  remediation="Change default communities; use SNMPv3; ACL the listener",
                  tool="snmp")
    if store.is_active():
        store.record_service(host, port, "snmp", f"community '{working}'",
                             source_tool="snmp")

    print_subheader("SYSTEM (READ-ONLY)")
    values = {}
    for oid, name in SYSTEM_OIDS:
        ok, es, val = snmp_get(host, working, oid, port, timeout)
        if ok and val is not None:
            values[name] = val
            kv(name, str(val)[:64])
    print()

    if getattr(args, 'walk', False):
        print_subheader("INTERFACE SAMPLE")
        rows = snmp_walk(host, working, None, port)
        if rows:
            for name, desc in rows:
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {name:<12} {desc[:50]}")
        else:
            print(f"  {Colors.DIM}[·] interface table not readable{Colors.RESET}")
        print()

    print_summary("SNMP", [
        ("Community", working),
        ("System OIDs", len(values)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "snmp", "target": host, "port": port,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": values})

    print_success("SNMP probe completed")
