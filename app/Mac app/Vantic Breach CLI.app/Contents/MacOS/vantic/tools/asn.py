"""
ASN Intelligence Tool
Team Cymru IP-to-ASN (whois port 43 / DNS TXT) + ip-api.com geo

Answers: which ASN owns this IP/domain, what prefixes it announces,
which org runs it, what country it sits in. Hands CIDRs to reverse
sweeps (vantic dns --reverse-cidr).
"""

import json
import socket
import struct
from datetime import datetime

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, kv, Colors, emit_json
)

from vantic.core import net

META = {
    "name": "asn",
    "title": "ASN Intelligence",
    "category": "RECONNAISSANCE",
    "description": "IP/ASN ownership, prefixes, geo",
    "risk": "safe",
    "examples": [
        "vantic asn 8.8.8.8",
        "vantic asn example.com",
        "vantic asn AS15169 --prefixes",
        "vantic asn 8.8.8.8 --geo --reverse",
    ],
    "flow": [
        ("arg", "target", "Domain, IP or AS number (AS15169)", None),
        ("flag", "--prefixes", "List prefixes owned by the ASN?"),
        ("flag", "--geo", "Geo/ISP lookup (ip-api.com)?"),
    ],
    "guard": {},
}

CYMRU_WHOIS = "whois.cymru.com"


def dns_txt_query(name, timeout=5):
    """Minimal DNS TXT query via dnspython or a raw UDP fallback."""
    if HAS_DNSPYTHON:
        try:
            resolver = dns.resolver.get_default_resolver()
            resolver.lifetime = timeout
            answers = resolver.resolve(name, 'TXT')
            return b"".join(r for r in answers[0].strings).decode() if answers else None
        except Exception:
            return None
    # Raw fallback
    qname = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00'
    tid = 0x1234
    header = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    question = qname + struct.pack('>HH', 16, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(header + question, ("1.1.1.1", 53))
            data, _ = s.recvfrom(4096)
        # Walk to the answer TXT
        idx = 12
        while data[idx] != 0:
            if data[idx] & 0xC0:
                idx += 2
                break
            idx += data[idx] + 1
        else:
            idx += 1
        idx += 4
        # skip answer name (may be compressed)
        if data[idx] & 0xC0:
            idx += 2
        else:
            while data[idx] != 0:
                idx += data[idx] + 1
            idx += 1
        rtype, rclass, ttl, rdlen = struct.unpack('>HHIH', data[idx:idx + 10])
        idx += 10
        if rtype == 16 and rdlen > 0:
            txt_len = data[idx]
            return data[idx + 1:idx + 1 + txt_len].decode('utf-8', errors='replace')
    except Exception:
        return None
    return None


def cymru_lookup(value, timeout=15):
    """Team Cymru port-43 lookup. value = IP, AS15169, or domain."""
    try:
        with socket.create_connection((CYMRU_WHOIS, 43), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall((f"{value}\n").encode())
            chunks = []
            while True:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
        raw = b"".join(chunks).decode("utf-8", errors="replace").strip()
    except Exception:
        return None
    lines = [l.strip() for l in raw.splitlines() if l.strip() and '|' in l]
    if not lines:
        return None
    # Header line: first cell is 'AS' (padded, e.g. "AS     | IP | AS Name")
    if lines[0].split('|')[0].strip().lower() == 'as':
        lines = lines[1:]
    rows = []
    for line in lines:
        parts = [p.strip() for p in line.split('|')]
        if len(parts) >= 3:
            rows.append({'asn': parts[0], 'ip': parts[1], 'as_name': parts[2],
                        **({'country': parts[3], 'registry': parts[4]} if len(parts) > 4 else {})})
    return rows


def cymru_prefixes(asn, timeout=20):
    """Prefixes announced by an ASN (Team Cymru 'AS15169')."""
    rows = cymru_lookup("-" + asn.lstrip('ASas').strip(), timeout=timeout)
    return rows


def geo_lookup(ip):
    """ip-api.com free tier (45/min, HTTP-only)."""
    try:
        resp = net.request(f"http://ip-api.com/json/{ip}", timeout=10, max_retries=0)
        return json.loads(resp.body.decode("utf-8", errors="replace"))
    except Exception:
        return None


def add_arguments(parser):
    parser.add_argument('target', help='Domain, IP, or AS number (e.g. AS15169)')
    parser.add_argument('--prefixes', action='store_true',
                        help='List prefixes owned by the ASN')
    parser.add_argument('--geo', action='store_true', help='Geo/ISP lookup (ip-api.com)')
    parser.add_argument('--reverse', action='store_true',
                        help='Peers/siblings via Team Cymru bulk view')
    parser.add_argument('--dns', action='store_true',
                        help='Use the DNS TXT interface (origin.<ip>.origin.asn.cymru.com)')


def run(args):
    target = args.target.strip()
    print_header("ASN INTELLIGENCE", target)
    if HAS_DNSPYTHON:
        kv("Backend", "dnspython + port-43")
    else:
        kv("Backend", "raw sockets (port-43 + UDP DNS)")
    print()

    # Normalize input
    asn = None
    ip = None
    domain = None
    if target.upper().startswith('AS') and target[2:].isdigit():
        asn = target.upper()
    else:
        try:
            socket.inet_aton(target)
            ip = target
        except OSError:
            domain = target

    # Domain -> IP
    if domain:
        asn_name = f"origin.{domain}.origin.asn.cymru.com"
        try:
            resolved = socket.gethostbyname(domain)
            ip = resolved
            print_info(f"{domain} resolves to {resolved}")
        except socket.gaierror:
            print_error(f"Cannot resolve {domain}")
            return

    # DNS TXT route (per-IP origin)
    if getattr(args, 'dns', False) and ip:
        txt = dns_txt_query(f"{'.'.join(reversed(ip.split('.')))}.origin.asn.cymru.com")
        if txt:
            print_info(f"DNS TXT origin: {txt}")

    # Port-43 lookup
    if asn:
        rows = cymru_lookup(asn)
    elif ip:
        rows = cymru_lookup(ip)
    else:
        rows = None

    if not rows:
        print_error("Team Cymru lookup failed (port 43 blocked or unknown target)")
        return

    for row in rows:
        print_subheader(f"AS{row['asn']} · {row.get('as_name', '?')}")
        kv("ASN", row['asn'], Colors.BOLD)
        if row.get('ip'):
            kv("Prefix", row['ip'])
        if row.get('country'):
            kv("Country", row['country'])
        if row.get('registry'):
            kv("Registry", row['registry'])
        if asn and row.get('ip') and '/' in row['ip']:
            print_info(f"Reverse sweep this block: vantic dns --reverse-cidr {row['ip']}")
        print()

    # Prefixes
    if getattr(args, 'prefixes', False) and rows:
        asn_num = rows[0]['asn']
        print_subheader("ANNOUNCED PREFIXES")
        prefixes = cymru_prefixes(asn_num)
        if prefixes:
            rows_fmt = [((p.get('ip', '?'), p.get('as_name', '')), None) for p in prefixes[:100]]
            print_table(["PREFIX", "AS NAME"], rows_fmt, widths=[24, 40])
            print(f"  {Colors.DIM}{len(prefixes)} prefixes total{Colors.RESET}")
        else:
            print_warning("Prefix listing unavailable (bulk mode blocked?)")
        print()

    # Geo
    if getattr(args, 'geo', False) and ip:
        print_subheader("GEO / ISP (ip-api.com)")
        geo = geo_lookup(ip)
        if geo and geo.get('status') == 'success':
            kv("Country", f"{geo.get('country')} ({geo.get('countryCode')})")
            kv("Region", f"{geo.get('regionName')} / {geo.get('city')}")
            kv("ISP", geo.get('isp'))
            kv("Org", geo.get('org'))
            kv("AS", geo.get('as'))
        else:
            print_warning("Geo lookup failed (rate limit or offline)")
        print()

    print_summary("ASN LOOKUP", [
        ("Target", target),
        ("Records", len(rows)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "asn", "target": target,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": rows})

    net.close_connections()
    print_success("ASN lookup completed")
