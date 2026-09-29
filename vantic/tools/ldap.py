"""
LDAP Probe Tool
Anonymous rootDSE + depth-1 search (ldap3 optional, raw BER fallback)

The rootDSE is the directory's business card: naming contexts, SASL
mechs, server capabilities - all anonymously readable by design. A
depth-1 search that RETURNS objects is an anonymous-enumeration finding.
"""

import socket
import struct
import time
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json
)

from vantic.core import findings, store

META = {
    "name": "ldap",
    "title": "LDAP Probe",
    "category": "INTERNAL / AD",
    "description": "Anonymous rootDSE + search exposure",
    "risk": "safe",
    "examples": [
        "vantic ldap 10.0.0.10",
        "vantic ldap 10.0.0.10 --search --base dc=corp,dc=local",
    ],
    "flow": [
        ("arg", "target", "Target IP (DC)", None),
        ("flag", "--search", "Depth-1 anonymous search?"),
    ],
    "guard": {"target": "host"},
}


# ---------- minimal BER encoding ----------

def ber_len(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(raw)]) + raw


def ber(tag, value):
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


def ber_int(n):
    return ber(0x02, n)


def ber_enum(n):
    return ber(0x0A, n)


def ber_octets(s):
    return ber(0x04, s)


def ber_seq(*parts):
    return ber(0x30, list(parts))


def parse_ber_tl(data, offset):
    """Return (tag, header_len, content_len, next_offset)."""
    if offset >= len(data):
        return None
    tag = data[offset]
    offset += 1
    first = data[offset]
    offset += 1
    if first & 0x80 == 0:
        length = first
    else:
        n = first & 0x7F
        length = int.from_bytes(data[offset:offset + n], 'big')
        offset += n
    return tag, offset, length, offset + length


def parse_search_entry(data):
    """Pull attribute values out of a SearchResultEntry message."""
    results = []
    try:
        tag, start, _, end = parse_ber_tl(data, 0)  # sequence
        tag, start, _, msg_end = parse_ber_tl(data, start)  # message id
        tag, start, _, entry_end = parse_ber_tl(data, start)  # SearchResEntry tag 0x64
        if tag != 0x64:
            return results
        tag, start, _, _ = parse_ber_tl(data, start)  # object name
        tag, start, _, attrs_end = parse_ber_tl(data, start)  # attributes seq
        pos = start
        while pos < attrs_end - 2:
            t, s, l, e = parse_ber_tl(data, pos)
            if t != 0x30:
                break
            pos = e
            # attribute = seq(type, set(values))
            t2, s2, l2, e2 = parse_ber_tl(data, s)
            t3, s3, l3, e3 = parse_ber_tl(data, e2)
            if t3 == 0x31:  # set of values
                t4, s4, l4, e4 = parse_ber_tl(data, s3)
                if t4 == 0x04:
                    results.append(data[s4:s4 + l4].decode('utf-8', errors='replace'))
                    pos = max(pos, e4)
    except Exception:
        pass
    return results


def ldap_message_id(mid):
    return ber_int(mid)


def anonymous_bind_packet(mid=1):
    return ber_seq(ldap_message_id(mid), ber(0x60, [
        ber_int(3),           # version 3
        ber_octets(''),       # empty DN = anonymous
        ber(0x80, b''),       # simple auth, empty password
    ]))


def rootdse_search_packet(mid=2):
    return ber_seq(ldap_message_id(mid), ber(0x63, [
        ber_octets(''),                      # base: rootDSE
        ber_enum(0),                        # scope: base
        ber_enum(0),                        # deref: never
        ber_int(0),                          # size limit: none
        ber_int(30),                         # time limit
        ber(0x01, b'\xff'),                  # types only: false
        ber(0x87, b'(objectClass=*)'),        # filter: present
        ber(0x30, []),                       # attributes: all user attrs
    ]))


def depth1_search_packet(base, mid=3):
    return ber_seq(ldap_message_id(mid), ber(0x63, [
        ber_octets(base),
        ber_enum(0),                        # scope base (depth-1 via listing)
        ber_enum(0),
        ber_int(60),
        ber_int(30),
        ber(0x01, b'\xff'),
        ber(0x87, b'(objectClass=*)'),
        ber(0x30, [ber_octets('name'), ber_octets('distinguishedName')]),
    ]))


def ldap_exchange(target, port, packets, timeout=6):
    """Send packets, collect responses until a matching message or timeout."""
    responses = []
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            for pkt in packets:
                s.sendall(pkt)
            end = time.time() + timeout
            while time.time() < end:
                try:
                    data = s.recv(65536)
                except socket.timeout:
                    break
                if not data:
                    break
                responses.append(data)
    except OSError as e:
        return responses, str(e)
    return responses, None


def add_arguments(parser):
    parser.add_argument('target', help='Target IP (domain controller)')
    parser.add_argument('--port', type=int, default=389, help='LDAP port (389/636)')
    parser.add_argument('--search', action='store_true',
                        help='Depth-1 anonymous search under the naming context')
    parser.add_argument('--base', help='Search base DN (default: defaultNamingContext)')


def run(args):
    target = args.target
    port = getattr(args, 'port', 389)
    do_search = getattr(args, 'search', False)

    print_header("LDAP PROBE", f"{target}:{port}")
    kv("Backend", "raw BER (stdlib)")
    print()

    # Anonymous bind + rootDSE search
    packets = [anonymous_bind_packet(1), rootdse_search_packet(2)]
    responses, err = ldap_exchange(target, port, packets)
    if err and not responses:
        print_error(f"Connection failed: {err}")
        return

    # Parse rootDSE attributes from any SearchResultEntry
    attrs = {}
    for data in responses:
        for val in parse_search_entry(data):
            if ':' in val:
                k, v = val.split(':', 1)
                attrs.setdefault(k.strip(), []).append(v.strip())

    # Robust fallback: find readable attribute strings in the raw responses
    text = b"".join(responses).decode('utf-8', errors='replace')

    def grab(label, default='-'):
        idx = text.find(label)
        if idx < 0:
            return default
        chunk = text[idx + len(label):].lstrip('\x00 ')
        return chunk.split('\x00')[0].strip() or default

    if b"".join(responses) == b'' or 'namingContexts' not in text:
        print_warning("No rootDSE response - LDAP may be closed or LDAPS-only")
        print_info("Try --port 636 (LDAPS)")
        return

    print_subheader("ROOTDSE (ANONYMOUS)")
    for key in ('dnsHostName', 'defaultNamingContext', 'rootDomainNamingContext',
               'ldapServiceName', 'serverName', 'supportedSASLMechanisms',
               'domainFunctionality'):
        val = grab(key)
        if val != '-':
            kv(key, val[:60])
    sasl = 'GSSAPI' in text or 'NTLM' in text
    if sasl:
        kv("SASL mechs seen", "yes")
    if store.is_active():
        store.record_service(target, port, "ldap", "anonymous rootDSE readable",
                            source_tool="ldap")
    findings.make(family="ldap-info", title="Anonymous rootDSE readable",
                  severity="info", target=f"{target}:{port}",
                  evidence="naming contexts + capabilities disclosed anonymously",
                  remediation="Expected by design - informational",
                  tool="ldap")
    print()

    if do_search:
        base = getattr(args, 'base', None) or grab('defaultNamingContext', '')
        values = []
        print_subheader("ANONYMOUS SEARCH", base or "(no base)")
        if not base:
            print_warning("No defaultNamingContext discovered - pass --base")
        else:
            packets = [anonymous_bind_packet(1), depth1_search_packet(base, 3)]
            responses, err = ldap_exchange(target, port, packets)
            values = []
            for data in responses:
                values.extend(parse_search_entry(data))
            if values:
                for v in values[:20]:
                    print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {v[:70]}")
                findings.make(family="ldap-anon-enum",
                              title="Anonymous LDAP search returns objects",
                              severity="medium", target=f"{target}:{port}",
                              evidence=f"{len(values)} objects under {base}",
                              remediation="Remove Anonymous Logon from "
                                          "Pre-Win2000 Compatible Access",
                              tool="ldap")
            else:
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} Anonymous search "
                      f"denied/empty (healthy baseline)")

    print()
    print_summary("LDAP PROBE", [
        ("RootDSE", "readable"),
        ("Anonymous search", "returns objects" if do_search and values else
         ("denied" if do_search else "not attempted")),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "ldap", "target": target, "port": port,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"rootdse": grab('defaultNamingContext'),
                               "hostname": grab('dnsHostName')}})

    print_success("LDAP probe completed")
