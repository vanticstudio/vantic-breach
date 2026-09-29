"""
Kerberos Username Enumeration Tool
Raw AS-REQ probes against the KDC (TCP 88, no pre-auth)

KDC_ERROR_PREAUTH_REQUIRED (6) = user exists;
KDC_ERR_C_PRINCIPAL_UNKNOWN (5) = no such user;
a full AS-REP = pre-auth disabled (ASREPRoast exposure).

No passwords are submitted - these probes cannot lock accounts out.
"""

import socket
import struct
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, ProgressBar, kv, Colors,
    emit_json, resolve_wordlist, load_lines
)

from vantic.core import findings, store

META = {
    "name": "kerbprobe",
    "title": "Kerberos Probe",
    "category": "INTERNAL / AD",
    "description": "Username enumeration + AS-REP exposure",
    "risk": "intrusive",
    "examples": [
        "vantic kerbprobe 10.0.0.10 --users users.txt",
        "vantic kerbprobe corp.local --users names.txt --dc-ip 10.0.0.10",
    ],
    "flow": [
        ("arg", "target", "Domain or KDC", None),
        ("opt", "--users", "Usernames wordlist (blank = small defaults)", ""),
    ],
    "guard": {},
}

KDC_ERRS = {
    5: "no such principal",
    6: "pre-auth required (user exists)",
    10: "principal not unique",
    16: "encryption type unsupported",
    18: "pre-auth expired",
    23: "password expired (user exists)",
    24: "pre-auth failed (weak crypto offered)",
    25: "pre-auth required (new type)",
    35: "client realm unknown",
    50: "revoked",
}

DEFAULT_CANDIDATES = [
    'administrator', 'admin', 'guest', 'krbtgt', 'sqlservice', 'sqlsvc',
    'backup', 'test', 'jsmith', 'asmith', 'temp', 'helpdesk', 'svc_account',
]


# ---------- minimal DER encoding ----------

def der_len(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(raw)]) + raw


def der(tag, value):
    if isinstance(value, int):
        if value == 0:
            return bytes([tag, 1, 0])
        raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        return bytes([tag]) + der_len(len(raw)) + raw
    if isinstance(value, str):
        value = value.encode()
    if isinstance(value, bytes):
        return bytes([tag]) + der_len(len(value)) + value
    if isinstance(value, list):
        inner = b"".join(value)
        return bytes([tag | 0x20]) + der_len(len(inner)) + inner
    raise TypeError(value)


def der_gkstring(s):
    return der(0x1B, s)


def der_oid(oid_str):
    parts = [int(p) for p in oid_str.split('.')]
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
    return der(0x06, body)


def build_asreq(principal, realm, nonce):
    """AS-REQ without pre-auth (PA-ENC-TIMESTAMP omitted)."""
    cname = der(0xA1, [der(0x30, [der(0xA0, [der(0x02, 1)]), der_gkstring(principal)])])
    sname = der(0xA2, [der(0x30, [der(0xA0, [der(0x02, 2)]), der_gkstring('krbtgt'),
                                der_gkstring(realm)])])
    realm_tag = der(0xA0, der_gkstring(realm))
    body = der(0x30, [realm_tag, cname, sname,
                     der(0xA5, der(0x18, nonce)),
                     der(0xA7, [der(0x30, [der_oid('1.2.840.113554.1.2.2')]),  # AES256
                               der(0x30, [der_oid('1.2.840.113554.1.2.2')]),
                               der(0x30, [der_oid('1.2.840.48018.1.2.2')]),
                               der(0x30, [der_oid('1.2.840.113554.1.2.2')]),
                               der(0x30, [der_oid('1.2.840.113554.1.2.2')])])])
    pvno = der(0xA0, der(0x02, 5))
    msg_type = der(0xA1, der(0x02, 10))  # AS-REQ
    msg = der(0x6A, [pvno, msg_type, der(0xA2, [der(0x30, [der(0xA0, [der(0x02, 1)]),
                                                        der_gkstring(realm)])]),
                der(0xA3, body)])
    # Inner Application tag 10 = AS-REQ
    inner = der(0x6E, [pvno, msg_type, realm_tag, cname, sname,
                      der(0xA5, der(0x18, nonce)),
                      der(0xA7, [der(0x30, [der_oid('1.2.840.113554.1.2.2')])])])
    return der(0x6A, [pvno, msg_type, realm_tag, cname, sname,
                    der(0xA5, der(0x18, nonce)),
                    der(0xA7, [der(0x30, [der_oid('1.2.840.113554.1.2.2')])])])


def parse_kdc_error(data):
    """Parse a KRB-ERROR -> error code, or detect an AS-REP (returns -11)."""
    if not data:
        return None
    # AS-REP is [APPLICATION 11] (0x6B) - full reply without pre-auth
    if data[0] == 0x6B:
        return -11
    # KRB-ERROR is [APPLICATION 30] (0x7E); error-code is context tag [6]
    if data[0] == 0x7E or b'\xa6' in data[:64]:
        idx = data.find(b'\xa6\x03\x02')
        if idx >= 0 and idx + 4 <= len(data):
            return data[idx + 3]
        idx = data.find(b'\xa6\x04\x02')
        if idx >= 0 and idx + 6 <= len(data):
            return int.from_bytes(data[idx + 3:idx + 5], 'big')
    return None


def probe_user(kdc, realm, user, timeout=5):
    """One AS-REQ. Returns (user, code)."""
    pkt = build_asreq(user, realm, 0x12345678)
    try:
        with socket.create_connection((kdc, 88), timeout=timeout) as s:
            s.settimeout(timeout)
            # TCP framing: 4-byte length prefix
            s.sendall(struct.pack('>I', len(pkt)) + pkt)
            data = s.recv(65536)
        if len(data) > 4:
            body = data[4:] if struct.unpack('>I', data[:4])[0] == len(data) - 4 else data
            return user, parse_kdc_error(body)
        return user, None
    except OSError:
        return user, None


def add_arguments(parser):
    parser.add_argument('target', help='Domain (realm) or KDC hostname/IP')
    parser.add_argument('--users', help='Usernames wordlist')
    parser.add_argument('--dc-ip', help='KDC address (default: resolve _kerberos SRV)')
    parser.add_argument('--threads', type=int, default=10)


def run(args):
    import socket as s
    domain = args.target.rstrip('.').upper()
    users_file = getattr(args, 'users', None)
    dc_ip = getattr(args, 'dc_ip', None)

    users = DEFAULT_CANDIDATES
    if users_file:
        loaded = load_lines(users_file)
        if loaded:
            users = loaded
        else:
            print_warning(f"Wordlist not found: {users_file} - using defaults")

    # Resolve KDC
    if not dc_ip:
        try:
            dc_ip = s.gethostbyname(domain.lower())
        except s.gaierror:
            try:
                dc_ip = s.gethostbyname(f"dc.{domain.lower()}")
            except s.gaierror:
                print_error(f"Cannot resolve a KDC for {domain} - pass --dc-ip")
                return

    print_header("KERBEROS PROBE", f"{domain} via {dc_ip}")
    kv("KDC", f"{dc_ip}:88")
    kv("Realm", domain)
    kv("Candidates", len(users))
    print_info("No passwords are sent - these probes cannot lock accounts")
    print()

    results = []
    with ThreadPoolExecutor(max_workers=min(10, getattr(args, 'threads', 10))) as executor:
        futures = {executor.submit(probe_user, dc_ip, domain, u): u for u in users}
        progress = ProgressBar(len(users), "AS-REQ")
        for future in as_completed(futures):
            user, code = future.result()
            results.append((user, code))
            if code == -11:
                progress.interrupt()
                print(f"  {Colors.BOLD}{Colors.BRIGHT_RED}[!!] {user}{Colors.RESET} "
                      f"answered with an AS-REP (pre-auth disabled - ASREPRoast exposure)")
            elif code == 6 or code == 23:
                progress.interrupt()
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {Colors.BOLD}{user:<24}{Colors.RESET}"
                      f" exists ({KDC_ERRS.get(code, code)})")
            elif code == 5:
                pass  # unknown user - expected noise
            elif code is None:
                pass
            else:
                progress.interrupt()
                print(f"  {Colors.DIM}[·] {user:<24} {KDC_ERRS.get(code, f'code {code}')}{Colors.RESET}")
            progress.update()

    existing = [u for u, c in results if c in (6, 23, -11)]

    print()
    print_subheader("CONFIRMED USERS", len(existing))
    if existing:
        rows = [((u, KDC_ERRS.get(c, str(c))), Colors.BRIGHT_GREEN) for u, c in results
                if c in (6, 23)]
        print_table(["USERNAME", "KDC SAYS"], rows, widths=[24, 30])
        findings.make(family="kerb-userenum",
                      title="Kerberos username enumeration possible",
                      severity="medium", target=domain,
                      evidence=f"{len(existing)}/{len(users)} candidates confirmed",
                      remediation="Inherent NTLM-era behavior; note in report, "
                                  "monitor KDC logs for enumeration bursts",
                      tool="kerbprobe")
        for u in existing:
            if store.is_active():
                store.record_target(u, "host", group_name="domain-users")
    else:
        print_warning("No confirmed users - check the realm name and KDC reachability")

    print_summary("KERBEROS PROBE", [
        ("Probed", len(users)),
        ("Exist", len(existing)),
        ("Unknown", len([u for u, c in results if c == 5])),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "kerbprobe", "domain": domain, "kdc": dc_ip,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": [{"user": u, "code": c} for u, c in results]})

    print_success("Kerberos probe completed")
