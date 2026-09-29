"""
Whois Lookup Tool
Port-43 whois chain: IANA -> TLD server -> registrar

Parses registrant/org/registrar/creation/expiry; flags soon-expiring
domains and privacy-protected registrations.
"""

import re
import socket
from datetime import datetime, timezone

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json
)

META = {
    "name": "whois",
    "title": "Whois Lookup",
    "category": "RECONNAISSANCE",
    "description": "Domain registration intelligence",
    "risk": "safe",
    "examples": [
        "vantic whois example.com",
        "vantic whois example.com --raw",
    ],
    "flow": [
        ("arg", "domain", "Domain", None),
        ("flag", "--contacts", "Show contact fields?"),
    ],
    "guard": {"domain": "domain"},
}

IANA_WHOIS = "whois.iana.org"


def whois_query(server, query, timeout=15):
    """One port-43 whois query. Returns raw text or None."""
    try:
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall((query + "\r\n").encode())
            chunks = []
            while True:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
        return b"".join(chunks).decode("utf-8", errors="replace")
    except Exception:
        return None


def find_referral(raw):
    """Extract the next whois server from a response."""
    if not raw:
        return None
    m = re.search(r"whois:\s+(\S+)", raw, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"Registrar WHOIS Server:\s+(\S+)", raw, re.IGNORECASE)
    if m:
        return m.group(1)
    return None


FIELD_MAP = {
    'registrar': [r"Registrar:\s*(.+)", r"Sponsoring Registrar:\s*(.+)"],
    'registrar_url': [r"Registrar URL:\s*(.+)"],
    'registrant_org': [r"Registrant Organization:\s*(.+)"],
    'registrant_name': [r"Registrant Name:\s*(.+)"],
    'registrant_country': [r"Registrant Country:\s*(.+)"],
    'created': [r"Creation Date:\s*(.+)", r"Registered on:\s*(.+)", r"Created:\s*(.+)"],
    'updated': [r"Updated Date:\s*(.+)", r"Last updated:\s*(.+)"],
    'expires': [r"Registry Expiry Date:\s*(.+)", r"Expiry Date:\s*(.+)",
               r"Expiry date:\s*(.+)", r"Expiration Date:\s*(.+)"],
    'status': [r"Domain Status:\s*(.+)"],
    'name_servers': [r"Name Server:\s*(.+)"],
}


def parse_whois(raw):
    """Extract common fields from whois text."""
    fields = {}
    if not raw:
        return fields
    for key, patterns in FIELD_MAP.items():
        for pat in patterns:
            matches = re.findall(pat, raw, re.IGNORECASE)
            if matches:
                if key == 'name_servers':
                    fields[key] = sorted({m.strip() for m in matches})
                else:
                    fields[key] = matches[0].strip()
                break
    return fields


def add_arguments(parser):
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('--raw', action='store_true', help='Print raw whois response')
    parser.add_argument('--contacts', action='store_true', help='Show contact fields')


def run(args):
    domain = args.domain.rstrip('.').lower()
    if '/' in domain:
        domain = domain.split('/')[-1]

    print_header("WHOIS LOOKUP", domain)
    print()

    # Step 1: IANA -> TLD referral
    raw = whois_query(IANA_WHOIS, domain)
    if raw is None:
        print_error(f"Cannot reach {IANA_WHOIS} (port 43 blocked?)")
        return
    referral = find_referral(raw)
    if not referral:
        print_error(f"IANA has no record for '{domain}' - invalid domain?")
        return
    print_info(f"TLD whois server: {referral}")

    # Step 2: TLD server
    raw = whois_query(referral, domain)
    if raw is None:
        print_error(f"Cannot reach {referral}")
        return
    fields = parse_whois(raw)
    registrar_server = find_referral(raw)

    # Step 3: registrar server (deeper data)
    if registrar_server and registrar_server != referral:
        deeper = whois_query(registrar_server, domain)
        if deeper:
            deeper_fields = parse_whois(deeper)
            for k, v in deeper_fields.items():
                fields.setdefault(k, v)
            if getattr(args, 'raw', False):
                raw = deeper

    if not fields:
        print_warning("No recognizable fields - showing raw response")
        print()
        print(raw[:2000])
        return

    # Render
    order = ['registrar', 'registrar_url', 'registrant_org', 'registrant_name',
             'registrant_country', 'created', 'updated', 'expires', 'status']
    for key in order:
        if key in fields:
            kv(key.replace('_', ' ').title(), fields[key])
    if 'name_servers' in fields:
        kv("Name servers", ', '.join(fields['name_servers'][:4]))

    if getattr(args, 'contacts', False):
        print_subheader("CONTACTS")
        for pat, label in [
            (r"Admin Name:\s*(.+)", "Admin name"),
            (r"Admin Email:\s*(.+)", "Admin email"),
            (r"Tech Email:\s*(.+)", "Tech email"),
            (r"Abuse-Mailbox:\s*(.+)", "Abuse mailbox"),
        ]:
            m = re.search(pat, raw, re.IGNORECASE)
            if m:
                kv(label, m.group(1).strip())

    # Findings: expiry + privacy
    if fields.get('expires'):
        try:
            exp = datetime.fromisoformat(
                fields['expires'].replace('Z', '+00:00'))
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                print()
                print_warning(f"Domain EXPIRED {-days} days ago")
            elif days < 45:
                print()
                print_warning(f"Domain expires in {days} days")
        except ValueError:
            pass
    joined = ' '.join(str(v) for v in fields.values())
    if any(s in joined.lower() for s in ('privacy', 'redacted', 'whoisguard',
                                        'domains by proxy', 'data protected')):
        print()
        print_info("Registration is privacy-protected (normal for consumer domains)")

    if getattr(args, 'raw', False):
        print_subheader("RAW RESPONSE")
        print(raw[:4000])

    print()
    print_summary("WHOIS", [
        ("Registrar", fields.get('registrar', '-')),
        ("Created", fields.get('created', '-')[:10]),
        ("Expires", fields.get('expires', '-')[:10]),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "whois", "target": domain,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": fields})

    print_success("Whois lookup completed")
