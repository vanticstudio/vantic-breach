"""
OSINT Harvest Tool
Keyless open-source intelligence: certificate emails, passive host data

Gathers publicly published information only: SAN e-mails from CT logs,
hostnames from HackerTarget. Prints links for manual review - never scrapes
search engines.
"""

import json
import re
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json, Spinner
)

from vantic.core import net

META = {
    "name": "osint",
    "title": "OSINT Harvest",
    "category": "RECONNAISSANCE",
    "description": "Keyless OSINT: emails + hostnames",
    "risk": "safe",
    "examples": [
        "vantic osint example.com",
        "vantic osint example.com --emails --hosts",
    ],
    "flow": [
        ("arg", "domain", "Domain", None),
        ("flag", "--emails", "Harvest e-mail addresses (CT logs)?"),
        ("flag", "--hosts", "Harvest hostnames (HackerTarget)?"),
    ],
    "guard": {"domain": "domain"},
}

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


def ct_emails(domain):
    """Certificate transparency SANs -> e-mail addresses."""
    try:
        resp = net.request(f"https://crt.sh/?q=%.{domain}&output=json", timeout=45,
                           max_retries=1)
        data = json.loads(resp.body.decode("utf-8", errors="replace"))
        emails = set()
        for entry in data:
            for name in str(entry.get("name_value", "")).split("\n"):
                for m in EMAIL_RE.findall(name):
                    if domain.split('.')[-2] in m.split('@')[-1]:
                        emails.add(m.lower())
        return sorted(emails)
    except Exception:
        return []


def ht_hosts(domain):
    """HackerTarget hostsearch (50/day; quota exhaustion = HTTP 200 + text)."""
    try:
        resp = net.request(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                           timeout=20, max_retries=0)
        body = resp.body.decode("utf-8", errors="replace")
        if "API count exceeded" in body:
            return None, "quota exhausted (50/day)"
        hosts = set()
        for line in body.splitlines():
            if "," in line:
                name, ip = line.split(",", 1)
                if name.endswith(domain):
                    hosts.add((name.strip(), ip.strip()))
        return sorted(hosts), None
    except Exception:
        return [], "unavailable"


def add_arguments(parser):
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('--emails', action='store_true', help='Harvest e-mails (CT logs)')
    parser.add_argument('--hosts', action='store_true', help='Harvest hostnames (HackerTarget)')


def run(args):
    domain = args.domain.rstrip('.')
    do_emails = getattr(args, 'emails', False)
    do_hosts = getattr(args, 'hosts', False)
    if not do_emails and not do_hosts:
        do_emails = do_hosts = True

    print_header("OSINT HARVEST", domain)
    kv("Sources", "crt.sh" + (", HackerTarget" if do_hosts else ""))
    print()

    emails = []
    hosts = []

    if do_emails:
        print_subheader("E-MAIL ADDRESSES (CT logs)")
        with Spinner("querying crt.sh..."):
            emails = ct_emails(domain)
        if emails:
            for email in emails:
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {Colors.BOLD}{email}{Colors.RESET}")
        else:
            print(f"  {Colors.DIM}[·] no e-mails in certificate SANs{Colors.RESET}")
        print()

    if do_hosts:
        print_subheader("HOSTNAMES (HackerTarget)")
        hosts, err = ht_hosts(domain)
        if hosts:
            for name, ip in hosts:
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {name:<42} {ip}")
        elif err:
            print(f"  {Colors.DIM}[·] {err}{Colors.RESET}")
        else:
            print(f"  {Colors.DIM}[·] no hostnames returned{Colors.RESET}")
        print()

    print_summary("OSINT RESULTS", [
        ("E-mails", len(emails)),
        ("Hostnames", len(hosts)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "osint", "target": domain,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"emails": emails,
                               "hosts": [{"host": h, "ip": i} for h, i in hosts]}})

    net.close_connections()
    print_success("OSINT harvest completed")
