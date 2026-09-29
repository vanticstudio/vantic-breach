"""
Gateway Audit Tool
Identify the gateway/router, assess its admin planes, audit default
credentials, and check DNS posture. Optional UPnP (see the upnp tool).
"""

import base64
import re
import socket
import urllib.parse
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json,
    resolve_wordlist, load_lines, load_json_data
)

from vantic.core import net, findings, store

META = {
    "name": "gateway",
    "title": "Gateway Audit",
    "category": "GATEWAY / INFRA",
    "description": "Router identify + admin + creds + DNS",
    "risk": "intrusive",
    "examples": [
        "vantic gateway 192.168.1.1",
        "vantic gateway 192.168.1.1 --creds",
    ],
    "flow": [
        ("arg", "target", "Gateway IP", None),
        ("flag", "--creds", "Default-credential audit?"),
    ],
    "guard": {"target": "host"},
}

ADMIN_PORTS = [(80, 'http'), (443, 'https'), (8080, 'http'), (8443, 'https'),
               (23, 'telnet'), (22, 'ssh'), (7547, 'tr-069'), (161, 'snmp')]

# Static vendor DNS names (resolve against the gateway resolver)
VENDOR_NAMES = ['routerlogin.net', 'fritz.box', 'tplinkwifi.net',
                'dlinkrouter.local', 'router.asus.com', 'openwrt.lan']


def fingerprint_http(target, port, scheme, timeout=8):
    """HTTP identity: Server, realm, title."""
    try:
        resp = net.request(f"{scheme}://{target}:{port}/", "GET", timeout=timeout,
                           follow_redirects=False, max_retries=0)
        server = resp.header("Server", "") or ""
        realm = resp.header("WWW-Authenticate", "") or ""
        title = ''
        m = re.search(r'<title[^>]*>(.*?)</title>', resp.text(16384),
                      re.IGNORECASE | re.DOTALL)
        if m:
            title = m.group(1).strip()[:48]
        return {'port': port, 'status': resp.status, 'server': server,
                'realm': realm, 'title': title}
    except Exception:
        return None


def banner_grab(target, port, timeout=4):
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return s.recv(128).decode(errors='replace').strip()
    except OSError:
        return None


def identify_vendor(signatures, fp):
    """Match a fingerprint against the signature DB."""
    if not fp:
        return None
    hay = ' '.join([fp.get('server', ''), fp.get('realm', ''),
                   fp.get('title', '')]).lower()
    for entry in signatures:
        for sig in entry.get('signatures', []):
            if sig.lower() in hay:
                return entry
    return None


def default_cred_attempt(target, port, scheme, user, pwd, timeout=8):
    """Basic-auth default credential attempt."""
    try:
        cred = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        resp = net.request(f"{scheme}://{target}:{port}/", "GET", timeout=timeout,
                           follow_redirects=False, max_retries=0,
                           headers={"Authorization": f"Basic {cred}"})
        # 200 = in; 401 = out
        return resp.status != 401
    except Exception:
        return None


def add_arguments(parser):
    parser.add_argument('target', help='Gateway IP')
    parser.add_argument('--creds', action='store_true',
                        help='Default-credential audit (vendor-filtered)')
    parser.add_argument('--dns', action='store_true', default=True,
                        help='DNS posture check (resolver + recursion)')
    parser.add_argument('--timeout', type=float, default=8)


def run(args):
    target = args.target
    timeout = getattr(args, 'timeout', 8)
    signatures = load_json_data("router_signatures.json") or []

    print_header("GATEWAY AUDIT", target)
    print()

    # 1. Management planes
    print_subheader("MANAGEMENT PLANES")
    fps = []
    for port, scheme in ADMIN_PORTS:
        if port in (80, 443, 8080, 8443):
            fp = fingerprint_http(target, port, scheme, timeout)
            if fp:
                fps.append((scheme, fp))
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} :{port:<5} {scheme:<5} "
                      f"{fp['status']} {Colors.DIM}{fp['server'] or fp['title']}{Colors.RESET}")
                if store.is_active():
                    store.record_service(target, port, scheme,
                                         f"{fp['server']} {fp['title']}",
                                         source_tool='gateway')
        else:
            banner = banner_grab(target, port)
            if banner:
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} :{port:<5} "
                      f"{Colors.BOLD}{banner[:40]}{Colors.RESET}")
                if port == 23:
                    findings.make(family="gateway-telnet",
                                  title="Telnet on gateway",
                                  severity="high", target=target, port=port,
                                  evidence=banner[:80],
                                  remediation="Disable telnet, use SSH",
                                  tool="gateway")
                if store.is_active():
                    store.record_service(target, port, None, banner,
                                        source_tool='gateway')
    if not fps:
        print_warning("No management planes answered")
    print()

    # 2. Identify
    print_subheader("IDENTIFY")
    vendor = None
    for scheme, fp in fps:
        vendor = identify_vendor(signatures, fp)
        if vendor:
            break
    if vendor:
        kv("Vendor guess", f"{vendor.get('vendor', '?')} "
                           f"{vendor.get('model', '')}".strip(), Colors.BOLD)
        print_info(f"Default-cred list: {vendor.get('wordlist', 'router_defaults.txt')}")
    else:
        # Vendor static DNS names
        for name in VENDOR_NAMES:
            try:
                ip = socket.gethostbyname(name)
                if ip == target:
                    kv("Vendor guess", f"via {name}", Colors.BOLD)
                    break
            except socket.gaierror:
                continue
        else:
            print_info("Vendor not identified from signatures "
                       "(add it to vantic/data/router_signatures.json)")
    print()

    # 3. Admin plane posture
    for scheme, fp in fps:
        plain_http = scheme == 'http'
        if plain_http and fp['status'] in (200, 401):
            findings.make(family="gateway-admin-http",
                          title="Admin interface on plain HTTP",
                          severity="medium", target=f"{target}:{fp['port']}",
                          evidence=f"status {fp['status']} without redirect to https",
                          remediation="Enforce HTTPS + HSTS for admin access",
                          tool="gateway")
            print_warning(f"Admin UI on plain HTTP :{fp['port']}")

    # 4. Default credentials (opt-in)
    if getattr(args, 'creds', False):
        print_subheader("DEFAULT CREDENTIALS")
        wordlist = resolve_wordlist(None, 'router_defaults.txt')
        pairs = load_lines(wordlist) if wordlist else None
        if not pairs:
            print_warning("router_defaults.txt not found in wordlists/")
        elif not fps:
            print_warning("No HTTP admin plane - skipping Basic-auth audit")
        else:
            scheme, fp = fps[0]
            port = fp['port']
            creds = []
            for line in pairs:
                if line.startswith('#') or ':' not in line:
                    continue
                parts = line.split(':')
                if len(parts) >= 3:
                    # vendor:user:pass
                    v, u, p = parts[0].lower(), parts[1], parts[2]
                    if vendor and vendor.get('vendor', '').lower() in v:
                        creds.append((u, p))
                else:
                    u, p = parts[0], parts[1] if len(parts) > 1 else ''
                    creds.append((u, p))
            if vendor:
                creds = creds[:15]  # vendor-filtered cap
            else:
                creds = creds[:10]
            hit = None
            for user, pwd in creds:
                ok = default_cred_attempt(target, port, scheme, user, pwd, timeout)
                if ok:
                    hit = (user, pwd)
                    break
                if ok is None:
                    print_info("Admin plane stopped answering - aborting cred audit")
                    break
            if hit:
                print(f"  {Colors.BOLD}{Colors.BRIGHT_RED}[!!] DEFAULT LOGIN: "
                      f"{hit[0]}:{hit[1]}{Colors.RESET}")
                findings.make(family="gateway-creds",
                              title="Default credentials on gateway",
                              severity="critical", target=f"{target}:{port}",
                              evidence=f"{hit[0]}:{hit[1]}",
                              remediation="Rotate the admin password",
                              tool="gateway")
            else:
                print_success(f"No default login from {len(creds)} pairs")
            print()

    # 5. DNS posture
    if getattr(args, 'dns', True):
        print_subheader("DNS POSTURE")
        # resolver role: does it answer for a public name?
        from vantic.core.net import udp_exchange
        import struct
        # simple A query for example.com
        q = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' \
            b'\x07example\x03com\x00\x00\x01\x00\x01'
        reply = udp_exchange(target, 53, q, timeout=3, retries=1)
        if reply:
            print_success("Gateway answers DNS (resolver role)")
            # open resolver: does it recurse for an external domain?
            q2 = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' \
                 b'\x07example\x03com\x00\x00\x01\x00\x01'
            if reply and len(reply) > 12 and (reply[3] & 0x80):
                kv("Recursive", "yes (expected for a LAN resolver)")
        else:
            print_info("Gateway does not answer DNS on :53")
        print()

    print_summary("GATEWAY", [
        ("Admin planes", len(fps)),
        ("Vendor", (vendor or {}).get('vendor', 'unknown')),
        ("Findings", len(findings.drain()) or 'see store'),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "gateway", "target": target,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"planes": [fp for _s, fp in fps],
                               "vendor": vendor}})

    net.close_connections()
    print_success("Gateway audit completed")
