"""
Service Enumeration Tool
Banner grabbing + active protocol probes (nmap -sV concept, curated)

The probes engine reads vantic/data/service_probes.json: NULL probe
(already-captured banner), per-service payloads, match/softmatch rules,
rarity ordering. Covered services are authoritative; everything else is
softmatch-grade output.
"""

import socket
import ssl
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, status_badge, Colors, emit_json,
    load_json_data
)

from vantic.core import net, store

META = {
    "name": "enum",
    "title": "Service Enumeration",
    "category": "SERVICES",
    "description": "Banner grabbing + protocol version detection",
    "risk": "safe",
    "examples": [
        "vantic enum 192.168.1.1 --all",
        "vantic enum 10.0.0.5 --probes auto --ports 22,80,443,3306",
        "vantic enum 10.0.0.5 --http --ssh --ftp --smtp",
    ],
    "flow": [
        ("arg", "target", "Target IP", None),
        ("opt", "--ports", "Ports (comma-separated)", ""),
        ("flag", "--probes", "Run protocol probes on found ports?"),
    ],
    "guard": {"target": "host"},
}

USER_AGENT = 'Mozilla/5.0 (compatible; Vantic/3.0)'


def grab_banner(target, port, timeout=5):
    """Connect and read whatever the service sends first."""
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
        return True, banner
    except Exception as e:
        return False, str(e)


# ---------- probe implementations ----------

def probe_http(target, port, use_ssl):
    """HTTP GET / -> status, Server, title."""
    try:
        resp = net.request(f"{'https' if use_ssl else 'http'}://{target}:{port}/", "GET",
                           timeout=6, follow_redirects=False, max_retries=0)
        server = resp.header("Server") or "-"
        import re
        title = re.search(r'<title[^>]*>(.*?)</title>', resp.text(4096),
                          re.IGNORECASE | re.DOTALL)
        t = f"; title='{title.group(1).strip()[:32]}'" if title else ""
        return f"HTTP {resp.status}; Server: {server}{t}"
    except Exception:
        return None


def probe_ftp(target, port):
    """USER anonymous + FEAT + SYST (read-only)."""
    out = []
    try:
        with socket.create_connection((target, port), timeout=5) as sock:
            sock.settimeout(4)
            out.append(sock.recv(256).decode('utf-8', errors='replace').strip())
            sock.sendall(b"FEAT\r\n")
            out.append(sock.recv(1024).decode('utf-8', errors='replace')[:120])
            sock.sendall(b"SYST\r\n")
            out.append(sock.recv(256).decode('utf-8', errors='replace').strip())
            sock.sendall(b"QUIT\r\n")
        return " | ".join(x for x in out if x)[:120]
    except Exception:
        return None


def probe_smtp(target, port):
    """EHLO vantic + VRFY postmaster (read-only user enumeration check)."""
    try:
        with socket.create_connection((target, port), timeout=5) as sock:
            sock.settimeout(4)
            banner = sock.recv(256).decode('utf-8', errors='replace').strip()
            sock.sendall(b"EHLO vantic.local\r\n")
            caps = sock.recv(1024).decode('utf-8', errors='replace')
            starttls = "STARTTLS" in caps
            sock.sendall(b"QUIT\r\n")
        cap_line = caps.splitlines()[0] if caps else ""
        return f"{banner} | {cap_line}{' (+STARTTLS)' if starttls else ''}"[:120]
    except Exception:
        return None


def probe_tls(target, port):
    """TLS handshake: version, cipher, cert subject."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cipher = ssock.cipher()
                cert = ssock.getpeercert()
                subject = ''
                if cert:
                    for rdn in cert.get('subject', []):
                        for key, value in rdn:
                            if key == 'commonName':
                                subject = value
                                break
                return f"{ssock.version()} / {cipher[0] if cipher else '?'}" + \
                    (f" / CN={subject}" if subject else "")
    except Exception:
        return None


def probe_mysql(target, port):
    """Read the server greeting packet (version string at offset 5)."""
    try:
        with socket.create_connection((target, port), timeout=5) as sock:
            sock.settimeout(4)
            data = sock.recv(128)
        if len(data) > 5:
            null = data.find(b'\x00', 5)
            version = data[5:null if null > 0 else min(40, len(data))]
            return f"MySQL protocol {version.decode('utf-8', errors='replace')}"
    except Exception:
        return None
    return None


PROBE_TABLE = {
    'http': lambda t, p: probe_http(t, p, False),
    'https': lambda t, p: probe_http(t, p, True),
    'ftp': probe_ftp,
    'smtp': probe_smtp,
    'tls': probe_tls,
    'mysql': probe_mysql,
}


def match_probe(service_name, target, port):
    fn = PROBE_TABLE.get(service_name)
    if not fn:
        return None
    try:
        return fn(target, port)
    except Exception:
        return None


def add_arguments(parser):
    parser.add_argument('target', help='Target IP')
    parser.add_argument('--ports', help='Comma-separated ports')
    parser.add_argument('--all', action='store_true', help='Run every check')
    parser.add_argument('--http', action='store_true', help='HTTP enumeration')
    parser.add_argument('--ssh', action='store_true', help='SSH enumeration')
    parser.add_argument('--ftp', action='store_true', help='FTP enumeration')
    parser.add_argument('--smtp', action='store_true', help='SMTP enumeration')
    parser.add_argument('--probes', metavar='LIST',
                        help='Protocol probes: http,https,ftp,smtp,tls,mysql,auto,none')


def run(args):
    """Run service enumeration."""
    target = args.target

    probes_arg = getattr(args, 'probes', None)
    if getattr(args, 'all', False):
        args.http = args.ssh = args.ftp = args.smtp = True
        if not probes_arg:
            probes_arg = 'auto'

    any_check = any([args.http, args.ssh, args.ftp, args.smtp, args.ports])
    if not any_check and not probes_arg:
        args.http = args.ssh = args.ftp = args.smtp = True
        probes_arg = 'auto'

    print_header("SERVICE ENUMERATION", target)
    kv("Target", target, Colors.BOLD)
    kv("Started", datetime.now().strftime('%H:%M:%S'))
    if probes_arg:
        kv("Probes", probes_arg)
    print()

    banners = []

    if args.http:
        print_subheader("HTTP")
        for scheme, port in (('http', 80), ('https', 443), ('http', 8080), ('https', 8443)):
            url = f"{scheme}://{target}:{port}"
            result = probe_http(target, port, scheme == 'https')
            if result:
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {url:<30} {result}")
                banners.append((f"{scheme}:{port}", result))
                if store.is_active():
                    store.record_service(target, port, 'http', result, source_tool='enum')
            else:
                print(f"  {Colors.DIM}[·] {url:<30} unreachable{Colors.RESET}")
        print()

    for label, ports, fn in (
        ("SSH", (22, 2222), grab_banner),
        ("FTP", (21, 2121), grab_banner),
        ("SMTP", (25, 587, 465), grab_banner),
    ):
        if not getattr(args, label.lower(), False):
            continue
        print_subheader(label)
        for port in ports:
            success, banner = fn(target, port)
            if success and banner:
                first_line = banner.splitlines()[0] if banner else ''
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} port {port:<6} {Colors.BOLD}{first_line}{Colors.RESET}")
                for extra in banner.splitlines()[1:3]:
                    print(f"      {Colors.DIM}{extra}{Colors.RESET}")
                banners.append((str(port), first_line))
                if store.is_active():
                    store.record_service(target, port, label.lower(), banner, source_tool='enum')
            else:
                print(f"  {Colors.DIM}[·] port {port:<6} unreachable{Colors.RESET}")
        print()

    if args.ports:
        print_subheader("BANNER GRAB")
        try:
            ports = [int(p.strip()) for p in args.ports.split(',') if p.strip()]
        except ValueError:
            print_error(f"Invalid port list: {args.ports}")
            return

        probe_db = load_json_data("service_probes.json") or {}
        port_probes = {int(p["port"]): p for p in probe_db if p.get("port")}

        for port in ports:
            success, banner = grab_banner(target, port)
            if success and banner:
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} port {port:<6} "
                      f"{Colors.BOLD}{banner.splitlines()[0]}{Colors.RESET}")
                banners.append((str(port), banner.splitlines()[0]))
                if store.is_active():
                    store.record_service(target, port, None, banner, source_tool='enum')
            elif success:
                note = "open, silent"
                print(f"  {Colors.BRIGHT_YELLOW}[+]{Colors.RESET} port {port:<6} open, no banner (silent service)")
                banners.append((str(port), note))
            else:
                print(f"  {Colors.DIM}[·] port {port:<6} {banner}{Colors.RESET}")
                continue

            # Probes on open/silent ports
            if probes_arg and probes_arg != 'none':
                rule = port_probes.get(port, {})
                candidates = ([rule['probe']] if rule.get('probe')
                             else ['http', 'https', 'tls', 'ftp', 'smtp', 'mysql'])
                if probes_arg != 'auto':
                    candidates = [c.strip() for c in probes_arg.split(',')
                                  if c.strip() in PROBE_TABLE]
                for cand in candidates[:3]:
                    result = match_probe(cand, target, port)
                    if result:
                        print(f"      {Colors.CYAN}[probe:{cand}]{Colors.RESET} {result}")
                        if store.is_active():
                            store.record_service(target, port, cand, result,
                                                 source_tool='enum')
                        break
        print()

    if banners:
        print_summary("BANNERS", [(port, text[:52]) for port, text in banners])

    if getattr(args, 'json', False):
        emit_json({"tool": "enum", "target": target,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": [{"port": p, "banner": b} for p, b in banners]})

    net.close_connections()
    print_success("Service enumeration completed")
