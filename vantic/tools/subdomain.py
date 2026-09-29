"""
Subdomain Enumeration Tool
Brute force + passive (keyless CT-log/OSINT sources) with wildcard
suppression and source attribution
"""

import json
import socket
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, ProgressBar, status_badge,
    kv, Colors, load_lines, emit_json
)

from vantic.core import net, store

META = {
    "name": "subdomain",
    "title": "Subdomain Finder",
    "category": "RECONNAISSANCE",
    "description": "Brute + passive subdomain enumeration",
    "risk": "safe",
    "examples": [
        "vantic subdomain example.com --brute",
        "vantic subdomain example.com --passive",
        "vantic subdomain example.com --brute --passive --alive",
    ],
    "flow": [
        ("arg", "domain", "Domain", None),
        ("flag", "--brute", "Brute force with a wordlist?"),
        ("flag", "--passive", "Query passive sources (CT logs etc.)?"),
        ("flag", "--alive", "Check which hosts are alive?"),
    ],
    "guard": {"domain": "domain"},
}

DEFAULT_WORDS = [
    'www', 'mail', 'ftp', 'admin', 'dev', 'test', 'staging',
    'api', 'app', 'web', 'blog', 'shop', 'store', 'cms',
    'portal', 'login', 'auth', 'secure', 'm', 'mobile',
    'cdn', 'static', 'assets', 'images', 'media',
    'git', 'github', 'svn', 'wiki', 'docs',
    'db', 'database', 'mysql', 'postgres', 'mongo',
    'smtp', 'pop', 'imap', 'mx',
    'ns1', 'ns2', 'dns', 'ftp01',
    'old', 'new', 'v1', 'v2', 'beta', 'alpha',
    'stage', 'stg', 'prd', 'prod', 'uat',
    'internal', 'intra', 'corp', 'office', 'remote',
]

# Passive source registry (keyless): (name, fetch function added below)
PASSIVE_SOURCES = ["crtsh", "hackertarget", "rapiddns", "otx"]


def make_resolver(dns_servers=None):
    if HAS_DNSPYTHON:
        if dns_servers:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = dns_servers
        else:
            resolver = dns.resolver.get_default_resolver()
        resolver.lifetime = 3
        return resolver
    return None


def resolve_subdomain(resolver, fqdn):
    """Resolve a subdomain via dnspython, falling back to socket.gethostbyname."""
    if resolver is not None:
        try:
            answers = resolver.resolve(fqdn, 'A')
            return True, fqdn, [r.to_text() for r in answers]
        except Exception:
            return False, fqdn, []
    try:
        ip = socket.gethostbyname(fqdn)
        return True, fqdn, [ip]
    except socket.gaierror:
        return False, fqdn, []
    except Exception:
        return False, fqdn, []


def check_alive(ip, timeout=2):
    """Check if host answers on 80 or 443."""
    for port in (80, 443):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True
        except Exception:
            continue
    return False


# ---------- passive sources ----------

def _passive_crtsh(domain):
    """Certificate transparency logs (flakiest source - long timeout, 1 retry)."""
    try:
        resp = net.request(f"https://crt.sh/?q=%.{domain}&output=json", timeout=45,
                           max_retries=1)
        data = json.loads(resp.body.decode("utf-8", errors="replace"))
        names = set()
        for entry in data:
            for name in str(entry.get("name_value", "")).split("\n"):
                name = name.strip().lstrip("*.").lower()
                if name.endswith(domain) and name != domain:
                    names.add(name)
        return sorted(names)
    except Exception:
        return []


def _passive_hackertarget(domain):
    """HackerTarget hostsearch (50/day; quota exhaustion is HTTP 200 + text)."""
    try:
        resp = net.request(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20)
        body = resp.body.decode("utf-8", errors="replace")
        if "API count exceeded" in body or "error" in body.lower()[:40]:
            return []
        names = set()
        for line in body.splitlines():
            if "," in line:
                name = line.split(",")[0].strip().lower()
                if name.endswith(domain) and name != domain:
                    names.add(name)
        return sorted(names)
    except Exception:
        return []


def _passive_rapiddns(domain):
    """RapidDNS dump (needs a browser UA - net.request provides one)."""
    try:
        resp = net.request(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=25)
        import re
        body = resp.body.decode("utf-8", errors="replace")
        names = set()
        for m in re.finditer(r">([a-zA-Z0-9_.-]+\." + re.escape(domain) + r")<", body):
            name = m.group(1).strip().lower()
            if name != domain:
                names.add(name)
        return sorted(names)
    except Exception:
        return []


def _passive_otx(domain):
    """AlienVault OTX passive DNS."""
    try:
        resp = net.request(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=25)
        data = json.loads(resp.body.decode("utf-8", errors="replace"))
        names = set()
        for entry in data.get("passive_dns", [])[:2000]:
            name = str(entry.get("hostname", "")).strip().lower()
            if name.endswith(domain) and name != domain:
                names.add(name)
        return sorted(names)
    except Exception:
        return []


PASSIVE_FETCHERS = {
    "crtsh": _passive_crtsh,
    "hackertarget": _passive_hackertarget,
    "rapiddns": _passive_rapiddns,
    "otx": _passive_otx,
}


def passive_sweep(domain, sources):
    """Query the requested passive sources; per-source failure is never fatal."""
    from vantic.utils import Spinner
    results = {}
    for src in sources:
        fetcher = PASSIVE_FETCHERS.get(src)
        if not fetcher:
            continue
        with Spinner(f"querying {src}..."):
            got = fetcher(domain)
        results[src] = got
        if got:
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {src:<14} "
                  f"{Colors.BOLD}{len(got)}{Colors.RESET} names")
        else:
            print(f"  {Colors.DIM}[·] {src:<14} no data / unavailable{Colors.RESET}")
    return results


def add_arguments(parser):
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('--brute', action='store_true', help='Brute force mode')
    parser.add_argument('--wordlist', help='Wordlist path')
    parser.add_argument('--recursive', action='store_true', help='One extra level on hits')
    parser.add_argument('--resolve', action='store_true', help='Resolve IPs (default on)')
    parser.add_argument('--alive', action='store_true', help='Check alive hosts')
    parser.add_argument('--dns-servers', help='Custom DNS servers')
    parser.add_argument('--passive', action='store_true', help='Query passive sources (CT logs etc.)')
    parser.add_argument('--sources', help=f"Passive sources ({','.join(PASSIVE_SOURCES)})")
    parser.add_argument('--no-wildcard', action='store_true', help='Skip wildcard detection')


def run(args):
    """Run subdomain enumeration."""
    domain = args.domain.rstrip('.')
    brute = getattr(args, 'brute', False)
    passive = getattr(args, 'passive', False)
    wordlist = getattr(args, 'wordlist', None)
    recursive = getattr(args, 'recursive', False)
    check_alive_flag = getattr(args, 'alive', False)
    dns_servers = getattr(args, 'dns_servers', None)
    if dns_servers:
        dns_servers = [s.strip() for s in dns_servers.split(',') if s.strip()]

    if not brute and not passive:
        brute = True  # bare invocation does the classic wordlist sweep

    if not HAS_DNSPYTHON:
        print_info("dnspython not installed - using system resolver fallback")
        print(f"  {Colors.DIM}for better performance: pip3 install dnspython{Colors.RESET}")

    resolver = make_resolver(dns_servers)

    print_header("SUBDOMAIN ENUMERATION", domain)
    kv("Domain", domain, Colors.BOLD)
    kv("Mode", (" + ".join(filter(None, ["brute" if brute else None,
                                          "passive" if passive else None]))))
    if check_alive_flag:
        kv("Alive check", "yes")
    kv("Resolver", "dnspython" if HAS_DNSPYTHON else "system (socket)")
    print()

    # Wildcard detection (authoritative NS - ISP hijack proof)
    wildcard_ips = []
    if brute and not getattr(args, 'no_wildcard', False):
        from vantic.tools.dns_enum import detect_wildcard
        with Spinner("checking for DNS wildcards..."):
            wildcard_ips = detect_wildcard(domain, resolver)
        if wildcard_ips:
            print_warning(f"Wildcard detected (*.{domain} → {', '.join(wildcard_ips)}) - "
                          f"suppressing those IPs")
            print()

    candidates = set()

    # --- passive ---
    if passive:
        srcs = [s.strip() for s in (getattr(args, 'sources', None) or
                                    ','.join(PASSIVE_SOURCES)).split(',') if s.strip()]
        print_subheader("PASSIVE SOURCES")
        results = passive_sweep(domain, srcs)
        for src, names in results.items():
            candidates.update(names)
        print()

    # --- brute ---
    found = []
    if brute:
        words = DEFAULT_WORDS
        if wordlist:
            loaded = load_lines(wordlist)
            if loaded is None:
                print_warning(f"Wordlist not found: {wordlist}, using built-in list")
            else:
                words = loaded

        def is_wildcard_only(ips):
            return bool(wildcard_ips) and ips and all(ip in wildcard_ips for ip in ips)

        def sweep(base_domains, label):
            found_list = []
            fqdns = [f"{w}.{d}" for d in base_domains for w in words]
            print_info(f"{label}: {len(fqdns)} candidates")
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(resolve_subdomain, resolver, fqdn): fqdn
                          for fqdn in fqdns}
                progress = ProgressBar(len(fqdns), label)
                for future in as_completed(futures):
                    ok, fqdn, ips = future.result()
                    if ok and not is_wildcard_only(ips):
                        found_list.append({'subdomain': fqdn, 'ips': ips, 'source': 'brute'})
                        ip_str = ', '.join(ips[:2]) + (f" (+{len(ips) - 2})" if len(ips) > 2 else '')
                        progress.interrupt()
                        print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} "
                              f"{Colors.BOLD}{fqdn:<42}{Colors.RESET} {ip_str}")
                    progress.update()
            print()
            return found_list

        found += sweep([domain], "sweep")

        if recursive and found:
            bases = [item['subdomain'] for item in found[:20]]
            found += sweep(bases, "recursive")

    # --- merge passive candidates (resolve + dedupe with brute hits) ---
    if passive and candidates:
        seen = {item['subdomain'] for item in found}
        todo = [c for c in sorted(candidates) if c not in seen]
        print_subheader("RESOLVING PASSIVE NAMES", len(todo))
        resolved_extra = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(resolve_subdomain, resolver, fqdn): fqdn
                      for fqdn in todo}
            progress = ProgressBar(len(todo), "resolve")
            for future in as_completed(futures):
                ok, fqdn, ips = future.result()
                if ok:
                    resolved_extra.append({'subdomain': fqdn, 'ips': ips, 'source': 'passive'})
                    progress.interrupt()
                    print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} "
                          f"{Colors.BOLD}{fqdn:<42}{Colors.RESET} {', '.join(ips[:2])}")
                progress.update()
        print()
        found += resolved_extra

    # dedupe (brute wins ordering)
    uniq = {}
    for item in found:
        uniq.setdefault(item['subdomain'], item)

    found = list(uniq.values())
    for item in found:
        if store.is_active():
            store.record_target(item['subdomain'], "domain")

    # --- alive check ---
    if check_alive_flag and found:
        print_subheader("ALIVE CHECK", f"{len(found)} hosts")
        alive = []
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(check_alive, item['ips'][0]): item for item in found}
            progress = ProgressBar(len(found), "alive check")
            for future in as_completed(futures):
                item = futures[future]
                if future.result():
                    alive.append(item)
                    print(f"\r  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} "
                          f"{item['subdomain']:<42} alive")
                progress.update()
        print()
        if alive:
            print_info(f"{len(alive)}/{len(found)} hosts answered on 80/443")
        else:
            print_warning("No hosts answered on 80/443")

    # Summary
    print()
    print_summary("RESULTS", [
        ("Subdomains", len(found)),
        ("Sources", ', '.join(sorted({i['source'] for i in found})) or 'none'),
    ])

    if found:
        rows = [((item['subdomain'], ', '.join(item['ips'][:2]), item['source']),
                Colors.BRIGHT_GREEN)
                for item in sorted(found, key=lambda x: x['subdomain'])]
        print_table(["SUBDOMAIN", "IP", "SOURCE"], rows, widths=[42, 26, 10])

    if getattr(args, 'json', False):
        emit_json({"tool": "subdomain", "target": domain,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": sorted(found, key=lambda x: x['subdomain'])})

    print_success("Subdomain enumeration completed")
