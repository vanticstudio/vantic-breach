"""
Subdomain Takeover Tool
CNAME chain walk -> dangling detection -> provider fingerprint

A dangling CNAME (points at a deprovisioned resource) can let an attacker
claim the namespace at the provider. This tool DETECTS and REPORTS it -
claiming is a manual, deliberate step during remediation verification.

Confidence: HIGH = dangling CNAME + provider fingerprint match;
LOW = HTTP body text match only.
"""

import json
import socket
from datetime import datetime
from urllib.parse import urlsplit

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, kv, Colors, emit_json,
    load_lines
)

from vantic.core import net, findings, store

META = {
    "name": "takeover",
    "title": "Takeover Check",
    "category": "RECONNAISSANCE",
    "description": "Dangling CNAME / subdomain takeover detection",
    "risk": "safe",
    "examples": [
        "vantic takeover --input subs.json",
        "vantic takeover --input subs.json --probe",
        "vantic takeover --domain example.com",
    ],
    "flow": [
        ("opt", "--input", "Subdomains JSON (from vantic subdomain --json)", ""),
        ("opt", "--domain", "Domain (enumerate inline first)", ""),
        ("flag", "--probe", "HTTP body confirmation?"),
    ],
    "guard": {"domain": "domain"},
}

# Provider fingerprints: CNAME suffix -> (provider, HTTP body signatures)
FINGERPRINTS = {
    "cloudfront.net": ("AWS CloudFront", ["bad request", "error: the request could not be satisfied"]),
    "s3.amazonaws.com": ("AWS S3", ["nosuchbucket", "the specified bucket does not exist"]),
    "s3-website": ("AWS S3 website", ["nosuchbucket", "the specified bucket does not exist"]),
    "azurewebsites.net": ("Azure App Service", ["404 web site not found"]),
    "cloudapp.net": ("Azure CloudApp", []),
    "trafficmanager.net": ("Azure Traffic Manager", []),
    "github.io": ("GitHub Pages", ["there isn't a github pages site here"]),
    "herokuapp.com": ("Heroku", ["no such app", "nothing is here yet"]),
    "netlify.app": ("Netlify", ["not found", "site not found"]),
    "netlify.com": ("Netlify", ["not found"]),
    "fastly.net": ("Fastly", ["fastly error: unknown domain"]),
    "shopify.com": ("Shopify", ["sorry, this shop is currently unavailable"]),
    "zendesk.com": ("Zendesk", ["help center closed"]),
    "intercom.io": ("Intercom", ["this page is reserved for artistic dogs"]),
    "webflow.io": ("Webflow", ["the page you are looking for doesn't exist"]),
    "pantheon.io": ("Pantheon", ["404 error unknown site"]),
    "tumblr.com": ("Tumblr", ["whatever you were looking for doesn't currently exist"]),
    "wordpress.com": ("WordPress.com", ["do you want to register"]),
    "surge.sh": ("Surge.sh", ["project not found"]),
    "cargo": ("Cargo", ["404 not found"]),
    "statuspage.io": ("StatusPage", []),
    "bitbucket.io": ("BitBucket", ["repository not found"]),
    "readme.io": ("Readme.io", []),
    "cargocollective.com": ("CargoCollective", []),
}


def resolve_cname_chain(fqdn):
    """Walk the CNAME chain; returns [(cname_target), ...] and terminal state."""
    chain = []
    current = fqdn.rstrip('.')
    for _ in range(8):
        if HAS_DNSPYTHON:
            try:
                resolver = dns.resolver.get_default_resolver()
                resolver.lifetime = 4
                answers = resolver.resolve(current, 'CNAME')
                target = str(answers[0].target).rstrip('.')
                chain.append(target)
                current = target
                continue
            except Exception:
                pass
        # terminal record: does it resolve to an A?
        try:
            socket.gethostbyname(current)
            return chain, 'alive'
        except socket.gaierror:
            return chain, 'dead'
    return chain, 'loop'


def probe_http(name):
    """Fetch the dangling name over HTTP; return (status, body-snippet)."""
    for scheme in ('https', 'http'):
        try:
            resp = net.request(f"{scheme}://{name}/", "GET", timeout=8,
                               follow_redirects=False, max_retries=0)
            return resp.status, resp.text(2048)
        except Exception:
            continue
    return None, ''


def check_host(name, do_probe):
    """Full takeover assessment for one name. Returns finding dict or None."""
    chain, state = resolve_cname_chain(name)
    if not chain:
        return None
    target = chain[-1]
    if state == 'alive':
        return None  # resolves fine - no takeover surface

    # Dangling! Fingerprint the provider
    provider = None
    for suffix, (prov, sigs) in FINGERPRINTS.items():
        if target.endswith(suffix):
            provider = prov
            signatures = sigs
            break
    else:
        signatures = []

    confidence = 'LOW'
    status, body = (None, '')
    if do_probe:
        status, body = probe_http(name)
        if provider and any(s in body.lower() for s in signatures):
            confidence = 'HIGH'
    elif provider:
        confidence = 'MEDIUM'

    return {
        'name': name, 'cname': target, 'provider': provider or 'unknown',
        'confidence': confidence, 'http_status': status,
        'body_hint': (signatures[0] if signatures else ''),
    }


def add_arguments(parser):
    parser.add_argument('--input', help='Subdomains JSON (vantic subdomain --json output)')
    parser.add_argument('--domain', help='Enumerate this domain inline first')
    parser.add_argument('--probe', action='store_true', help='HTTP body confirmation')
    parser.add_argument('--threads', type=int, default=10, help='Thread count')


def run(args):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from vantic.utils import ProgressBar

    input_file = getattr(args, 'input', None)
    domain = getattr(args, 'domain', None)
    do_probe = getattr(args, 'probe', False)

    names = []
    if input_file:
        try:
            with open(input_file) as f:
                data = json.load(f)
            if isinstance(data, dict) and 'results' in data:
                names = [r['subdomain'] for r in data['results'] if r.get('subdomain')]
            elif isinstance(data, list):
                names = [str(n) for n in data]
        except (OSError, ValueError) as e:
            print_error(f"Cannot read {input_file}: {e}")
            return
    elif domain:
        from vantic.tools.subdomain import resolve_subdomain, make_resolver, DEFAULT_WORDS
        resolver = make_resolver()
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(resolve_subdomain, resolver, f"{w}.{domain}"): w
                       for w in DEFAULT_WORDS}
            for future in as_completed(futures):
                ok, fqdn, _ips = future.result()
                if ok:
                    names.append(fqdn)
    else:
        print_error("Give --input subs.json or --domain example.com")
        return

    names = sorted(set(names))
    if not names:
        print_warning("No subdomains to check")
        return

    print_header("TAKEOVER CHECK", f"{len(names)} names")
    kv("Probe HTTP", "yes" if do_probe else "no (CNAME-only)")
    print()

    results = []
    with ThreadPoolExecutor(max_workers=max(1, getattr(args, 'threads', 10))) as executor:
        futures = {executor.submit(check_host, n, do_probe): n for n in names}
        progress = ProgressBar(len(names), "takeover")
        for future in as_completed(futures):
            r = future.result()
            if r:
                results.append(r)
                progress.interrupt()
                conf_color = (Colors.BRIGHT_RED if r['confidence'] == 'HIGH'
                              else Colors.BRIGHT_YELLOW if r['confidence'] == 'MEDIUM'
                              else Colors.DIM)
                print(f"  {Colors.BRIGHT_RED}[!]{Colors.RESET} "
                      f"{Colors.BOLD}{r['name']}{Colors.RESET} → {r['cname']}"
                      f"  {conf_color}[{r['confidence']} · {r['provider']}]{Colors.RESET}")
            progress.update()

    print()
    if results:
        rows = []
        for r in sorted(results, key=lambda x: x['confidence']):
            rows.append(((r['name'], r['cname'], r['provider'], r['confidence']),
                         Colors.BRIGHT_RED if r['confidence'] == 'HIGH' else None))
        print_table(["SUBDOMAIN", "CNAME TARGET", "PROVIDER", "CONFIDENCE"],
                    rows, widths=[30, 32, 16, 12])
        for r in results:
            sev = 'high' if r['confidence'] == 'HIGH' else \
                'medium' if r['confidence'] == 'MEDIUM' else 'low'
            findings.make(family="dns-takeover",
                         title=f"Dangling CNAME ({r['provider']})",
                         severity=sev, target=r['name'],
                         evidence=f"{r['name']} CNAME {r['cname']} "
                                  f"(terminal NXDOMAIN, {r['confidence']} confidence)",
                         remediation="Remove the dangling DNS record or reclaim the "
                                     "resource at the provider",
                         tool="takeover")
            if store.is_active():
                store.record_target(r['name'], "domain")
        print_warning("Verify manually before claiming any namespace during remediation")
    else:
        print_success("No dangling CNAMEs detected")

    print_summary("TAKEOVER", [
        ("Checked", len(names)),
        ("Dangling", len(results)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "takeover",
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": results})

    net.close_connections()
    print_success("Takeover check completed")
