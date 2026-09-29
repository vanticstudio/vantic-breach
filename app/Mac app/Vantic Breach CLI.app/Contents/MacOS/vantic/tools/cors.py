"""
CORS Tool
Origin matrix: attacker origin, null, subdomain variants, arbitrary

HIGH = arbitrary origin echoed + credentials allowed;
ACAO:* with credentials = config error.
"""

import urllib.parse
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json
)

from vantic.core import net, findings

META = {
    "name": "cors",
    "title": "CORS Audit",
    "category": "WEB ANALYSIS",
    "description": "Origin reflection matrix",
    "risk": "safe",
    "examples": [
        "vantic cors https://api.example.com",
        "vantic cors https://app.example.com --origin evil.example.org --null",
    ],
    "flow": [
        ("arg", "url", "Target URL", None),
        ("opt", "--origin", "Attacker origin to test", "https://evil.example.org"),
    ],
    "guard": {"url": "url"},
}


def probe_origin(url, origin, cookies=False, timeout=10):
    """One request with a custom Origin header."""
    headers = {"Origin": origin}
    if cookies:
        headers["Cookie"] = "session=vantic-cors-test"
    try:
        resp = net.request(url, "GET", timeout=timeout, follow_redirects=False,
                           max_retries=0, headers=headers)
        acao = resp.header("Access-Control-Allow-Origin")
        acac = resp.header("Access-Control-Allow-Credentials")
        return resp.status, acao, acac
    except Exception:
        return None, None, None


def add_arguments(parser):
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--origin', default='https://evil.example.org',
                        help='Attacker origin')
    parser.add_argument('--null', action='store_true', help='Also test Origin: null')


def run(args):
    url = args.url
    if '://' not in url:
        url = 'https://' + url
    attacker = getattr(args, 'origin', 'https://evil.example.org')

    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ''
    domain = '.'.join(host.split('.')[-2:]) if host.count('.') >= 1 else host

    # Build the origin matrix
    origins = [
        (attacker, "attacker origin"),
        (f"https://{domain}", "parent domain"),
        (f"https://vantic.{domain}", "arbitrary subdomain"),
        (f"https://{domain}.evil.example.org", "suffix confusion"),
        (f"https://{host}:8080", "port variant"),
    ]
    if getattr(args, 'null', False):
        origins.append(("null", "Origin: null"))

    print_header("CORS AUDIT", url)
    kv("Attacker origin", attacker)
    print()

    print_subheader("ORIGIN MATRIX")
    findings_rows = []
    for origin, label in origins:
        status, acao, acac = probe_origin(url, origin)
        if status is None:
            print(f"  {Colors.DIM}[·] {label:<22} request failed{Colors.RESET}")
            continue
        reflected = acao is not None and acao == origin
        wildcard = acao == '*'
        creds = (acac or '').lower() == 'true'
        mark = Colors.BRIGHT_GREEN
        note = 'no reflection'
        if reflected:
            mark = Colors.BRIGHT_YELLOW if not creds else Colors.BRIGHT_RED
            note = f"ECHOED{' + credentials' if creds else ''}"
        elif wildcard:
            mark = Colors.BRIGHT_YELLOW
            note = 'wildcard *'
        findings_rows.append({'origin': origin, 'label': label, 'status': status,
                             'acao': acao, 'creds': creds})
        print(f"  {mark}[{status}]{Colors.RESET} {Colors.BOLD}{label:<22}{Colors.RESET}"
              f"{Colors.DIM}{origin[:40]:<42}{Colors.RESET} {note}")
    print()

    # Findings
    arbitrary = [r for r in findings_rows
                 if r['acao'] and r['acao'] not in ('*',) and
                 r['origin'] not in (url, f"https://{host}", f"http://{host}")
                 and r['label'] in ('attacker origin', 'arbitrary subdomain',
                                   'suffix confusion', 'port variant')]
    cred_arbitrary = [r for r in arbitrary if r['creds']]
    wildcard = [r for r in findings_rows if r['acao'] == '*']
    null_reflected = [r for r in findings_rows if r['origin'] == 'null' and r['acao'] == 'null']

    if cred_arbitrary:
        worst = cred_arbitrary[0]
        findings.make(family="cors-creds",
                      title="CORS reflects arbitrary origins WITH credentials",
                      severity="high", target=url,
                      evidence=f"Origin {worst['origin']} -> ACAO {worst['acao']} + ACAC true",
                      remediation="Allow-list exact trusted origins; never reflect "
                                 "arbitrary origins with credentials",
                      tool="cors")
        print_warning("Arbitrary origin + credentials = data exfiltration path")
    elif arbitrary:
        findings.make(family="cors-reflect",
                      title="CORS reflects arbitrary origins",
                      severity="medium", target=url,
                      evidence=f"Origin {arbitrary[0]['origin']} echoed",
                      remediation="Allow-list exact origins",
                      tool="cors")
        print_warning("Arbitrary origins reflected (no credentials observed)")
    if wildcard:
        findings.make(family="cors-wildcard",
                      title="ACAO:* in use", severity="low", target=url,
                      evidence="Access-Control-Allow-Origin: *",
                      remediation="Fine without credentials; a config error with them",
                      tool="cors")
        print_info("Wildcard ACAO (fine unless used with credentials)")
    if null_reflected:
        findings.make(family="cors-null", title="Origin: null reflected",
                      severity="medium", target=url,
                      evidence="ACAO echoed the null origin",
                      remediation="Reject the null origin",
                      tool="cors")
        print_warning("Origin: null is reflected (sandboxed iframe exploit path)")
    if not (arbitrary or wildcard or null_reflected):
        print_success("No permissive CORS reflection detected")

    print_summary("CORS", [
        ("Origins tested", len(findings_rows)),
        ("Reflected", len(arbitrary)),
        ("With credentials", len(cred_arbitrary)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "cors", "target": url,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": findings_rows})

    net.close_connections()
    print_success("CORS audit completed")
