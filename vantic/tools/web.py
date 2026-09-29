"""
Web Scanner Tool
Web application assessment: security headers, CSP deep parse, cookie
audit, reflective XSS with context awareness, SQLi error + boolean
differential probes, technology fingerprint
"""

import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, ProgressBar, kv, Spinner,
    Colors, emit_json
)

from vantic.core import net, findings

META = {
    "name": "web",
    "title": "Web Scanner",
    "category": "WEB ANALYSIS",
    "description": "Web vulnerability assessment",
    "risk": "safe",
    "examples": [
        "vantic web http://example.com --headers --csp",
        "vantic web http://example.com --xss --sqli",
        "vantic web http://example.com --deep",
    ],
    "flow": [
        ("arg", "url", "Target URL (http://target)", None),
        ("flag", "--headers", "Security headers check?"),
        ("flag", "--csp", "CSP deep parse?"),
        ("flag", "--cookie-audit", "Cookie attribute audit?"),
        ("flag", "--xss", "Reflective XSS probes?"),
        ("flag", "--sqli", "SQLi probes?"),
        ("flag", "--tech", "Technology fingerprint?"),
    ],
    "guard": {"url": "url"},
}

SECURITY_HEADERS = {
    'X-Frame-Options': 'clickjacking protection',
    'X-Content-Type-Options': 'MIME sniffing protection',
    'Strict-Transport-Security': 'HSTS',
    'Content-Security-Policy': 'CSP',
    'Referrer-Policy': 'referrer policy',
    'Permissions-Policy': 'permissions policy',
}

DEFAULT_DIRS = [
    '/admin', '/login', '/wp-admin', '/phpmyadmin', '/.git',
    '/.env', '/config', '/backup', '/test', '/dev',
    '/api', '/api/v1', '/docs', '/assets', '/static'
]

SQL_PAYLOADS = [
    ("'", "quote break"),
    ("' OR '1'='1", "boolean tautology"),
    ("1' AND '1'='1", "boolean tautology"),
    ("1 UNION SELECT 1,2,3--", "union probe"),
    ("1' AND '1'='2", "boolean false"),
]

SQL_ERRORS = [
    'sql syntax', 'mysql', 'postgresql', 'sqlite', 'odbc', 'jdbc',
    'ora-', 'sqlserver', 'syntax error', 'unclosed quotation',
]


def add_param(url, key, value):
    import urllib.parse
    sep = '&' if '?' in url else '?'
    return f"{url}{sep}{key}={urllib.parse.quote(value)}"


def check_security_headers(resp):
    present, missing = [], []
    for header, desc in SECURITY_HEADERS.items():
        value = resp.header(header)
        if value is not None:
            present.append((header, desc, value))
        else:
            missing.append((header, desc))
    return present, missing


def audit_csp(csp_value):
    """Deep CSP parse -> list of (issue, severity, fix)."""
    issues = []
    directives = {}
    for part in csp_value.split(';'):
        part = part.strip()
        if part:
            tokens = part.split()
            directives[tokens[0]] = tokens[1:]

    script_src = directives.get('script-src', [])
    for bad in ('unsafe-inline', 'unsafe-eval'):
        if bad in script_src:
            issues.append((f"script-src allows {bad}", 'medium',
                           f"Remove {bad} from script-src (use nonces/hashes)"))
    if 'default-src' not in directives and 'script-src' not in directives:
        issues.append(("no default-src / script-src fallback", 'low',
                       "Add default-src as a baseline policy"))
    if 'object-src' not in directives:
        issues.append(("object-src undefined (falls back to default-src)",
                       'low', "Add object-src 'none'"))
    if 'frame-ancestors' not in directives:
        issues.append(("frame-ancestors undefined (clickjacking)", 'low',
                       "Add frame-ancestors 'none' or 'self'"))
    for directive, values in directives.items():
        for v in values:
            if v == '*' or v.startswith('http:') or (v == 'data:' and 'img' not in directive):
                issues.append((f"{directive} allows broad source '{v}'", 'low',
                               f"Restrict {directive} sources"))
                break
    return issues


def audit_cookies(resp):
    """Parse Set-Cookie headers -> list of (issue, severity, fix)."""
    issues = []
    for cookie in resp.cookies():
        name = cookie.split('=')[0].strip()
        lower = cookie.lower()
        bits = lower.split(';')
        body = bits[0]
        flags = {b.strip().split('=')[0] for b in bits[1:]}
        if 'secure' not in flags:
            issues.append((f"'{name}' missing Secure flag", 'medium',
                          "Set the Secure attribute on all cookies"))
        if 'httponly' not in flags:
            issues.append((f"'{name}' missing HttpOnly flag", 'low',
                          "Set HttpOnly on session cookies"))
        if 'samesite' not in flags:
            issues.append((f"'{name}' missing SameSite attribute", 'low',
                          "Set SameSite=Lax or Strict"))
        else:
            for b in bits[1:]:
                b = b.strip()
                if b.lower().startswith('samesite=none') and 'secure' not in flags:
                    issues.append((f"'{name}' SameSite=None without Secure", 'medium',
                                   "SameSite=None requires the Secure attribute"))
        if name.startswith('__Host-') and ('secure' not in flags or 'path=/' not in lower):
            issues.append((f"'{name}' violates the __Host- prefix rules", 'low',
                          "__Host- cookies need Secure, no Domain, Path=/"))
        if any(s in name.lower() for s in ('sess', 'session', 'auth', 'token', 'jwt')) \
                and 'httponly' not in flags:
            issues.append((f"session cookie '{name}' without HttpOnly", 'medium',
                           "Set HttpOnly on session cookies"))
    return issues


def xss_context(body, payload):
    """Classify where the payload lands; only unencoded contexts are findings."""
    idx = body.find(payload)
    if idx < 0:
        return None
    before = body[:idx]
    # Inside <script>?
    last_script = before.rfind('<script')
    last_script_end = before.rfind('</script>')
    if last_script > last_script_end:
        return ('script', 'HIGH - lands inside a <script> block')
    # Inside a tag attribute?
    last_lt = before.rfind('<')
    last_gt = before.rfind('>')
    if last_lt > last_gt:
        # Check for quote wrap
        seg = before[last_lt:idx]
        quote = "'" if seg.count("'") % 2 else ('"' if seg.count('"') % 2 else None)
        if quote:
            return ('attribute-quoted', 'MEDIUM - lands in a quoted attribute (needs breakout)')
        return ('attribute', 'HIGH - lands in an unquoted attribute/event handler')
    # Raw HTML body
    return ('body', 'HIGH - lands in raw HTML')


def check_xss(url, timeout=10):
    payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><svg onload=alert(1)>',
    ]
    hits = []
    for payload in payloads:
        try:
            resp = net.request(add_param(url, 'vtest', payload), "GET",
                               timeout=timeout, follow_redirects=True, max_retries=0)
            body = resp.text()
            ctx = xss_context(body, payload)
            if ctx:
                hits.append((payload, ctx[0], ctx[1]))
        except Exception:
            pass
    return hits


def check_sqli(url, timeout=10):
    """Error signatures + boolean differential (truthy vs falsy payload)."""
    hits = []

    def fetch(payload):
        resp = net.request(add_param(url, 'id', payload), "GET", timeout=timeout,
                           follow_redirects=True, max_retries=0)
        body = resp.text().lower()
        return resp.status, len(resp.body), body

    try:
        status_true, size_true, body_true = fetch("1' AND '1'='1")
        status_false, size_false, body_false = fetch("1' AND '1'='2")
    except Exception:
        status_true = status_false = None

    for payload, ptype in SQL_PAYLOADS:
        try:
            status, size, body = fetch(payload)
            matched = next((e for e in SQL_ERRORS if e in body), None)
            if matched:
                hits.append((payload, ptype, f"db error '{matched}'"))
        except Exception:
            continue

    # Boolean differential: same status, stable-but-different sizes
    if status_true and status_true == status_false and \
            abs(size_true - size_false) > 16 and \
            (size_true > 0 or size_false > 0):
        # Guard against dynamic jitter: re-fetch both once
        try:
            st2, szt2, _ = fetch("1' AND '1'='1")
            sf2, szf2, _ = fetch("1' AND '1'='2")
            if st2 == sf2 and abs(szt2 - szf2) > 16 and \
                    abs((size_true - size_false) - (szt2 - szf2)) < 8:
                hits.append(("1' AND '1'='1", "boolean differential",
                            f"truthy {size_true}B vs falsy {size_false}B (stable)"))
        except Exception:
            pass
    return hits


def tech_detection(resp):
    detected = []
    headers = resp.headers_dict()
    if headers.get('Server'):
        detected.append(('Server header', headers['Server']))
    if headers.get('X-Powered-By'):
        detected.append(('X-Powered-By', headers['X-Powered-By']))
    content = resp.text(200000)
    techs = {
        'WordPress': r'wp-content|wp-includes',
        'Drupal': r'drupal|sites/default',
        'Joomla': r'joomla|media/jui',
        'React': r'react',
        'Vue': r'vue\.js',
        'Angular': r'angular|ng-',
        'jQuery': r'jquery',
        'Bootstrap': r'bootstrap',
        'Laravel': r'laravel',
        'Django': r'csrfmiddlewaretoken|__django',
        'Flask': r'flask',
        'Next.js': r'__next',
        'Nginx': r'nginx',
    }
    for tech, pattern in techs.items():
        if re.search(pattern, content, re.IGNORECASE):
            detected.append(('Content signature', tech))
    return detected


def add_arguments(parser):
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--csp', action='store_true', help='Check CSP headers')
    parser.add_argument('--xss', action='store_true', help='Basic XSS reflection checks')
    parser.add_argument('--sqli', action='store_true', help='Basic SQLi checks')
    parser.add_argument('--dir', action='store_true', help='Directory brute force')
    parser.add_argument('--tech', action='store_true', help='Technology detection')
    parser.add_argument('--headers', action='store_true', help='Security headers check')
    parser.add_argument('--cookie-audit', action='store_true', help='Cookie attribute audit')
    parser.add_argument('--csp-deep', dest='csp', action='store_true', help='CSP deep parse')
    parser.add_argument('--follow-redirects', action='store_true', help='Follow redirects')
    parser.add_argument('--deep', action='store_true', help='Run every check')
    parser.add_argument('--threads', type=int, default=10, help='Thread count')
    parser.add_argument('--delay', type=float, default=0.0, help='Delay between probes (s)')


def run(args):
    """Run web scanner."""
    url = args.url
    if not url.startswith('http'):
        url = f'http://{url}'

    deep = getattr(args, 'deep', False)

    any_flag = any([args.headers, args.csp, args.xss, args.sqli, args.dir, args.tech,
                    getattr(args, 'cookie_audit', False)])
    if not any_flag:
        args.headers = True
        args.tech = True
    if deep:
        args.headers = args.csp = args.xss = args.sqli = args.tech = True
        args.cookie_audit = True

    delay = getattr(args, 'delay', 0.0)

    print_header("WEB SCANNER", url)
    kv("Target", url, Colors.BOLD)
    kv("Started", datetime.now().strftime('%H:%M:%S'))
    print()

    # Sanity: can we reach it?
    try:
        resp = net.request(url, "GET", timeout=10, follow_redirects=True)
    except Exception as e:
        print_error(f"Target unreachable: {e}")
        return

    title = re.search(r'<title[^>]*>(.*?)</title>', resp.text(65536),
                      re.IGNORECASE | re.DOTALL)
    color = (Colors.BRIGHT_GREEN if 200 <= resp.status < 300
             else Colors.BRIGHT_YELLOW if resp.status < 400 else Colors.BRIGHT_RED)
    t = f" - {title.group(1).strip()[:60]}" if title and title.group(1).strip() else ""
    print(f"  {color}[{resp.status}]{Colors.RESET} reachable{Colors.DIM}{t}{Colors.RESET}")
    print()

    findings_count = 0

    # Security headers
    if args.headers:
        print_subheader("SECURITY HEADERS")
        present, missing = check_security_headers(resp)
        for header, desc, value in present:
            val = value if len(value) <= 60 else value[:57] + '...'
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {Colors.BOLD}{header:<28}{Colors.RESET} {val}")
        for header, desc in missing:
            print(f"  {Colors.BRIGHT_RED}[-]{Colors.RESET} {Colors.BOLD}{header:<28}{Colors.RESET} "
                  f"{Colors.DIM}missing ({desc}){Colors.RESET}")
            findings_count += 1
            findings.make(family="web-headers", title=f"{header} missing",
                          severity="low", target=url,
                          evidence=f"{header} absent ({desc})",
                          remediation=f"Add the {header} response header", tool="web")
        print()

    # CSP deep
    if args.csp:
        print_subheader("CSP DEEP PARSE")
        csp_value = resp.header('Content-Security-Policy')
        if not csp_value:
            print(f"  {Colors.BRIGHT_RED}[-]{Colors.RESET} No Content-Security-Policy at all")
            findings_count += 1
            findings.make(family="web-csp", title="Content-Security-Policy missing",
                          severity="medium", target=url,
                          evidence="no CSP header on the landing response",
                          remediation="Publish a restrictive CSP", tool="web")
        else:
            issues = audit_csp(csp_value)
            if issues:
                for issue, sev, fix in issues:
                    print(f"  {Colors.BRIGHT_YELLOW}[!]{Colors.RESET} {issue}")
                    findings_count += 1
                    findings.make(family="web-csp", title=issue, severity=sev,
                                  target=url, evidence=csp_value[:200],
                                  remediation=fix, tool="web")
            else:
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} CSP looks sane")
        print()

    # Cookie audit
    if getattr(args, 'cookie_audit', False):
        print_subheader("COOKIE AUDIT")
        cookies = resp.cookies()
        if not cookies:
            print(f"  {Colors.DIM}[·] no cookies on the landing response{Colors.RESET}")
        else:
            issues = audit_cookies(resp)
            for cookie in cookies:
                print(f"  {Colors.CYAN}[c]{Colors.RESET} {cookie[:72]}")
            for issue, sev, fix in issues:
                print(f"  {Colors.BRIGHT_YELLOW}[!]{Colors.RESET} {issue}")
                findings_count += 1
                findings.make(family="web-cookies", title=issue, severity=sev,
                              target=url, evidence="; ".join(cookies)[:200],
                              remediation=fix, tool="web")
            if not issues:
                print_success("All cookies carry the recommended attributes")
        print()

    # XSS
    if args.xss:
        print_subheader("XSS PROBES")
        with Spinner("Testing reflection..."):
            hits = check_xss(url)
        if hits:
            for payload, ctx, note in hits:
                print(f"  {Colors.BRIGHT_RED}[!]{Colors.RESET} Reflected "
                      f"{Colors.BOLD}{payload[:34]}{Colors.RESET} → context: {ctx} ({note})")
                findings_count += 1
                findings.make(family="web-xss", title=f"Reflected XSS ({ctx} context)",
                              severity="high", target=url,
                              evidence=f"payload {payload!r} reflected in {ctx} context",
                              remediation="Encode output by context; validate input",
                              tool="web")
        else:
            print_success("No reflected payloads detected")
        print()

    # SQLi
    if args.sqli:
        print_subheader("SQLI PROBES")
        with Spinner("Probing (errors + boolean differential)..."):
            hits = check_sqli(url)
        if hits:
            for payload, ptype, detail in hits:
                print(f"  {Colors.BRIGHT_RED}[!]{Colors.RESET} {ptype}: {detail} "
                      f"on payload {Colors.BOLD}{payload[:30]}{Colors.RESET}")
                findings_count += 1
                findings.make(family="web-sqli", title=f"SQL injection indicator ({ptype})",
                              severity="high", target=url,
                              evidence=f"payload {payload!r}: {detail}",
                              remediation="Parameterize queries; validate inputs",
                              tool="web")
        else:
            print_success("No database error signatures or stable differentials")
        print()

    # Technology
    if args.tech:
        print_subheader("TECHNOLOGY FINGERPRINT")
        try:
            detected = tech_detection(resp)
            if detected:
                for source, tech in detected:
                    print(f"  {Colors.BRIGHT_MAGENTA}[+]{Colors.RESET} "
                          f"{Colors.BOLD}{tech:<24}{Colors.RESET} {Colors.DIM}via {source}{Colors.RESET}")
            else:
                print(f"  {Colors.DIM}[·] no known signatures found{Colors.RESET}")
        except Exception as e:
            print_error(f"Tech detection failed: {e}")
        print()

    # Directory brute (compact default list)
    if args.dir:
        print_subheader("DIRECTORY PROBE")
        found = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(_probe_dir, url, d): d for d in DEFAULT_DIRS}
            for future in as_completed(futures):
                hit = future.result()
                if hit:
                    found.append(hit)
                    print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {Colors.BOLD}{hit[0]}{Colors.RESET} [{hit[1]}]")
        if not found:
            print(f"  {Colors.DIM}[·] no hits from default list{Colors.RESET}")
        print()

    # Summary
    if findings_count:
        print_summary("SCAN RESULTS", [
            ("Issues flagged", findings_count),
            ("Target", url),
        ])
    if getattr(args, 'json', False):
        emit_json({"tool": "web", "target": url,
                  "started": datetime.now().isoformat(timespec='seconds'),
                  "results": [f.to_dict() for f in findings.drain()]})

    net.close_connections()
    print_success(f"Scan completed at {datetime.now().strftime('%H:%M:%S')}")


def _probe_dir(url, directory):
    try:
        resp = net.request(f"{url.rstrip('/')}{directory}", "GET", timeout=5,
                           follow_redirects=False, max_retries=0)
        if resp.status == 200:
            return (directory, resp.status)
    except Exception:
        pass
    return None
