"""
HTTP Probe Tool
Deep HTTP service analysis
"""

import ssl
import re
import urllib.request
import urllib.error
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, status_badge, Colors, emit_json
)

META = {
    "name": "http",
    "title": "HTTP Probe",
    "category": "WEB ANALYSIS",
    "description": "HTTP service analysis",
    "risk": "safe",
    "examples": [
        "vantic http http://example.com --all",
        "vantic http example.com --headers --waf --robots",
    ],
    "flow": [
        ("arg", "url", "Target URL (http://target)", None),
        ("flag", "--headers", "Show all headers?"),
        ("flag", "--cookies", "Check cookies?"),
        ("flag", "--forms", "Find forms?"),
        ("flag", "--links", "Extract links?"),
        ("flag", "--waf", "WAF detection?"),
        ("flag", "--robots", "Check robots.txt?"),
        ("flag", "--sitemap", "Check sitemap.xml?"),
    ],
    "guard": {"url": "url"},
}

USER_AGENT = 'Mozilla/5.0 (compatible; Vantic/2.0)'

TECH_PATTERNS = {
    'WordPress': r'wp-content|wp-includes',
    'Drupal': r'drupal|sites/default',
    'Joomla': r'joomla',
    'React': r'react',
    'Vue.js': r'vue\.js',
    'Angular': r'angular|ng-',
    'jQuery': r'jquery',
    'Bootstrap': r'bootstrap',
    'Laravel': r'laravel',
    'Django': r'csrfmiddlewaretoken',
    'Node.js': r'node|express',
    'Apache': r'apache',
    'Nginx': r'nginx',
}

WAF_SIGNATURES = {
    'Cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
    'AWS WAF': ['aws-waf', 'cloudfront'],
    'Akamai': ['akamai-gum', 'ak_bmsc'],
    'Imperva': ['incap_ses', 'visid_incap'],
    'Sucuri': ['sucuri', 'cloudproxy'],
    'F5 BIG-IP': ['bigip', 'ts='],
    'ModSecurity': ['mod_security', 'modsecurity'],
}


def make_opener():
    """Opener that tolerates self-signed certificates."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


def fetch(opener, url, timeout=10):
    """Fetch a URL, returning (ok, status, headers, content)."""
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    try:
        with opener.open(req, timeout=timeout) as response:
            return True, response.status, dict(response.headers), response.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        return True, e.code, dict(e.headers or {}), ''
    except Exception as e:
        return False, None, {}, str(e)


def get_http_info(opener, url):
    """Comprehensive HTTP information."""
    info = {'status': None, 'headers': {}, 'cookies': [], 'forms': [], 'links': [], 'tech': [], 'warnings': []}

    ok, status, headers, content = fetch(opener, url)
    if not ok:
        info['error'] = status
        return info

    info['status'] = status
    info['headers'] = headers
    info['cookies'] = headers.get_all('Set-Cookie', []) if hasattr(headers, 'get_all') else []

    info['forms'] = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', content, re.IGNORECASE)
    info['links'] = re.findall(r'href=["\']([^"\']+)["\']', content)

    haystack = content + headers.get('Server', '')
    for tech, pattern in TECH_PATTERNS.items():
        if re.search(pattern, haystack, re.IGNORECASE):
            info['tech'].append(tech)

    if 'X-Frame-Options' not in headers:
        info['warnings'].append('Missing X-Frame-Options (clickjacking risk)')
    if 'X-Content-Type-Options' not in headers:
        info['warnings'].append('Missing X-Content-Type-Options')
    if 'Strict-Transport-Security' not in headers and url.startswith('https'):
        info['warnings'].append('Missing HSTS header')
    if 'Content-Security-Policy' not in headers:
        info['warnings'].append('No Content-Security-Policy defined')

    return info


def add_arguments(parser):
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--headers', action='store_true', help='Show all headers')
    parser.add_argument('--cookies', action='store_true', help='Check cookies')
    parser.add_argument('--forms', action='store_true', help='Find forms')
    parser.add_argument('--links', action='store_true', help='Extract links')
    parser.add_argument('--all', action='store_true', help='Every check')
    parser.add_argument('--screenshot', action='store_true', help='Take screenshot (not yet supported)')
    parser.add_argument('--waf', action='store_true', help='WAF detection')
    parser.add_argument('--robots', action='store_true', help='Check robots.txt')
    parser.add_argument('--sitemap', action='store_true', help='Check sitemap.xml')


def run(args):
    """Run HTTP probe."""
    url = args.url
    if not url.startswith('http'):
        url = f'http://{url}'

    if getattr(args, 'all', False):
        args.headers = args.cookies = args.forms = args.links = True
        args.waf = args.robots = args.sitemap = True
    elif not any([args.headers, args.cookies, args.forms, args.links,
                  args.waf, args.robots, args.sitemap]):
        args.headers = True

    if getattr(args, 'screenshot', False):
        print_warning("--screenshot is not supported in CLI mode yet (needs a headless browser)")
        print()

    opener = make_opener()

    print_header("HTTP PROBE", url)
    kv("Target", url, Colors.BOLD)
    kv("Started", datetime.now().strftime('%H:%M:%S'))
    print()

    info = get_http_info(opener, url)
    if 'error' in info:
        print_error(f"Connection failed: {info['error']}")
        return

    status = info['status']
    status_color = (Colors.BRIGHT_GREEN if 200 <= status < 300
                    else Colors.BRIGHT_YELLOW if status < 400
                    else Colors.BRIGHT_RED)
    print(f"  {status_color}[{status}]{Colors.RESET} {url}")
    print()

    if args.headers:
        print_subheader("HEADERS")
        for key, value in info['headers'].items():
            print(f"  {Colors.CYAN}{key}{Colors.RESET}: {value}")
        print()

    if args.cookies and info['cookies']:
        print_subheader("COOKIES")
        for cookie in info['cookies']:
            print(f"  {Colors.YELLOW}[cookie]{Colors.RESET} {cookie}")
        print()

    if args.forms:
        print_subheader("FORMS", len(info['forms']) or None)
        if info['forms']:
            for form in info['forms']:
                print(f"  {Colors.BRIGHT_MAGENTA}▸{Colors.RESET} {form}")
        else:
            print(f"  {Colors.DIM}[·] no forms found{Colors.RESET}")
        print()

    if args.links:
        internal = [l for l in info['links'] if not l.startswith(('http://', 'https://', '//', 'mailto:', 'tel:'))]
        print_subheader("LINKS", len(internal) or None)
        if internal:
            for link in internal[:20]:
                print(f"  {Colors.CYAN}▸{Colors.RESET} {link}")
            if len(internal) > 20:
                print(f"  {Colors.DIM}... and {len(internal) - 20} more{Colors.RESET}")
        else:
            print(f"  {Colors.DIM}[·] no links found{Colors.RESET}")
        print()

    if info['tech']:
        print_subheader("TECHNOLOGIES", len(info['tech']))
        for tech in info['tech']:
            print(f"  {Colors.BRIGHT_MAGENTA}[+]{Colors.RESET} {Colors.BOLD}{tech}{Colors.RESET}")
        print()

    if args.waf:
        print_subheader("WAF DETECTION")
        detected = []
        headers_str = ' '.join(f"{k}: {v}" for k, v in info['headers'].items()).lower()
        cookies_str = ' '.join(info['cookies']).lower()
        for waf, sigs in WAF_SIGNATURES.items():
            if any(sig in headers_str or sig in cookies_str for sig in sigs):
                detected.append(waf)
        if detected:
            for waf in detected:
                print(f"  {Colors.BRIGHT_YELLOW}[!]{Colors.RESET} WAF detected: {Colors.BOLD}{waf}{Colors.RESET}")
        else:
            print_success("No WAF signatures detected")
        print()

    if args.robots:
        print_subheader("ROBOTS.TXT")
        ok, status, _, content = fetch(opener, url.rstrip('/') + '/robots.txt', timeout=5)
        if ok and status == 200 and content:
            print_success("robots.txt found")
            disallows = re.findall(r'Disallow:\s*(\S+)', content)
            allows = re.findall(r'Allow:\s*(\S+)', content)
            for path in disallows[:15]:
                print(f"  {Colors.BRIGHT_RED}▸{Colors.RESET} Disallow: {path}")
            for path in allows[:5]:
                print(f"  {Colors.BRIGHT_GREEN}▸{Colors.RESET} Allow: {path}")
            sitemaps = re.findall(r'Sitemap:\s*(\S+)', content)
            for sm in sitemaps:
                print(f"  {Colors.CYAN}▸{Colors.RESET} Sitemap: {sm}")
        else:
            print(f"  {Colors.DIM}[·] no robots.txt{Colors.RESET}")
        print()

    if args.sitemap:
        print_subheader("SITEMAP")
        ok, status, _, content = fetch(opener, url.rstrip('/') + '/sitemap.xml', timeout=5)
        if ok and status == 200 and content:
            url_count = len(re.findall(r'<url>', content))
            print_success(f"sitemap.xml found ({url_count} URLs)")
        else:
            print(f"  {Colors.DIM}[·] no sitemap.xml{Colors.RESET}")
        print()

    if info['warnings']:
        print_subheader("SECURITY WARNINGS", len(info['warnings']))
        for warning in info['warnings']:
            print(f"  {Colors.BRIGHT_YELLOW}[!]{Colors.RESET} {warning}")
        print()

    print_summary("PROBE RESULTS", [
        ("Status", status),
        ("Cookies", len(info['cookies'])),
        ("Forms", len(info['forms'])),
        ("Links", len(info['links'])),
        ("Warnings", len(info['warnings'])),
    ])

    print_success("HTTP probe completed")
