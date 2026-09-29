"""
Web Crawler Tool
Same-origin BFS with robots.txt + sitemap seeds

Emits deduplicated URLs, forms and parameters for the web tool chain. A
redirect to a third-party host is recorded as an open-redirect finding,
never crawled.
"""

import re
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, kv, Colors, emit_json,
    Spinner
)

from vantic.core import net, findings, store

META = {
    "name": "crawler",
    "title": "Web Crawler",
    "category": "WEB ANALYSIS",
    "description": "Same-origin BFS URL/form discovery",
    "risk": "safe",
    "examples": [
        "vantic crawler http://example.com --depth 3",
        "vantic crawler http://example.com --forms --max-pages 200",
    ],
    "flow": [
        ("arg", "url", "Start URL", None),
        ("opt", "--depth", "Max depth", "3"),
        ("flag", "--forms", "Extract forms?"),
    ],
    "guard": {"url": "url"},
}

HREF_RE = re.compile(r'href=["\']([^"\'#]+)["\']', re.IGNORECASE)
ACTION_RE = re.compile(r'<form[^>]*action=["\']([^"\']+)["\']', re.IGNORECASE)
INPUT_RE = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)
JS_URL_RE = re.compile(r'["\'](/[A-Za-z0-9_\-./?=&%]{2,80})["\']')


def normalize(base, href):
    """Absolutize + strip fragments. Returns None for non-http(s)."""
    href = href.strip()
    if href.startswith(('javascript:', 'mailto:', 'tel:', 'data:')):
        return None
    url = urllib.parse.urljoin(base, href)
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ('http', 'https'):
        return None
    url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or '/',
                                   parts.query, ''))
    return url


def same_origin(a, b):
    pa, pb = urllib.parse.urlsplit(a), urllib.parse.urlsplit(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def add_arguments(parser):
    parser.add_argument('url', help='Start URL')
    parser.add_argument('--depth', type=int, default=3, help='Max BFS depth')
    parser.add_argument('--max-pages', type=int, default=100, help='Page cap')
    parser.add_argument('--forms', action='store_true', help='Extract forms + inputs')
    parser.add_argument('--threads', type=int, default=8)
    parser.add_argument('--delay', type=float, default=0.1, help='Delay per page (s)')


def run(args):
    import time

    start = args.url
    if '://' not in start:
        start = 'http://' + start
    max_depth = max(1, getattr(args, 'depth', 3))
    max_pages = max(1, getattr(args, 'max_pages', 100))
    want_forms = getattr(args, 'forms', True)
    delay = getattr(args, 'delay', 0.1)

    print_header("WEB CRAWLER", start)
    kv("Depth", max_depth)
    kv("Page cap", max_pages)
    print()

    seeds = set()
    # robots.txt seeds
    try:
        resp = net.request(start.rstrip('/') + '/robots.txt', "GET", timeout=8,
                           follow_redirects=False, max_retries=0)
        if resp.status == 200:
            for m in re.finditer(r'(?:Disallow|Allow):\s*(\S+)', resp.text()):
                path = m.group(1)
                if path.startswith('/'):
                    seeds.add(normalize(start, path))
            print_info(f"robots.txt: {len(seeds)} seed paths")
    except Exception:
        pass
    # sitemap seeds
    try:
        resp = net.request(start.rstrip('/') + '/sitemap.xml', "GET", timeout=8,
                           follow_redirects=False, max_retries=0)
        if resp.status == 200:
            found = re.findall(r'<loc>([^<]+)</loc>', resp.text(200000))
            seeds.update(found[:50])
            print_info(f"sitemap.xml: {len(found)} URLs")
    except Exception:
        pass

    queue = [(start, 0)]
    visited = set()
    urls = set()
    forms = []
    third_party_redirects = set()

    with ThreadPoolExecutor(max_workers=1) as executor:  # polite: sequential fetch
        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)
            norm = url
            if norm in visited:
                continue
            visited.add(norm)
            if delay:
                time.sleep(delay)
            try:
                resp = net.request(url, "GET", timeout=8, follow_redirects=True,
                                   max_retries=0)
            except Exception:
                continue

            # Third-party redirect = finding, never a crawl target
            for origin, _status, location in resp.redirects:
                target = urllib.parse.urljoin(origin, location)
                if not same_origin(start, target):
                    third_party_redirects.add((origin, target))

            body = resp.text(300000)
            urls.add(url)

            if depth >= max_depth:
                continue

            # Links
            for m in HREF_RE.finditer(body):
                nxt = normalize(url, m.group(1))
                if nxt and same_origin(start, nxt) and nxt not in visited:
                    queue.append((nxt, depth + 1))
            # JS string URLs
            for m in JS_URL_RE.finditer(body):
                nxt = normalize(url, m.group(1))
                if nxt and same_origin(start, nxt) and nxt not in visited:
                    queue.append((nxt, depth + 1))

            if want_forms:
                for m in ACTION_RE.finditer(body):
                    action = normalize(url, m.group(1)) or url
                    inputs = INPUT_RE.findall(body)
                    if action not in [f['action'] for f in forms]:
                        forms.append({'action': action, 'inputs': inputs})

    print_subheader("URLS DISCOVERED", len(urls))
    for u in sorted(urls)[:40]:
        print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {u[:78]}")
    if len(urls) > 40:
        print(f"  {Colors.DIM}... and {len(urls) - 40} more{Colors.RESET}")
    print()

    if want_forms and forms:
        print_subheader("FORMS", len(forms))
        for f in forms:
            print(f"  {Colors.BRIGHT_MAGENTA}[f]{Colors.RESET} {f['action'][:60]}")
            if f['inputs']:
                print(f"      {Colors.DIM}params: {', '.join(f['inputs'][:8])}{Colors.RESET}")
        print()

    if third_party_redirects:
        print_subheader("THIRD-PARTY REDIRECTS", len(third_party_redirects))
        for origin, target in sorted(third_party_redirects):
            print(f"  {Colors.BRIGHT_YELLOW}[!]{Colors.RESET} {origin[:40]} → {target[:60]}")
        findings.make(family="open-redirect",
                      title="Third-party redirect during crawl",
                      severity="medium", target=start,
                      evidence="; ".join(f"{o} -> {t}" for o, t in
                                         list(third_party_redirects)[:5]),
                      remediation="Validate redirect targets (allow-list)",
                      tool="crawler")
        print()

    if store.is_active():
        for u in urls:
            store.record_target(u, "url")

    print_summary("CRAWL", [
        ("Pages", len(visited)),
        ("URLs", len(urls)),
        ("Forms", len(forms)),
        ("External redirects", len(third_party_redirects)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "crawler", "target": start,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"urls": sorted(urls), "forms": forms,
                               "third_party_redirects": sorted(third_party_redirects)}})

    net.close_connections()
    print_success("Crawl completed")
