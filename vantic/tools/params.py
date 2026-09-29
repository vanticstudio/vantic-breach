"""
Hidden Parameter Tool
Arjun-style parameter discovery: candidate names in GET/POST/JSON,
reflection markers + stabilized baseline content-length analysis
"""

import urllib.parse
import random
import string
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json, resolve_wordlist,
    load_lines
)

from vantic.core import net, findings

META = {
    "name": "params",
    "title": "Hidden Params",
    "category": "WEB ANALYSIS",
    "description": "Hidden parameter discovery",
    "risk": "safe",
    "examples": [
        "vantic params http://example.com/search",
        "vantic params http://example.com/api --method post,json",
    ],
    "flow": [
        ("arg", "url", "Target URL", None),
        ("flag", "--post", "Also try POST (form + JSON)?"),
    ],
    "guard": {"url": "url"},
}

DEFAULT_PARAMS = ['id', 'debug', 'test', 'admin', 'user', 'action', 'view',
                  'page', 'file', 'path', 'dir', 'cmd', 'exec', 'query',
                  'type', 'format', 'lang', 'debug', 'trace', 'verbose',
                  'internal', 'redirect', 'url', 'next', 'callback', 'jsonp',
                  'token', 'key', 'auth', 'role', 'level', 'access', 'hidden',
                  'output', 'render', 'template', 'name', 'email', 'search',
                  'sort', 'order', 'filter', 'limit', 'offset', 'fields',
                  'include', 'exclude', 'expand', 'embed', 'raw', 'source',
                  'preview', 'draft', 'archive', 'backup', 'old', 'new']

MARKER = 'vantic' + ''.join(random.choice(string.ascii_lowercase) for _ in range(6))


def baseline(url, method, timeout=10):
    """Two identical baseline requests to measure dynamic jitter."""
    sizes = []
    for _ in range(2):
        try:
            resp = net.request(url, "GET" if method == 'get' else "POST", timeout=timeout,
                               follow_redirects=True, max_retries=0)
            sizes.append(len(resp.body))
        except Exception:
            return None
    return sizes


def try_param(url, name, method, timeout=10):
    """One request with the candidate param carrying a reflection marker."""
    marker = f"{MARKER}{random.randint(100, 999)}"
    try:
        if method == 'get':
            resp = net.request(url + ('&' if '?' in url else '?') +
                               urllib.parse.quote(name) + '=' + marker,
                               "GET", timeout=timeout, follow_redirects=True,
                               max_retries=0)
        elif method == 'post':
            resp = net.request(url, "POST", timeout=timeout,
                               data=urllib.parse.urlencode({name: marker}),
                               headers={"Content-Type": "application/x-www-form-urlencoded"},
                               follow_redirects=True, max_retries=0)
        else:  # json
            resp = net.request(url, "POST", timeout=timeout,
                              data={name: marker},
                              follow_redirects=True, max_retries=0)
        return resp.status, len(resp.body), marker in resp.text(200000)
    except Exception:
        return None, None, False


def add_arguments(parser):
    parser.add_argument('url', help='Target URL (with existing query if any)')
    parser.add_argument('--method', default='get',
                        help='Methods: get,post,json (comma-separated)')
    parser.add_argument('-w', '--wordlist', help='Candidate parameter wordlist')
    parser.add_argument('--delay', type=float, default=0.0, help='Delay between probes')


def run(args):
    import time

    url = args.url
    if '://' not in url:
        url = 'http://' + url
    methods = [m.strip().lower() for m in getattr(args, 'method', 'get').split(',')
              if m.strip() in ('get', 'post', 'json')]
    delay = getattr(args, 'delay', 0.0)

    wordlist = getattr(args, 'wordlist', None)
    candidates = DEFAULT_PARAMS
    if wordlist:
        loaded = load_lines(resolve_wordlist(wordlist, None) if '/' not in wordlist
                           else wordlist)
        if loaded:
            candidates = loaded

    print_header("HIDDEN PARAMETERS", url)
    kv("Methods", ', '.join(methods))
    kv("Candidates", len(candidates))
    print()

    found = []
    for method in methods:
        print_subheader(method.upper())
        sizes = baseline(url, method)
        if sizes is None:
            print_error("Baseline failed - target unreachable?")
            continue
        jitter = abs(sizes[0] - sizes[1])
        base = sum(sizes) / 2
        print_info(f"baseline ~{int(base)}B, jitter {jitter}B")

        for name in candidates:
            if delay:
                time.sleep(delay)
            status, size, reflected = try_param(url, name, method)
            if status is None:
                continue
            # Reflection is the reliable signal
            if reflected:
                found.append({'param': name, 'method': method,
                              'evidence': 'reflected marker', 'status': status})
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} "
                      f"{Colors.BOLD}{name}{Colors.RESET} reflects its value ({status})")
                continue
            # Size anomaly beyond jitter (needs a real delta to be meaningful)
            if size is not None and abs(size - base) > max(64, jitter * 3) and \
                    jitter < abs(size - base) / 2:
                # confirm with a second probe
                s2, sz2, _ = try_param(url, name, method)
                if s2 == status and sz2 is not None and \
                        abs(sz2 - base) > max(64, jitter * 3):
                    found.append({'param': name, 'method': method,
                                 'evidence': f'stable size delta {int(sz2 - base)}B',
                                 'status': status})
                    print(f"  {Colors.BRIGHT_YELLOW}[?]{Colors.RESET} "
                          f"{Colors.BOLD}{name}{Colors.RESET} stable delta "
                          f"{int(sz2 - base)}B ({status}) - probably live")
        print()

    if found:
        findings.make(family="hidden-params",
                      title=f"{len(found)} hidden parameters discovered",
                      severity="low", target=url,
                      evidence=", ".join(f"{f['param']} ({f['method']})" for f in found[:12]),
                      remediation="Document parameters; remove debug/dead ones",
                      tool="params")
        print_summary("PARAMS FOUND", [
            (f"{f['param']} ({f['method']})", f['evidence']) for f in found[:10]
        ])
    else:
        print_info("No hidden parameters responded - try a bigger wordlist or POST/JSON")

    if getattr(args, 'json', False):
        emit_json({"tool": "params", "target": url,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": found})

    net.close_connections()
    print_success("Parameter discovery completed")
