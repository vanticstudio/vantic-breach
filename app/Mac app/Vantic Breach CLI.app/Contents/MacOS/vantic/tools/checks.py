"""
Template Check Tool (nuclei-lite)
JSON templates, six matcher types, GET/POST only, no DSL

Templates live in vantic/data/checks/*.json. This converts the web
tool's hardcoded checks into data anyone can extend.
"""

import json
import os
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json, resolve_datafile
)

from vantic.core import net, findings

META = {
    "name": "checks",
    "title": "Template Checks",
    "category": "WEB ANALYSIS",
    "description": "JSON template vulnerability checks",
    "risk": "safe",
    "examples": [
        "vantic checks http://example.com",
        "vantic checks http://example.com --severity high,medium",
    ],
    "flow": [
        ("arg", "url", "Target URL", None),
        ("opt", "--severity", "Filter: high,medium,low (blank = all)", ""),
    ],
    "guard": {"url": "url"},
}


def load_templates(templates_dir=None):
    """Load JSON templates from the bundled checks dir or --templates."""
    paths = []
    if templates_dir and os.path.isdir(templates_dir):
        for f in sorted(os.listdir(templates_dir)):
            if f.endswith('.json'):
                paths.append(os.path.join(templates_dir, f))
    else:
        bundled = resolve_datafile('checks')
        if bundled and os.path.isdir(bundled):
            for f in sorted(os.listdir(bundled)):
                if f.endswith('.json'):
                    paths.append(os.path.join(bundled, f))
    templates = []
    for p in paths:
        try:
            with open(p) as f:
                t = json.load(f)
            if isinstance(t, dict) and 'request' in t and 'match' in t:
                t['_file'] = os.path.basename(p)
                templates.append(t)
        except (OSError, ValueError):
            continue
    return templates


def run_matchers(match, resp, wordlist_words=None):
    """Evaluate one matcher group against a Response."""
    def one(m):
        mtype = m.get('type')
        if mtype == 'status':
            return resp.status in (m.get('value') or [])
        if mtype == 'header':
            name = m.get('name', '')
            val = resp.header(name)
            if m.get('absent'):
                return val is None
            if val is None:
                return False
            if m.get('contains'):
                return m['contains'].lower() in val.lower()
            if m.get('value'):
                return val.lower() == m['value'].lower()
            return True
        if mtype == 'word':
            part = resp.text(500000) if m.get('part', 'body') == 'body' else \
                ' '.join(f"{k}: {v}" for k, v in resp.headers)
            words = m.get('value') or []
            ci = m.get('case_insensitive', True)
            hay = part.lower() if ci else part
            found = any((w.lower() if ci else w) in hay for w in words)
            return not found if m.get('not_match') else found
        if mtype == 'regex':
            part = resp.text(500000) if m.get('part', 'body') == 'body' else \
                ' '.join(f"{k}: {v}" for k, v in resp.headers)
            flags = re.IGNORECASE if m.get('case_insensitive', True) else 0
            try:
                found = re.search(m.get('value', 'x'), part, flags) is not None
            except re.error:
                return False
            return not found if m.get('not_match') else found
        if mtype == 'size':
            actual = len(resp.body)
            expected = m.get('value', 0)
            tol = m.get('tolerance', 32)
            hit = abs(actual - expected) <= tol
            return not hit if m.get('not_match') else hit
        return False

    matchers = match.get('matchers', [])
    condition = match.get('condition', 'and')
    results = [one(m) for m in matchers]
    if not results:
        return False
    return all(results) if condition == 'and' else any(results)


def add_arguments(parser):
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--templates', metavar='DIR',
                        help='Template directory (default: bundled checks)')
    parser.add_argument('--severity', help='Filter by severity (high,medium,low)')
    parser.add_argument('--threads', type=int, default=8)


def run(args):
    url = args.url
    if '://' not in url:
        url = 'http://' + url
    severity_filter = getattr(args, 'severity', None)
    wanted = {s.strip().lower() for s in severity_filter.split(',')} if severity_filter else None

    templates = load_templates(getattr(args, 'templates', None))
    if not templates:
        print_error("No templates found (expected vantic/data/checks/*.json)")
        return
    if wanted:
        templates = [t for t in templates
                     if t.get('info', {}).get('severity', 'low').lower() in wanted]
    # https-only templates skip plain-http targets
    if url.startswith('http://'):
        templates = [t for t in templates
                    if not t.get('info', {}).get('https_only')]

    print_header("TEMPLATE CHECKS", f"{len(templates)} templates")
    kv("Target", url, Colors.BOLD)
    if severity_filter:
        kv("Severity filter", severity_filter)
    print()

    hits = []
    errors = 0

    def run_one(template):
        req = template['request']
        path = (req.get('path') or '/').format(FUZZ='/')
        method = (req.get('method') or 'GET').upper()
        full = url.rstrip('/') + path
        try:
            resp = net.request(full, method, timeout=8, follow_redirects=False,
                               max_retries=0, headers=req.get('headers') or {},
                               data=req.get('body'))
        except Exception:
            return template, None, 'error'
        if run_matchers(template['match'], resp):
            return template, resp, 'hit'
        return template, resp, 'miss'

    with ThreadPoolExecutor(max_workers=max(1, getattr(args, 'threads', 8))) as executor:
        futures = {executor.submit(run_one, t): t for t in templates}
        for future in as_completed(futures):
            template, resp, verdict = future.result()
            if verdict == 'error':
                errors += 1
            elif verdict == 'hit':
                info = template.get('info', {})
                sev = info.get('severity', 'low')
                title = info.get('name', template.get('id', '?'))
                hits.append(template)
                color = getattr(Colors, 'BRIGHT_RED' if sev in ('critical', 'high')
                                else 'BRIGHT_YELLOW' if sev == 'medium' else 'DIM')
                print(f"  {color}[!]{Colors.RESET} [{sev.upper():<8}] "
                      f"{Colors.BOLD}{title}{Colors.RESET} "
                      f"{Colors.DIM}{template.get('_file', '')}{Colors.RESET}")
                findings.make(family="template",
                              title=title, severity=sev, target=url,
                              evidence=f"template {template.get('id')} matched "
                                       f"on {template['request'].get('path', '/')}",
                              remediation=info.get('remediation', 'See template notes'),
                              tool="checks")

    print()
    print_summary("TEMPLATE CHECKS", [
        ("Templates run", len(templates)),
        ("Hits", len(hits)),
        ("Errors", errors),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "checks", "target": url,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": [t.get('id') for t in hits]})

    net.close_connections()
    print_success("Template checks completed")
