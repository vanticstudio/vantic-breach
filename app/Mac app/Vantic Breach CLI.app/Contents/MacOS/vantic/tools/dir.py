"""
Directory Buster Tool
Web path brute forcing with soft-404 calibration, recursion, real
redirect handling, multi-wordlists and rate control
"""

import difflib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_error, print_info,
    print_success, print_summary, print_warning, print_table,
    ProgressBar, status_badge, kv, Colors, resolve_wordlist, load_lines,
    emit_json
)

from vantic.core import net, store

META = {
    "name": "dir",
    "title": "Directory Buster",
    "category": "WEB ANALYSIS",
    "description": "Path brute force with soft-404 filtering",
    "risk": "safe",
    "examples": [
        "vantic dir http://example.com",
        "vantic dir http://example.com -w big.txt -e php,html --recursive",
        "vantic dir http://example.com --category admin,vcs --auto-calibrate",
    ],
    "flow": [
        ("arg", "url", "Target URL (http://target)", None),
        ("opt", "-w", "Wordlist (blank = bundled, repeatable)", ""),
        ("opt", "-e", "Extensions (php,asp - blank = none)", ""),
        ("opt", "--category", "Wordlist category (admin/config/backup/vcs/cms)", ""),
        ("flag", "--recursive", "Recurse into found directories?"),
        ("flag", "--auto-calibrate", "Soft-404 auto-calibration? (default on)"),
    ],
    "guard": {"url": "url"},
}

DEFAULT_WORDLIST = 'directories.txt'
INTERESTING_CODES = [200, 201, 204, 301, 302, 307, 308, 401, 403, 407]

# Tagged probe categories (split out of hardcoded lists)
CATEGORY_PATHS = {
    'admin': ['/admin', '/administrator', '/adminer', '/manager', '/panel',
              '/wp-admin', '/phpmyadmin', '/cpanel', '/webadmin'],
    'config': ['/.env', '/config', '/config.php', '/configuration.php',
               '/settings', '/wp-config.php', '/appsettings.json', '/config.yml',
               '/web.config', '/.config'],
    'backup': ['/backup', '/backups', '/old', '/bak', '/dump', '/db.sql',
               '/database.sql', '/site.tar.gz', '/backup.zip'],
    'vcs': ['/.git/HEAD', '/.git/config', '/.svn/entries', '/.hg/store',
            '/CVS/Root'],
    'cms': ['/wp-login.php', '/xmlrpc.php', '/wp-content', '/administrator',
            '/joomla', '/drupal', '/sites/default', '/typo3'],
    'api': ['/api', '/api/v1', '/api/v2', '/graphql', '/rest', '/swagger.json',
            '/openapi.json', '/api-docs'],
    'misc': ['/test', '/dev', '/tmp', '/debug', '/info.php', '/phpinfo.php',
             '/server-status', '/.DS_Store', '/robots.txt', '/sitemap.xml',
             '/.htaccess', '/README.md', '/README.txt'],
}


def check_path(base_url, path, timeout=5, follow_redirects=False):
    """Check one path. Returns a result dict or None (network error)."""
    url = f"{base_url}{path}"
    try:
        resp = net.request(url, "GET", timeout=timeout,
                           follow_redirects=follow_redirects, max_retries=1)
        body = resp.body
        return {
            'path': path, 'status': resp.status, 'size': len(body),
            'url': url,
            'words': len(body.split()),
            'body': body,
            'redirects': resp.redirects,
        }
    except Exception:
        return None


def soft404_baseline(base_url, follow_redirects=False):
    """Fetch two random nonexistent paths to learn the soft-404 signature."""
    import random
    import string
    sigs = []
    for _ in range(2):
        rnd = ''.join(random.choice(string.ascii_lowercase) for _ in range(14))
        r = check_path(base_url, f"/{rnd}{random.randint(1000, 9999)}",
                       follow_redirects=follow_redirects)
        if r:
            sigs.append(r)
    if not sigs:
        return None
    return {
        'status': {s['status'] for s in sigs},
        'size': sum(s['size'] for s in sigs) / len(sigs),
        'words': sum(s['words'] for s in sigs) / len(sigs),
        'body': sigs[0]['body'],
    }


def is_soft404(result, baseline):
    """True when a hit looks like the custom-not-found page."""
    if baseline is None:
        return False
    if result['status'] not in baseline['status']:
        return False
    if abs(result['size'] - baseline['size']) < 32 and \
       abs(result['words'] - baseline['words']) < 3:
        return True
    if result['body'] and baseline['body']:
        try:
            ratio = difflib.SequenceMatcher(
                None, result['body'][:4096], baseline['body'][:4096]).quick_ratio()
            return ratio > 0.9
        except Exception:
            return False
    return False


def load_wordlists(paths):
    """Merge + dedupe multiple wordlists."""
    words = []
    seen = set()
    for p in paths:
        loaded = load_lines(p)
        if loaded is None:
            print_warning(f"Wordlist not found: {p}")
            continue
        for w in loaded:
            if w not in seen:
                seen.add(w)
                words.append(w)
    return words


def add_arguments(parser):
    parser.add_argument('url', help='Target URL')
    parser.add_argument('-w', '--wordlist', action='append', default=[],
                        help='Wordlist path (repeatable; default: bundled directories.txt)')
    parser.add_argument('-e', '--extensions', help='File extensions (comma-separated)')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Thread count')
    parser.add_argument('--status-codes', help='Interesting status codes')
    parser.add_argument('--follow-redirects', action='store_true', help='Follow redirects')
    parser.add_argument('--exclude', help='Exclude patterns')
    parser.add_argument('--category', help=f"Tagged categories ({','.join(CATEGORY_PATHS)})")
    parser.add_argument('--recursive', action='store_true', help='Recurse into found dirs')
    parser.add_argument('--recursion-depth', type=int, default=2, help='Max recursion depth')
    parser.add_argument('--auto-calibrate', dest='calibrate', action='store_true',
                        default=True, help='Soft-404 calibration (default on)')
    parser.add_argument('--no-calibrate', dest='calibrate', action='store_false',
                        help='Disable soft-404 calibration')
    parser.add_argument('--filter-size', help='Filter results of this size (bytes)')
    parser.add_argument('--filter-words', help='Filter results with this word count')
    parser.add_argument('--delay', type=float, default=0.0, help='Delay between requests (s)')
    parser.add_argument('--rate', type=float, default=0, help='Max requests/second (0 = off)')


def run(args):
    """Run directory buster."""
    url = args.url.rstrip('/')
    if not url.startswith('http'):
        url = f"http://{url}"

    threads = max(1, args.threads)
    follow = getattr(args, 'follow_redirects', False)

    # Resolve wordlists: explicit paths, categories, or the bundled default
    wordlist_paths = list(args.wordlist)
    words = []
    if getattr(args, 'category', None):
        cats = [c.strip() for c in args.category.split(',') if c.strip()]
        for cat in cats:
            if cat not in CATEGORY_PATHS:
                print_warning(f"Unknown category: {cat} "
                              f"(choose from {', '.join(CATEGORY_PATHS)})")
            else:
                words.extend(CATEGORY_PATHS[cat])
        if words:
            print_info(f"Category mode: {len(words)} tagged paths")
    if wordlist_paths:
        words = load_wordlists(wordlist_paths) or words
    if not words and not wordlist_paths and not getattr(args, 'category', None):
        default = resolve_wordlist(None, DEFAULT_WORDLIST)
        if not default:
            print_error("No wordlist found. Pass one with -w /path/to/words.txt")
            return
        words = load_wordlist_checked(default)
        if words is None:
            return

    if not words:
        print_error("Nothing to scan - empty wordlist/category")
        return

    # Extensions
    extensions = ['']
    if args.extensions:
        extensions = [''] + ['.' + ext.strip().lstrip('.') for ext in args.extensions.split(',')
                             if ext.strip()]

    interesting_codes = INTERESTING_CODES
    if args.status_codes:
        try:
            interesting_codes = [int(c.strip()) for c in args.status_codes.split(',')]
        except ValueError:
            print_error(f"Invalid status codes: {args.status_codes}")
            return

    exclude_patterns = [p.strip() for p in (args.exclude or '').split(',') if p.strip()]
    filter_size = int(args.filter_size) if getattr(args, 'filter_size', None) else None
    filter_words = int(args.filter_words) if getattr(args, 'filter_words', None) else None

    if getattr(args, 'rate', 0):
        net.set_rate(args.rate)

    print_header("DIRECTORY BUSTER", url)
    kv("Wordlist", f"{len(words)} entries" + (f" (+{len(extensions) - 1} ext)" if len(extensions) > 1 else ""))
    kv("Extensions", ', '.join(e.lstrip('.') or '(none)' for e in extensions) or '(none)')
    kv("Threads", threads)
    kv("Status codes", ', '.join(map(str, interesting_codes)))
    kv("Calibration", "soft-404 on" if getattr(args, 'calibrate', True) else "off")
    if getattr(args, 'recursive', False):
        kv("Recursion", f"depth {args.recursion_depth}")
    print()

    # Build targets: word x extension
    targets = []
    for word in words:
        base = word if word.startswith('/') else f"/{word}"
        for ext in extensions:
            targets.append(f"{base}{ext}")

    # Soft-404 baseline
    baseline = None
    if getattr(args, 'calibrate', True):
        print_info("Calibrating soft-404 baseline (2 random paths)...")
        baseline = soft404_baseline(url, follow)
        if baseline:
            print(f"  {Colors.DIM}baseline: status={sorted(baseline['status'])} "
                  f"size~{int(baseline['size'])}B words~{int(baseline['words'])}{Colors.RESET}")
        else:
            print(f"  {Colors.DIM}baseline unavailable (unreachable target?){Colors.RESET}")
        print()

    print_info(f"{len(words)} entries x {len(extensions)} ext = "
               f"{Colors.BOLD}{len(targets)}{Colors.RESET} requests")
    print()

    found = []
    errors = 0
    dirs_found = set()
    depth = 0
    queue = list(targets)
    scanned = 0

    while queue:
        batch = queue
        queue = []
        scanned += len(batch)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(
                check_path, url, target, 5, follow): target for target in batch}
            progress = ProgressBar(len(batch), "dirb" if depth == 0 else f"dirb d{depth}")

            for future in as_completed(futures):
                result = future.result()
                progress.update()
                if result is None:
                    errors += 1
                    continue
                if result['status'] not in interesting_codes:
                    continue
                if exclude_patterns and any(p in result['path'] for p in exclude_patterns):
                    continue
                if filter_size is not None and result['size'] == filter_size:
                    continue
                if filter_words is not None and result['words'] == filter_words:
                    continue
                if is_soft404(result, baseline):
                    continue
                found.append(result)
                del result['body']  # keep memory small
                progress.interrupt()
                color = (Colors.BRIGHT_GREEN if 200 <= result['status'] < 300
                         else Colors.BRIGHT_YELLOW if result['status'] < 400
                         else Colors.BRIGHT_RED)
                redir = ''
                if result['redirects']:
                    redir = f"{Colors.DIM} → {result['redirects'][-1][2][:38]}{Colors.RESET}"
                print(f"  {color}{result['status']}{Colors.RESET}  "
                      f"{Colors.BOLD}{result['path']}{Colors.RESET}"
                      f"{Colors.DIM}  ({result['size']:,} bytes){Colors.RESET}{redir}")
                if store.is_active():
                    from urllib.parse import urlsplit
                    host = urlsplit(url).hostname
                    store.record_service(host, 80 if url.startswith('http://') else 443,
                                        'http', f"found {result['path']}", source_tool='dir')
                # Queue recursion candidates (directory-shaped hits only)
                if getattr(args, 'recursive', False) and \
                        depth < args.recursion_depth and \
                        200 <= result['status'] < 400:
                    redir_path = result['redirects'][-1][2].split('?')[0] \
                        if result['redirects'] else ''
                    if result['path'].endswith('/') or redir_path.endswith('/'):
                        dirs_found.add(result['path'] if result['path'].endswith('/')
                                       else result['path'] + '/')

        depth += 1
        if getattr(args, 'recursive', False) and dirs_found and depth <= args.recursion_depth:
            new_dirs = dirs_found
            dirs_found = set()
            queue = [f"{d.rstrip('/')}/{w.lstrip('/')}" for d in new_dirs for w in words]
            queue = [q for q in queue if len(q) < 120][:2000]

    print()
    print_subheader("SUMMARY")

    by_status = {}
    for f in found:
        by_status.setdefault(f['status'], []).append(f)

    print_summary("RESULTS", [
        ("Requests", scanned),
        ("Findings", len(found)),
        ("Errors", errors),
        ("Hit codes", ', '.join(map(str, sorted(by_status))) or 'none'),
    ])

    if found:
        rows = []
        for item in sorted(found, key=lambda x: (x['status'], x['path'])):
            color = (Colors.BRIGHT_GREEN if 200 <= item['status'] < 300
                     else Colors.BRIGHT_YELLOW if item['status'] < 400
                     else Colors.BRIGHT_RED)
            rows.append(((str(item['status']), item['path'], f"{item['size']:,}"), color))
        print_table(["STATUS", "PATH", "SIZE"], rows, widths=[10, 44, 16])
    elif errors:
        print()
        print_warning(f"No findings and {errors} request errors - target may be unreachable")

    if getattr(args, 'json', False):
        emit_json({"tool": "dir", "target": url,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": [{'path': f['path'], 'status': f['status'],
                                'size': f['size'], 'url': f['url']} for f in found]})

    net.close_connections()
    print_success("Directory brute force completed")


def load_wordlist_checked(filepath):
    words = load_lines(filepath)
    if words is None:
        print_error(f"Wordlist not found: {filepath}")
        return None
    if not words:
        print_error(f"Wordlist is empty: {filepath}")
        return None
    return words
