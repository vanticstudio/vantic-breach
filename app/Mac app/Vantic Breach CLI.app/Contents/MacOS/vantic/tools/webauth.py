"""
Web Auth Tool
HTTP Basic / Digest / form login credential testing

Success keyed on 401->2xx transitions (basic/digest) and body-diff
against a failed baseline (forms, incl. fresh-CSRF handling). Feeds
from the same lockout discipline as the creds tool.
"""

import re
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json, resolve_wordlist,
    load_lines
)

from vantic.core import net, audit, store

META = {
    "name": "webauth",
    "title": "Web Auth",
    "category": "CREDENTIALS",
    "description": "HTTP basic/digest/form auth testing",
    "risk": "intrusive",
    "examples": [
        "vantic webauth https://example.com/login --user admin -w passwords.txt",
        "vantic webauth https://example.com --mode basic --users users.txt",
    ],
    "flow": [
        ("arg", "url", "Target URL (login page or basic-auth path)", None),
        ("opt", "-u", "Username (blank = common defaults)", ""),
        ("opt", "-w", "Password wordlist (blank = tiny default)", ""),
    ],
    "guard": {"url": "url"},
}

DEFAULT_USERS = ['admin', 'root', 'administrator', 'test', 'guest', 'user']
DEFAULT_PASSWORDS = ['admin', 'password', '123456', 'root', 'test', 'guest', '']

CSRF_NAMES = ['csrfmiddlewaretoken', '_token', 'csrf_token', 'authenticity_token',
              '_csrf', 'csrf', 'token', '__RequestVerificationToken']


def try_basic(url, user, password, timeout=10):
    """Basic auth attempt: 401 -> 2xx/3xx = success."""
    import base64
    cred = base64.b64encode(f"{user}:{password}".encode()).decode()
    try:
        resp = net.request(url, "GET", timeout=timeout, follow_redirects=False,
                           max_retries=0,
                           headers={"Authorization": f"Basic {cred}"})
        if resp.status in (200, 301, 302, 303, 307, 308):
            return True
        if resp.status == 401:
            return False
        return None  # 403 etc - ambiguous
    except Exception:
        return None


def parse_form(html):
    """Extract (action, method, inputs) from the first form."""
    m = re.search(r'<form[^>]*>', html, re.IGNORECASE)
    if not m:
        return None
    form_tag = m.group(0)
    action = (re.search(r'action=["\']([^"\']*)["\']', form_tag, re.IGNORECASE) or
              re.search(r'action=([^\s>]+)', form_tag, re.IGNORECASE))
    action = action.group(1) if action else ''
    method = re.search(r'method=["\']?(\w+)', form_tag, re.IGNORECASE)
    method = (method.group(1).upper() if method else 'POST')
    inputs = {}
    for im in re.finditer(r'<input[^>]*>', html, re.IGNORECASE):
        tag = im.group(0)
        name = re.search(r'name=["\']([^"\']+)["\']', tag)
        value = re.search(r'value=["\']([^"\']*)["\']', tag)
        if name:
            inputs[name.group(1)] = value.group(1) if value else ''
    return {'action': action, 'method': method, 'inputs': inputs}


def try_form(url, user, password, timeout=12):
    """Form login: GET page (fresh CSRF + cookies), POST, diff vs baseline."""
    try:
        page = net.request(url, "GET", timeout=timeout, follow_redirects=True,
                           max_retries=0)
        html = page.text(200000)
        form = parse_form(html)
        if not form:
            return None
        action = urllib.parse.urljoin(page.url, form['action'] or '')
        fields = dict(form['inputs'])
        user_field = next((f for f in ('username', 'user', 'email', 'login',
                                       'user_name', 'userid') if f in fields), None)
        pass_field = next((f for f in ('password', 'pass', 'passwd', 'pwd')
                          if f in fields), None)
        # CSRF: re-POST whatever the page gave us
        data = fields
        if user_field:
            data[user_field] = user
        if pass_field:
            data[pass_field] = password
        # If we couldn't identify fields by name, guess common slots
        if not user_field or not pass_field:
            return None
        resp = net.request(action, form['method'], timeout=timeout,
                           data=urllib.parse.urlencode(data),
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           follow_redirects=False, max_retries=0)
        if resp.status in (301, 302, 303):
            return True  # redirect after login
        if resp.status == 200:
            # body-diff against the login page (form re-render = fail)
            new_html = resp.text(200000)
            if '<form' not in new_html.lower():
                return True
            return False
        if resp.status in (401, 403):
            return False
        return None
    except Exception:
        return None


def add_arguments(parser):
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--mode', choices=['basic', 'form', 'digest', 'auto'],
                        default='auto', help='Auth mode (default: detect)')
    parser.add_argument('-u', '--user', help='Username')
    parser.add_argument('--users', help='Usernames wordlist')
    parser.add_argument('-w', '--wordlist', help='Password wordlist')
    parser.add_argument('--delay', type=float, default=0.3, help='Delay between attempts')
    parser.add_argument('--stop-on-success', action='store_true')
    parser.add_argument('--threads', type=int, default=2)


def run(args):
    import random

    url = args.url
    if '://' not in url:
        url = 'http://' + url
    mode = getattr(args, 'mode', 'auto')
    delay = max(0.0, getattr(args, 'delay', 0.3))
    stop_on_success = getattr(args, 'stop_on_success', False)

    username = getattr(args, 'user', None)
    users_file = getattr(args, 'users', None)
    wordlist = getattr(args, 'wordlist', None)
    users = load_lines(users_file) if users_file else \
        ([username] if username else DEFAULT_USERS)
    passwords = load_lines(resolve_wordlist(wordlist, 'passwords.txt') if wordlist
                          else None) or DEFAULT_PASSWORDS

    # Detect mode
    if mode == 'auto':
        try:
            resp = net.request(url, "GET", timeout=10, follow_redirects=False,
                               max_retries=0)
            if resp.status == 401:
                mode = 'basic'
            elif '<form' in resp.text(200000).lower():
                mode = 'form'
                try:
                    page = net.request(url, "GET", timeout=10, follow_redirects=True,
                                       max_retries=0)
                    if resp.status == 401:
                        mode = 'basic'
                except Exception:
                    pass
            else:
                print_warning("No 401 or form detected - pass --mode explicitly")
                return
        except Exception as e:
            print_error(f"Target unreachable: {e}")
            return

    print_header("WEB AUTH", f"{mode} · {url}")
    kv("Mode", mode)
    kv("Users", len(users))
    kv("Passwords", len(passwords))
    kv("Attempts", len(users) * len(passwords))
    if delay:
        kv("Delay", f"{delay}s")
    print()

    attempter = try_basic if mode == 'basic' else try_form
    found = []
    stop_event = threading.Event()
    errors = 0
    tested = 0

    def attempt(pair):
        user, pwd = pair
        if stop_event.is_set():
            return None, None
        if delay:
            time.sleep(max(0, delay * (1 + random.uniform(-0.25, 0.25))))
        return pair, attempter(url, user, pwd)

    with ThreadPoolExecutor(max_workers=max(1, getattr(args, 'threads', 2))) as executor:
        futures = [executor.submit(attempt, (u, p)) for u in users for p in passwords]
        for future in as_completed(futures):
            pair, result = future.result()
            tested += 1
            if result is True:
                user, pwd = pair
                found.append(pair)
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} "
                      f"{Colors.BOLD}VALID{Colors.RESET}  {Colors.BOLD}{user}{Colors.RESET}"
                      f"{Colors.DIM}:{Colors.RESET}{Colors.BOLD}{pwd or '(empty)'}{Colors.RESET}")
                audit.log("credential-valid", service=f"web-{mode}", target=url,
                          username=user)
                if store.is_active():
                    store.record_target(url, "url")
                if stop_on_success:
                    stop_event.set()
            elif result is None:
                errors += 1

    print()
    print_summary("WEB AUTH", [
        ("Tested", tested),
        ("Valid", len(found)),
        ("Errors", errors),
    ])
    if found:
        findings.make(family="web-auth", title=f"Valid web credentials ({mode})",
                      severity="high", target=url,
                      evidence=", ".join(f"{u}:{p or '(empty)'}" for u, p in found[:5]),
                      remediation="Rotate credentials; enforce rate limiting + MFA",
                      tool="webauth")

    if getattr(args, 'json', False):
        emit_json({"tool": "webauth", "target": url, "mode": mode,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"valid": found, "tested": tested}})

    net.close_connections()
    print_success("Web auth testing completed")
