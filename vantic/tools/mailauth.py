"""
Mail Auth Tool
IMAP / POP3 / SMTP credential testing (stdlib clients, throttle-aware)

Mail lockout policies vary by server - keep delays conservative.
"""

import imaplib
import poplib
import smtplib
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, kv, Colors, emit_json,
    resolve_wordlist, load_lines
)

from vantic.core import findings, audit, store

META = {
    "name": "mailauth",
    "title": "Mail Auth",
    "category": "CREDENTIALS",
    "description": "IMAP/POP3/SMTP auth testing",
    "risk": "intrusive",
    "examples": [
        "vantic mailauth mail.example.com --proto imap -u jane -w passwords.txt",
        "vantic mailauth mail.example.com --proto smtp --port 587",
    ],
    "flow": [
        ("arg", "target", "Mail server", None),
        ("opt", "--proto", "Protocol (imap/pop3/smtp)", "imap"),
    ],
    "guard": {"target": "host"},
}

DEFAULT_USERS = ['admin', 'postmaster', 'root', 'test', 'info']
DEFAULT_PASSWORDS = ['admin', 'password', '123456', 'mail', 'test', '']


def imap_attempt(host, port, user, pwd, use_ssl, timeout=10):
    try:
        M = imaplib.IMAP4_SSL if use_ssl else imaplib.IMAP4
        m = M(host, port, timeout=timeout)
        try:
            m.login(user, pwd)
            m.logout()
            return True
        except imaplib.IMAP4.error:
            return False
    except Exception:
        return None


def pop3_attempt(host, port, user, pwd, use_ssl, timeout=10):
    try:
        M = poplib.POP3_SSL if use_ssl else poplib.POP3
        m = M(host, port, timeout=timeout)
        try:
            m.user(user)
            m.pass_(pwd)
            m.quit()
            return True
        except poplib.error_proto:
            return False
    except Exception:
        return None


def smtp_attempt(host, port, user, pwd, use_ssl, timeout=10):
    try:
        if use_ssl:
            s = smtplib.SMTP_SSL(host, port, timeout=timeout)
        else:
            s = smtplib.SMTP(host, port, timeout=timeout)
            try:
                s.starttls()
            except smtplib.SMTPException:
                pass
        try:
            s.login(user, pwd)
            s.quit()
            return True
        except smtplib.SMTPAuthenticationError:
            return False
        except smtplib.SMTPException:
            return None
    except Exception:
        return None


PROTO_PORTS = {'imap': (143, 993), 'pop3': (110, 995), 'smtp': (587, 465)}


def add_arguments(parser):
    parser.add_argument('target', help='Mail server')
    parser.add_argument('--proto', choices=['imap', 'pop3', 'smtp'], default='imap')
    parser.add_argument('--port', type=int, default=None)
    parser.add_argument('-u', '--user', help='Username (full address usually)')
    parser.add_argument('--users', help='Usernames wordlist')
    parser.add_argument('-w', '--wordlist', help='Password wordlist')
    parser.add_argument('--delay', type=float, default=2.0,
                        help='Delay between attempts (mail servers throttle hard)')
    parser.add_argument('--stop-on-success', action='store_true')


def run(args):
    import random

    target = args.target
    proto = getattr(args, 'proto', 'imap')
    plain_port, ssl_port = PROTO_PORTS[proto]
    port = getattr(args, 'port', None) or plain_port
    use_ssl = port == ssl_port
    delay = max(0.0, getattr(args, 'delay', 2.0))
    stop_on_success = getattr(args, 'stop_on_success', False)

    username = getattr(args, 'user', None)
    users_file = getattr(args, 'users', None)
    wordlist = getattr(args, 'wordlist', None)
    users = load_lines(users_file) if users_file else \
        ([username] if username else DEFAULT_USERS)
    passwords = load_lines(resolve_wordlist(wordlist, 'passwords.txt') if wordlist
                          else None) or DEFAULT_PASSWORDS

    attempter = {'imap': imap_attempt, 'pop3': pop3_attempt, 'smtp': smtp_attempt}[proto]

    print_header("MAIL AUTH", f"{proto} · {target}:{port}"
                             f"{' (ssl)' if use_ssl else ''}")
    kv("Users", len(users))
    kv("Passwords", len(passwords))
    kv("Delay", f"{delay}s (mail servers throttle hard)")
    if not use_ssl:
        print_info(f"For TLS use --port {ssl_port}")
    print()

    found = []
    stop_event = threading.Event()
    errors = 0
    tested = 0

    def attempt(pair):
        user, pwd = pair
        if stop_event.is_set():
            return None, None
        if delay:
            time.sleep(max(0, delay * (1 + random.uniform(-0.2, 0.2))))
        return pair, attempter(target, port, user, pwd, use_ssl)

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:  # serial: be polite
            futures = [executor.submit(attempt, (u, p)) for u in users for p in passwords]
            for future in as_completed(futures):
                pair, result = future.result()
                if pair is None:
                    continue
                tested += 1
                if result is True:
                    found.append(pair)
                    user, pwd = pair
                    print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} "
                          f"{Colors.BOLD}VALID{Colors.RESET}  "
                          f"{Colors.BOLD}{user}{Colors.RESET}"
                          f"{Colors.DIM}:{Colors.RESET}{Colors.BOLD}{pwd or '(empty)'}{Colors.RESET}")
                    audit.log("credential-valid", service=proto, target=target,
                              username=user)
                    if stop_on_success:
                        stop_event.set()
                elif result is None:
                    errors += 1
    except KeyboardInterrupt:
        print()
        print_warning("Interrupted - results so far shown below")

    print()
    print_summary("MAIL AUTH", [
        ("Tested", tested),
        ("Valid", len(found)),
        ("Errors", errors),
    ])
    if found:
        findings.make(family="mail-auth", title=f"Valid {proto} credentials",
                      severity="high", target=f"{target}:{port}",
                      evidence=", ".join(f"{u}:{p or '(empty)'}" for u, p in found[:5]),
                      remediation="Rotate credentials; enforce MFA on mail",
                      tool="mailauth")
        print_table(["USERNAME", "PASSWORD"],
                   [((u, p or '(empty)'), Colors.BRIGHT_GREEN) for u, p in found])

    if getattr(args, 'json', False):
        emit_json({"tool": "mailauth", "target": f"{target}:{port}", "proto": proto,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"valid": found, "tested": tested}})

    print_success("Mail auth testing completed")
