"""
SMTP Enumeration Tool
VRFY / EXPN / RCPT user enumeration (read-only)

Interprets: 250/251/252 = exists, 550/551/553 = no, 502 = VRFY disabled.
Verbatim response logging for the engagement record.
"""

import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, ProgressBar, kv, Colors,
    emit_json, resolve_wordlist, load_lines
)

from vantic.core import findings, store

META = {
    "name": "smtp",
    "title": "SMTP Enum",
    "category": "SERVICES",
    "description": "VRFY/EXPN/RCPT user enumeration",
    "risk": "intrusive",
    "examples": [
        "vantic smtp 10.0.0.10 --vrfy --users users.txt",
        "vantic smtp mail.example.com --rcpt --delay 1",
    ],
    "flow": [
        ("arg", "target", "Target mail server", None),
        ("opt", "--users", "Usernames wordlist (blank = small defaults)", ""),
        ("flag", "--vrfy", "VRFY enumeration?"),
    ],
    "guard": {"target": "host"},
}

DEFAULT_USERS = ['root', 'admin', 'postmaster', 'abuse', 'webmaster', 'info',
                'support', 'sales', 'contact', 'helpdesk', 'it', 'test']


class SMTPSession:
    """One SMTP conversation (EHLO, probes, QUIT)."""

    def __init__(self, host, port, timeout=10):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.banner = self._read()

    def _read(self):
        data = b''
        try:
            while True:
                chunk = self.sock.recv(1024)
                if not chunk:
                    break
                data += chunk
                # multi-line replies: last line has a space after the code
                lines = data.decode(errors='replace').splitlines()
                if lines and lines[-1][3:4] == ' ':
                    break
        except socket.timeout:
            pass
        return data.decode(errors='replace').strip()

    def cmd(self, command):
        self.sock.sendall((command + "\r\n").encode())
        return self._read()

    def close(self):
        try:
            self.cmd('QUIT')
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


def add_arguments(parser):
    parser.add_argument('target', help='SMTP server')
    parser.add_argument('--port', type=int, default=25, help='SMTP port (25/587)')
    parser.add_argument('--vrfy', action='store_true', help='VRFY each user')
    parser.add_argument('--expn', action='store_true', help='EXPN each list')
    parser.add_argument('--rcpt', action='store_true',
                        help='RCPT TO enumeration (needs --from)')
    parser.add_argument('--from', dest='mail_from', default='vantic@test.local',
                        help='MAIL FROM for RCPT mode')
    parser.add_argument('--users', help='Usernames wordlist')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between probes (s)')


def run(args):
    import time

    target = args.target
    port = getattr(args, 'port', 25)
    users_file = getattr(args, 'users', None)
    delay = max(0.0, getattr(args, 'delay', 0.5))

    modes = [m for m, on in (('vrfy', getattr(args, 'vrfy', False)),
                            ('expn', getattr(args, 'expn', False)),
                            ('rcpt', getattr(args, 'rcpt', False))) if on]
    if not modes:
        modes = ['vrfy']

    users = DEFAULT_USERS
    if users_file:
        loaded = load_lines(resolve_wordlist(users_file, None) if '/' not in users_file
                            else users_file)
        if loaded:
            users = loaded
        else:
            print_warning(f"Wordlist not found: {users_file} - using defaults")

    print_header("SMTP ENUMERATION", f"{target}:{port}")
    kv("Modes", ', '.join(modes))
    kv("Candidates", len(users))
    kv("Delay", f"{delay}s")
    print()

    try:
        session = SMTPSession(target, port)
    except OSError as e:
        print_error(f"Connection failed: {e}")
        return

    print_info(f"Banner: {session.banner.splitlines()[0] if session.banner else '(silent)'}")
    ehlo = session.cmd("EHLO vantic.local")
    caps = ehlo.splitlines()
    if 'STARTTLS' in ehlo:
        kv("STARTTLS", "offered")
    else:
        kv("STARTTLS", "not offered (cleartext mail)")
        findings.make(family="smtp-starttls", title="SMTP without STARTTLS",
                      severity="low", target=f"{target}:{port}",
                      evidence=session.banner.splitlines()[0] if session.banner else '',
                      remediation="Enable STARTTLS + enforce TLS",
                      tool="smtp")
    if store.is_active():
        store.record_service(target, port, "smtp",
                            session.banner.splitlines()[0], source_tool="smtp")
    print()

    found = []
    disabled = set()

    def interpret(code):
        """Response code -> (exists, note)."""
        try:
            code = int(code)
        except (TypeError, ValueError):
            return None, 'unparseable'
        if code in (250, 251, 252):
            return True, ('250' if code != 252 else '252 (will accept)')
        if code in (550, 551, 553):
            return False, f"{code} (no such user)"
        if code == 502:
            return None, '502 (command disabled)'
        if code == 252:
            return True, '252'
        return None, str(code)

    for mode in modes:
        print_subheader(mode.upper())
        for user in users:
            if delay:
                time.sleep(delay)
            try:
                if mode == 'vrfy':
                    resp = session.cmd(f"VRFY {user}")
                elif mode == 'expn':
                    resp = session.cmd(f"EXPN {user}")
                else:  # rcpt
                    session.cmd(f"MAIL FROM:<{args.mail_from}>")
                    resp = session.cmd(f"RCPT TO:<{user}@{target}>")
                    session.cmd("RSET")
            except (OSError, socket.timeout) as e:
                print_error(f"Connection lost: {e}")
                session = SMTPSession(target, port)
                continue
            code = resp[:3]
            exists, note = interpret(code)
            if exists is True:
                found.append({'user': user, 'mode': mode, 'code': code})
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} "
                      f"{Colors.BOLD}{user:<24}{Colors.RESET} {note}")
            elif exists is None and '502' in resp:
                disabled.add(mode)
                print(f"  {Colors.DIM}[·] {mode} disabled on this server{Colors.RESET}")
                break
            elif exists is None and '421' in resp:
                print_warning("Server throttling (421) - increasing delay")
                time.sleep(2)

        if mode in disabled:
            print_info(f"{mode.upper()} is disabled server-side")

    session.close()

    print()
    if found:
        rows = [((f['user'], f['mode'], f['code']), Colors.BRIGHT_GREEN) for f in found]
        print_table(["USER", "MODE", "CODE"], rows, widths=[24, 10, 8])
        findings.make(family="smtp-userenum",
                      title=f"SMTP user enumeration ({', '.join(modes)})",
                      severity="medium", target=f"{target}:{port}",
                      evidence=f"{len(found)} users confirmed",
                      remediation="Disable VRFY/EXPN; rate-limit RCPT",
                      tool="smtp")
    else:
        print_info("No confirmed users (VRFY may be disabled - try --rcpt)")

    print_summary("SMTP ENUM", [
        ("Probed", len(users)),
        ("Confirmed", len(found)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "smtp", "target": f"{target}:{port}",
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": found})

    print_success("SMTP enumeration completed")
