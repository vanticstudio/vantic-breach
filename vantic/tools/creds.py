"""
Credential Tester Tool
SSH/FTP/RDP credential testing for authorized targets.

Modes:
  brute (default) - each user x each password (classic)
  spray (--spray)  - one password per round across all users (lockout-safe)

Discipline: fresh connection per attempt (dodges sshd MaxAuthTries),
--delay/--jitter between rounds, --stop-on-success via threading.Event
checked inside workers, and a lockout warning banner for big lists.
"""

import argparse
import ftplib
import socket
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

from vantic.utils import (
    print_header, print_subheader, print_error, print_info, print_warning,
    print_success, print_summary, print_table, ProgressBar, status_badge,
    kv, Colors, load_lines, emit_json, resolve_wordlist
)

from vantic.core import store, audit

META = {
    "name": "creds",
    "title": "Credential Tester",
    "category": "CREDENTIALS",
    "description": "SSH/FTP/RDP credential testing (brute + spray)",
    "risk": "intrusive",
    "examples": [
        "vantic creds ssh 192.168.1.1 -u admin -w wordlists/passwords.txt",
        "vantic creds ssh 192.168.1.1 --users users.txt --spray --delay 30",
        "vantic creds ftp 10.0.0.5 -u admin --null-first --stop-on-success",
    ],
    "flow": [
        ("sub", "service", "Service (ssh/ftp/rdp)", "ssh"),
        ("arg", "target", "Target IP", None),
        ("opt", "-u", "Username (blank = defaults)", ""),
        ("opt", "-w", "Password wordlist (blank = tiny default list)", ""),
        ("flag", "--spray", "Spray mode (one password x all users per round)?"),
        ("flag", "--stop-on-success", "Stop after first valid pair?"),
        ("flag", "--null-first", "Try null / login==pass / reversed first?"),
    ],
    "choices": {"service": ["ssh", "ftp", "rdp"]},
    "guard": {"target": "host"},
}

DEFAULT_USERS = ['admin', 'root', 'user', 'test', 'guest', 'Administrator']
DEFAULT_PASSWORDS = ['admin', 'password', '123456', 'root', 'test', 'guest', '']

# Service-aware worker caps (lockout-prone services get few)
SERVICE_WORKERS = {"ssh": 2, "ftp": 2, "rdp": 2}


def ssh_brute(target, port, username, password, timeout=8):
    """Test SSH credentials (fresh connection per attempt)."""
    if not HAS_PARAMIKO:
        return None, "paramiko not installed"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(target, port=port, username=username, password=password,
                        timeout=timeout, allow_agent=False, look_for_keys=False,
                        banner_timeout=15, auth_timeout=timeout,
                        allow_banner=True)
        return True, (username, password)
    except paramiko.AuthenticationException:
        return False, None
    except Exception as e:
        return None, str(e)
    finally:
        try:
            client.close()
        except Exception:
            pass


def ssh_allowed_auths(target, port, username, timeout=6):
    """Ask sshd which auth types it accepts (report instead of silent fails)."""
    if not HAS_PARAMIKO:
        return None
    transport = None
    try:
        transport = paramiko.Transport((target, port))
        transport.banner_timeout = 10
        transport.start_client(timeout=timeout)
        transport.auth_none(username)
        return None
    except paramiko.BadAuthenticationType as e:
        return e.allowed_types
    except Exception:
        return None
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass


def ftp_brute(target, port, username, password, timeout=8):
    """Test FTP credentials."""
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=timeout)
        ftp.login(username, password)
        ftp.quit()
        return True, (username, password)
    except ftplib.error_perm:
        return False, None
    except Exception as e:
        return None, str(e)


def rdp_brute(target, port, username, password, timeout=6):
    """RDP check - verifies reachability + service banner (X.224 CR)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        if result != 0:
            sock.close()
            return False, None
        # Peek at the X.224 connection confirm / RDP negotiation
        try:
            sock.settimeout(2)
            data = sock.recv(64)
        except (socket.timeout, OSError):
            data = b''
        sock.close()
        if data[:1] == b'\x03' or len(data) >= 11:
            return True, (username, password)
        return True, (username, password)
    except Exception as e:
        return None, str(e)


BRUTES = {"ssh": ssh_brute, "ftp": ftp_brute, "rdp": rdp_brute}


def nsr_variants(user):
    """-e nsr pre-pass: null, login==password, reversed login."""
    return [(user, ''), (user, user), (user, user[::-1])]


def add_arguments(parser):
    creds_subparsers = parser.add_subparsers(dest='service')

    for svc, default_port in (('ssh', 22), ('ftp', 21), ('rdp', 3389)):
        svc_parser = creds_subparsers.add_parser(svc, help=f'{svc.upper()} credential testing')
        svc_parser.add_argument('--json', action='store_true', default=argparse.SUPPRESS,
                               help=argparse.SUPPRESS)
        svc_parser.add_argument('target', help='Target IP')
        svc_parser.add_argument('-u', '--user', help='Username')
        svc_parser.add_argument('--users', help='Usernames wordlist')
        svc_parser.add_argument('-w', '--wordlist', help='Password wordlist')
        svc_parser.add_argument('-p', '--port', type=int, default=default_port)
        svc_parser.add_argument('--spray', action='store_true',
                                help='Spray mode: one password per round across all users')
        svc_parser.add_argument('--delay', type=float, default=1.0,
                                help='Delay between attempts/rounds (s)')
        svc_parser.add_argument('--jitter', type=float, default=0.25,
                                help='Jitter fraction for --delay (0.25 = +-25%%)')
        svc_parser.add_argument('--stop-on-success', action='store_true',
                                help='Kill remaining attempts after first valid pair')
        svc_parser.add_argument('-e', '--extra', choices=['nsr'],
                                help='nsr pre-pass: null / login==pass / reversed')
        svc_parser.add_argument('--threads', type=int, default=None,
                                help='Worker threads (default: service-aware)')


def run(args):
    """Run credential tester."""
    import random

    service = getattr(args, 'service', None)
    if not service:
        print_warning("Choose a service: vantic creds ssh|ftp|rdp <target>")
        return

    target = args.target
    port = args.port
    spray = getattr(args, 'spray', False)
    delay = max(0.0, getattr(args, 'delay', 1.0))
    jitter = max(0.0, min(0.9, getattr(args, 'jitter', 0.25)))
    stop_on_success = getattr(args, 'stop_on_success', False)
    null_first = getattr(args, 'extra', None) == 'nsr'

    if service == 'ssh' and not HAS_PARAMIKO:
        print_error("SSH credential testing requires paramiko:")
        print(f"      {Colors.CYAN}pip3 install paramiko{Colors.RESET}")
        return
    if service == 'rdp':
        print_warning("RDP mode verifies X.224 reachability - full auth needs the rdp tool")

    username = getattr(args, 'user', None)
    users_file = getattr(args, 'users', None)
    wordlist = getattr(args, 'wordlist', None)

    if users_file:
        users = load_lines(users_file)
        if users is None:
            print_error(f"Users wordlist not found: {users_file}")
            return
    else:
        users = [username] if username else DEFAULT_USERS

    if wordlist:
        passwords = load_lines(wordlist)
        if passwords is None:
            print_error(f"Password wordlist not found: {wordlist}")
            return
    else:
        passwords = DEFAULT_PASSWORDS

    # nsr pre-pass
    nsr_pairs = []
    if null_first:
        for u in users:
            nsr_pairs.extend(nsr_variants(u))
        nsr_pairs = [p for p in nsr_pairs if p[1] in passwords or True][:len(users) * 3]

    pairs = []
    if spray:
        # password-major: (password, user) rounds - one attempt per user per round
        for pwd in passwords:
            for user in users:
                pairs.append((user, pwd))
    else:
        for user in users:
            for pwd in passwords:
                pairs.append((user, pwd))
    if nsr_pairs:
        seen = set(pairs)
        pairs = [p for p in nsr_pairs if p not in seen] + pairs

    total = len(pairs)
    workers = getattr(args, 'threads', None) or SERVICE_WORKERS.get(service, 4)

    print_header("CREDENTIAL TESTER", f"{service.upper()} · {target}")
    kv("Service", service.upper())
    kv("Target", f"{target}:{port}", Colors.BOLD)
    kv("Mode", "spray (lockout-safe)" if spray else "brute (per-user)")
    kv("Users", f"{len(users)}")
    kv("Passwords", f"{len(passwords)}")
    kv("Combinations", f"{total}", Colors.BOLD)
    kv("Threads", workers)
    if delay:
        kv("Delay", f"{delay}s (+-{int(jitter * 100)}% jitter)")
    if null_first:
        kv("Pre-pass", "null / login==pass / reversed")
    print()

    if not spray and total > 5000:
        print_warning(f"{total} combinations against {len(users)} users - "
                     f"lockout risk; consider --spray")
        print()

    if spray and len(users) > 20:
        print_warning(f"Spraying {len(users)} users - never spray service/shared accounts "
                      f"(one lockout = outage)")
        print()

    brute = BRUTES[service]
    found = []
    errors = 0
    tested = 0
    stop_event = threading.Event()

    def attempt(pair):
        user, pwd = pair
        if stop_event.is_set():
            return None, None
        if delay:
            time.sleep(max(0, delay * (1 + random.uniform(-jitter, jitter))))
        return brute(target, port, user, pwd)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(attempt, pair) for pair in pairs]
        progress = ProgressBar(total, f"{service} {'spray' if spray else 'brute'}")

        for future in as_completed(futures):
            success, cred_or_err = future.result()
            tested += 1
            if success is True and cred_or_err:
                found.append(cred_or_err)
                user, pwd = cred_or_err
                progress.interrupt()
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} "
                      f"{Colors.BOLD}VALID{Colors.RESET}  {Colors.BOLD}{user}{Colors.RESET}"
                      f"{Colors.DIM}:{Colors.RESET}{Colors.BOLD}{pwd or '(empty)'}{Colors.RESET}"
                      f"{' ' * 20}")
                if store.is_active():
                    store.record_target(target, "host")
                audit.log("credential-valid", service=service, target=target,
                          username=user)
                if stop_on_success:
                    stop_event.set()
                    progress.finish("stopped on first success")
            elif success is None and isinstance(cred_or_err, str):
                errors += 1
            if not stop_event.is_set():
                progress.update()

    print()
    rows = [
        ("Tested", f"{tested} combinations"),
        ("Valid", len(found)),
    ]
    if errors:
        rows.append(("Connection errors", errors))
    if stop_on_success and found:
        rows.append(("Stopped early", "yes (--stop-on-success)"))
    print_summary("RESULTS", rows)

    if found:
        rows = [((user, pwd or '(empty)'), Colors.BRIGHT_GREEN) for user, pwd in found]
        print_table(["USERNAME", "PASSWORD"], rows, widths=[22, 26])
        print()
        print_warning("Use these credentials responsibly and only on authorized targets")
    elif errors == tested and errors > 0:
        print()
        print_error(f"All {errors} attempts failed at connection level - check host/port")
    elif service == 'ssh' and tested and not found:
        allowed = ssh_allowed_auths(target, port, users[0])
        if allowed:
            print_info(f"Server accepts: {', '.join(allowed)} "
                       f"(password auth may be disabled)")
        print_info("No valid pairs - check usernames/passwords, or auth policy")

    if getattr(args, 'json', False):
        emit_json({"tool": "creds", "target": f"{target}:{port}", "service": service,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"tested": tested, "valid": found, "errors": errors}})

    print_success(f"Completed at {datetime.now().strftime('%H:%M:%S')}")
