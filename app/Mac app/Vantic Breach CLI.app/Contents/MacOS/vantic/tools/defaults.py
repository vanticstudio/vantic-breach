"""
Default Credentials Tool
Vendor default credential audit (ssh/ftp/http/snmp/redis) - feeds the
lockout-aware engine, stop-on-success per service
"""

import base64
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, kv, Colors, emit_json,
    resolve_wordlist, load_lines
)

from vantic.core import net, findings, audit, store

META = {
    "name": "defaults",
    "title": "Default Creds",
    "category": "CREDENTIALS",
    "description": "Vendor default credential audit",
    "risk": "intrusive",
    "examples": [
        "vantic defaults 192.168.1.1 --service http",
        "vantic defaults 10.0.0.5 --service ssh",
        "vantic defaults 192.168.1.1 --service snmp",
    ],
    "flow": [
        ("arg", "target", "Target IP", None),
        ("opt", "--service", "Service (ssh/ftp/http/snmp/redis)", "http"),
    ],
    "guard": {"target": "host"},
}

WORDLISTS = {
    'ssh': 'defaults_ssh.txt',
    'ftp': 'defaults_ftp.txt',
    'http': 'defaults_http.txt',
    'snmp': 'defaults_snmp.txt',
    'redis': 'defaults_redis.txt',
}


def ssh_attempt(target, port, user, pwd, timeout=8):
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(target, port=port, username=user, password=pwd,
                       timeout=timeout, allow_agent=False, look_for_keys=False,
                       banner_timeout=15, auth_timeout=timeout)
        client.close()
        return True
    except Exception:
        return False


def ftp_attempt(target, port, user, pwd, timeout=8):
    import ftplib
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=timeout)
        ftp.login(user, pwd)
        ftp.quit()
        return True
    except Exception:
        return False


def http_attempt(target, port, user, pwd, timeout=8):
    try:
        cred = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        resp = net.request(f"http://{target}:{port}/", "GET", timeout=timeout,
                           follow_redirects=False, max_retries=0,
                           headers={"Authorization": f"Basic {cred}"})
        return resp.status in (200, 301, 302)
    except Exception:
        return False


def redis_attempt(target, port, user, pwd, timeout=5):
    """Redis requirepass check via AUTH."""
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            cmd = f"*2\r\n$4\r\nAUTH\r\n${len(pwd)}\r\n{pwd}\r\n".encode()
            s.sendall(cmd)
            reply = s.recv(64)
            return reply.startswith(b'+OK')
    except OSError:
        return False


def snmp_attempt(target, port, community, timeout=3):
    """Community-string test via the snmp module."""
    from vantic.tools.snmp import snmp_get
    ok, _es, val = snmp_get(target, community, "1.3.6.1.2.1.1.1.0", port, timeout)
    return bool(ok)


ATTEMPTERS = {
    'ssh': lambda t, p, u, w: ssh_attempt(t, 22, u, w),
    'ftp': lambda t, p, u, w: ftp_attempt(t, 21, u, w),
    'http': lambda t, p, u, w: http_attempt(t, 80, u, w),
    'redis': lambda t, p, u, w: redis_attempt(t, 6379, u, w),
    'snmp': lambda t, p, u, w: snmp_attempt(t, 161, w, u),
}


def add_arguments(parser):
    parser.add_argument('target', help='Target IP')
    parser.add_argument('--service', choices=sorted(WORDLISTS), default='http',
                        help='Service to audit')
    parser.add_argument('--port', type=int, default=None, help='Override port')
    parser.add_argument('--delay', type=float, default=0.2, help='Delay between attempts')


def run(args):
    import time

    target = args.target
    service = getattr(args, 'service', 'http')
    port = getattr(args, 'port', None) or \
        {'ssh': 22, 'ftp': 21, 'http': 80, 'snmp': 161, 'redis': 6379}[service]
    delay = max(0.0, getattr(args, 'delay', 0.2))

    wordlist = resolve_wordlist(None, WORDLISTS[service])
    pairs = load_lines(wordlist) if wordlist else None
    if not pairs:
        print_error(f"Default-credential list not found: {WORDLISTS[service]} "
                    f"(expected in wordlists/)")
        return

    # Parse "user:pass" or "user pass" lines
    creds = []
    for line in pairs:
        for sep in (':', ' '):
            if sep in line:
                user, pwd = line.split(sep, 1)
                creds.append((user.strip(), pwd.strip()))
                break

    print_header("DEFAULT CREDENTIALS", f"{service} · {target}:{port}")
    kv("Candidates", len(creds))
    kv("Note", "These are vendor defaults as shipped - pairs are valid creds, "
              "lockout is not a factor")
    print()

    attempter = ATTEMPTERS[service]
    stop_event = threading.Event()
    found = []

    def attempt(pair):
        user, pwd = pair
        if stop_event.is_set():
            return None
        if delay:
            time.sleep(delay)
        return pair, attempter(target, port, user, pwd)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(attempt, p) for p in creds]
        for future in as_completed(futures):
            result = future.result()
            if result is None:
                continue
            pair, ok = result
            if ok:
                found.append(pair)
                user, pwd = pair
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} "
                      f"{Colors.BOLD}DEFAULT LOGIN{Colors.RESET}  "
                      f"{Colors.BOLD}{user}{Colors.RESET}{Colors.DIM}:{Colors.RESET}"
                      f"{Colors.BOLD}{pwd or '(empty)'}{Colors.RESET}")
                audit.log("default-cred-valid", service=service, target=target,
                          username=user)
                # stop-on-success per service: default creds found - no need to hammer
                stop_event.set()
                break

    print()
    if found:
        user, pwd = found[0]
        severity = "critical" if service in ('http', 'redis', 'snmp') else "high"
        findings.make(family="default-creds",
                      title=f"Default credentials active ({service})",
                      severity=severity, target=f"{target}:{port}",
                      evidence=f"{user}:{pwd or '(empty)'}",
                      remediation="Rotate the credential; disable default accounts",
                      tool="defaults")
        if store.is_active():
            store.record_service(target, port, service, "default creds",
                                source_tool="defaults")
        print_table(["USERNAME", "PASSWORD"],
                   [((user, pwd or '(empty)'), Colors.BRIGHT_GREEN)])
        print_warning("Rotate immediately - default creds are in every attacker wordlist")
    else:
        print_success(f"No default credentials from {len(creds)} vendor pairs")

    print_summary("DEFAULTS", [
        ("Tried", len(creds) if not found else "stopped on success"),
        ("Valid", len(found)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "defaults", "target": f"{target}:{port}",
                   "service": service,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"found": found}})

    net.close_connections()
    print_success("Default credential audit completed")
