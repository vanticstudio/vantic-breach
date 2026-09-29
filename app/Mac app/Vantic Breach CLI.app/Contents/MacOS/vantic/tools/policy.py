"""
Password Policy Tool
Read the AD password policy + lockout thresholds (authenticated LDAP)

Outputs the numbers the credential engine needs: how many guesses per
user per window are safe. Read-only.
"""

import ssl
import struct
import socket
from datetime import datetime

try:
    import ldap3
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json
)

from vantic.core import findings

META = {
    "name": "policy",
    "title": "Password Policy",
    "category": "INTERNAL / AD",
    "description": "AD password/lockout policy read",
    "risk": "safe",
    "examples": [
        "vantic policy 10.0.0.10 --user jsmith",
        "vantic policy corp.local --user jsmith --ldaps",
    ],
    "flow": [
        ("arg", "target", "Domain controller", None),
        ("opt", "--user", "Username (a valid one)", ""),
    ],
    "guard": {"target": "host"},
}


def read_policy_ldap3(target, user, password, port, use_ssl):
    """Authenticated read of the default domain policy via ldap3."""
    server = ldap3.Server(target, port=port, use_ssl=use_ssl,
                          get_info=ldap3.ALL, connect_timeout=8)
    conn = ldap3.Connection(server, user=user, password=password,
                           auto_bind=True, receive_timeout=8)
    try:
        base = server.info.other.get('defaultNamingContext', [None])[0]
        if not base:
            return None, "no defaultNamingContext"
        conn.search(base, '(objectClass=domain)',
                    attributes=['minPwdLength', 'pwdHistoryLength',
                               'pwdProperties', 'lockoutThreshold',
                               'lockoutDuration', 'lockOutObservationWindow',
                               'maxPwdAge'])
        if not conn.entries:
            return None, "domain object not found"
        entry = conn.entries[0]
        out = {}
        for attr in ('minPwdLength', 'pwdHistoryLength', 'pwdProperties',
                    'lockoutThreshold', 'lockoutDuration',
                    'lockOutObservationWindow', 'maxPwdAge'):
            try:
                out[attr] = int(entry[attr].value or 0)
            except (TypeError, ValueError, KeyError):
                out[attr] = None
        return out, None
    finally:
        conn.unbind()


def _neg_ticks(value):
    """AD stores negative FILETIME ticks -> seconds."""
    if value in (None, '', 0):
        return None
    try:
        return abs(int(value)) / 10_000_000
    except (TypeError, ValueError):
        return None


def add_arguments(parser):
    parser.add_argument('target', help='Domain controller')
    parser.add_argument('--user', required=True, help='A valid username')
    parser.add_argument('--pass', dest='password', help='Password')
    parser.add_argument('--port', type=int, default=389)
    parser.add_argument('--ldaps', action='store_true', help='Use LDAPS (636)')


def run(args):
    target = args.target
    user = getattr(args, 'user', None)
    password = getattr(args, 'password', None) or ''
    port = getattr(args, 'port', 389)
    use_ssl = getattr(args, 'ldaps', False) or port == 636

    if not password:
        import getpass
        password = getpass.getpass(f"  Password for {user}: ")

    print_header("PASSWORD POLICY", target)
    kv("Bind", f"{user}@{target}:{port}", Colors.BOLD)
    print()

    if not HAS_LDAP3:
        print_error("policy needs ldap3 (authenticated read):")
        print(f"      {Colors.CYAN}pip3 install ldap3{Colors.RESET}")
        print_info("Anonymous-friendly alternatives: vantic smbenum --policy")
        return

    try:
        policy, err = read_policy_ldap3(target, user, password, port, use_ssl)
    except ldap3.core.exceptions.LDAPException as e:
        print_error(f"LDAP bind/search failed: {e}")
        return
    if err or not policy:
        print_error(f"Policy read failed: {err or 'empty'}")
        return

    min_len = policy.get('minPwdLength')
    history = policy.get('pwdHistoryLength')
    complexity = policy.get('pwdProperties') or 0
    threshold = policy.get('lockoutThreshold')
    lockout_s = _neg_ticks(policy.get('lockoutDuration'))
    window_s = _neg_ticks(policy.get('lockOutObservationWindow'))
    max_age_s = _neg_ticks(policy.get('maxPwdAge'))

    print_subheader("DOMAIN PASSWORD POLICY")
    kv("Min length", str(min_len))
    kv("History", str(history))
    kv("Complexity", "required" if complexity & 0x1 else "off")
    if max_age_s:
        kv("Max age", f"{max_age_s / 86400:.0f} days")
    print()

    print_subheader("LOCKOUT")
    if threshold == 0:
        kv("Threshold", "0 (lockout DISABLED)")
    else:
        kv("Threshold", str(threshold))
    kv("Duration", f"{lockout_s / 60:.0f} min" if lockout_s else "-")
    kv("Observation window", f"{window_s / 60:.0f} min" if window_s else "-")
    print()

    # Spray budget guidance
    if threshold and threshold > 0:
        budget = max(1, threshold - 2)
        window_min = window_s / 60 if window_s else 30
        print_info(f"Safe spray budget: {budget} password(s) per user per "
                  f"~{window_min:.0f} min window")
    elif threshold == 0:
        print_warning("Lockout disabled - brute force is not lockout-limited "
                     "(still rate-limit politely)")
        findings.make(family="lockout-disabled",
                      title="Account lockout policy disabled",
                      severity="medium", target=target,
                      evidence="lockoutThreshold=0",
                      remediation="Enable lockout (threshold 5-10, with "
                                 "auto-unlock) - also protects against "
                                 "password spraying",
                      tool="policy")

    if (min_len or 0) < 8:
        findings.make(family="password-policy",
                      title="Weak domain password policy",
                      severity="medium", target=target,
                      evidence=f"minPwdLength={min_len} history={history} "
                               f"complexity={bool(complexity & 1)}",
                      remediation="Raise minimum length to 14+, keep complexity + history",
                      tool="policy")
    if (min_len or 0) >= 8 and complexity & 1:
        print_success("Minimum length + complexity look sane")

    print_summary("POLICY", [
        ("Min length", min_len),
        ("Complexity", "on" if complexity & 1 else "off"),
        ("Lockout", threshold),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "policy", "target": target,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": policy})

    print_success("Policy read completed")
