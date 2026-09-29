"""
JWT Tool
Offline parse + audit; opt-in active checks (alg-none, secret wordlist)

Audits: exp/nbf/iat sanity, missing exp, long-lived, missing aud/iss,
kid metacharacters, jku/x5u external URLs, empty signature.
Active (opt-in): alg=none variants, HMAC secret dictionary.
"""

import base64
import hashlib
import hmac
import json
import re
import time
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json, resolve_wordlist,
    load_lines
)

from vantic.core import findings

META = {
    "name": "jwt",
    "title": "JWT Audit",
    "category": "WEB ANALYSIS",
    "description": "Parse, audit, alg-none + secret checks",
    "risk": "safe",
    "examples": [
        "vantic jwt eyJhbG...",
        "vantic jwt token.txt --secrets",
        "vantic jwt token.txt --none --secrets wordlist.txt",
    ],
    "flow": [
        ("arg", "token", "JWT string or file path", None),
        ("flag", "--none", "Active alg-none variants?"),
        ("flag", "--secrets", "HMAC secret wordlist check?"),
    ],
    "guard": {},
}

NONE_VARIANTS = ["none", "None", "NONE", "nOnE"]


def b64url_decode(data):
    pad = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def parse_token(token):
    parts = token.strip().split('.')
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        signature = parts[2]
        return {'header': header, 'payload': payload, 'signature': signature,
                'raw_parts': parts}
    except (ValueError, TypeError):
        return None


def verify_hs256(signing_input, signature, secret):
    digest = hmac.new(secret.encode() if isinstance(secret, str) else secret,
                     signing_input.encode(), hashlib.sha256).digest()
    return hmac.compare_digest(b64url_encode(digest), signature)


def add_arguments(parser):
    parser.add_argument('token', help='JWT string or a file containing one')
    parser.add_argument('--audit', action='store_true', default=True,
                        help='Offline audit (default on)')
    parser.add_argument('--none', action='store_true',
                        help='Active: try alg=none variants against a URL is not '
                             'possible offline; re-signs token locally to demo')
    parser.add_argument('--secrets', nargs='?', const='passwords.txt', metavar='WORDLIST',
                        help='Active: HMAC secret wordlist (default passwords.txt)')


def run(args):
    token = args.token
    # File or literal?
    import os
    if os.path.isfile(token):
        content = open(token, errors='ignore').read().strip()
        token = content.splitlines()[0].strip() if content else ''
    if not token or token.count('.') != 2:
        print_error("Not a JWT (expect header.payload.signature)")
        return

    parsed = parse_token(token)
    if not parsed:
        print_error("Could not decode header/payload as JSON")
        return

    header, payload, signature = parsed['header'], parsed['payload'], parsed['signature']
    alg = header.get('alg', '?')

    print_header("JWT AUDIT", f"alg={alg}")
    print()

    print_subheader("HEADER")
    for k, v in header.items():
        kv(k, str(v)[:60])
    print()

    print_subheader("PAYLOAD")
    for k, v in payload.items():
        if k in ('exp', 'iat', 'nbf') and isinstance(v, (int, float)):
            when = datetime.fromtimestamp(v).strftime('%Y-%m-%d %H:%M')
            kv(k, f"{v} ({when})")
        else:
            kv(k, str(v)[:60])
    print()

    # ---- audit ----
    issues = []
    now = time.time()
    if alg == 'none' or alg.lower() == 'none':
        issues.append(('alg-none', 'Token signed with alg=none', 'high',
                       'Reject alg=none server-side'))
    if not signature:
        issues.append(('no-sig', 'Empty signature', 'critical',
                       'Reject unsigned tokens'))
    if 'exp' not in payload:
        issues.append(('no-exp', 'No expiry (exp) claim', 'medium',
                       'Require exp on all tokens'))
    else:
        exp = payload['exp']
        if exp < now:
            issues.append(('expired', f"Token expired {int((now - exp) / 86400)}d ago",
                           'low', 'Expected - informational'))
        elif exp - now > 86400 * 30:
            issues.append(('long-lived', f"Token lives {int((exp - now) / 86400)} days",
                           'low', 'Cap token lifetime (<= 24h typical)'))
    for claim in ('aud', 'iss'):
        if claim not in payload:
            issues.append((f'no-{claim}', f"Missing {claim} claim", 'low',
                           f'Include {claim} to constrain token use'))
    kid = header.get('kid')
    if kid and re.search(r"[^A-Za-z0-9_\-/.]", str(kid)):
        issues.append(('kid-meta', f"kid contains metacharacters: {kid!r}",
                      'medium', 'Sanitize kid (injection surface)'))
    for claim in ('jku', 'x5u'):
        if header.get(claim) and str(header[claim]).startswith('http'):
            issues.append((claim, f"{claim} points at a URL ({header[claim]})",
                           'medium', f'Validate {claim} against an allow-list'))

    if issues:
        print_subheader("FINDINGS", len(issues))
        for fid, msg, sev, fix in issues:
            color = getattr(Colors, 'BRIGHT_RED' if sev in ('critical', 'high')
                            else 'BRIGHT_YELLOW' if sev == 'medium' else 'DIM')
            print(f"  {color}[!]{Colors.RESET} {msg}")
            findings.make(family=f"jwt-{fid}", title=msg, severity=sev,
                         evidence=f"alg={alg}",
                         remediation=fix, tool="jwt")
    else:
        print_success("Offline audit clean")
    print()

    # ---- active: HMAC secret wordlist ----
    secrets_arg = getattr(args, 'secrets', None)
    if secrets_arg and alg.startswith('HS'):
        wordlist = resolve_wordlist(secrets_arg, 'passwords.txt')
        secrets = load_lines(wordlist) if wordlist else None
        if not secrets:
            print_warning(f"Secret wordlist not found: {secrets_arg}")
        else:
            print_subheader("SECRET WORDLIST", f"{len(secrets)} candidates")
            signing_input = f"{parsed['raw_parts'][0]}.{parsed['raw_parts'][1]}"
            hit = None
            for i, secret in enumerate(secrets):
                if verify_hs256(signing_input, signature, secret):
                    hit = secret
                    break
            if hit:
                print(f"  {Colors.BOLD}{Colors.BRIGHT_RED}[!!] SECRET FOUND: "
                      f"{hit}{Colors.RESET}")
                findings.make(family="jwt-weak-secret",
                              title="JWT signed with a guessable secret",
                              severity="high",
                              evidence=f"secret={hit!r}",
                              remediation="Use a long random secret (>=256 bits)",
                              tool="jwt")
            else:
                print(f"  {Colors.DIM}[·] no match in {len(secrets)} candidates{Colors.RESET}")
            print()

    # ---- active: alg-none demo ----
    if getattr(args, 'none', False):
        print_subheader("ALG=NONE VARIANT")
        none_token = b64url_encode(json.dumps({**header, "alg": "none"}).encode()) + \
            "." + parsed['raw_parts'][1] + "."
        print_info("Re-signed with alg=none (test it against the endpoint):")
        print(f"  {Colors.CYAN}{none_token[:80]}...{Colors.RESET}")
        print()

    print_summary("JWT", [
        ("Algorithm", alg),
        ("Issues", len(issues)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "jwt",
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"header": header, "payload": payload,
                               "issues": [i[1] for i in issues]}})

    print_success("JWT audit completed")
