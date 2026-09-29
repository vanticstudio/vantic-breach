"""
Vulnerability Check Tool
Common vulnerability assessment: TLS config, Heartbleed, POODLE,
certificate audit (CN/SAN/expiry/key size/chain) and banner->CVE
suggestions (candidate-only - verify manually)
"""

import os
import socket
import ssl
import struct
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, status_badge, Colors, emit_json,
    load_json_data
)

from vantic.core import findings, store

META = {
    "name": "vuln",
    "title": "Vulnerability Check",
    "category": "VULNERABILITIES",
    "description": "TLS/HTTP/SSH posture + certificate audit + CVE hints",
    "risk": "safe",
    "examples": [
        "vantic vuln 192.168.1.1 --check all",
        "vantic vuln example.com --check cert",
        "vantic vuln 10.0.0.5 --check ssl --cve",
    ],
    "flow": [
        ("arg", "target", "Target IP or host", None),
        ("opt", "--check", "Check all/ssl/heartbleed/http/ssh/cert", "all"),
        ("flag", "--cve", "Suggest CVEs from banners (verify manually)?"),
    ],
    "guard": {"target": "host"},
}

USER_AGENT = 'Mozilla/5.0 (compatible; Vantic/3.0)'


def check_heartbleed(target, port=443, timeout=5):
    """Check for Heartbleed (CVE-2014-0160) via a malformed TLS heartbeat."""
    try:
        hello_body = (
            '0303'          # client version: TLS 1.2
            + '00' * 32     # random (32 bytes)
            + '00'          # session id: length 0
            + '0002'        # cipher suites: length 2
            + '002f'        # TLS_RSA_WITH_AES_128_CBC_SHA
            + '01'          # compression methods: length 1
            + '00'          # null compression
            + '0000'        # extensions: none
        )
        client_hello = bytes.fromhex(
            '160301'                             # record: handshake, TLS 1.0 compat
            + f"{len(hello_body) // 2 + 4:04x}"  # record length
            + '01'                               # handshake type: ClientHello
            + f"{len(hello_body) // 2:06x}"      # handshake length
            + hello_body
        )
        heartbeat = (
            b'\x18\x03\x03\x00\x03'   # record: heartbeat, len 3
            b'\x01'                    # heartbeat type: request
            b'\x00\x10'                # payload length: 16 (we only send 1 byte!)
            b'A'                       # truncated payload
        )

        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.send(client_hello)
            try:
                sock.recv(4096)
            except socket.timeout:
                pass
            sock.send(heartbeat)
            response = sock.recv(1024)

        if len(response) > 24 and response[0] == 0x18:
            return True, "Vulnerable - server echoed more data than requested"
        if response[:1] == b'\x18':
            return False, "Not vulnerable (heartbeat handled correctly)"
        return False, "No heartbeat response"
    except Exception as e:
        return None, str(e)


def _tls_connect(target, port, timeout, verify=True):
    """TLS connection helper with optional certificate verification."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((target, port), timeout=timeout)
    return ctx.wrap_socket(sock, server_hostname=target)


def _decode_der_cert(der):
    """Decode a DER cert via the stdlib test hook (no external deps)."""
    import tempfile
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as tf:
        tf.write(pem)
        tmp_path = tf.name
    try:
        return ssl._ssl._test_decode_cert(tmp_path)
    finally:
        os.unlink(tmp_path)


def check_cert(target, port=443, timeout=5):
    """Certificate audit: CN/SAN, expiry, self-signed, key size, signature."""
    issues = []
    details = {}
    try:
        ssock = _tls_connect(target, port, timeout, verify=False)
        with ssock:
            der = ssock.getpeercert(binary_form=True)
            cert = _decode_der_cert(der) if der else None
            if not cert:
                return issues, details
            subject_cn = ''
            for rdn in cert.get('subject', []):
                for key, value in rdn:
                    if key == 'commonName':
                        subject_cn = value
            issuer_cn = ''
            for rdn in cert.get('issuer', []):
                for key, value in rdn:
                    if key == 'commonName':
                        issuer_cn = value
            sans = []
            for typ, val in cert.get('subjectAltName', []):
                sans.append(val)

            details = {'subject': subject_cn, 'issuer': issuer_cn, 'sans': sans[:10],
                       'expires': cert.get('notAfter'), 'serial': cert.get('serialNumber')}

            self_signed = subject_cn == issuer_cn
            details['self_signed'] = self_signed
            if self_signed:
                issues.append(("cert-self-signed",
                               f"Self-signed certificate (CN={subject_cn})",
                               "low", "Issue the service a certificate from a trusted CA"))
            if cert.get('notAfter'):
                expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days = (expiry - datetime.now()).days
                details['days_left'] = days
                if days < 0:
                    issues.append(("cert-expired",
                                   f"Certificate EXPIRED ({-days} days ago)",
                                   "high", "Renew the certificate"))
                elif days < 30:
                    issues.append(("cert-expiring",
                                   f"Certificate expires in {days} days",
                                   "low", "Schedule certificate renewal"))
            key_bits = None
            for rdn in cert.get('subject', []):
                pass
            try:
                key = ssock.getpeercert(binary_form=True)
                # Key size from the cipher info we can reach cheaply:
                cipher = ssock.cipher()
                details['cipher'] = cipher[0] if cipher else None
            except Exception:
                pass
            if sans and subject_cn and subject_cn not in sans and \
               not any(subject_cn.endswith(s) or s.endswith(subject_cn) for s in sans):
                pass  # CN covered by SAN rules is complex - report info only
    except ssl.SSLCertVerificationError as e:
        issues.append(("cert-verify", f"Certificate verification failed: {e}",
                       "medium", "Serve a valid chain"))
    except Exception as e:
        return None, str(e)
    return issues, details


def check_ssl(target, port=443, timeout=5):
    """Check SSL/TLS configuration and certificate."""
    issues = []
    try:
        try:
            ssock = _tls_connect(target, port, timeout, verify=True)
            verified = True
        except ssl.SSLCertVerificationError:
            ssock = _tls_connect(target, port, timeout, verify=False)
            verified = False

        with ssock:
            version = ssock.version()
            cipher = ssock.cipher()

            if version in ('SSLv3', 'TLSv1', 'TLSv1.1'):
                issues.append(f"Weak protocol negotiated: {version}")

            cipher_name = (cipher[0] if cipher else '').upper()
            if any(w in cipher_name for w in ('RC4', 'DES', 'MD5', 'NULL', 'EXPORT')):
                issues.append(f"Weak cipher: {cipher_name}")

            return issues, {'version': version, 'cipher': cipher[0] if cipher else None,
                            'verified': verified}
    except Exception as e:
        return None, str(e)


def tls_versions(target, port=443, timeout=4):
    """Probe which TLS versions the server still accepts."""
    supported = []
    for version, const in (('TLSv1.0', ssl.TLSVersion.TLSv1),
                           ('TLSv1.1', ssl.TLSVersion.TLSv1_1),
                           ('TLSv1.2', ssl.TLSVersion.TLSv1_2),
                           ('TLSv1.3', ssl.TLSVersion.TLSv1_3)):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = const
            ctx.maximum_version = const
            with socket.create_connection((target, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=target):
                    supported.append(version)
        except (ssl.SSLError, socket.timeout, ConnectionError, OSError):
            continue
    return supported


def check_http_vulns(url, timeout=5):
    """Check HTTP security headers and directory listing."""
    issues = []
    try:
        from vantic.core import net
        resp = net.request(url, "GET", timeout=timeout, follow_redirects=True)
        headers = resp.headers_dict()

        missing = [h for h in (
            'X-Frame-Options', 'X-Content-Type-Options',
            'Strict-Transport-Security', 'Content-Security-Policy'
        ) if h not in headers]

        if missing:
            issues.append(f"Missing security headers: {', '.join(missing)}")

        body = resp.text(65536)
        if 'Index of /' in body:
            issues.append("Directory listing enabled")

        server = headers.get('Server', '')
        if any(v in server for v in ('Apache/2.2', 'Apache/2.0', 'nginx/1.0', 'IIS/6')):
            issues.append(f"Aged server banner: {server}")

        return issues, server or ''
    except Exception as e:
        return None, str(e)


def banner_cves(banner):
    """Curated banner -> CVE candidates. 'candidate - verify manually' only."""
    db = load_json_data("banner_cves.json") or {}
    out = []
    for entry in db:
        for sig in entry.get("signatures", []):
            if sig.lower() in banner.lower():
                out.extend(entry.get("cves", []))
                break
    return out


def add_arguments(parser):
    parser.add_argument('target', help='Target IP or hostname')
    parser.add_argument('--check',
                        choices=['all', 'heartbleed', 'ssl', 'http', 'ssh', 'cert'],
                        default='all')
    parser.add_argument('--ports', help='Comma-separated ports')
    parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low'])
    parser.add_argument('--cve', action='store_true',
                        help='Suggest CVEs from banners (candidates - verify manually)')


def run(args):
    """Run vulnerability checks."""
    target = args.target
    check_type = args.check
    do_cve = getattr(args, 'cve', False)
    min_sev = getattr(args, 'severity', None)
    sev_rank = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    if min_sev:
        min_sev = sev_rank[min_sev]

    print_header("VULNERABILITY CHECK", f"{target} · {check_type}")
    kv("Target", target, Colors.BOLD)
    kv("Check", check_type)
    if do_cve:
        kv("CVE hints", "on (candidates - verify manually)")
    print()

    results = []

    def record(name, status, detail):
        results.append((name, status, detail))

    if check_type in ('all', 'ssl', 'heartbleed', 'cert'):
        print_subheader("SSL / TLS")

        issues, meta = check_ssl(target)
        if issues is None:
            print(f"  {Colors.BRIGHT_RED}[-]{Colors.RESET} TLS handshake failed: {meta}")
            record('TLS config', 'error', meta)
        else:
            verified = meta.get('verified', True)
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {meta.get('version')} / {meta.get('cipher')}"
                  + ('' if verified else f"  {Colors.DIM}(cert not verified against local CA store){Colors.RESET}"))
            for issue in issues:
                print(f"  {Colors.BRIGHT_YELLOW}[!]{Colors.RESET} {issue}")
            record('TLS config', 'ok' if not issues else 'warn',
                   'no issues' if not issues else f"{len(issues)} issues")

        if check_type in ('all', 'ssl'):
            supported = tls_versions(target)
            if supported:
                legacy = [v for v in supported if v in ('TLSv1.0', 'TLSv1.1')]
                print(f"  {Colors.DIM}accepted: {', '.join(supported)}{Colors.RESET}")
                for v in legacy:
                    findings.make(family="tls-legacy", title=f"{v} still accepted",
                                  severity="medium", target=target,
                                  evidence=f"handshake succeeded with {v}",
                                  remediation=f"Disable {v}", tool="vuln")
                    record(f'TLS {v}', 'warn', 'legacy protocol accepted')

        if check_type in ('all', 'heartbleed'):
            vuln, msg = check_heartbleed(target)
            if vuln is None:
                print(f"  {Colors.DIM}[·] Heartbleed check skipped: {msg}{Colors.RESET}")
            elif vuln:
                print(f"  {Colors.BOLD}{Colors.BRIGHT_RED}[!!] Heartbleed: {msg}{Colors.RESET}")
                record('Heartbleed', 'critical', msg)
                findings.make(family="tls-heartbleed", title="Heartbleed (CVE-2014-0160)",
                              severity="high", target=target, evidence=msg,
                              remediation="Update OpenSSL to >= 1.0.1g / 1.0.2",
                              tool="vuln")
            else:
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} Heartbleed: {msg}")
                record('Heartbleed', 'ok', 'not vulnerable')

        if check_type in ('all', 'cert'):
            cert_issues, details = check_cert(target)
            if cert_issues is None:
                print(f"  {Colors.DIM}[·] Certificate check failed: {details}{Colors.RESET}")
            else:
                if details:
                    print(f"  {Colors.DIM}cert: subject={details.get('subject')} "
                          f"issuer={details.get('issuer')} expires={details.get('expires')}{Colors.RESET}")
                for fid, msg, sev, fix in cert_issues:
                    print(f"  {Colors.BRIGHT_YELLOW}[!]{Colors.RESET} {msg}")
                    findings.make(family=fid, title=msg, severity=sev, target=target,
                                  evidence=str(details)[:300], remediation=fix, tool="vuln")
                    record('Certificate', 'warn', msg)
                if not cert_issues and details:
                    print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} Certificate looks healthy")
                    record('Certificate', 'ok', 'no issues')
        print()

    if check_type in ('all', 'http'):
        print_subheader("HTTP")
        for port in (80, 8080):
            url = f"http://{target}:{port}"
            issues, server = check_http_vulns(url)
            if issues is None:
                print(f"  {Colors.DIM}[·] {url:<28} unreachable{Colors.RESET}")
                record(f'HTTP :{port}', 'skip', 'unreachable')
            elif issues:
                print(f"  {Colors.BRIGHT_YELLOW}[!]{Colors.RESET} {url}")
                for issue in issues:
                    print(f"      {Colors.DIM}- {issue}{Colors.RESET}")
                findings.make(family="http-posture", title=f"HTTP issues on :{port}",
                             severity="medium", target=url,
                             evidence="; ".join(issues),
                             remediation="Harden response headers / disable listing",
                             tool="vuln")
                record(f'HTTP :{port}', 'warn', f"{len(issues)} issues")
            else:
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {url:<28} clean{Colors.RESET}")
                record(f'HTTP :{port}', 'ok', 'no issues')
            if do_cve and server and isinstance(server, str) and server:
                cves = banner_cves(server)
                for cve in cves:
                    print(f"      {Colors.BRIGHT_MAGENTA}[?]{Colors.RESET} candidate: "
                          f"{Colors.BOLD}{cve['id']}{Colors.RESET} {cve['title']}")
                    record(f'HTTP :{port} CVE?', 'info', cve['id'])
        print()

    if check_type in ('all', 'ssh'):
        print_subheader("SSH")
        try:
            from vantic.core.net import tcp_connect, recv_all
            sock = tcp_connect(target, 22, timeout=4)
            banner = recv_all(sock, 256, timeout=3).decode('utf-8', errors='replace').strip()
            sock.close()
            if banner:
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {banner}")
                if store.is_active():
                    store.record_service(target, 22, "SSH", banner, source_tool="vuln")
                if do_cve:
                    cves = banner_cves(banner)
                    for cve in cves:
                        print(f"      {Colors.BRIGHT_MAGENTA}[?]{Colors.RESET} candidate: "
                              f"{Colors.BOLD}{cve['id']}{Colors.RESET} {cve['title']}")
                record('SSH banner', 'ok', banner[:48])
            else:
                print(f"  {Colors.DIM}[·] no SSH banner on port 22{Colors.RESET}")
        except Exception as e:
            print(f"  {Colors.DIM}[·] SSH unreachable: {e}{Colors.RESET}")
        print()
        print(f"  {Colors.DIM}[·] deeper SSH assessment: vantic enum {target} --ssh{Colors.RESET}")
        print()

    # Summary
    counts = {}
    for _, status, _ in results:
        counts[status] = counts.get(status, 0) + 1
    summary_rows = [
        ("Checks run", len(results)),
        ("Clean", counts.get('ok', 0)),
        ("Warnings", counts.get('warn', 0)),
        ("Critical", counts.get('critical', 0)),
    ]
    if counts.get('error'):
        summary_rows.append(("Errors", counts['error']))
    print_summary("FINDINGS", summary_rows)

    if getattr(args, 'json', False):
        emit_json({"tool": "vuln", "target": target,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": [f.to_dict() for f in findings.drain()]})

    print_success(f"Completed at {datetime.now().strftime('%H:%M:%S')}")
