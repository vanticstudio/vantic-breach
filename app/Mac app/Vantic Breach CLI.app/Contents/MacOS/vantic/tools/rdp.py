"""
RDP Assessment Tool
Pre-auth X.224 security-layer negotiation + NTLM SSP info disclosure

The negotiation happens BEFORE any credentials: NLA enforced? legacy RDP
Security Layer? which TLS versions? what does the NTLM type2 leak
(hostname/domain/OS build)? Serialized connections (~1 per 3s per host)
so a real user's session is never shadowed.
"""

import socket
import ssl
import struct
import time
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json
)

from vantic.core import findings, store

META = {
    "name": "rdp",
    "title": "RDP Assessment",
    "category": "INTERNAL / AD",
    "description": "X.224/NLA posture + NTLM disclosure",
    "risk": "intrusive",
    "examples": [
        "vantic rdp 192.168.1.10",
        "vantic rdp 10.0.0.5 --tls --cert",
    ],
    "flow": [
        ("arg", "target", "Target IP or host", None),
        ("flag", "--tls", "TLS version check?"),
        ("flag", "--cert", "Certificate health?"),
    ],
    "guard": {"target": "host"},
}

PROTO_NAMES = {0x1: "SSL", 0x2: "HYBRID (NLA/CredSSP)", 0x4: "RDSTLS",
              0x8: "HYBRID_EX (Restricted Admin)"}

FAIL_CODES = {
    1: "SSL_REQUIRED_BY_SERVER",
    2: "SSL_NOT_ALLOWED_BY_SERVER (GPO forces RDP Security Layer)",
    3: "SSL_CERT_NOT_ON_SERVER",
    4: "INCONSISTENT_FLAGS",
    5: "HYBRID_REQUIRED_BY_SERVER (NLA enforced)",
    6: "SSL_WITH_USER_AUTH_REQUIRED",
}


def x224_negotiate(target, port, requested=0x00000003, timeout=6):
    """Send an X.224 CR + RDP Negotiation Request; parse the response.

    Returns dict with: selected protocol, failure code, legacy (plain CC).
    """
    # TPKT (03 00 len) + COTP CR + cookie + negotiation request
    cookie = b"Cookie: mstshash=vantic\r\n"
    neg_req = struct.pack("<BBHI", 0x02, 0x00, 0x08, requested)
    cr_len = 6 + len(cookie) + len(neg_req)
    tpkt = b"\x03\x00" + struct.pack(">H", cr_len + 4)
    cotp_cr = bytes([cr_len, 0xE0, 0, 0, 0, 0])
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(tpkt + cotp_cr + cookie + neg_req)
            data = s.recv(256)
    except OSError as e:
        return {'error': str(e)}

    if len(data) < 4 or data[:2] != b"\x03\x00":
        return {'error': 'not a TPKT/RDP service'}
    # COTP CC: length byte then code 0xD0; then optional negotiation response
    out = {}
    if len(data) >= 11 and data[5] in (0xD0,):
        # search for negotiation response (type 0x02) and failure (0x03)
        idx = data.find(b"\x02\x00\x08\x00", 7)
        if idx >= 0:
            selected = struct.unpack("<I", data[idx + 4:idx + 8])[0]
            out['selected'] = selected
            out['selected_names'] = [name for bit, name in PROTO_NAMES.items()
                                     if selected & bit]
        idx = data.find(b"\x03\x00\x08\x00", 7)
        if idx >= 0:
            failure = struct.unpack("<I", data[idx + 4:idx + 8])[0]
            out['failure'] = failure
            out['failure_name'] = FAIL_CODES.get(failure, f"code {failure}")
        if 'selected' not in out and 'failure' not in out:
            # plain CC, no negotiation response = legacy RDP security layer only
            out['legacy'] = True
    else:
        out['legacy'] = True
    return out


def ntlm_type2(target, port, timeout=8):
    """After HYBRID negotiation: TLS + TSRequest with a bare NTLM Type1.

    The server's Type2 leaks NetBIOS name, DNS name, AD domain, OS build.
    """
    # Type1 message (bare NTLM negotiate)
    type1 = bytearray()
    type1 += b"NTLMSSP\x00"          # signature
    type1 += struct.pack("<I", 1)     # type 1
    type1 += struct.pack("<I", 0xB201)  # flags: request unicode + target info
    type1 += struct.pack("<I", 0)    # supplied domain
    type1 += struct.pack("<I", 0)
    type1 += struct.pack("<I", 0)    # supplied workstation
    type1 += struct.pack("<I", 0)
    # Build TSRequest (CredSSP): version 2 + SPNEGO token carrying the Type1
    inner = struct.pack("<BB", 0x02, 0x02) + b"\x00\x02"
    octets = b"\x04" + _der_len(len(type1)) + bytes(type1)
    ctx = b"\xa1" + _der_len(len(octets)) + octets
    body = inner + ctx
    tsrequest = b"\x30" + _der_len(len(body)) + body

    try:
        ctx_ssl = ssl.create_default_context()
        ctx_ssl.check_hostname = False
        ctx_ssl.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with ctx_ssl.wrap_socket(sock, server_hostname=target) as tls:
                tls.settimeout(timeout)
                tls.sendall(tsrequest)
                resp = tls.recv(4096)
    except (OSError, ssl.SSLError) as e:
        return None, str(e)

    # Find NTLMSSP Type2 in the response
    idx = resp.find(b"NTLMSSP\x00\x02\x00\x00\x00")
    if idx < 0:
        idx = resp.find(b"NTLMSSP")
        if idx < 0:
            return None, "no NTLM type2 in response"
    t2 = resp[idx:]
    return parse_ntlm_type2(t2), None


def _der_len(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(raw)]) + raw


def parse_ntlm_type2(data):
    """Parse AV_PAIRs from an NTLM Type2 challenge."""
    if len(data) < 32 or data[:8] != b"NTLMSSP\x00":
        return {}
    info = {}
    try:
        # Target info length at offset 40 (16-bit) + offset 44 (32-bit)
        if len(data) >= 48:
            ti_len = struct.unpack("<H", data[40:42])[0]
            ti_off = struct.unpack("<I", data[44:48])[0]
            if ti_len and ti_off + ti_len <= len(data):
                pos = ti_off
                names = {2: "netbios domain", 1: "netbios name",
                         3: "dns domain", 4: "dns name", 5: "forest",
                         6: "timestamp", 7: "target SPN", 9: "channel bindings"}
                while pos + 4 <= ti_off + ti_len:
                    av_id, av_len = struct.unpack("<HH", data[pos:pos + 4])
                    if av_id == 0:
                        break
                    val = data[pos + 4:pos + 4 + av_len]
                    if av_id in (1, 2, 3, 4, 5, 7):
                        try:
                            info[names.get(av_id, av_id)] = \
                                val.decode("utf-16-le", errors="replace")
                        except Exception:
                            pass
                    elif av_id == 6 and av_len >= 8:
                        ts = struct.unpack("<Q", val[:8])[0]
                        secs = ts / 10_000_000 - 11644473600
                        try:
                            from datetime import datetime as dt
                            info["server time"] = dt.utcfromtimestamp(secs).strftime(
                                '%Y-%m-%d %H:%M:%S')
                        except Exception:
                            pass
                    pos += 4 + av_len
        # Version block (if present, trailing 8 bytes after target info)
        if len(data) >= 56:
            ver = data[48:56]
            if len(ver) == 8 and ver[0]:
                info["os build"] = (f"{ver[0]}.{ver[1]}.{struct.unpack('<H', ver[2:4])[0]}")
        # OS build -> friendly name
        builds = {"10.0.14393": "Server 2016", "10.0.17763": "Server 2019",
                 "10.0.19041": "Win10 2004", "10.0.20348": "Server 2022",
                 "10.0.26100": "Win11/Server 2025", "6.1.7601": "Win7/2008R2",
                 "6.3.9600": "Win8.1/2012R2", "6.2.9200": "Win8/2012"}
        info["os guess"] = builds.get(info.get("os build", ""), "")
    except (struct.error, IndexError):
        pass
    return info


def tls_versions(target, port, timeout=4):
    """Which TLS versions does 3389 accept?"""
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


def cert_info(target, port, timeout=6):
    """Certificate subject/issuer/expiry/serial for RDP."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as tls:
                der = tls.getpeercert(binary_form=True)
                cert = tls.getpeercert()
                if not cert and der:
                    import tempfile
                    import os as _os
                    pem = ssl.DER_cert_to_PEM_cert(der)
                    with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as tf:
                        tf.write(pem)
                        path = tf.name
                    try:
                        cert = ssl._ssl._test_decode_cert(path)
                    finally:
                        _os.unlink(path)
        if not cert:
            return {}
        subj = {k: v for rdn in cert.get('subject', []) for k, v in rdn}
        iss = {k: v for rdn in cert.get('issuer', []) for k, v in rdn}
        return {'subject': subj.get('commonName', '-'), 'issuer': iss.get('commonName', '-'),
                'expires': cert.get('notAfter', '-'),
                'serial': cert.get('serialNumber', '-')}
    except Exception:
        return {}


def add_arguments(parser):
    parser.add_argument('target', help='Target IP or hostname')
    parser.add_argument('--port', type=int, default=3389, help='RDP port')
    parser.add_argument('--ports', help='Comma-separated additional ports')
    parser.add_argument('--tls', action='store_true', help='TLS version check')
    parser.add_argument('--cert', action='store_true', help='Certificate health')
    parser.add_argument('--ntlm-info', action='store_true', default=True,
                        help='NTLM type2 disclosure (default on)')


def run(args):
    target = args.target
    port = getattr(args, 'port', 3389)
    ports = [port]
    if getattr(args, 'ports', None):
        ports += [int(p) for p in args.ports.split(',') if p.strip().isdigit()]

    print_header("RDP ASSESSMENT", f"{target}")
    kv("Ports", ', '.join(map(str, sorted(set(ports)))))
    print()

    all_posture = []
    for p in sorted(set(ports)):
        if p != ports[0]:
            time.sleep(3)  # serialize: never shadow a live session
        posture = _assess_port(args, target, p)
        all_posture.append({'port': p, **posture})

    # Aggregate findings print
    print()
    print_summary("RDP POSTURE", [
        ("Ports", len(ports)),
        ("NLA", "enforced" if any(pp.get('nla') for pp in all_posture) else "not confirmed"),
        ("Legacy layer", "yes" if any(pp.get('legacy') for pp in all_posture) else "no"),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "rdp", "target": target,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": all_posture})
    print_success("RDP assessment completed")


def _assess_port(args, target, port):
    print_subheader(f"X.224 NEGOTIATION · :{port}")
    neg = x224_negotiate(target, port)
    if neg.get('error'):
        print_error(f":{port} {neg['error']}")
        return {}

    result = {'nla': False, 'legacy': False}
    if neg.get('failure'):
        fname = neg['failure_name']
        print(f"  {Colors.BRIGHT_YELLOW}[!]{Colors.RESET} negotiation failure: {fname}")
        if neg['failure'] == 5:
            result['nla'] = True
            print(f"      {Colors.DIM}→ NLA is ENFORCED (good){Colors.RESET}")
        if neg['failure'] == 2:
            result['legacy'] = True
            findings.make(family="rdp-security-layer",
                          title="RDP forces legacy Security Layer (RC4-era)",
                          severity="high", target=target, port=port,
                          evidence=f"failure code 2 ({fname})",
                          remediation="Set GPO 'Require user authentication for "
                                     "remote connections by using network-level "
                                     "authentication' + SSL",
                          tool="rdp")
    elif neg.get('selected'):
        names = neg['selected_names']
        kv("Selected", ' + '.join(names) or 'none')
        result['nla'] = bool(neg['selected'] & 0x2)
        if neg['selected'] & 0x8:
            kv("HYBRID_EX", "advertised (Restricted Admin capable)")
        if result['nla']:
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} NLA enforced (pre-auth RCE class blocked)")
        else:
            findings.make(family="rdp-nla", title="NLA not required on RDP",
                          severity="high", target=target, port=port,
                          evidence=f"selected protocols: {names}",
                          remediation="Enforce NLA via GPO (CVE-2019-0708-class "
                                      "pre-auth exposure)",
                          tool="rdp")
    elif neg.get('legacy'):
        result['legacy'] = True
        print(f"  {Colors.BRIGHT_RED}[!!] Pre-Vista style plain CC - "
              f"legacy RDP Security Layer only{Colors.RESET}")
        findings.make(family="rdp-legacy", title="Legacy RDP stack (plain CC, no NLA)",
                      severity="critical", target=target, port=port,
                      evidence="X.224 connection confirm without negotiation response",
                      remediation="Upgrade RDP listener; enforce NLA + TLS",
                      tool="rdp")
    if store.is_active():
        store.record_service(target, port, "rdp", ' '.join(neg.get('selected_names', [])),
                            source_tool="rdp")
    print()

    # NTLM disclosure
    ntlm_info, err = ntlm_type2(target, port)
    print_subheader(f"NTLM DISCLOSURE · :{port}")
    if ntlm_info:
        for k, v in ntlm_info.items():
            if v:
                kv(k, str(v)[:48])
        if ntlm_info.get("dns domain") or ntlm_info.get("netbios domain"):
            findings.make(family="rdp-ntlm-info",
                          title="RDP pre-auth discloses domain identity",
                          severity="low", target=target, port=port,
                          evidence=str(ntlm_info)[:300],
                          remediation="Informational - expected NTLM behavior",
                          tool="rdp")
        result['ntlm'] = ntlm_info
    else:
        print(f"  {Colors.DIM}[·] no NTLM type2 ({err}){Colors.RESET}")
    print()

    # OS build context
    os_build = (ntlm_info or {}).get("os build")
    if os_build:
        guess = (ntlm_info or {}).get("os guess") or ''
        kv("OS build", f"{os_build} {guess}")
        if os_build.startswith("6.1") or os_build.startswith("6.0"):
            findings.make(family="rdp-legacy-stack",
                          title="Legacy Windows stack on RDP (6.1-era)",
                          severity="critical", target=target, port=port,
                          evidence=f"NTLM version block reports {os_build}",
                          remediation="Patch/replace the legacy host - "
                                      "CVE-2019-0708-class exposure (verify manually)",
                          tool="rdp")

    # TLS
    if getattr(args, 'tls', False):
        print_subheader(f"TLS VERSIONS · :{port}")
        supported = tls_versions(target, port)
        if supported:
            kv("Accepted", ', '.join(supported))
            legacy = [v for v in supported if v in ('TLSv1.0', 'TLSv1.1')]
            if legacy:
                findings.make(family="rdp-tls-legacy",
                              title=f"Legacy TLS on RDP ({', '.join(legacy)})",
                              severity="medium", target=target, port=port,
                              evidence=', '.join(supported),
                              remediation="Set 'SSL cipher suite' GPO to TLS 1.2+",
                              tool="rdp")
        else:
            print_warning("No TLS versions negotiated (untestable client stack?)")
        print()

    # Cert
    if getattr(args, 'cert', False):
        print_subheader(f"CERTIFICATE · :{port}")
        cert = cert_info(target, port)
        if cert:
            kv("Subject", cert['subject'])
            kv("Issuer", cert['issuer'])
            kv("Expires", cert['expires'])
            kv("Serial", cert['serial'])
            self_signed = cert['subject'] == cert['issuer']
            if self_signed:
                print(f"  {Colors.DIM}[·] self-signed (expected default for RDP){Colors.RESET}")
        else:
            print_warning("No certificate presented (legacy security layer?)")
        print()

    return result
