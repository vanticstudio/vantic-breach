"""
NTLM Disclosure Tool
One HTTP request with NTLM negotiation -> decode the Type2 challenge

Read-only: sends a bare Type1, decodes the server's Type2 AV_PAIRs
(domain, forest, hostname, OS). Never constructs a Type3 (no auth).
"""

import base64
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json
)

from vantic.core import net, findings

META = {
    "name": "ntlm",
    "title": "NTLM Disclosure",
    "category": "INTERNAL / AD",
    "description": "HTTP NTLM type2 info leak",
    "risk": "safe",
    "examples": [
        "vantic ntlm https://intranet.example.com",
    ],
    "flow": [
        ("arg", "url", "Target URL", None),
    ],
    "guard": {"url": "url"},
}


def build_type1():
    """A bare NTLM NEGOTIATE message (no credentials inside)."""
    msg = bytearray(b"NTLMSSP\x00")
    msg += (1).to_bytes(4, 'little')            # type 1
    msg += (0xB201).to_bytes(4, 'little')       # flags
    msg += (0).to_bytes(4, 'little') * 4        # empty domain/workstation buffers
    return base64.b64encode(bytes(msg)).decode()


def parse_type2(b64):
    """Decode the Type2 challenge + its AV_PAIRs."""
    try:
        data = base64.b64decode(b64)
    except (ValueError, TypeError):
        return None
    if len(data) < 32 or data[:8] != b"NTLMSSP\x00" or data[8] != 2:
        return None
    info = {}
    import struct
    try:
        if len(data) >= 48:
            ti_len = struct.unpack("<H", data[40:42])[0]
            ti_off = struct.unpack("<I", data[44:48])[0]
            names = {1: "netbios name", 2: "netbios domain", 3: "dns domain",
                    4: "dns name", 5: "forest", 7: "spn"}
            pos = ti_off
            while pos + 4 <= ti_off + ti_len and pos + 4 <= len(data):
                av_id, av_len = struct.unpack("<HH", data[pos:pos + 4])
                if av_id == 0:
                    break
                val = data[pos + 4:pos + 4 + av_len]
                if av_id in names:
                    info[names[av_id]] = val.decode('utf-16-le', errors='replace')
                elif av_id == 6 and av_len >= 8:
                    ts = struct.unpack("<Q", val[:8])[0] / 10_000_000 - 11644473600
                    from datetime import datetime as dt
                    try:
                        info["server time"] = dt.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M')
                    except (OSError, OverflowError):
                        pass
                pos += 4 + av_len
        if len(data) >= 56:
            ver = data[48:56]
            if ver and ver[0]:
                info["os build"] = f"{ver[0]}.{ver[1]}." \
                                  f"{struct.unpack('<H', ver[2:4])[0]}"
    except (struct.error, IndexError):
        pass
    return info


def add_arguments(parser):
    parser.add_argument('url', help='Target URL (NTLM-protected endpoint)')


def run(args):
    url = args.url
    if '://' not in url:
        url = 'http://' + url

    print_header("NTLM DISCLOSURE", url)
    print()

    # First request: get the 401 with WWW-Authenticate: NTLM
    try:
        resp = net.request(url, "GET", timeout=10, follow_redirects=False,
                           max_retries=0)
        auth_header = resp.header("WWW-Authenticate", "")
    except Exception as e:
        print_error(f"Request failed: {e}")
        return

    if 'NTLM' not in auth_header.upper():
        print_warning("No NTLM in WWW-Authenticate - endpoint may use Kerberos only")
        if auth_header:
            kv("Auth offered", auth_header)
        return

    # Second request: bare Type1 in the Authorization header
    type1 = build_type1()
    try:
        resp2 = net.request(url, "GET", timeout=10, follow_redirects=False,
                            max_retries=0,
                            headers={"Authorization": f"NTLM {type1}"})
        challenge = resp2.header("WWW-Authenticate", "")
    except Exception as e:
        print_error(f"Negotiation request failed: {e}")
        return

    if not challenge.upper().startswith("NTLM "):
        print_warning("Server did not return an NTLM challenge")
        return

    info = parse_type2(challenge[5:])
    if not info:
        print_warning("Could not parse the NTLM type2 challenge")
        return

    print_subheader("TYPE2 CHALLENGE")
    for key in ("netbios name", "netbios domain", "dns domain", "dns name",
                "forest", "spn", "server time", "os build"):
        if info.get(key):
            kv(key, info[key])
    print()

    if info.get("dns domain") or info.get("netbios domain"):
        findings.make(family="ntlm-info",
                      title="Web endpoint discloses AD identity via NTLM",
                      severity="low", target=url,
                      evidence=str(info), remediation="Informational",
                      tool="ntlm")
        print_info("Domain info disclosed pre-authentication (expected NTLM behavior)")

    print_summary("NTLM", [("Fields", len(info))])

    if getattr(args, 'json', False):
        emit_json({"tool": "ntlm", "target": url,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": info})

    net.close_connections()
    print_success("NTLM disclosure completed")
