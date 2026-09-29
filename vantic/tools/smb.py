"""
SMB Probe Tool
SMB dialect + signing assessment (raw) and anonymous share listing
(optional pysmb / smbprotocol)

Pre-auth negotiate packets reveal: SMB1 enabled? signing required?
encryption capable? Then optionally: null/guest sessions and share lists.
"""

import socket
import struct
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json
)

from vantic.core import findings, store

META = {
    "name": "smb",
    "title": "SMB Probe",
    "category": "INTERNAL / AD",
    "description": "Dialects, signing, anonymous shares",
    "risk": "safe",
    "examples": [
        "vantic smb 192.168.1.10",
        "vantic smb 10.0.0.5 --shares",
    ],
    "flow": [
        ("arg", "target", "Target IP", None),
        ("flag", "--shares", "List shares (anonymous/guest)?"),
    ],
    "guard": {"target": "host"},
}

SMB2_DIALECTS = [b"\x02\x02", b"\x02\x10", b"\x02\x00", b"\x02\x24", b"\x03\x00",
                b"\x03\x02", b"\x03\x11"]  # 2.0.2 ... 3.1.1


def smb1_negotiate(timeout=5):
    """SMB1 negotiate - servers with SMB1 disabled RST this."""
    nbss = b"\xff\x53\x4d\x42\x72" + b"\x00" * 14  # SMB1 negotiate
    pkt = struct.pack(">BH", 0x81, len(nbss)) + nbss
    return pkt


def smb2_negotiate(dialects=None, include_smb1=False):
    """SMB2 NEGOTIATE request with the given dialect list."""
    dialects = dialects or SMB2_DIALECTS
    body = struct.pack("<HHQ", 64, 2, 0)  # structure size, dialect count, security mode
    body += b"\x00" * 4  # reserved + capabilities placeholder
    body += b"\x00" * 16  # client GUID
    body += struct.pack("<HH", 0, 0)  # negotiate contexts offset/count
    for d in dialects:
        body += struct.pack("<H", len(d)) + d
    header = b"\xfe\x53\x4d\x42" + struct.pack("<QHH", 0, 0, 65)  # Negotiate
    header += struct.pack("<HHIQ", 1, 0, 0, 0)  # credit charge/resp, status, cmd=Negotiate
    header += b"\x00" * 4 + struct.pack("<HHQ", 64, 0, 0)
    netbios = b"\x00" + header + body
    return struct.pack(">BH", 0x00, len(netbios)) + netbios


def parse_smb2_negotiate_response(data):
    """Extract selected dialect + security mode bits."""
    if len(data) < 4 or data[:4] != b"\xfeSMB":
        return None
    try:
        offset = 64 + 4  # NBSS header(4) + SMB2 header(64)
        structure_size = struct.unpack("<H", data[offset:offset + 2])[0]
        security_mode = data[offset + 2]
        dialect = struct.unpack("<H", data[offset + 3:offset + 5])[0]
        caps = struct.unpack("<I", data[offset + 8:offset + 12])[0] if len(data) > offset + 12 else 0
        return {
            'security_mode': security_mode,
            'dialect_raw': dialect,
            'encryption': bool(caps & 0x40 if len(data) > offset + 12 else False),
        }
    except (struct.error, IndexError):
        return None


def parse_smb1_response(data):
    """SMB1 negotiate response: dialect index + security bits."""
    if len(data) < 40 or data[:4] != b"\xffSMB":
        return None
    try:
        word_count = data[36]
        if word_count >= 11:
            dialect_index = struct.unpack("<H", data[37:39])[0]
            security = data[39]
            return {'smb1': True, 'dialect_index': dialect_index,
                    'security': security}
    except (struct.error, IndexError):
        return None
    return {'smb1': True}


def negotiate_probe(target, port=445, timeout=5):
    """Full negotiate assessment. Returns a dict of posture facts."""
    out = {'tcp': False, 'smb1': None, 'smb2': None, 'error': None}
    # Plain TCP first: distinguishes "no SMB" from "filtered"
    try:
        s = socket.create_connection((target, port), timeout=timeout)
        s.close()
        out['tcp'] = True
    except OSError as e:
        out['error'] = str(e)
        return out

    # SMB1 probe (one connection)
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(smb1_negotiate())
            data = s.recv(1024)
        out['smb1'] = parse_smb1_response(data) if data and data[:4] == b"\xffSMB" else False
    except OSError:
        out['smb1'] = False

    # SMB2 probe (fresh connection - SMB1-disabled hosts RST on SMB1 only)
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(smb2_negotiate())
            data = s.recv(2048)
        out['smb2'] = parse_smb2_negotiate_response(data)
    except OSError as e:
        out['error'] = str(e)
    return out


def list_shares_pysmb(target, port=445, timeout=8):
    """Anonymous + guest share listing via pysmb (optional dep)."""
    try:
        from smb.SMBConn import SMBConn
    except ImportError:
        return None, "pysmb not installed (pip3 install pysmb)"
    shares = []
    for user, pwd in (('', ''), ('guest', ''), ('anonymous', '')):
        try:
            conn = SMBConn(target, target, use_ntlm_v2=True)
            conn.connect(target, port, timeout=timeout)
            # anonymous bind succeeded
            for share in conn.listShares(timeout=5):
                shares.append({'share': share.name, 'comment': share.comments or '',
                               'type': 'anonymous', 'user': user})
            conn.close()
            if shares:
                return shares, None
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
    return shares or [], None


def add_arguments(parser):
    parser.add_argument('target', help='Target IP or hostname')
    parser.add_argument('--port', type=int, default=445, help='SMB port')
    parser.add_argument('--shares', action='store_true',
                        help='List shares via anonymous/guest session (needs pysmb)')


def run(args):
    target = args.target
    port = getattr(args, 'port', 445)

    print_header("SMB PROBE", f"{target}:{port}")
    print()

    result = negotiate_probe(target, port)
    if not result['tcp']:
        print_error(f"TCP {port} unreachable: {result['error']}")
        if getattr(args, 'json', False):
            emit_json({"tool": "smb", "target": target, "port": port,
                       "started": datetime.now().isoformat(timespec='seconds'),
                       "results": {"error": result['error']}})
        return

    if result.get('error') and not result.get('smb2'):
        print_warning(f"Negotiate incomplete: {result['error']}")

    # SMB1
    if result['smb1']:
        print(f"  {Colors.BRIGHT_RED}[!]{Colors.RESET} SMB1 is enabled "
              f"(dialect index {result['smb1'].get('dialect_index')})")
        findings.make(family="smb-v1", title="SMBv1 enabled",
                      severity="high", target=target, port=port,
                      evidence="SMB1 negotiate accepted",
                      remediation="Disable SMB1 (removes WannaCry-class exposure)",
                      tool="smb")
    elif result['smb1'] is False:
        print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} SMB1 disabled")

    # SMB2+
    smb2 = result.get('smb2')
    if smb2:
        dialect = smb2['dialect_raw']
        names = {0x0202: "2.0.2", 0x0210: "2.1", 0x0200: "2.0?", 0x0224: "2.2.2?",
                 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}
        dname = names.get(dialect, hex(dialect))
        kv("Dialect", f"SMB {dname}", Colors.BOLD)
        signing_required = bool(smb2['security_mode'] & 0x02)
        signing_enabled = bool(smb2['security_mode'] & 0x01)
        kv("Signing", "required" if signing_required else
           ("enabled, not required" if signing_enabled else "off"))
        if smb2.get('encryption'):
            kv("Encryption", "capable")
        if not signing_required:
            findings.make(family="smb-signing",
                          title="SMB signing not required",
                          severity="high", target=target, port=port,
                          evidence=f"negotiate security_mode=0x{smb2['security_mode']:02x}",
                          remediation="Enforce 'Digitally sign communications (always)' via GPO",
                          tool="smb")
        else:
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} Signing required (relay-resistant)")
        if store.is_active():
            store.record_service(target, port, "smb", f"SMB {dname}", source_tool="smb")
    elif result.get('smb1'):
        print_info("SMB2 negotiate unanswered (SMB1-only host?)")

    # Shares
    if getattr(args, 'shares', False):
        print()
        print_subheader("SHARES (ANONYMOUS)")
        shares, err = list_shares_pysmb(target, port)
        if err:
            print_warning(err)
        elif shares:
            for sh in shares:
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} "
                      f"{Colors.BOLD}{sh['share']:<16}{Colors.RESET} {sh['comment'][:40]}")
            findings.make(family="smb-anon-shares",
                          title="Anonymous/guest share access",
                          severity="medium", target=target, port=port,
                          evidence=", ".join(s['share'] for s in shares),
                          remediation="Disable guest logons; restrict anonymous share access",
                          tool="smb")
        else:
            print(f"  {Colors.DIM}[·] no anonymous share access{Colors.RESET}")

    print()
    print_summary("SMB POSTURE", [
        ("SMB1", "enabled" if result['smb1'] else "disabled"),
        ("SMB2+", "yes" if result.get('smb2') else "no"),
        ("Signing", "required" if (smb2 and smb2['security_mode'] & 0x02) else "not required"),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "smb", "target": target, "port": port,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": result})

    print_success("SMB probe completed")
