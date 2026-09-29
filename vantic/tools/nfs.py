"""
NFS Export Tool
ONC RPC portmapper DUMP -> mountd EXPORT enumeration (raw XDR)

Flags anonymous-mountable exports and no_root_squash. Discovery only -
never mounts anything.
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
    "name": "nfs",
    "title": "NFS Export",
    "category": "SERVICES",
    "description": "Portmap + mountd export enumeration",
    "risk": "safe",
    "examples": [
        "vantic nfs 10.0.0.20",
        "vantic nfs 10.0.0.20 --port 111",
    ],
    "flow": [
        ("arg", "target", "Target IP", None),
    ],
    "guard": {"target": "host"},
}

PMAP_PROG = 100000
MOUNT_PROG = 100005


def rpc_call(host, port, prog, vers, proc, args=b'', timeout=6, xid=0x1234):
    """One ONC RPC call over TCP. Returns the reply payload or None."""
    header = struct.pack('>IIIII', xid, 1, prog, vers, proc)
    cred = struct.pack('>II', 0, 0)   # AUTH_NULL
    verf = struct.pack('>II', 0, 0)
    body = header + cred + verf + args
    frag = struct.pack('>I', 0x80000000 | len(body)) + body
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(frag)
            # Read the reply fragment
            hdr = s.recv(4)
            if len(hdr) < 4:
                return None
            flen = struct.unpack('>I', hdr)[0]
            length = flen & 0x7FFFFFFF
            data = b''
            while len(data) < length:
                chunk = s.recv(length - len(data))
                if not chunk:
                    break
                data += chunk
        # Reply: xid, msg_type=1, reply_stat, (accept_stat), payload
        if len(data) < 12:
            return None
        msg_type = struct.unpack('>I', data[4:8])[0]
        if msg_type != 1:
            return None
        reply_stat = struct.unpack('>I', data[8:12])[0]
        if reply_stat != 0:
            return None
        return data[20:]  # skip accept header
    except (OSError, struct.error):
        return None


def xdr_string(s):
    if isinstance(s, str):
        s = s.encode()
    pad = (4 - len(s) % 4) % 4
    return struct.pack('>I', len(s)) + s + b'\x00' * pad


def xdr_read_string(data, offset):
    length = struct.unpack('>I', data[offset:offset + 4])[0]
    s = data[offset + 4:offset + 4 + length].decode(errors='replace')
    offset += 4 + length + ((4 - length % 4) % 4)
    return s, offset


def pmap_dump(host, port, timeout=6):
    """PMAPPROC_DUMP -> [(prog, vers, proto, port)]."""
    payload = rpc_call(host, port, PMAP_PROG, 2, 4, b'', timeout)
    if payload is None:
        return []
    out = []
    offset = 0
    try:
        count = struct.unpack('>I', payload[0:4])[0]
        offset = 4
        for _ in range(min(count, 64)):
            prog, vers, proto, port_ = struct.unpack('>IIII', payload[offset:offset + 16])
            offset += 16
            out.append((prog, vers, proto, port_))
    except (struct.error, IndexError):
        pass
    return out


def mount_export(host, port, timeout=8):
    """MOUNTPROC_EXPORT -> export list strings."""
    payload = rpc_call(host, port, MOUNT_PROG, 3, 5, b'', timeout)
    if payload is None:
        # try v1/v2
        payload = rpc_call(host, port, MOUNT_PROG, 1, 5, b'', timeout)
    if payload is None:
        return None
    out = []
    offset = 0
    try:
        while offset + 4 <= len(payload):
            more = struct.unpack('>I', payload[offset:offset + 4])[0]
            if more == 0:
                break
            offset += 4
            path, offset = xdr_read_string(payload, offset)
            # skip the auth groups list
            if offset + 4 <= len(payload):
                ngroups = struct.unpack('>I', payload[offset:offset + 4])[0]
                offset += 4
                for _ in range(min(ngroups, 64)):
                    offset += 4
            out.append(path)
    except (struct.error, IndexError):
        pass
    return out


def add_arguments(parser):
    parser.add_argument('target', help='Target IP')
    parser.add_argument('--port', type=int, default=111, help='Portmapper port')


def run(args):
    host = args.target
    pm_port = getattr(args, 'port', 111)

    print_header("NFS EXPORT", host)
    print()

    print_subheader("PORTMAPPER DUMP")
    entries = pmap_dump(host, pm_port)
    if not entries:
        print_error(f"No portmapper response on :{pm_port} "
                    f"(TCP/UDP both tried? UDP needs a different client)")
        print_info("Filtered portmapper is itself a posture signal")
        return

    mount_ports = []
    nfs_ports = []
    for prog, vers, proto, port in entries:
        name = {100000: 'portmap', 100005: 'mountd', 100003: 'nfs',
                100021: 'nlockmgr', 100024: 'status'}.get(prog, f'prog {prog}')
        proto_s = 'tcp' if proto == 6 else 'udp'
        print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {name:<10} v{vers:<2} "
              f"{proto_s:<4} :{port}")
        if store.is_active():
            store.record_service(host, port, name, f"v{vers} {proto_s}",
                                source_tool="nfs")
        if prog == MOUNT_PROG and proto == 6:
            mount_ports.append(port)
        if prog == 100003:
            nfs_ports.append(port)
    print()

    # mountd EXPORT
    exports = None
    for mp in mount_ports or [2049]:
        exports = mount_export(host, mp)
        if exports:
            break

    print_subheader("EXPORTS")
    if exports is None:
        print_warning("mountd did not answer the EXPORT call "
                     "(may require NFSv3 auth or is firewalled)")
    elif not exports:
        print_info("No exports configured (empty list)")
    else:
        for path in exports:
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {Colors.BOLD}{path}{Colors.RESET}")
        findings.make(family="nfs-exports",
                      title="NFS exports discovered",
                      severity="medium", target=host,
                      evidence=", ".join(exports[:10]),
                      remediation="Restrict exports by IP; export with root_squash; "
                                 "verify no_root_squash per export on the server",
                      tool="nfs")
        print_info("no_root_squash / insecure flags are set per-export server-side - "
                  "verify on the host (this tool detects, never mounts)")

    print_summary("NFS", [
        ("Portmapper entries", len(entries)),
        ("Exports", len(exports) if isinstance(exports, list) else '?'),
        ("NFS ports", ', '.join(map(str, sorted(set(nfs_ports)))) or '-'),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "nfs", "target": host,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"portmap": [{"prog": p, "vers": v, "proto": pr, "port": po}
                                           for p, v, pr, po in entries],
                               "exports": exports}})

    print_success("NFS export enumeration completed")
