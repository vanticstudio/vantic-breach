"""
Redis Tool
Raw RESP probes: PING / INFO / DBSIZE / CONFIG GET / SCAN sample

One of the highest-hit internal findings: unauthenticated Redis with
CONFIG GET exposure. Read-only - never SET.
"""

import socket
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json
)

from vantic.core import findings, store

META = {
    "name": "redis",
    "title": "Redis Probe",
    "category": "SERVICES",
    "description": "Unauth access + version + exposure",
    "risk": "intrusive",
    "examples": [
        "vantic redis 10.0.0.30",
        "vantic redis 10.0.0.30 --port 6380 --sample 20",
    ],
    "flow": [
        ("arg", "target", "Target IP", None),
        ("opt", "--port", "Port", "6379"),
    ],
    "guard": {"target": "host"},
}


def resp_cmd(sock, *parts):
    """Send a RESP array command; read the reply."""
    cmd = f"*{len(parts)}\r\n".encode()
    for p in parts:
        p = str(p).encode()
        cmd += f"${len(p)}\r\n".encode() + p + b"\r\n"
    sock.sendall(cmd)
    return resp_read(sock)


def resp_read(sock):
    """Read one RESP reply."""
    line = _readline(sock)
    if not line:
        return None
    t, body = line[:1], line[1:]
    if t == b'+':
        return body.decode(errors='replace')
    if t == b'-':
        return Exception(body.decode(errors='replace'))
    if t == b':':
        return int(body)
    if t == b'$':
        n = int(body)
        if n == -1:
            return None
        data = b''
        while len(data) < n + 2:
            chunk = sock.recv(n + 2 - len(data))
            if not chunk:
                break
            data += chunk
        return data[:n].decode(errors='replace')
    if t == b'*':
        n = int(body)
        out = []
        for _ in range(n):
            item = resp_read(sock)
            if item is None:
                break
            out.append(item)
        return out
    return line.decode(errors='replace')


def _readline(sock):
    buf = b''
    while not buf.endswith(b'\r\n'):
        chunk = sock.recv(1)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 1 << 20:
            break
    return buf


def add_arguments(parser):
    parser.add_argument('target', help='Target IP')
    parser.add_argument('--port', type=int, default=6379)
    parser.add_argument('--sample', type=int, default=10,
                       help='Sample N keys with SCAN')
    parser.add_argument('--timeout', type=float, default=5)


def run(args):
    host = args.target
    port = getattr(args, 'port', 6379)
    timeout = getattr(args, 'timeout', 5)
    sample = max(0, min(50, getattr(args, 'sample', 10)))

    print_header("REDIS PROBE", f"{host}:{port}")
    print()

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        print_error(f"Connection failed: {e}")
        return
    sock.settimeout(timeout)

    try:
        pong = resp_cmd(sock, 'PING')
    except OSError as e:
        print_error(f"PING failed: {e}")
        sock.close()
        return

    if isinstance(pong, Exception):
        # NOAUTH / auth required
        print_warning(f"Auth required: {pong}")
        findings.make(family="redis-auth", title="Redis requires authentication",
                      severity="info", target=f"{host}:{port}",
                      evidence=str(pong), remediation="Good - keep auth enabled",
                      tool="redis")
        sock.close()
        return

    print_success("No authentication required (unauthenticated Redis)")
    findings.make(family="redis-unauth", title="Unauthenticated Redis access",
                  severity="high", target=f"{host}:{port}",
                  evidence="PING answered without AUTH",
                  remediation="Enable requirepass; bind to loopback/internal VLAN",
                  tool="redis")
    if store.is_active():
        store.record_service(host, port, "redis", "unauth access", source_tool="redis")

    info = resp_cmd(sock, 'INFO', 'server')
    version = None
    if isinstance(info, str):
        for line in info.splitlines():
            if line.startswith('redis_version:'):
                version = line.split(':', 1)[1]
    kv("Version", version or 'unknown', Colors.BOLD)
    if version:
        try:
            major = int(version.split('.')[0])
            if major < 6:
                findings.make(family="redis-old", title="Aged Redis version",
                              severity="low", target=f"{host}:{port}",
                              evidence=f"redis_version={version}",
                              remediation="Upgrade Redis (6+)",
                              tool="redis")
        except ValueError:
            pass

    dbsize = resp_cmd(sock, 'DBSIZE')
    kv("Keys (db0)", str(dbsize) if not isinstance(dbsize, Exception) else '?')

    # CONFIG GET: version + exposure verdict
    cfg = resp_cmd(sock, 'CONFIG', 'GET', 'requirepass')
    if not isinstance(cfg, Exception) and isinstance(cfg, list) and len(cfg) >= 2:
        protected = bool(cfg[1])
        kv("requirepass", "set" if protected else "empty")
    cfg_maxmem = resp_cmd(sock, 'CONFIG', 'GET', 'maxmemory')
    if isinstance(cfg_maxmem, list) and len(cfg_maxmem) >= 2:
        try:
            kv("maxmemory", f"{int(cfg_maxmem[1]) / 1048576:.0f} MB"
               if int(cfg_maxmem[1]) else "unlimited")
        except (ValueError, TypeError):
            pass
    print()

    if sample:
        print_subheader("KEY SAMPLE (SCAN, read-only)")
        keys = resp_cmd(sock, 'SCAN', '0', 'COUNT', str(sample))
        shown = 0
        if isinstance(keys, list) and len(keys) == 2:
            for key in (keys[1] or [])[:sample]:
                if isinstance(key, str):
                    print(f"  {Colors.CYAN}[k]{Colors.RESET} {key[:64]}")
                    shown += 1
        if not shown:
            print(f"  {Colors.DIM}[·] no keys sampled{Colors.RESET}")
        print()

    sock.close()

    print_summary("REDIS", [
        ("Auth", "none"),
        ("Version", version or '?'),
        ("Keys", dbsize if not isinstance(dbsize, Exception) else '?'),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "redis", "target": f"{host}:{port}",
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"version": version, "dbsize": dbsize}})

    print_success("Redis probe completed")
