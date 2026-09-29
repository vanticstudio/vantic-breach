"""
MQTT Tool
Raw MQTT CONNECT/CONNACK - anonymous access + version + topic sample

Anonymous CONNECT answered with rc=0x00 = unauthenticated broker.
A short read-only SUBSCRIBE to $SYS/# gives version and load stats.
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
    "name": "mqtt",
    "title": "MQTT Probe",
    "category": "SERVICES",
    "description": "Anonymous access + broker fingerprint",
    "risk": "intrusive",
    "examples": [
        "vantic mqtt 10.0.0.40",
        "vantic mqtt 10.0.0.40 --sample 15",
    ],
    "flow": [
        ("arg", "target", "Target IP", None),
        ("opt", "--port", "Port", "1883"),
    ],
    "guard": {"target": "host"},
}


def mqtt_remaining_length(n):
    out = bytearray()
    while True:
        byte = n % 128
        n //= 128
        if n:
            byte |= 0x80
        out.append(byte)
        if not n:
            break
    return bytes(out)


def mqtt_string(s):
    raw = s.encode()
    return struct.pack('>H', len(raw)) + raw


def build_connect(client_id='vantic-probe'):
    # CONNECT: protocol name/level, flags, keepalive, client id
    vh = mqtt_string('MQTT') + b'\x04'      # MQTT 3.1.1
    flags = 0x02                              # clean session
    vh += bytes([flags]) + struct.pack('>H', 60)
    payload = mqtt_string(client_id)
    body = vh + payload
    return b'\x10' + mqtt_remaining_length(len(body)) + body


def build_subscribe(packet_id, topic, qos=0):
    vh = struct.pack('>H', packet_id)
    payload = mqtt_string(topic) + bytes([qos])
    body = vh + payload
    return b'\x82' + mqtt_remaining_length(len(body)) + body


def parse_connack(data):
    if len(data) >= 4 and data[0] == 0x20:
        return data[3]  # return code
    return None


def read_publish(sock, timeout):
    """Read a few packets, return [(topic, payload)] from PUBLISH frames."""
    out = []
    sock.settimeout(timeout)
    try:
        while len(out) < 3:
            header = sock.recv(1)
            if not header:
                break
            # remaining length (varint)
            rl = 0
            mult = 1
            while True:
                b = sock.recv(1)
                rl += (b[0] & 0x7F) * mult
                mult *= 128
                if not b[0] & 0x80:
                    break
            body = b''
            while len(body) < rl:
                chunk = sock.recv(rl - len(body))
                if not chunk:
                    break
                body += chunk
            if header[0] >> 4 == 3 and len(body) >= 4:  # PUBLISH
                tlen = struct.unpack('>H', body[:2])[0]
                topic = body[2:2 + tlen].decode(errors='replace')
                payload = body[2 + tlen:].decode(errors='replace')
                out.append((topic, payload))
    except (socket.timeout, OSError):
        pass
    return out


def add_arguments(parser):
    parser.add_argument('target', help='Target IP')
    parser.add_argument('--port', type=int, default=1883)
    parser.add_argument('--sample', type=int, default=10,
                       help='Seconds to sample $SYS topics')
    parser.add_argument('--timeout', type=float, default=6)


def run(args):
    host = args.target
    port = getattr(args, 'port', 1883)
    timeout = getattr(args, 'timeout', 6)
    sample = max(0, min(30, getattr(args, 'sample', 10)))

    print_header("MQTT PROBE", f"{host}:{port}")
    print()

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        print_error(f"Connection failed: {e}")
        return
    sock.settimeout(timeout)

    try:
        sock.sendall(build_connect())
        connack = sock.recv(4)
    except OSError as e:
        print_error(f"CONNECT failed: {e}")
        sock.close()
        return

    rc = parse_connack(connack)
    if rc is None:
        print_warning("No CONNACK - not an MQTT broker?")
        sock.close()
        return
    if rc == 0:
        print_success("Anonymous CONNECT accepted (rc=0x00)")
        findings.make(family="mqtt-anon", title="Unauthenticated MQTT broker",
                      severity="high", target=f"{host}:{port}",
                      evidence="CONNECT without credentials answered rc=0",
                      remediation="Require username/password or client certs",
                      tool="mqtt")
        if store.is_active():
            store.record_service(host, port, "mqtt", "anonymous access",
                                 source_tool="mqtt")
    else:
        codes = {1: 'unacceptable protocol', 2: 'identifier rejected',
                 3: 'server unavailable', 4: 'bad user/pass',
                 5: 'not authorized'}
        print_info(f"CONNECT rejected rc={rc} ({codes.get(rc, '?')}) - auth required (good)")
        sock.close()
        print_summary("MQTT", [("Auth", "required")])
        print_success("MQTT probe completed")
        return

    # $SYS sample (read-only snapshot)
    version = None
    topics = []
    if sample:
        print_subheader(f"$SYS SAMPLE ({sample}s, read-only)")
        try:
            sock.sendall(build_subscribe(1, '$SYS/#'))
            sock.recv(4)  # SUBACK
            topics = read_publish(sock, sample)
        except OSError:
            pass
        if topics:
            for topic, payload in topics:
                print(f"  {Colors.CYAN}[t]{Colors.RESET} {topic:<48} {payload[:24]}")
                if topic.endswith('/version'):
                    version = payload.strip()
        else:
            print(f"  {Colors.DIM}[·] no $SYS messages (may be disabled){Colors.RESET}")
        print()

    # Be a good citizen: DISCONNECT
    try:
        sock.sendall(b'\xe0\x00')
    except OSError:
        pass
    sock.close()

    if version:
        kv("Broker version", version, Colors.BOLD)

    print_summary("MQTT", [
        ("Anonymous", "yes"),
        ("Version", version or '?'),
        ("$SYS messages", len(topics)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "mqtt", "target": f"{host}:{port}",
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"anonymous": True, "version": version,
                               "topics": [{"topic": t, "payload": p[:64]}
                                          for t, p in topics]}})

    print_success("MQTT probe completed")
