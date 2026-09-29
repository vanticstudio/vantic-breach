"""
Name Sniff Tool
Passive LLMNR + NBT-NS listener - poisoning-exposure evidence WITHOUT
building a poisoner

Joins the multicast/broadcast groups and logs name queries clients leak
(the Responder attack surface). Never sends a response.
"""

import socket
import struct
import threading
import time
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json
)

from vantic.core import findings, store

META = {
    "name": "namesniff",
    "title": "Name Sniffer",
    "category": "INTERNAL / AD",
    "description": "Passive LLMNR/NBT-NS exposure evidence",
    "risk": "intrusive",
    "examples": [
        "vantic namesniff --duration 60",
        "sudo vantic namesniff --llmnr --nbns --wpad-check corp.local",
    ],
    "flow": [
        ("opt", "--duration", "Listen duration (seconds)", "60"),
        ("flag", "--wpad-check", "Also check WPAD DNS resolution?"),
    ],
    "guard": {},
}

LLMNR_GROUP = ("224.0.0.252", 5355)
NBTNS_PORT = 137


def decode_dns_name(data, offset):
    """Read a DNS-style name from LLMNR/NBT-NS payloads."""
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0 or length & 0xC0:
            break
        offset += 1
        labels.append(data[offset:offset + length].decode('utf-8', errors='replace'))
        offset += length
    name = '.'.join(labels)
    # NBT-NS encodes names in first-level compression: decode 32-char form
    if len(name) == 32 and name.isupper() and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' for c in name):
        try:
            real = ''.join(chr((ord(name[i]) - ord('A')) + ((ord(name[i + 1]) - ord('A')) << 4))
                           for i in range(0, 30, 2)).strip()
            suffix = name[30:]
            return f"{real}:{suffix}"
        except Exception:
            pass
    return name


class LlmnrListener(threading.Thread):
    """UDP 5355 multicast listener - logs queries only, never answers."""

    def __init__(self, duration, sink):
        super().__init__(daemon=True)
        self.duration = duration
        self.sink = sink
        self.stop_event = threading.Event()

    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            sock.bind(("", LLMNR_GROUP[1]))
            mreq = struct.pack("4sl", socket.inet_aton(LLMNR_GROUP[0]), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.settimeout(1)
            end = time.time() + self.duration
            while not self.stop_event.is_set() and time.time() < end:
                try:
                    data, addr = sock.recvfrom(2048)
                except socket.timeout:
                    continue
                if len(data) > 12 and data[2] & 0x80 == 0:  # query (QR=0)
                    try:
                        name = decode_dns_name(data, 12)
                        if name:
                            self.sink(("LLMNR", name, addr[0]))
                    except Exception:
                        pass
            sock.close()
        except OSError as e:
            self.sink(("LLMNR-ERROR", str(e), "-"))


class NbnsListener(threading.Thread):
    """UDP 137 listener - logs NetBIOS name queries, never answers."""

    def __init__(self, duration, sink):
        super().__init__(daemon=True)
        self.duration = duration
        self.sink = sink
        self.stop_event = threading.Event()

    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            sock.bind(("", NBTNS_PORT))
            sock.settimeout(1)
            end = time.time() + self.duration
            while not self.stop_event.is_set() and time.time() < end:
                try:
                    data, addr = sock.recvfrom(2048)
                except socket.timeout:
                    continue
                if len(data) > 12 and data[2] & 0x80 == 0:
                    try:
                        name = decode_dns_name(data, 12)
                        if name:
                            self.sink(("NBT-NS", name, addr[0]))
                    except Exception:
                        pass
            sock.close()
        except OSError as e:
            self.sink(("NBTNS-ERROR", str(e), "-"))


def wpad_check(domain):
    """One benign DNS query for wpad.<domain> - answers prove WPAD exposure."""
    try:
        ip = socket.gethostbyname(f"wpad.{domain}")
        return ip
    except socket.gaierror:
        return None


def add_arguments(parser):
    parser.add_argument('--llmnr', action='store_true', help='Listen on LLMNR (5355)')
    parser.add_argument('--nbns', action='store_true', help='Listen on NBT-NS (137)')
    parser.add_argument('--duration', type=int, default=60, help='Seconds to listen')
    parser.add_argument('--wpad-check', metavar='DOMAIN',
                        help='Check whether wpad.<domain> resolves')


def run(args):
    import os
    do_llmnr = getattr(args, 'llmnr', False)
    do_nbns = getattr(args, 'nbns', False)
    duration = max(5, getattr(args, 'duration', 60))
    wpad = getattr(args, 'wpad_check', None)
    if not do_llmnr and not do_nbns and not wpad:
        do_llmnr = do_nbns = True

    is_root = (os.geteuid() == 0) if hasattr(os, 'geteuid') else False
    print_header("NAME SNIFFER", f"{duration}s passive")
    kv("LLMNR", "listening" if do_llmnr else "off")
    kv("NBT-NS", "listening" if do_nbns else "off")
    if wpad:
        kv("WPAD check", wpad)
    print()

    if (do_llmnr or do_nbns) and not is_root:
        print_warning("Not root - binding 137/5355 may fail (macOS may allow it)")
        print_info("Best: sudo vantic namesniff")
        print()

    # WPAD
    if wpad:
        print_subheader("WPAD CHECK")
        ip = wpad_check(wpad)
        if ip:
            print(f"  {Colors.BRIGHT_RED}[!]{Colors.RESET} wpad.{wpad} resolves "
                  f"({ip}) - WPAD proxy auto-discovery is live")
            findings.make(family="wpad", title="WPAD hostname resolvable",
                          severity="medium", target=wpad,
                          evidence=f"wpad.{wpad} -> {ip}",
                          remediation="Disable WPAD or reserve the name in DNS",
                          tool="namesniff")
        else:
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} wpad.{wpad} does not resolve")
        print()

    events = []
    lock = threading.Lock()

    def sink(event):
        with lock:
            events.append(event)
            print(f"  {Colors.BRIGHT_YELLOW}[!]{Colors.RESET} {event[0]:<7} "
                  f"{Colors.BOLD}{event[1]}{Colors.RESET} from {event[2]}")

    threads = []
    if do_llmnr:
        t = LlmnrListener(duration, sink)
        t.start()
        threads.append(t)
    if do_nbns:
        t = NbnsListener(duration, sink)
        t.start()
        threads.append(t)

    if not threads:
        return

    print_info(f"Listening for {duration}s - Ctrl+C to stop early")
    print()
    try:
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=1.0)
    except KeyboardInterrupt:
        print()
        for t in threads:
            t.stop_event.set()
        for t in threads:
            t.join(timeout=2)

    print()
    llmnr_count = len([e for e in events if e[0] == 'LLMNR'])
    nbns_count = len([e for e in events if e[0] == 'NBT-NS'])
    errors = [e for e in events if e[2] == '-']
    if errors:
        for e in errors:
            print_warning(f"{e[0]} listener: {e[1]}")

    print_summary("NAME QUERIES", [
        ("Duration", f"{duration}s"),
        ("LLMNR queries", llmnr_count),
        ("NBT-NS queries", nbns_count),
        ("Clients", len({e[2] for e in events if e[2] != '-'})),
    ])

    if llmnr_count:
        findings.make(family="llmnr", title="LLMNR queries observed on segment",
                      severity="high",
                      evidence=f"{llmnr_count} queries from "
                               f"{len({e[2] for e in events if e[0] == 'LLMNR' and e[2] != '-'})} clients",
                      remediation="Disable LLMNR via GPO "
                                  "('Turn off multicast name resolution')",
                      tool="namesniff")
    if nbns_count:
        findings.make(family="nbns", title="NBT-NS queries observed on segment",
                      severity="medium",
                      evidence=f"{nbns_count} queries from "
                               f"{len({e[2] for e in events if e[0] == 'NBT-NS' and e[2] != '-'})} clients",
                      remediation="Disable NetBIOS over TCP/IP on hosts",
                      tool="namesniff")

    if getattr(args, 'json', False):
        emit_json({"tool": "namesniff", "duration": duration,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": [dict(zip(("proto", "name", "source"), e))
                               for e in events if e[2] != '-']})

    print_success("Name sniffing completed")
