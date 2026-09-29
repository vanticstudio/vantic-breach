"""
DHCP Audit Tool
BOOTP DISCOVER broadcast -> collect OFFERs (scapy optional, root)

Two differing servers answering = rogue-DHCP candidate (critical).
Detection only - the report names the candidate, never starves it.
"""

import os
import struct
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json
)

from vantic.core import findings

META = {
    "name": "dhcp",
    "title": "DHCP Audit",
    "category": "GATEWAY / INFRA",
    "description": "Rogue DHCP detection (OFFER capture)",
    "risk": "intrusive",
    "examples": [
        "sudo vantic dhcp",
        "sudo vantic dhcp --count 3",
    ],
    "flow": [
        ("opt", "--count", "DISCOVER packets to send", "2"),
    ],
    "guard": {},
}

try:
    from scapy.all import Ether, IP, UDP, BOOTP, DHCP, RandMAC, conf as scapy_conf, srp1
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def build_discover():
    """A BOOTP DISCOVER with a random client MAC."""
    mac = RandMAC()
    discover = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex(mac.replace(':', '')) + b'\x00' * 10) /
        DHCP(options=[("message-type", "discover"), "end"])
    )
    return discover, str(mac)


def parse_offer_options(payload):
    """Parse DHCP options tail -> dict (server id, router, etc.)."""
    opts = {}
    i = 240
    while i < len(payload) - 2:
        code = payload[i]
        if code == 0:
            i += 1
            continue
        if code == 255:
            break
        length = payload[i + 1]
        value = payload[i + 2:i + 2 + length]
        if code == 53:
            opts['message_type'] = value[0]
        elif code == 54:
            opts['server_id'] = '.'.join(str(b) for b in value)
        elif code == 3:
            opts['router'] = '.'.join(str(b) for b in value)
        elif code == 1:
            opts['subnet'] = '.'.join(str(b) for b in value)
        elif code == 6:
            opts['dns'] = '.'.join(str(b) for b in value)
        elif code == 51:
            opts['lease'] = struct.unpack('>I', value)[0]
        i += 2 + length
    return opts


def add_arguments(parser):
    parser.add_argument('--count', type=int, default=2,
                       help='DISCOVER packets to send (default 2)')
    parser.add_argument('--timeout', type=int, default=4)


def run(args):
    count = max(1, min(5, getattr(args, 'count', 2)))
    timeout = getattr(args, 'timeout', 4)

    print_header("DHCP AUDIT", "broadcast segment")
    print()

    if not HAS_SCAPY:
        print_error("DHCP discovery requires scapy:")
        print(f"      {Colors.CYAN}pip3 install scapy{Colors.RESET}")
        return

    is_root = (os.geteuid() == 0) if hasattr(os, 'geteuid') else False
    if not is_root:
        print_warning("Not root - DHCP usually needs it; trying anyway")
        print_info(f"Best: sudo vantic dhcp")

    offers = {}
    used_macs = []
    for n in range(count):
        discover, mac = build_discover()
        used_macs.append(mac)
        try:
            resp = srp1(discover, timeout=timeout, verbose=0)
        except Exception as e:
            print_error(f"DISCOVER failed: {e}")
            return
        if resp is None:
            print_info(f"DISCOVER #{n + 1}: no OFFER (no DHCP server on this segment?)")
            continue
        if BOOTP not in resp:
            continue
        bootp = resp[BOOTP]
        opts = parse_offer_options(bytes(resp[UDP].payload) if UDP in resp
                                  else bytes(bootp))
        if opts.get('message_type') != 2:  # 2 = OFFER
            continue
        yiaddr = '.'.join(str(b) for b in struct.pack('>I', bootp.yiaddr))
        server_ip = opts.get('server_id', '?')
        key = (server_ip, yiaddr)
        offers[key] = {
            'server': server_ip, 'offered_ip': yiaddr,
            'router': opts.get('router', '-'),
            'dns': opts.get('dns', '-'),
            'subnet': opts.get('subnet', '-'),
            'lease': opts.get('lease', 0),
        }
        print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} OFFER from "
              f"{Colors.BOLD}{server_ip}{Colors.RESET}: {yiaddr} "
              f"{Colors.DIM}router={opts.get('router', '-')}{Colors.RESET}")

    print()
    servers = {o['server'] for o in offers.values()}
    if not servers:
        print_warning("No DHCP OFFERs captured")
    elif len(servers) == 1:
        o = list(offers.values())[0]
        print_success(f"One DHCP server ({o['server']}) - healthy")
    else:
        print_warning(f"MULTIPLE DHCP servers answered: {', '.join(sorted(servers))}")
        for o in offers.values():
            kv(f"server {o['server']}",
               f"offers {o['offered_ip']} router={o['router']}")
        findings.make(family="rogue-dhcp",
                      title="Multiple DHCP servers on segment (rogue candidate)",
                      severity="critical",
                      evidence="; ".join(f"{o['server']} offered {o['offered_ip']}"
                                         for o in offers.values()),
                      remediation="Identify the rogue server (port security / "
                                  "DHCP snooping); remove it",
                      tool="dhcp")

    print_summary("DHCP", [
        ("DISCOVERs", count),
        ("OFFERs", len(offers)),
        ("Servers", len(servers)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "dhcp",
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": list(offers.values())})

    print_success("DHCP audit completed")
