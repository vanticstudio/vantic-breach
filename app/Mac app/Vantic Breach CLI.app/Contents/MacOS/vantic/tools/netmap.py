"""
Network Map Tool
Pure-stdlib segment map: ARP cache, routes, default gateway, OUI notes

One-screen answer to "what does this box see": interfaces, the local
segment inventory from the ARP cache, the routing table, and DNS server
hints. Feeds segmentation findings.
"""

import re
import socket
import subprocess
import sys
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, kv, Colors, emit_json
)

from vantic.core import store

META = {
    "name": "netmap",
    "title": "Network Map",
    "category": "DISCOVERY",
    "description": "Local segment + route inventory (stdlib)",
    "risk": "safe",
    "examples": [
        "vantic netmap",
        "vantic netmap --routes --trace 8.8.8.8",
    ],
    "flow": [
        ("flag", "--routes", "Show the routing table?"),
        ("flag", "--arp-cache", "Show the ARP cache?"),
    ],
    "guard": {},
}

OUI_DB = {
    '00:50:56': 'VMware', '00:0C:29': 'VMware', '00:15:5D': 'Hyper-V',
    '08:00:27': 'VirtualBox', 'F4:5C:89': 'Apple', 'AC:DE:48': 'Apple',
    'B8:27:EB': 'Raspberry Pi', 'DC:A6:32': 'Raspberry Pi',
    '00:0D:93': 'Synology', '00:11:32': 'Synology', '90:2B:34': 'TP-Link',
    '00:1E:58': 'D-Link', '00:14:5E': 'Fortinet', '00:09:0F': 'Fortinet',
}


def default_gateway():
    """Best-effort default gateway discovery."""
    try:
        if sys.platform == 'darwin':
            out = subprocess.run(['route', '-n', 'get', 'default'],
                                 capture_output=True, text=True, timeout=4).stdout
            for line in out.splitlines():
                if 'gateway:' in line:
                    return line.split('gateway:')[1].strip()
        else:
            out = subprocess.run(['ip', 'route', 'show', 'default'],
                                 capture_output=True, text=True, timeout=4).stdout
            m = re.search(r'via (\d+\.\d+\.\d+\.\d+)', out)
            if m:
                return m.group(1)
            out = subprocess.run(['route', '-n'],
                                 capture_output=True, text=True, timeout=4).stdout
            for line in out.splitlines():
                if line.startswith('0.0.0.0'):
                    return line.split()[1]
    except Exception:
        pass
    return None


def local_interfaces():
    """[(name, ipv4)] via a UDP-connect trick + getaddrinfo."""
    out = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        out.append(('primary', s.getsockname()[0]))
        s.close()
    except Exception:
        pass
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith('127.') and ('primary', ip) not in out:
                out.append((host, ip))
    except Exception:
        pass
    return out


def arp_cache():
    """[(ip, mac, iface)] from the OS."""
    out = []
    try:
        if sys.platform == 'darwin':
            text = subprocess.run(['arp', '-a'], capture_output=True,
                                  text=True, timeout=5).stdout
            for line in text.splitlines():
                m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+) on (\S+)', line)
                if m:
                    out.append((m.group(1), m.group(2).lower(), m.group(3)))
        else:
            with open('/proc/net/arp') as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 6:
                        out.append((parts[0], parts[3].lower(), parts[5]))
    except Exception:
        pass
    return out


def dns_servers():
    """Resolver hints from /etc/resolv.conf (macOS hides scoping - still useful)."""
    out = []
    try:
        with open('/etc/resolv.conf') as f:
            for line in f:
                if line.startswith('nameserver'):
                    out.append(line.split()[1])
    except OSError:
        pass
    return out


def traceroute(target, max_hops=15):
    """System traceroute, parsed lightly. Returns [hop strings]."""
    try:
        out = subprocess.run(['traceroute', '-n', '-m', str(max_hops), '-w', '1', target],
                             capture_output=True, text=True, timeout=max_hops * 3).stdout
        hops = []
        for line in out.splitlines():
            if re.match(r'\s*\d+', line):
                hops.append(line.strip())
        return hops
    except Exception:
        return []


def add_arguments(parser):
    parser.add_argument('--arp-cache', action='store_true', help='Show ARP cache')
    parser.add_argument('--routes', action='store_true', help='Show routing table')
    parser.add_argument('--gateway', action='store_true', help='Resolve default gateway')
    parser.add_argument('--trace', metavar='TARGET', help='Traceroute to a target')


def run(args):
    print_header("NETWORK MAP", "local segment view")
    print()

    # Interfaces
    ifaces = local_interfaces()
    print_subheader("LOCAL ADDRESSES")
    if ifaces:
        for name, ip in ifaces:
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {name:<12} {ip}")
    else:
        print(f"  {Colors.DIM}[·] no external addresses found (offline?){Colors.RESET}")
    print()

    # Gateway
    gw = default_gateway()
    if gw:
        print_subheader("DEFAULT GATEWAY")
        print(f"  {Colors.BOLD}{gw}{Colors.RESET}")
        vendor = ''
        for ip, mac, _ in arp_cache():
            if ip == gw:
                vendor = OUI_DB.get(mac.upper()[:8], '')
        if vendor:
            print(f"  {Colors.DIM}OUI hint: {vendor}{Colors.RESET}")
        print_info(f"Gateway audit: vantic gateway {gw}")
        if store.is_active():
            store.record_target(gw, "host", group_name="gateway")
        print()

    # ARP cache
    if getattr(args, 'arp_cache', False) or not any(
            [getattr(args, 'routes', False), getattr(args, 'trace', None)]):
        print_subheader("ARP CACHE")
        cache = arp_cache()
        if cache:
            rows = []
            for ip, mac, iface in sorted(cache):
                vendor = OUI_DB.get(mac.upper()[:8], '-')
                rows.append(((ip, mac, iface, vendor), None))
                if store.is_active():
                    store.record_target(ip, "host")
            print_table(["IP", "MAC", "IFACE", "OUI"], rows,
                        widths=[16, 20, 10, 14])
        else:
            print(f"  {Colors.DIM}[·] empty ARP cache{Colors.RESET}")
        print()

    # Routes
    if getattr(args, 'routes', False):
        print_subheader("ROUTES")
        try:
            if sys.platform == 'darwin':
                out = subprocess.run(['netstat', '-rn'], capture_output=True,
                                     text=True, timeout=5).stdout
            else:
                out = subprocess.run(['ip', 'route'], capture_output=True,
                                     text=True, timeout=5).stdout
            for line in out.splitlines()[:25]:
                if line.strip():
                    print(f"  {Colors.DIM}{line.strip()}{Colors.RESET}")
        except Exception:
            print_warning("Could not read the routing table")
        print()

    # DNS
    dns = dns_servers()
    if dns:
        print_subheader("RESOLVERS")
        for server in dns[:4]:
            print(f"  {Colors.CYAN}{server}{Colors.RESET}")
        print()

    # Traceroute
    if getattr(args, 'trace', None):
        print_subheader("TRACEROUTE", getattr(args, 'trace'))
        hops = traceroute(args.trace)
        for hop in hops:
            print(f"  {Colors.DIM}{hop}{Colors.RESET}")
        if hops:
            print_info(f"{len(hops)} hops - segmentation evidence for the report")
        print()

    print_summary("NETWORK MAP", [
        ("Local addresses", len(ifaces)),
        ("Gateway", gw or '-'),
        ("ARP entries", len(arp_cache())),
        ("Resolvers", len(dns)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "netmap",
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"interfaces": ifaces, "gateway": gw,
                               "arp": arp_cache(), "dns": dns}})

    print_success("Network map completed")
