"""
ARP Sweep Tool
L2 host discovery on the local segment (root + scapy), with an
unprivileged passive fallback that reads the OS ARP cache

Findings: MAC<->IP pairs, OUI vendor guesses, hypervisor detection
(VMware 00:50:56 / 00:0C:29, Hyper-V 00:15:5D).
"""

import os
import re
import subprocess
import sys
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, ProgressBar, kv, Colors,
    emit_json
)

from vantic.core import store

META = {
    "name": "arpsweep",
    "title": "ARP Sweep",
    "category": "DISCOVERY",
    "description": "L2 host discovery + MAC/OUI inventory",
    "risk": "intrusive",
    "examples": [
        "sudo vantic arpsweep --cidr 192.168.1.0/24",
        "vantic arpsweep --passive",
    ],
    "flow": [
        ("opt", "--cidr", "CIDR (blank = active on local subnet)", ""),
        ("flag", "--passive", "Passive mode (ARP cache only, no root)?"),
    ],
    "guard": {"cidr": "cidr"},
}

try:
    from scapy.all import srp, Ether, ARP, conf as scapy_conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

OUI_DB = {
    '00:50:56': 'VMware', '00:0C:29': 'VMware', '00:05:69': 'VMware',
    '00:15:5D': 'Hyper-V', '00:03:FF': 'Hyper-V',
    '08:00:27': 'VirtualBox', '0A:00:27': 'VirtualBox',
    '00:1A:11': 'Google', '3C:52:82': 'Google', 'F4:5C:89': 'Apple',
    'AC:DE:48': 'Apple', '00:1B:63': 'Apple', 'D8:96:95': 'Apple',
    'B8:27:EB': 'Raspberry Pi', 'DC:A6:32': 'Raspberry Pi', 'E4:5F:01': 'Raspberry Pi',
    '00:1A:2B': 'Ayecom', '00:00:5E': 'VRRP (virtual router)', '02:00:00': 'locally administered',
    '00:17:88': 'Signify (Philips Hue)', '00:17:88': 'Philips Hue',
    '00:24:E9': 'Silex (printers)', '00:1E:58': 'D-Link', '00:0D:93': 'Synology',
    '00:11:32': 'Synology', '90:2B:34': 'TP-Link', '50:C7:BF': 'TP-Link',
    '00:0C:29': 'VMware', '00:14:5E': 'Fortinet', '00:09:0F': 'Fortinet',
}


def vendor_for(mac):
    prefix = mac.upper()[:8]
    return OUI_DB.get(prefix, '')


def active_sweep(cidr, iface=None):
    """scapy ARP who-has per host. Returns [(ip, mac)]."""
    results = []
    try:
        if iface:
            scapy_conf.iface = iface
        ans, _unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                         timeout=2, verbose=0, inter=0.02)
        for _sent, received in ans:
            results.append((received[ARP].psrc, received[ARP].hwsrc))
    except Exception as e:
        print_error(f"ARP sweep failed: {e}")
    return results


def passive_cache():
    """Read the OS ARP cache: [(ip, mac)]."""
    out = []
    try:
        if sys.platform == 'darwin':
            text = subprocess.run(['arp', '-a'], capture_output=True,
                                  text=True, timeout=5).stdout
            for line in text.splitlines():
                # example: ? (192.168.1.1) at a:b:c:d:e:f on en0 ...
                m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)', line)
                if m:
                    out.append((m.group(1), m.group(2).lower()))
        else:
            with open('/proc/net/arp') as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != '00:00:00:00:00:00':
                        out.append((parts[0], parts[3].lower()))
    except Exception:
        pass
    return out


def add_arguments(parser):
    parser.add_argument('--cidr', help='CIDR to sweep (e.g. 192.168.1.0/24)')
    parser.add_argument('--iface', help='Interface (default: scapy routing)')
    parser.add_argument('--passive', action='store_true',
                        help='Passive mode: read the OS ARP cache (no root)')
    parser.add_argument('--timeout', type=int, default=2, help='Reply timeout (s)')


def run(args):
    cidr = getattr(args, 'cidr', None)
    passive = getattr(args, 'passive', False)
    iface = getattr(args, 'iface', None)

    print_header("ARP SWEEP", cidr or "passive")
    if passive:
        kv("Mode", "passive (OS ARP cache)")
    else:
        kv("Mode", "active (scapy who-has)")
    if iface:
        kv("Interface", iface)
    if cidr and not passive:
        kv("Range", cidr)
    print()

    if passive or not HAS_SCAPY or not cidr:
        if not passive:
            if not HAS_SCAPY:
                print_warning("scapy not installed - falling back to passive mode")
                print(f"      {Colors.CYAN}pip3 install scapy{Colors.RESET}")
            elif not cidr:
                print_warning("No --cidr given - showing passive ARP cache")
        pairs = passive_cache()
        if not pairs:
            print_warning("ARP cache empty (ping something first, or use active mode)")
            return
        for ip, mac in sorted(pairs):
            vendor = vendor_for(mac)
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {ip:<16} {mac:<20} "
                  f"{Colors.DIM}{vendor}{Colors.RESET}")
            if store.is_active():
                store.record_target(ip, "host")
        print()
        print_summary("ARP CACHE", [("Entries", len(pairs))])
        if getattr(args, 'json', False):
            emit_json({"tool": "arpsweep", "mode": "passive",
                       "started": datetime.now().isoformat(timespec='seconds'),
                       "results": [{"ip": ip, "mac": mac} for ip, mac in pairs]})
        return

    is_root = (os.geteuid() == 0) if hasattr(os, 'geteuid') else False
    if not is_root:
        print_warning("Not root - scapy ARP usually needs sudo; trying anyway")
        print_info(f"Best: sudo vantic arpsweep --cidr {cidr}")

    import ipaddress
    try:
        net_obj = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        print_error(f"Invalid CIDR: {cidr}")
        return
    if net_obj.num_addresses > 4096:
        print_error(f"{cidr} is {net_obj.num_addresses} addresses - keep sweeps <= /20")
        return

    pairs = active_sweep(cidr, iface)
    if not pairs:
        print_warning("No ARP replies - wrong interface? try --iface en0")
        return

    rows = []
    for ip, mac in sorted(pairs, key=lambda x: tuple(map(int, x[0].split('.')))):
        vendor = vendor_for(mac)
        rows.append(((ip, mac, vendor or '-'), None))
        if store.is_active():
            store.record_target(ip, "host")

    print_subheader("ALIVE HOSTS", len(pairs))
    print_table(["IP", "MAC", "VENDOR (OUI)"], rows, widths=[16, 20, 24])

    vendors = {}
    for _ip, mac in pairs:
        v = vendor_for(mac) or 'unknown'
        vendors[v] = vendors.get(v, 0) + 1
    hypervisors = {v: n for v, n in vendors.items()
                  if v in ('VMware', 'Hyper-V', 'VirtualBox')}
    print()
    print_summary("ARP SWEEP", [
        ("Alive", len(pairs)),
        ("Vendors", len(vendors)),
    ] + ([(f"Hypervisor", ', '.join(hypervisors))] if hypervisors else []))

    if getattr(args, 'json', False):
        emit_json({"tool": "arpsweep", "cidr": cidr,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": [{"ip": ip, "mac": mac, "vendor": vendor_for(mac)}
                               for ip, mac in pairs]})

    print_success("ARP sweep completed")
