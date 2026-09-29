"""
Nmap-style Network Mapper
Host discovery and network mapping
"""

import socket
import subprocess
import sys
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, ProgressBar, status_badge,
    kv, Spinner, Colors, emit_json
)

from vantic.core import store

META = {
    "name": "nmap",
    "title": "Network Mapper",
    "category": "DISCOVERY",
    "description": "Host discovery & network mapping",
    "risk": "safe",
    "examples": [
        "vantic nmap 192.168.1.0/24",
        "vantic nmap 192.168.1.0/24 -s ping -p 22,80,443",
    ],
    "flow": [
        ("arg", "target", "Target IP or CIDR (192.168.1.0/24)", None),
        ("opt", "-s", "Scan type ping/arp/host", "ping"),
        ("opt", "-p", "Ports to check on alive hosts (blank = none)", ""),
        ("flag", "--banner", "Grab banners on open ports?"),
        ("flag", "-o", "Export alive hosts to a file?"),
    ],
    "guard": {"target": "cidr"},
}


def ping_scan(ip, timeout=2):
    """Ping scan with macOS/Linux flag compatibility."""
    try:
        if sys.platform == 'darwin':
            cmd = ['ping', '-c', '1', '-t', str(timeout), '-W', str(timeout * 1000), ip]
        else:
            cmd = ['ping', '-c', '1', '-W', str(timeout), ip]
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
        return result.returncode == 0
    except Exception:
        return False


def arp_scan(ip, timeout=2):
    """ARP scan for local network."""
    try:
        result = subprocess.run(
            ['arping', '-c', '1', '-w', str(timeout), ip],
            capture_output=True, timeout=timeout + 2
        )
        return result.returncode == 0
    except Exception:
        return False


def port_check(ip, port, timeout=1, banner=False):
    """Check if a TCP port is open; optionally read the first bytes."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        text = ''
        if result == 0 and banner:
            try:
                sock.settimeout(1.5)
                data = sock.recv(128)
                if data.strip():
                    text = data.decode('utf-8', errors='replace').strip().splitlines()[0]
            except Exception:
                text = ''
        sock.close()
        return result == 0, text
    except Exception:
        return False, ''


def expand_cidr(cidr):
    """Expand CIDR to list of host IPs."""
    network = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in network.hosts()]


def add_arguments(parser):
    parser.add_argument('target', help='Target IP or CIDR range')
    parser.add_argument('-s', '--scan-type', choices=['ping', 'arp', 'host'], default='ping')
    parser.add_argument('-p', '--ports', help='Ports to check on alive hosts')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--banner', action='store_true', help='Grab banners on open ports')


def run(args):
    """Run network mapper."""
    target = args.target
    scan_type = args.scan_type
    grab_banner = getattr(args, 'banner', False)

    print_header("NETWORK MAPPER", target)
    kv("Target", target, Colors.BOLD)
    kv("Scan type", scan_type)

    try:
        if '/' in target:
            ips = expand_cidr(target)
        else:
            ips = [target]
    except ValueError:
        print_error(f"Invalid target: {target}")
        return

    if len(ips) > 1:
        kv("Hosts", len(ips))
    print()

    alive_hosts = []

    def check_host(ip):
        if scan_type == 'ping':
            return ping_scan(ip)
        if scan_type == 'arp':
            return arp_scan(ip)
        return port_check(ip, 80)[0] or port_check(ip, 443)[0] or ping_scan(ip)

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(check_host, ip): ip for ip in ips}
        progress = ProgressBar(len(ips), f"{scan_type} sweep")

        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                alive_hosts.append(ip)
                if store.is_active():
                    store.record_target(ip, "host")
            progress.update()

    alive_hosts.sort(key=lambda ip: tuple(int(o) for o in ip.split('.')) if ip.replace('.', '').isdigit() else (999,))

    print()
    print_subheader("DISCOVERY RESULTS")

    if alive_hosts:
        rows = [((ip, "[ALIVE]"), Colors.BRIGHT_GREEN) for ip in alive_hosts]
        down = len(ips) - len(alive_hosts)
        if down:
            rows.append(((f"{down} host{'s' if down != 1 else ''}", "[DOWN]"), Colors.DIM))
        print_table(["HOST", "STATUS"], rows, widths=[26, 14])
    else:
        print_warning("No alive hosts found")

    # Port scan for alive hosts
    if alive_hosts and args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',') if p.strip()]
        except ValueError:
            print_error(f"Invalid port list: {args.ports}")
            return

        print()
        print_subheader("PORT SWEEP", f"{len(ports)} ports x {len(alive_hosts)} hosts")

        for ip in alive_hosts:
            open_ports = []
            with ThreadPoolExecutor(max_workers=30) as executor:
                futures = {executor.submit(port_check, ip, p, 1, grab_banner): p for p in ports}
                for future in as_completed(futures):
                    ok, banner = future.result()
                    if ok:
                        open_ports.append((futures[future], banner))

            open_ports.sort()
            if open_ports:
                port_str = ', '.join(f"{p}{f' ({b[:20]})' if b else ''}" for p, b in open_ports)
                for p, b in open_ports:
                    if store.is_active():
                        store.record_service(ip, p, None, b or None, source_tool='nmap')
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {Colors.BOLD}{ip:<16}{Colors.RESET} "
                      f"open: {port_str}")
            else:
                print(f"  {Colors.DIM}[·] {ip:<16} no open ports from list{Colors.RESET}")

    # Summary
    print()
    print_summary("NETWORK MAP", [
        ("Hosts scanned", len(ips)),
        ("Alive", len(alive_hosts)),
        ("Down", len(ips) - len(alive_hosts)),
    ])

    # Export
    if getattr(args, 'output', None):
        try:
            with open(args.output, 'w') as f:
                f.write(f"# Vantic Network Scan - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                for ip in alive_hosts:
                    f.write(f"{ip}\n")
            print()
            print_success(f"Alive hosts exported to {Colors.CYAN}{args.output}{Colors.RESET}")
        except OSError as e:
            print_error(f"Export failed: {e}")

    if getattr(args, 'json', False):
        emit_json({"tool": "nmap", "target": target,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"scanned": len(ips), "alive": alive_hosts}})

    print_success("Network mapping completed")
