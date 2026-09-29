"""
Port Scanner Tool
TCP/UDP port scanning for exposure assessment
"""

import csv
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from vantic.utils import (
    print_header, print_subheader, print_error, print_info, print_warning,
    print_success, print_summary, print_table, ProgressBar, status_badge,
    kv, Colors, load_lines, emit_json
)

from vantic.core import store

META = {
    "name": "scan",
    "title": "Port Scanner",
    "category": "DISCOVERY",
    "description": "TCP/UDP port scanning with banner grab",
    "risk": "safe",
    "examples": [
        "vantic scan 192.168.1.1 -p 1-1000",
        "vantic scan 10.0.0.5 --top 100 --banner",
        "vantic scan 192.168.1.1 --udp -p 53,161",
    ],
    "flow": [
        ("arg", "target", "Target IP or host", None),
        ("opt", "-p", "Ports (80 | 1-100 | 22,80,443)", "1-1000"),
        ("flag", "--banner", "Grab banners on open ports?"),
        ("flag", "-e", "Export results to CSV?"),
    ],
    "guard": {"target": "host"},
}

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 443: "HTTPS", 110: "POP3", 143: "IMAP",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 11211: "Memcached", 9200: "Elasticsearch",
    5672: "RabbitMQ", 1935: "RTMP", 389: "LDAP", 636: "LDAPS",
    8000: "HTTP-Alt", 3000: "Node.js", 5000: "Django", 8888: "Jupyter",
    161: "SNMP", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    5938: "TeamViewer", 7070: "AnyDesk", 1883: "MQTT", 8883: "MQTT-TLS",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 7547: "TR-069",
}

TOP_PORTS = [
    80, 443, 22, 21, 25, 3389, 110, 143, 445, 139, 53, 33, 135, 8080, 1723,
    111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 636, 81,
    3306, 5432, 1433, 27017, 6379, 11211, 9200, 8000, 8443, 3000, 5000,
    5984, 161, 179, 1080, 3128, 4444, 5555, 1337, 6667, 1883, 5985, 7547
]


def parse_port_spec(spec):
    """Parse '80', '1-100', '22,80,443', '22,80,100-200' into a sorted port list."""
    ports = set()
    for part in str(spec).split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                start, end = int(start), int(end)
                if start > end:
                    start, end = end, start
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    return None
                ports.update(range(start, end + 1))
            except ValueError:
                return None
        else:
            try:
                p = int(part)
                if not (1 <= p <= 65535):
                    return None
                ports.add(p)
            except ValueError:
                return None
    return sorted(ports) if ports else None


def scan_port(target, port, timeout, is_udp=False, banner=False):
    """Check if a single port is open (optionally grabbing a banner)."""
    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM if is_udp else socket.SOCK_STREAM
        )
        sock.settimeout(timeout)
        start = datetime.now()

        banner_text = ''
        if is_udp:
            sock.settimeout(timeout)
            sock.connect((target, port))
            sock.send(b'\x00')
            try:
                data, _ = sock.recvfrom(1024)
                status = "OPEN"
                banner_text = data[:128].decode('utf-8', errors='replace').strip()
            except ConnectionRefusedError:
                status = "CLOSED"
            except socket.timeout:
                status = "FILTERED"
        else:
            result = sock.connect_ex((target, port))
            status = "OPEN" if result == 0 else "CLOSED"
            if status == "OPEN" and banner:
                try:
                    sock.settimeout(1.5)
                    data = sock.recv(128)
                    banner_text = data.decode('utf-8', errors='replace').strip()
                except (socket.timeout, OSError):
                    banner_text = ''

        response_time = (datetime.now() - start).total_seconds() * 1000
        sock.close()

        return {
            'port': port,
            'status': status,
            'service': COMMON_PORTS.get(port, 'unknown'),
            'response_time': round(response_time, 1),
            'banner': banner_text,
        }
    except Exception:
        return {
            'port': port,
            'status': 'FILTERED',
            'service': COMMON_PORTS.get(port, 'unknown'),
            'response_time': 0.0,
            'banner': '',
        }


def add_arguments(parser):
    parser.add_argument('target', help='Target IP or hostname')
    parser.add_argument('-p', '--ports', default='1-1000',
                        help='Ports: 80 | 1-100 | 22,80,443 | mix')
    parser.add_argument('-t', '--timeout', type=int, default=2, help='Connection timeout (s)')
    parser.add_argument('-e', '--export', action='store_true', help='Export results to CSV')
    parser.add_argument('-c', '--common', action='store_true', help='Common ports (1-1024)')
    parser.add_argument('-w', '--web', action='store_true', help='Web ports preset')
    parser.add_argument('-d', '--database', action='store_true', help='Database ports preset')
    parser.add_argument('--udp', action='store_true', help='UDP scan mode')
    parser.add_argument('--banner', action='store_true', help='Grab banners on open ports')
    parser.add_argument('--top', type=int, metavar='N', help='Top N most common ports')


def run(args):
    """Run port scanner."""
    target = args.target
    timeout = args.timeout
    is_udp = getattr(args, 'udp', False)
    grab_banner = getattr(args, 'banner', False)

    # Resolve port list
    if getattr(args, 'web', False):
        ports = [80, 443, 8080, 8443, 3000, 5000, 8000]
        preset = 'web'
    elif getattr(args, 'database', False):
        ports = [3306, 5432, 1433, 27017, 6379, 11211, 9200, 5672]
        preset = 'database'
    elif getattr(args, 'common', False):
        ports = list(range(1, 1025))
        preset = 'common (1-1024)'
    elif getattr(args, 'top', None):
        ports = TOP_PORTS[:args.top]
        preset = f'top {args.top}'
    else:
        ports = parse_port_spec(args.ports)
        if ports is None:
            print_error(f"Invalid port spec: {args.ports} "
                        f"(examples: 80, 1-1000, 22,80,443)")
            return
        preset = args.ports

    protocol = "UDP" if is_udp else "TCP"
    total = len(ports)

    print_header("PORT SCANNER", f"{protocol} · {target}")
    kv("Target", target, Colors.BOLD)
    kv("Protocol", protocol)
    kv("Ports", f"{total} ({preset})")
    kv("Timeout", f"{timeout}s")
    if grab_banner:
        kv("Banner grab", "on")
    print()

    results = []
    open_ports = []

    def paint(r):
        if r['status'] == 'OPEN':
            return Colors.BRIGHT_GREEN
        if r['status'] == 'CLOSED':
            return Colors.DIM
        return Colors.YELLOW

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, target, port, timeout, is_udp, grab_banner): port
                   for port in ports}
        progress = ProgressBar(total, f"{protocol} scan")

        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if result['status'] == 'OPEN':
                open_ports.append(result)
                if store.is_active():
                    store.record_service(target, result['port'],
                                        result['service'], result['banner'] or None,
                                        protocol=protocol.lower(), source_tool='scan')
                progress.interrupt()
                svc = result['service']
                svc_str = f" {Colors.DIM}({svc}){Colors.RESET}" if svc != 'unknown' else ''
                banner_str = ''
                if result['banner']:
                    b = result['banner'].splitlines()[0][:40] if result['banner'] else ''
                    banner_str = f"  {Colors.DIM}{b}{Colors.RESET}"
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} "
                      f"port {Colors.BOLD}{result['port']:<6}{Colors.RESET}"
                      f"{svc_str:<24} "
                      f"{result['response_time']:>7.1f} ms{banner_str}")
            progress.update()

    print()
    print_subheader("SCAN SUMMARY")

    closed = len([r for r in results if r['status'] == 'CLOSED'])
    filtered = len([r for r in results if r['status'] == 'FILTERED'])
    print_summary("RESULTS", [
        ("Scanned", f"{len(results)} ports"),
        ("Open", len(open_ports)),
        ("Closed", closed),
        ("Filtered", filtered),
    ])

    if open_ports:
        rows = []
        for p in sorted(open_ports, key=lambda x: x['port']):
            rows.append((
                (str(p['port']), p['service'], p['status'], f"{p['response_time']:.1f} ms",
                 (p['banner'].splitlines()[0][:28] if p['banner'] else '')),
                paint(p)
            ))
        print_table(
            ["PORT", "SERVICE", "STATUS", "RESPONSE", "BANNER"],
            rows, widths=[10, 18, 12, 12, 30]
        )
    else:
        print()
        print_warning(f"No open {protocol} ports found on {target}")

    # Export
    if getattr(args, 'export', False):
        filename = f"vantic_scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['port', 'status', 'service', 'response_time', 'banner'])
                writer.writeheader()
                writer.writerows(results)
            print()
            print_success(f"Results exported to {Colors.CYAN}{filename}{Colors.RESET}")
        except OSError as e:
            print_error(f"Export failed: {e}")

    if getattr(args, 'json', False):
        emit_json({"tool": "scan", "target": target, "started": timestamp_str(),
                   "results": sorted(results, key=lambda r: r['port'])})


def timestamp_str():
    return datetime.now().isoformat(timespec='seconds')
