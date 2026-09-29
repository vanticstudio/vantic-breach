"""
DNS Reverse Sweep Tool
PTR sweep over a CIDR, cross-checked against a live probe

Records pointing at dead hosts = stale DNS (scavenging finding).
"""

import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.reversename
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, ProgressBar, kv, Colors,
    emit_json
)

from vantic.core import findings, store

META = {
    "name": "dnssweep",
    "title": "DNS Reverse Sweep",
    "category": "DISCOVERY",
    "description": "PTR sweep + stale record detection",
    "risk": "safe",
    "examples": [
        "vantic dnssweep --cidr 10.0.1.0/24",
        "vantic dnssweep --cidr 10.0.1.0/24 --live-check",
    ],
    "flow": [
        ("opt", "--cidr", "CIDR to sweep (e.g. 10.0.1.0/24)", ""),
        ("flag", "--live-check", "Verify hosts are actually alive?"),
    ],
    "guard": {"cidr": "cidr"},
}


def ptr_lookup(ip, resolver=None):
    if HAS_DNSPYTHON and resolver:
        try:
            rev = dns.reversename.from_address(ip)
            answers = resolver.resolve(rev, 'PTR')
            return str(answers[0]).rstrip('.')
        except Exception:
            return None
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def tcp_alive(ip, timeout=1.0):
    for port in (80, 443, 22, 445):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            r = s.connect_ex((ip, port))
            s.close()
            if r == 0:
                return True
        except Exception:
            continue
    return False


def add_arguments(parser):
    parser.add_argument('--cidr', required=True, help='CIDR to sweep (e.g. 10.0.1.0/24)')
    parser.add_argument('--dns', help='Custom DNS server')
    parser.add_argument('--live-check', action='store_true',
                        help='TCP-probe hosts to find stale records')
    parser.add_argument('--threads', type=int, default=50)


def run(args):
    import ipaddress
    try:
        net = ipaddress.ip_network(args.cidr, strict=False)
    except ValueError:
        print_error(f"Invalid CIDR: {args.cidr}")
        return
    if net.num_addresses > 1024:
        print_error(f"{args.cidr} is {net.num_addresses} addresses - cap is /22")
        return

    resolver = None
    if getattr(args, 'dns', None):
        if HAS_DNSPYTHON:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [args.dns]
            resolver.lifetime = 3
    elif HAS_DNSPYTHON:
        resolver = dns.resolver.get_default_resolver()
        resolver.lifetime = 3

    hosts = [str(ip) for ip in net.hosts()] or [str(net.network_address)]
    live_check = getattr(args, 'live_check', False)

    print_header("DNS REVERSE SWEEP", args.cidr)
    kv("Hosts", len(hosts))
    kv("Live check", "yes" if live_check else "no")
    kv("Backend", "dnspython" if HAS_DNSPYTHON else "socket")
    print()

    results = []
    with ThreadPoolExecutor(max_workers=max(1, getattr(args, 'threads', 50))) as executor:
        futures = {executor.submit(ptr_lookup, ip, resolver): ip for ip in hosts}
        progress = ProgressBar(len(hosts), "PTR sweep")
        for future in as_completed(futures):
            ip = futures[future]
            name = future.result()
            if name:
                results.append({'ip': ip, 'ptr': name, 'alive': None})
                progress.interrupt()
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {ip:<16} {name}")
                if store.is_active():
                    store.record_target(name, "domain")
            progress.update()

    # Optional live cross-check
    stale = []
    if live_check and results:
        print()
        print_subheader("LIVE CHECK", f"{len(results)} PTR hosts")
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(tcp_alive, r['ip']): r for r in results}
            progress = ProgressBar(len(results), "alive")
            for future in as_completed(futures):
                r = futures[future]
                r['alive'] = future.result()
                if not r['alive']:
                    progress.interrupt()
                    print(f"  {Colors.BRIGHT_YELLOW}[!]{Colors.RESET} "
                          f"{r['ip']:<16} {r['ptr']:<34} not answering 22/80/443/445")
                progress.update()
        stale = [r for r in results if r['alive'] is False]
        if stale:
            print()
            print_warning(f"{len(stale)} records may be stale (hosts not answering)")
            findings.make(family="dns-stale",
                          title="Stale DNS records detected",
                          severity="low", target=args.cidr,
                          evidence=", ".join(f"{r['ptr']} ({r['ip']})" for r in stale[:10]),
                          remediation="Enable DNS scavenging / prune dead records",
                          tool="dnssweep")

    print()
    print_summary("PTR SWEEP", [
        ("Hosts", len(hosts)),
        ("PTR records", len(results)),
        ("Possibly stale", len(stale)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "dnssweep", "cidr": args.cidr,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": sorted(results, key=lambda r: r['ip'])})

    print_success("Reverse sweep completed")
