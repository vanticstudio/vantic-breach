"""
SYN Scanner Tool
Half-open TCP scanning via scapy (root required)

SYN|ACK -> open, RST -> closed, ICMP/timeout -> filtered. Loopback is
special-cased to connect-scan (scapy cannot SYN-scan 127.0.0.1).
Degrades gracefully without root or scapy.
"""

import os
import socket
import sys
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, ProgressBar, kv, Colors,
    emit_json, print_box
)

from vantic.core import store

META = {
    "name": "synscan",
    "title": "SYN Scanner",
    "category": "DISCOVERY",
    "description": "Half-open port scan (root + scapy)",
    "risk": "intrusive",
    "examples": [
        "vantic synscan 192.168.1.1 -p 1-1000",
        "sudo vantic synscan 10.0.0.5 --mode fin",
    ],
    "flow": [
        ("arg", "target", "Target IP", None),
        ("opt", "-p", "Ports", "1-1000"),
        ("opt", "--mode", "Scan mode (syn/fin/null/xmas/ack)", "syn"),
    ],
    "guard": {"target": "host"},
}

try:
    from scapy.all import sr1, IP, TCP, ICMP, conf as scapy_conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def parse_ports(spec):
    from vantic.tools.port_scanner import parse_port_spec
    return parse_port_spec(spec)


def syn_probe(target, port, mode='syn'):
    """One half-open probe. Returns state string."""
    flags_map = {
        'syn': 'S', 'fin': 'F', 'null': 0, 'xmas': 'FPU', 'ack': 'A',
    }
    flags = flags_map.get(mode, 'S')
    pkt = IP(dst=target) / TCP(dport=port, flags=flags, sport=40000 + (port % 20000))
    try:
        resp = sr1(pkt, timeout=1.2, verbose=0)
    except Exception:
        return 'filtered'
    finally:
        scapy_conf.verb = 0
    if resp is None:
        return 'filtered'
    if resp.haslayer(TCP):
        rflags = int(resp[TCP].flags)
        if mode == 'syn':
            if rflags & 0x12 == 0x12:  # SYN|ACK
                return 'open'
            if rflags & 0x04:  # RST
                return 'closed'
        elif mode == 'ack':
            if rflags & 0x04:
                return 'unfiltered'
        else:  # fin/null/xmas: open ports stay silent, closed answer RST
            if rflags & 0x04:
                return 'closed'
            return 'open|filtered'
    if resp.haslayer(ICMP):
        return 'filtered'
    return 'filtered'


def add_arguments(parser):
    parser.add_argument('target', help='Target IP')
    parser.add_argument('-p', '--ports', default='1-1000', help='Port spec')
    parser.add_argument('--mode', choices=['syn', 'fin', 'null', 'xmas', 'ack'],
                        default='syn', help='Scan type (default syn)')
    parser.add_argument('--rate', type=int, default=200, help='Packets per second cap')


def run(args):
    target = args.target
    mode = getattr(args, 'mode', 'syn')

    print_header("SYN SCANNER", f"{target} · {mode}")
    print()

    if not HAS_SCAPY:
        print_error("SYN scanning requires scapy:")
        print(f"      {Colors.CYAN}pip3 install scapy{Colors.RESET}")
        print_info("Connect-scan fallback: vantic scan " + target)
        return

    is_root = (os.geteuid() == 0) if hasattr(os, 'geteuid') else False
    is_loopback = target in ('127.0.0.1', 'localhost', '::1')
    if not is_root:
        print_warning("Not running as root - scapy raw sockets usually need sudo")
        print_info(f"Try: sudo vantic synscan {target}")
    if is_loopback and mode == 'syn':
        print_warning("Loopback: scapy can't SYN-scan 127.0.0.1 - using connect-scan")
        mode = 'connect'

    ports = parse_ports(args.ports)
    if ports is None:
        print_error(f"Invalid port spec: {args.ports}")
        return

    kv("Ports", f"{len(ports)} ({args.ports})")
    kv("Mode", mode)
    print()

    if mode == 'connect':
        from vantic.tools.port_scanner import scan_port
        worker = lambda p: scan_port(target, p, 1.5)['status'].lower()
        workers = 100
    else:
        rate = max(10, getattr(args, 'rate', 200))
        workers = min(50, rate // 4)
        send_lock = threading.Lock()
        last_send = [0.0]

        def worker(p):
            with send_lock:
                wait = 1.0 / rate - (time.monotonic() - last_send[0])
                if wait > 0:
                    time.sleep(wait)
                last_send[0] = time.monotonic()
            return syn_probe(target, p, mode)

    results = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {executor.submit(worker, p): p for p in ports}
        progress = ProgressBar(len(ports), f"{mode} scan")
        for future in as_completed(futures):
            port = futures[future]
            state = future.result()
            results.append({'port': port, 'state': state})
            if state in ('open', 'unfiltered', 'open|filtered'):
                if store.is_active():
                    store.record_service(target, port, source_tool='synscan')
                progress.interrupt()
                color = Colors.BRIGHT_GREEN if state == 'open' else Colors.YELLOW
                print(f"  {color}[+]{Colors.RESET} port {Colors.BOLD}{port:<6}{Colors.RESET}"
                      f" {color}{state}{Colors.RESET}")
            progress.update()

    print()
    open_count = len([r for r in results if r['state'] == 'open'])
    closed = len([r for r in results if r['state'] == 'closed'])
    filtered = len([r for r in results if r['state'] == 'filtered'])
    print_summary("RESULTS", [
        ("Scanned", len(results)),
        ("Open", open_count),
        ("Closed", closed),
        ("Filtered", filtered),
    ])
    if open_count:
        rows = [((str(r['port']), r['state']), Colors.BRIGHT_GREEN)
                for r in sorted(results, key=lambda x: x['port']) if r['state'] == 'open']
        print_table(["PORT", "STATE"], rows, widths=[10, 14])
        print_info("Banner-grab the hits: vantic enum " + target + " --ports "
                   + ','.join(str(r['port']) for r in sorted(results, key=lambda x: x['port'])
                   if r['state'] == 'open')[:200])

    if getattr(args, 'json', False):
        emit_json({"tool": "synscan", "target": target, "mode": mode,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": sorted(results, key=lambda x: x['port'])})

    print_success("SYN scan completed")
