"""
Packet Sniffer Tool
Network traffic capture via tcpdump (no root? falls back to guidance)
"""

import os
import shlex
import signal
import subprocess
import sys
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors
)

META = {
    "name": "sniff",
    "title": "Packet Sniffer",
    "category": "ANALYSIS & REPORTING",
    "description": "Live traffic capture with protocol presets",
    "risk": "intrusive",
    "examples": [
        "vantic sniff -c 10",
        "vantic sniff en0 --preset http",
        "vantic sniff --preset dns --capture out.pcap",
    ],
    "flow": [
        ("opt", "interface", "Interface (blank = auto-detect)", ""),
        ("opt", "-c", "Packet count (blank = endless)", ""),
        ("opt", "--preset", "Preset filter (http/dns/smb/creds/blank = none)", ""),
    ],
    "guard": {},
}

# BPF presets (roadmap Wave-2 "sniff presets")
PRESETS = {
    'http': 'tcp port 80 or tcp port 8080 or tcp port 443 or tcp port 8443',
    'https': 'tcp port 443 or tcp port 8443',
    'dns': 'port 53',
    'smb': 'port 139 or port 445',
    'creds': ('tcp port 21 or tcp port 22 or tcp port 23 or tcp port 80 or '
              'tcp port 443 or tcp port 3389 or port 53'),
    'mail': 'tcp port 25 or tcp port 110 or tcp port 143 or tcp port 587',
}


def detect_interface():
    """Best-effort default interface detection (macOS: en0, Linux: route)."""
    try:
        if sys.platform == 'darwin':
            result = subprocess.run(
                ['route', '-n', 'get', 'default'],
                capture_output=True, text=True, timeout=3
            )
            for line in result.stdout.splitlines():
                if 'interface:' in line:
                    return line.split('interface:')[1].strip()
        else:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=3
            )
            for part in result.stdout.split():
                if part == 'dev':
                    continue
            # fallback: first non-loopback iface
            result = subprocess.run(['ls', '/sys/class/net'], capture_output=True, text=True, timeout=3)
            ifaces = [i for i in result.stdout.split() if i != 'lo']
            if ifaces:
                return ifaces[0]
    except Exception:
        pass
    return 'en0' if sys.platform == 'darwin' else 'eth0'


def run_tcpdump(interface, count, bpf, capture):
    """Stream tcpdump output, styled lightly."""
    cmd = ['tcpdump', '-i', interface, '-nn', '-l']
    if count:
        cmd += ['-c', str(count)]
    if capture:
        cmd += ['-w', capture]
    if bpf:
        cmd += shlex.split(bpf)

    print(f"  {Colors.DIM}> {' '.join(cmd)}{Colors.RESET}")
    print()

    packets = 0
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def handle_sigint(*_):
        try:
            proc.send_signal(signal.SIGINT)
        except Exception:
            pass

    try:
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            packets += 1
            print(f"  {Colors.DIM}{line}{Colors.RESET}")
    except KeyboardInterrupt:
        proc.terminate()
    finally:
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        stderr = proc.stderr.read() if proc.stderr else ''
        returncode = proc.returncode

    if returncode not in (0, None) and not packets:
        return False, stderr.strip() or f"tcpdump exited with code {returncode}"
    return True, packets


def add_arguments(parser):
    parser.add_argument('interface', nargs='?', default=None,
                        help='Interface (default: auto-detect)')
    parser.add_argument('-c', '--count', type=int, default=None, help='Packet count')
    parser.add_argument('-f', '--filter', help='BPF filter')
    parser.add_argument('--preset', choices=sorted(PRESETS.keys()),
                        help='Protocol preset filter (http/dns/smb/creds/mail)')
    parser.add_argument('--capture', help='Save capture to PCAP file')
    parser.add_argument('--http', action='store_true', help='HTTP traffic only')
    parser.add_argument('--dns', action='store_true', help='DNS traffic only')
    parser.add_argument('--decrypt', action='store_true', help='Decrypt HTTPS (not supported)')


def run(args):
    """Run packet sniffer."""
    interface = args.interface or detect_interface()

    if getattr(args, 'decrypt', False):
        print_warning("--decrypt is not supported; TLS interception needs a proxy (e.g. mitmproxy)")
        return

    # Map helper flags + presets to BPF filters
    bpf = args.filter
    if getattr(args, 'preset', None):
        bpf = PRESETS[args.preset]
    if getattr(args, 'http', False):
        bpf = 'tcp port 80 or tcp port 8080'
    if getattr(args, 'dns', False):
        bpf = 'port 53'

    print_header("PACKET SNIFFER", interface)
    kv("Interface", interface, Colors.BOLD)
    if args.count:
        kv("Packet count", args.count)
    if bpf:
        kv("Filter", bpf)
    if args.capture:
        kv("Capture file", args.capture)
    kv("Started", datetime.now().strftime('%H:%M:%S'))
    print()

    # Availability pre-flight
    tcpdump_path = None
    try:
        result = subprocess.run(['which', 'tcpdump'], capture_output=True, text=True)
        if result.returncode == 0:
            tcpdump_path = result.stdout.strip()
    except Exception:
        pass

    if not tcpdump_path:
        print_error("tcpdump not found - install it with:")
        print(f"      {Colors.CYAN}brew install tcpdump{Colors.RESET}")
        print()
        print_info("Live capture unavailable; showing sample output format")
        _demo_output()
        return

    print_info("Starting capture... (Ctrl+C to stop)")
    print()

    ok, result = run_tcpdump(interface, args.count, bpf, args.capture)

    if not ok:
        err = str(result)
        print()
        if 'permission denied' in err.lower() or 'bpf' in err.lower() or 'not authorized' in err.lower():
            print_error("Capture requires root privileges:")
            print(f"      {Colors.CYAN}sudo vantic sniff {interface}{Colors.RESET}")
        else:
            print_error(f"Capture failed: {err}")
        print()
        print_info("Showing sample output format instead")
        _demo_output()
        return

    if isinstance(result, int) and result > 0:
        print_summary("CAPTURE", [("Packets", result)])

    if args.capture and os.path.exists(args.capture):
        print_success(f"Capture written to {Colors.CYAN}{args.capture}{Colors.RESET}")

    print_success("Packet capture finished")


def _demo_output():
    """Sample format shown when live capture is unavailable."""
    print()
    print_subheader("SAMPLE OUTPUT FORMAT")
    samples = [
        ("14:23:01.123456", "IP 192.168.1.100.45678 > 93.184.216.34.443: Flags [S]"),
        ("14:23:01.130221", "IP 93.184.216.34.443 > 192.168.1.100.45678: Flags [S.]"),
        ("14:23:01.130290", "IP 192.168.1.100.45678 > 93.184.216.34.443: Flags [.]"),
        ("14:23:02.455110", "IP 192.168.1.100.53421 > 8.8.8.8.53: 512+ A? example.com"),
        ("14:23:02.468902", "IP 8.8.8.8.53 > 192.168.1.100.53421: 512 1/0/0 A 93.184.216.34"),
    ]
    for ts, line in samples:
        print(f"  {Colors.DIM}{ts}{Colors.RESET} {line}")
    print()
    print_info(f"For live capture: {Colors.CYAN}sudo vantic sniff{Colors.RESET}")
