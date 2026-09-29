"""
OS Fingerprint Tool
Best-effort OS guessing from TTL / TCP window / DF / MSS / options

Labels itself as a guess (nmap -O is authoritative). TTL 64 = Linux-era,
128 = Windows, 255 = Cisco/BSD; window + MSS refine the call.
"""

import os
import socket
import struct
import subprocess
import sys
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json
)

try:
    from scapy.all import sr1, IP, TCP, conf as scapy_conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

META = {
    "name": "osfp",
    "title": "OS Fingerprint",
    "category": "DISCOVERY",
    "description": "Best-effort OS guess from TCP stack",
    "risk": "intrusive",
    "examples": [
        "vantic osfp 192.168.1.1",
        "sudo vantic osfp 10.0.0.5 --port 443",
    ],
    "flow": [
        ("arg", "target", "Target IP", None),
        ("opt", "--port", "Open TCP port to probe", "80"),
    ],
    "guard": {"target": "host"},
}

TTL_FAMILIES = [
    (32, 'Windows (old) / low-TTL path', 5),
    (60, 'Linux / Android / macOS era', 64),
    (120, 'Windows', 128),
    (250, 'Cisco / BSD / Solaris', 255),
]

WINDOW_HINTS = {
    5840: 'Linux (older)',
    29200: 'Linux 4.x+',
    65535: 'Windows XP era / BSD',
    8192: 'Windows Vista+',
    64240: 'Windows 10 / Server (scaled)',
    16384: 'macOS / BSD',
}


def ttl_guess(ttl):
    for ceiling, label, base in TTL_FAMILIES:
        if ttl <= ceiling:
            hops = max(0, base - ttl)
            return label, hops
    return 'unknown', 0


def os_guess(ttl, window, mss, options, df):
    """Combine stack signals into a labelled guess."""
    family, hops = ttl_guess(ttl)
    wint = WINDOW_HINTS.get(window, '')
    guesses = []
    if ttl >= 61 and ttl <= 64 and window in (5840, 29200, 5720):
        guesses.append(('Linux', 'high'))
    elif ttl >= 121 and ttl <= 128 and (window in (8192, 64240) or window >= 8192):
        guesses.append(('Windows', 'high'))
    elif ttl >= 251:
        guesses.append(('Network gear (Cisco/BSD-family)', 'medium'))
    elif 60 <= ttl <= 65 and window in (16384, 65535):
        guesses.append(('macOS / BSD', 'medium'))
    if not guesses:
        guess = wint or family
        guesses.append((guess, 'low'))
    top, conf = guesses[0]
    return top, conf, family, hops, wint


def add_arguments(parser):
    parser.add_argument('target', help='Target IP')
    parser.add_argument('--port', type=int, default=80, help='Open TCP port to probe')


def run(args):
    target = args.target
    port = getattr(args, 'port', 80)
    is_root = (os.geteuid() == 0) if hasattr(os, 'geteuid') else False

    print_header("OS FINGERPRINT", target)
    kv("Probe port", port)
    kv("Method", "scapy SYN response" if (HAS_SCAPY and is_root) else
       "ping TTL (fallback)")
    print()

    ttl = window = mss = None
    options = []
    df = False

    if HAS_SCAPY and is_root:
        try:
            pkt = IP(dst=target) / TCP(dport=port, flags='S', sport=44444)
            resp = sr1(pkt, timeout=2, verbose=0)
            if resp is not None and resp.haslayer(IP) and resp.haslayer(TCP):
                ttl = resp[IP].ttl
                window = resp[TCP].window
                df = bool(resp[IP].flags & 0x2)
                opts = resp[TCP].options
                options = [o[0] for o in opts if isinstance(o, (tuple, list)) and o]
                for o in opts:
                    if isinstance(o, tuple) and o[0] == 'MSS':
                        mss = o[1]
        except Exception as e:
            print_warning(f"scapy probe failed: {e}")

    if ttl is None:
        # Fallback: parse the ping reply TTL
        try:
            if sys.platform == 'darwin':
                cmd = ['ping', '-c', '1', '-t', '2', target]
            else:
                cmd = ['ping', '-c', '1', '-W', '2', target]
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=4).stdout
            import re
            m = re.search(r'ttl=(\d+)', out)
            if m:
                ttl = int(m.group(1))
            else:
                print_error("Host did not answer ping - give an open --port and run as root")
                return
        except Exception as e:
            print_error(f"Ping failed: {e}")
            return

    guess, confidence, family, hops, wint = os_guess(
        ttl, window or 0, mss, options, df)

    kv("TTL", f"{ttl} ({hops} hops from a {family.split(' ')[0]} baseline)")
    if window:
        kv("TCP window", f"{window} {('· ' + wint) if wint else ''}")
    if mss:
        kv("MSS", mss)
    if options:
        kv("TCP options", ', '.join(options[:6]))
    if df:
        kv("DF bit", "set")
    print()

    color = (Colors.BRIGHT_GREEN if confidence == 'high'
             else Colors.BRIGHT_YELLOW if confidence == 'medium' else Colors.DIM)
    print(f"  {Colors.BOLD}Best-effort OS guess:{Colors.RESET} "
          f"{color}{Colors.BOLD}{guess}{Colors.RESET} "
          f"{Colors.DIM}(confidence: {confidence}){Colors.RESET}")
    print_info("nmap -O is authoritative; this is a stack-signal heuristic")
    print()

    print_summary("FINGERPRINT", [
        ("Guess", guess),
        ("Confidence", confidence),
        ("TTL", ttl),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "osfp", "target": target,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"guess": guess, "confidence": confidence, "ttl": ttl,
                               "window": window, "mss": mss, "df": df}})

    print_success("OS fingerprint completed")
