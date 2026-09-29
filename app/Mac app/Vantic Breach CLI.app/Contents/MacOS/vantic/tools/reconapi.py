"""
Recon API Tool
Keyed + keyless API recon: Shodan InternetDB (keyless, default),
optional Shodan/Censys/VT when keys exist in ~/.vantic/apikeys.json
"""

import json
import os
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json
)

from vantic.core import net

META = {
    "name": "reconapi",
    "title": "API Recon",
    "category": "RECONNAISSANCE",
    "description": "Shodan InternetDB + keyed API lookups",
    "risk": "safe",
    "examples": [
        "vantic reconapi 1.2.3.4",
        "vantic reconapi 1.2.3.4 --source shodan",
    ],
    "flow": [
        ("arg", "target", "Target IP", None),
        ("opt", "--source", "Source (internetdb/shodan/censys/vt)", "internetdb"),
    ],
    "guard": {},
}

KEYS_FILE = os.path.join(os.path.expanduser("~"), ".vantic", "apikeys.json")


def load_keys():
    try:
        with open(KEYS_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def internetdb(ip):
    """Shodan InternetDB - keyless, single IP, daily refresh."""
    try:
        resp = net.request(f"https://internetdb.shodan.io/{ip}", timeout=15, max_retries=0)
        return json.loads(resp.body.decode("utf-8", errors="replace"))
    except Exception:
        return None


def shodan_host(ip, key):
    try:
        resp = net.request(f"https://api.shodan.io/shodan/host/{ip}?key={key}",
                           timeout=15, max_retries=0)
        return json.loads(resp.body.decode("utf-8", errors="replace"))
    except Exception:
        return None


def censys_host(ip, uid, secret):
    try:
        import base64
        auth = base64.b64encode(f"{uid}:{secret}".encode()).decode()
        resp = net.request(f"https://search.censys.io/api/v2/hosts/{ip}",
                           timeout=15, max_retries=0,
                           headers={"Authorization": f"Basic {auth}"})
        return json.loads(resp.body.decode("utf-8", errors="replace"))
    except Exception:
        return None


def add_arguments(parser):
    parser.add_argument('target', help='Target IP')
    parser.add_argument('--source',
                        choices=['internetdb', 'shodan', 'censys'],
                        default='internetdb',
                        help='API source (internetdb = keyless default)')


def run(args):
    ip = args.target.strip()
    source = getattr(args, 'source', 'internetdb')

    print_header("API RECON", f"{ip} · {source}")
    print()

    if source == 'internetdb':
        data = internetdb(ip)
        if not data:
            print_error("InternetDB lookup failed (offline or rate-limited)")
            return
        if data.get('detail'):
            print_warning(f"No data: {data['detail']}")
            return
        ports = data.get('ports', [])
        cpes = data.get('cpes', [])
        vulns = data.get('vulns', [])
        hostnames = data.get('hostnames', [])
        kv("IP", ip, Colors.BOLD)
        kv("Open ports", ', '.join(map(str, ports)) or 'none')
        kv("Hostnames", ', '.join(hostnames[:5]) or 'none')
        if cpes:
            kv("Products", ', '.join(cpes[:5]) + ('…' if len(cpes) > 5 else ''))
        if vulns:
            print()
            print_warning(f"{len(vulns)} known CVEs on this host (Shodan data)")
            for v in vulns[:20]:
                print(f"  {Colors.BRIGHT_YELLOW}[!]{Colors.RESET} {v}")
        print()

    elif source == 'shodan':
        keys = load_keys()
        key = keys.get('shodan')
        if not key:
            print_error("No shodan key in ~/.vantic/apikeys.json "
                        "({\"shodan\": \"YOUR_KEY\"})")
            return
        data = shodan_host(ip, key)
        if not data or data.get('error'):
            print_error(f"Shodan lookup failed: {data.get('error', 'unknown') if data else 'no data'}")
            return
        kv("IP", f"{data.get('ip_str')} ({data.get('country_code', '?')})", Colors.BOLD)
        kv("Org", data.get('org') or '-')
        kv("ISP", data.get('isp') or '-')
        for svc in data.get('data', [])[:10]:
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} "
                  f":{svc.get('port')}/{svc.get('transport', 'tcp')} "
                  f"{Colors.BOLD}{svc.get('product', '')} {svc.get('version', '')}{Colors.RESET}")
        if data.get('vulns'):
            print_warning(f"Vulnerable: {', '.join(data['vulns'][:15])}")
        print()

    elif source == 'censys':
        keys = load_keys()
        if not keys.get('censys_id') or not keys.get('censys_secret'):
            print_error("No censys keys in ~/.vantic/apikeys.json "
                        "({\"censys_id\": .., \"censys_secret\": ..})")
            return
        data = censys_host(ip, keys['censys_id'], keys['censys_secret'])
        result = (data or {}).get('result', {})
        if not result:
            print_error("Censys lookup failed (rate limit or unknown host)")
            return
        services = result.get('services', [])
        kv("IP", ip, Colors.BOLD)
        kv("Services", len(services))
        for svc in services:
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} "
                  f":{svc.get('port')}/{svc.get('transport', 'tcp')} "
                  f"{svc.get('service_name', '')}")
        print()

    print_summary("API RECON", [("Source", source), ("Target", ip)])

    if getattr(args, 'json', False):
        emit_json({"tool": "reconapi", "target": ip, "source": source,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": data if source != 'shodan' else {
                       'org': data.get('org'), 'ports': [s.get('port') for s in data.get('data', [])]}})

    net.close_connections()
    print_success("API recon completed")
