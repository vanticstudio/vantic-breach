"""
UPnP Tool
SSDP discovery + device XML parse + read-only IGD actions

M-SEARCH to 239.255.255.250:1900, parse LOCATION device XML, optionally
query WANIPConnection (GetExternalIPAddress / GetStatusInfo /
GetGenericPortMappingEntry). Read-only - AddPortMapping-class writes are
whitelisted OUT.
"""

import re
import socket
import struct
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, kv, Colors, emit_json
)

from vantic.core import net, findings, store

META = {
    "name": "upnp",
    "title": "UPnP Audit",
    "category": "GATEWAY / INFRA",
    "description": "SSDP discovery + IGD port mappings",
    "risk": "safe",
    "examples": [
        "vantic upnp",
        "vantic upnp --cidr 192.168.1.0/24",
        "vantic upnp --host 192.168.1.1 --igd-read",
    ],
    "flow": [
        ("opt", "--cidr", "CIDR (blank = multicast sweep)", ""),
        ("flag", "--igd-read", "Read IGD port mappings?"),
    ],
    "guard": {"cidr": "cidr"},
}

SSDP_GROUP = ("239.255.255.250", 1900)

M_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


def ssdp_discover(timeout=4):
    """Multicast M-SEARCH; collect (location, server, usn) triples."""
    results = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        sock.settimeout(timeout)
        sock.sendto(M_SEARCH.encode(), SSDP_GROUP)
        end = datetime.now().timestamp() + timeout
        seen = set()
        while datetime.now().timestamp() < end:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            text = data.decode(errors='replace')
            location = re.search(r'LOCATION:\s*(\S+)', text, re.IGNORECASE)
            server = re.search(r'SERVER:\s*(.+)', text, re.IGNORECASE)
            usn = re.search(r'USN:\s*(\S+)', text, re.IGNORECASE)
            key = location.group(1) if location else text[:60]
            if key in seen:
                continue
            seen.add(key)
            results.append({
                'ip': addr[0],
                'location': location.group(1) if location else '',
                'server': server.group(1).strip() if server else '',
                'usn': usn.group(1) if usn else '',
            })
        sock.close()
    except OSError as e:
        print_warning(f"SSDP send failed: {e}")
    return results


def parse_device_xml(url, timeout=8):
    """Fetch + parse a device description XML."""
    try:
        resp = net.request(url, "GET", timeout=timeout, follow_redirects=False,
                           max_retries=0)
        root = ET.fromstring(resp.text(200000))
    except Exception:
        return None

    def findtext(path):
        el = root.find('.//' + path)
        return (el.text or '').strip() if el is not None and el.text else ''

    ns_stripped = re.sub(r'\{[^}]+\}', '', resp.text(200000))
    info = {
        'friendlyName': findtext('friendlyName'),
        'manufacturer': findtext('manufacturer'),
        'modelName': findtext('modelName'),
        'modelNumber': findtext('modelNumber'),
        'firmware': findtext('modelNumber') or findtext('serialNumber'),
        'deviceType': findtext('deviceType'),
    }
    # Find the WANIPConnection control URL
    ctrl = re.search(r'<serviceType>([^<]*WANIPConnection[^<]*)</serviceType>\s*'
                     r'<controlURL>([^<]+)</controlURL>', resp.text(200000))
    if ctrl:
        info['control_url'] = urllib.parse.urljoin(url, ctrl.group(2))
        info['service_type'] = ctrl.group(1).strip()
    return info


def igd_action(control_url, service_type, action, args=None, timeout=8):
    """One read-only SOAP action. Returns (ok, response_xml_text)."""
    body_args = ''.join(
        f"<m:{k}>{v}</m:{k}>" for k, v in (args or {}).items())
    soap = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <m:{action} xmlns:m="{service_type}">{body_args}</m:{action}>
  </s:Body>
</s:Envelope>"""
    try:
        resp = net.request(control_url, "POST", timeout=timeout,
                           follow_redirects=False, max_retries=0,
                           data=soap,
                           headers={"Content-Type": "text/xml",
                                   "SOAPAction": f'"{service_type}#{action}"'})
        return resp.status == 200, resp.text(100000)
    except Exception:
        return False, ''


def parse_soap_values(xml_text):
    return dict(re.findall(r'<([^:>]+)>([^<]*)</\1>', xml_text))


def add_arguments(parser):
    parser.add_argument('--cidr', help='Sweep a CIDR (default: multicast)')
    parser.add_argument('--host', help='Direct SSDP at one host')
    parser.add_argument('--igd-read', action='store_true',
                        help='Read IGD port mappings (read-only actions)')
    parser.add_argument('--timeout', type=int, default=4)


def run(args):
    timeout = max(2, getattr(args, 'timeout', 4))

    print_header("UPnP AUDIT", "SSDP " + (getattr(args, 'cidr', '') or
                                        (getattr(args, 'host', '') or 'multicast')))
    print()

    print_subheader("SSDP DISCOVERY")
    devices = ssdp_discover(timeout)
    if not devices:
        print_warning("No SSDP responses - UPnP disabled or the switch filters multicast")
        print_info("Note listener position: IGMP snooping may block multicast "
                   "to your port")
        return

    for d in devices:
        print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {d['ip']:<16} "
              f"{Colors.DIM}{d['server'][:44]}{Colors.RESET}")
        if d['location']:
            print(f"      {Colors.DIM}{d['location'][:76]}{Colors.RESET}")
    print()

    # Device XML parse
    print_subheader("DEVICE DESCRIPTIONS")
    parsed = []
    for d in devices:
        if not d['location']:
            continue
        info = parse_device_xml(d['location'])
        if info:
            info['ip'] = d['ip']
            parsed.append(info)
            label = ' '.join(filter(None, [info.get('manufacturer'),
                                           info.get('modelName')]))
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {d['ip']:<16} "
                  f"{Colors.BOLD}{label[:40] or info.get('friendlyName', '?')}{Colors.RESET}")
            if store.is_active():
                store.record_target(d['ip'], 'host', group_name='upnp')

    findings.make(family="upnp-enabled",
                  title="UPnP/SSDP active on segment",
                  severity="low",
                  evidence=f"{len(devices)} devices responded to M-SEARCH",
                  remediation="Disable UPnP where not needed; at minimum "
                              "disable WAN-side discovery",
                  tool="upnp")
    print()

    # IGD read-only actions
    if getattr(args, 'igd_read', False):
        print_subheader("IGD PORT MAPPINGS (READ-ONLY)")
        mapped = False
        for info in parsed:
            if not info.get('control_url'):
                continue
            ctrl, svc = info['control_url'], info['service_type']
            # External IP
            ok, text = igd_action(ctrl, svc, 'GetExternalIPAddress')
            if ok:
                vals = parse_soap_values(text)
                ext_ip = vals.get('NewExternalIPAddress', '?')
                kv(f"{info['ip']} external IP", ext_ip)
            # Status
            ok, text = igd_action(ctrl, svc, 'GetStatusInfo')
            if ok:
                vals = parse_soap_values(text)
                kv(f"{info['ip']} WAN status",
                  vals.get('NewConnectionStatus', '?'))
            # Port mappings: iterate index until error 713/714
            idx = 0
            while idx < 64:
                ok, text = igd_action(ctrl, svc, 'GetGenericPortMappingEntry',
                                      {'NewPortMappingIndex': idx})
                if not ok or 'ErrorCode' in text or '713' in text:
                    break
                vals = parse_soap_values(text)
                desc = vals.get('NewPortMappingDescription', '?')
                ext = vals.get('NewExternalPort', '?')
                proto = vals.get('NewProtocol', 'TCP')
                internal = f"{vals.get('NewInternalClient', '?')}:" \
                          f"{vals.get('NewInternalPort', '?')}"
                mapped = True
                print(f"  {Colors.BRIGHT_YELLOW}[map]{Colors.RESET} {ext}/{proto:<3}"
                      f" → {internal:<22} {Colors.DIM}{desc[:28]}{Colors.RESET}")
                idx += 1
            if idx:
                findings.make(family="upnp-mappings",
                              title=f"NAT port mappings on {info['ip']}",
                              severity="medium", target=info['ip'],
                              evidence=f"{idx} mappings enumerated "
                                       "(includes forwarded services)",
                              remediation="Restrict UPnP mapping rights; "
                                          "review forwarded ports",
                              tool="upnp")
            break  # first IGD is enough
        if not mapped:
            print(f"  {Colors.DIM}[·] no port mappings (or no IGD device){Colors.RESET}")
        print()

    print_summary("UPnP", [
        ("SSDP devices", len(devices)),
        ("Descriptions", len(parsed)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "upnp",
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": {"discovered": devices, "devices": parsed}})

    net.close_connections()
    print_success("UPnP audit completed")
