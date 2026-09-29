"""
DNS Enumeration Tool
DNS reconnaissance: records, AXFR, mail security (SPF/DMARC/DKIM),
SRV enumeration, reverse CIDR sweeps, NSEC zone walking, wildcards
"""

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.resolver
    import dns.reversename
    import dns.query
    import dns.zone
    import dns.rdatatype
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, status_badge, ProgressBar, Spinner,
    Colors, emit_json
)

from vantic.core import findings, store

META = {
    "name": "dns",
    "title": "DNS Enumeration",
    "category": "RECONNAISSANCE",
    "description": "DNS records, mail security, SRV, zone walk",
    "risk": "safe",
    "examples": [
        "vantic dns example.com --all-records",
        "vantic dns example.com --mailsec",
        "vantic dns example.com --srv",
        "vantic dns --reverse-cidr 10.0.1.0/24",
    ],
    "flow": [
        ("arg", "domain", "Domain (blank = reverse-cidr only)", ""),
        ("flag", "--all-records", "Query all record types?"),
        ("flag", "--mailsec", "Mail security audit (SPF/DMARC/DKIM)?"),
        ("flag", "--srv", "Enumerate SRV records?"),
        ("flag", "--axfr", "Attempt zone transfer?"),
    ],
    "guard": {"domain": "domain"},
}

RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
EXTRA_TYPES = ['SRV', 'CAA', 'DNSKEY']

SRV_PREFIXES = [
    '_ldap._tcp', '_ldap._udp', '_kerberos._tcp', '_kerberos._udp',
    '_kpasswd._tcp', '_gc._tcp', '_gc._udp', '_sip._tcp', '_sip._tls',
    '_sip._udp', '_xmpp-client._tcp', '_xmpp-server._tcp',
    '_autodiscover._tcp', '_h323cs._tcp', '_ftp._tcp', '_ssh._tcp',
    '_imap._tcp', '_imaps._tcp', '_pop3._tcp', '_pop3s._tcp',
    '_smtp._tcp', '_http._tcp', '_https._tcp', '_caldav._tcp',
    '_carddav._tcp', '_minecraft._tcp', '_redis._tcp', '_mongodb._tcp',
    '_minecraft._udp', '_stun._udp', '_turn._udp',
]

DKIM_SELECTORS = [
    'google', 'default', 'selector', 'selector1', 'selector2', 's0', 's1',
    's2', 'k1', 'k2', 'mail', 'dkim', 'smtp', 'mdaemon', 'zoho',
    'everlytickey1', 'everlytickey2', 'e', 'tm', 'td', 'x',
]


def make_resolver(dns_servers=None, lifetime=5):
    if not HAS_DNSPYTHON:
        return None
    if dns_servers:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = dns_servers
    else:
        resolver = dns.resolver.get_default_resolver()
    resolver.lifetime = lifetime
    return resolver


def query_record(resolver, domain, record_type):
    try:
        answers = resolver.resolve(domain, record_type)
        return [r.to_text() for r in answers]
    except Exception:
        return None


def reverse_lookup(resolver, ip):
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev_name, 'PTR')
        return [r.to_text() for r in answers]
    except Exception:
        return None


def authoritative_ns_ips(resolver, domain):
    """Resolve the domain's authoritative nameservers to IPs."""
    ips = []
    ns_names = query_record(resolver, domain, 'NS') or []
    for ns in ns_names[:4]:
        host = ns.rstrip('.').split(' ')[0] if ' ' in ns else ns.rstrip('.')
        for rtype in ('A', 'AAAA'):
            got = query_record(resolver, host, rtype)
            if got:
                ips.extend(got)
                break
    return ips


def detect_wildcard(domain, resolver=None):
    """Query the authoritative NS with random labels; return wildcard IPs.

    Uses the authoritative servers (not the system resolver) so ISP
    NXDOMAIN hijacking cannot fake a wildcard.
    """
    if not HAS_DNSPYTHON:
        return []
    import random
    import string
    resolver = resolver or make_resolver()
    ns_ips = authoritative_ns_ips(resolver, domain)
    if not ns_ips:
        return []
    auth = dns.resolver.Resolver(configure=False)
    auth.nameservers = ns_ips
    auth.lifetime = 4
    wildcard_ips = set()
    for _ in range(2):
        label = ''.join(random.choice(string.ascii_lowercase) for _ in range(12))
        got = query_record(auth, f"{label}.{domain}", 'A')
        if got:
            wildcard_ips.update(got)
    return sorted(wildcard_ips)


def zone_transfer(domain, dns_servers=None):
    """Attempt AXFR against the domain's nameservers."""
    try:
        ns_records = make_resolver(dns_servers).resolve(domain, 'NS')
        nameservers = [str(ns) for ns in ns_records]
    except Exception as e:
        return None, f"could not resolve NS records: {e}"

    for ns in nameservers[:3]:
        ns_host = ns.rstrip('.')
        try:
            zone = dns.zone.from_xfr(
                dns.query.xfr(ns_host, domain, timeout=10)
            )
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    records.append(f"{name}.{domain} {rdataset.rdtype.name} {rdataset}")
            return records, f"via {ns_host}"
        except Exception:
            continue
    return None, "all nameservers refused the transfer"


# ---------- mail security ----------

def audit_spf(txt_records):
    """Parse SPF from TXT records -> (issues, details)."""
    spf = next((t for t in txt_records if t.startswith('"v=spf1') or t.startswith('v=spf1')), None)
    if spf is None:
        return [("no-spf", "No SPF record found", "medium",
                 "Publish a restrictive SPF record (v=spf1 ... -all)")], {}
    spf = spf.strip('"')
    issues = []
    terms = spf.split()[1:]
    include_count = sum(1 for t in terms if t.startswith('include:')) + \
        sum(1 for t in terms if t.startswith('redirect='))
    all_mech = next((t for t in terms if t.endswith('all')), None)
    if all_mech in ('+all',):
        issues.append(("spf-fail-open", f"SPF ends with {all_mech} (any sender passes)",
                      "high", "Change the SPF all mechanism to -all"))
    elif all_mech == '?all':
        issues.append(("spf-neutral", "SPF ends with ?all (neutral, unenforced)",
                       "low", "Change the SPF all mechanism to -all"))
    elif all_mech is None:
        issues.append(("spf-no-all", "SPF record has no 'all' mechanism",
                       "low", "Terminate the SPF record with -all"))
    if include_count > 10:
        issues.append(("spf-lookups", f"SPF needs {include_count} lookups (DNS cap is 10)",
                      "low", "Flatten SPF includes to stay under the 10-lookup limit"))
    details = {"record": spf, "includes": include_count, "all": all_mech or "none"}
    return issues, details


def audit_dmarc(resolver, domain):
    issues = []
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", 'TXT')
        record = ' '.join(str(a) for a in answers).strip('"')
        import re as _re
        p = _re.search(r'p=(\w+)', record)
        policy = p.group(1) if p else None
        if policy == 'none':
            issues.append(("dmarc-none", "DMARC policy is p=none (monitor only)",
                           "medium", "Escalate DMARC policy to quarantine or reject"))
        elif not policy:
            issues.append(("dmarc-no-policy", "DMARC record has no policy tag",
                           "medium", "Add p=quarantine or p=reject"))
        pct = _re.search(r'pct=(\d+)', record)
        if pct and int(pct.group(1)) < 100:
            issues.append((f"dmarc-pct", f"DMARC applied to only {pct.group(1)}% of mail",
                           "low", "Raise pct to 100"))
        return issues, {"record": record, "policy": policy}
    except Exception:
        return [("dmarc-missing", "No DMARC record found", "medium",
                 "Publish _dmarc DMARC policy")], {}


def audit_dkim(resolver, domain, selectors):
    """Sweep selectors, skipping zones that wildcard TXT (false-positive guard)."""
    import random
    import string
    rnd = ''.join(random.choice(string.ascii_lowercase) for _ in range(12))
    if query_record(resolver, f"{rnd}._domainkey.{domain}", 'TXT'):
        return [], f"zone wildcards TXT (*.{domain}) - selector sweep is meaningless"
    found = []
    for sel in selectors:
        got = query_record(resolver, f"{sel}._domainkey.{domain}", 'TXT')
        if got:
            found.append((sel, got[0][:64]))
    return found, None


# ---------- NSEC walk ----------

def nsec_walk(resolver, domain, cap=5000):
    """Walk a DNSSEC-signed zone via NSEC chain. Returns (names, note)."""
    first = query_record(resolver, domain, 'NSEC')
    if first is None:
        # Maybe the zone is signed with NSEC3
        nsec3 = query_record(resolver, domain, 'NSEC3')
        if nsec3:
            return [], "zone uses NSEC3 - walking is impractical (hashed names)"
        return [], "zone is not signed (no NSEC records)"
    names = set()
    current = domain
    seen = set()
    for _ in range(cap):
        rec = query_record(resolver, current, 'NSEC')
        if not rec:
            break
        # NSEC answer: "<next-name> [types]"
        nxt = rec[0].split()[0].rstrip('.')
        if nxt in seen or nxt == domain:
            break
        seen.add(nxt)
        names.add(nxt)
        current = nxt
    return sorted(names), f"{len(names)} names via NSEC chain"


# ---------- run ----------

def add_arguments(parser):
    parser.add_argument('domain', nargs='?', default=None, help='Target domain')
    parser.add_argument('--brute', action='store_true', help='Brute force subdomains')
    parser.add_argument('--wordlist', help='Subdomain wordlist')
    parser.add_argument('--dns-servers', help='Custom DNS servers (comma-separated)')
    parser.add_argument('--reverse', action='store_true', help='Reverse DNS lookup')
    parser.add_argument('--all-records', action='store_true', help='All record types')
    parser.add_argument('--axfr', action='store_true', help='Zone transfer attempt')
    parser.add_argument('--mailsec', action='store_true', help='Mail security audit (SPF/DMARC/DKIM)')
    parser.add_argument('--srv', action='store_true', help='Enumerate SRV records')
    parser.add_argument('--reverse-cidr', help='PTR sweep over a CIDR (max /24 unless --force)')
    parser.add_argument('--walk', action='store_true', help='NSEC zone walk (signed zones)')
    parser.add_argument('--wildcard', action='store_true', help='Detect DNS wildcards')
    parser.add_argument('--no-wildcard', action='store_true', help='Skip wildcard checks')
    parser.add_argument('--force', action='store_true', help='Lift the /24 reverse-sweep cap')


def run(args):
    """Run DNS enumeration."""
    domain = (args.domain or '').rstrip('.')
    dns_servers = getattr(args, 'dns_servers', None)
    if dns_servers:
        dns_servers = [s.strip() for s in dns_servers.split(',') if s.strip()]

    if not domain and not getattr(args, 'reverse_cidr', None):
        print_error("Give a domain, or use --reverse-cidr <cidr>")
        return

    print_header("DNS ENUMERATION", domain or args.reverse_cidr)
    if domain:
        kv("Domain", domain, Colors.BOLD)
    if dns_servers:
        kv("Resolvers", ', '.join(dns_servers))
    kv("Backend", "dnspython" if HAS_DNSPYTHON else "none")
    print()

    if not HAS_DNSPYTHON:
        print_error("DNS enumeration requires dnspython:")
        print(f"      {Colors.CYAN}pip3 install dnspython{Colors.RESET}")
        return

    resolver = make_resolver(dns_servers)
    found_records = {}
    wildcards = []

    # --- reverse CIDR sweep (standalone mode) ---
    if getattr(args, 'reverse_cidr', None):
        import ipaddress
        try:
            net = ipaddress.ip_network(args.reverse_cidr, strict=False)
        except ValueError:
            print_error(f"Invalid CIDR: {args.reverse_cidr}")
            return
        if net.num_addresses > 256 and not getattr(args, 'force', False):
            print_error(f"{args.reverse_cidr} has {net.num_addresses} addresses - "
                        f"use --force for larger sweeps")
            return
        hosts = [str(ip) for ip in net.hosts()] or [str(net.network_address)]
        print_subheader("REVERSE SWEEP", f"{len(hosts)} hosts")
        results = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(reverse_lookup, resolver, ip): ip for ip in hosts}
            progress = ProgressBar(len(hosts), "PTR sweep")
            for future in as_completed(futures):
                ip = futures[future]
                ptrs = future.result()
                if ptrs:
                    results.append((ip, ptrs[0].rstrip('.')))
                    if store.is_active():
                        store.record_target(ptrs[0].rstrip('.'), "domain")
                    progress.interrupt()
                    print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {ip:<16} → {ptrs[0].rstrip('.')}")
                progress.update()
        print()
        print_summary("PTR RECORDS", [("Hosts", len(hosts)), ("PTR found", len(results))])
        if getattr(args, 'json', False):
            emit_json({"tool": "dns", "mode": "reverse-cidr", "cidr": args.reverse_cidr,
                       "results": [{"ip": ip, "ptr": p} for ip, p in sorted(results)]})
        print_success("Reverse sweep completed")
        return

    # --- wildcard detection (auto with brute) ---
    if not getattr(args, 'no_wildcard', False):
        with Spinner("Checking for DNS wildcards..."):
            wildcards = detect_wildcard(domain, resolver)
        if wildcards:
            print_warning(f"DNS WILDCARD detected: *.{domain} → {', '.join(wildcards)}")
            print_info("Brute-force candidates resolving to only these IPs are suppressed")
            print()
        elif getattr(args, 'wildcard', False):
            print_success("No wildcard detected")
            print()

    # --- records ---
    record_types = list(RECORD_TYPES)
    if getattr(args, 'all_records', False):
        record_types += EXTRA_TYPES

    print_subheader("RECORDS")
    for rtype in record_types:
        results = query_record(resolver, domain, rtype)
        if results:
            found_records[rtype] = results
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {Colors.BOLD}{rtype:<8}{Colors.RESET}")
            for result in results[:6]:
                val = result if len(result) <= 70 else result[:67] + '...'
                print(f"      {Colors.CYAN}└─{Colors.RESET} {val}")
            if len(results) > 6:
                print(f"      {Colors.DIM}... and {len(results) - 6} more{Colors.RESET}")

    if not found_records:
        print_warning(f"No records found - is '{domain}' correct?")

    # --- AXFR ---
    if getattr(args, 'axfr', False):
        print_subheader("ZONE TRANSFER")
        records, detail = zone_transfer(domain, dns_servers)
        if records:
            print(f"  {Colors.BOLD}{Colors.BRIGHT_RED}[!!] Zone transfer SUCCEEDED {detail}{Colors.RESET}")
            for record in records[:50]:
                print(f"      {record}")
            if len(records) > 50:
                print(f"      {Colors.DIM}... and {len(records) - 50} more{Colors.RESET}")
            found_records['AXFR'] = [f"{len(records)} records leaked"]
            findings.make(family="dns-axfr", title="DNS zone transfer open",
                          severity="high", target=domain,
                          evidence=f"AXFR {detail}, {len(records)} records",
                          remediation="Restrict AXFR to designated secondaries",
                          tool="dns")
        else:
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} Zone transfer refused ({detail})")

    # --- mail security ---
    if getattr(args, 'mailsec', False):
        print_subheader("MAIL SECURITY")
        txt = found_records.get('TXT') or query_record(resolver, domain, 'TXT') or []
        spf_issues, spf_details = audit_spf(txt)
        for fid, msg, sev, fix in spf_issues:
            color = getattr(Colors, 'BRIGHT_RED' if sev == 'high' else
                            'BRIGHT_YELLOW' if sev == 'medium' else 'DIM')
            print(f"  {color}[!]{Colors.RESET} SPF: {msg}")
            findings.make(family="mail-spf", title=msg, severity=sev, target=domain,
                          evidence=str(spf_details), remediation=fix, tool="dns")
        if not spf_issues:
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} SPF looks sane "
                  f"({spf_details.get('all', 'n/a')})")
        dmarc_issues, dmarc_details = audit_dmarc(resolver, domain)
        for fid, msg, sev, fix in dmarc_issues:
            print(f"  {Colors.BRIGHT_YELLOW}[!]{Colors.RESET} DMARC: {msg}")
            findings.make(family="mail-dmarc", title=msg, severity=sev, target=domain,
                          evidence=str(dmarc_details), remediation=fix, tool="dns")
        if not dmarc_issues:
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} DMARC policy: "
                  f"{dmarc_details.get('policy')}")
        with Spinner("Sweeping DKIM selectors..."):
            dkim, dkim_note = audit_dkim(resolver, domain, DKIM_SELECTORS)
        if dkim:
            for sel, key in dkim:
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} DKIM selector "
                      f"{Colors.BOLD}{sel}{Colors.RESET} {Colors.DIM}{key}{Colors.RESET}")
        elif dkim_note:
            print(f"  {Colors.DIM}[·] {dkim_note}{Colors.RESET}")
        else:
            print(f"  {Colors.DIM}[·] no DKIM keys on {len(DKIM_SELECTORS)} common selectors{Colors.RESET}")
        print()

    # --- SRV ---
    if getattr(args, 'srv', False):
        print_subheader("SRV RECORDS")
        hits = 0
        for prefix in SRV_PREFIXES:
            got = query_record(resolver, f"{prefix}.{domain}", 'SRV')
            if got:
                hits += 1
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} "
                      f"{Colors.BOLD}{prefix:<22}{Colors.RESET} {got[0]}")
                if store.is_active():
                    store.record_target(f"{prefix}.{domain}", "domain")
        if not hits:
            print(f"  {Colors.DIM}[·] no SRV records on {len(SRV_PREFIXES)} prefixes{Colors.RESET}")
        print()

    # --- NSEC walk ---
    if getattr(args, 'walk', False):
        print_subheader("NSEC ZONE WALK")
        names, note = nsec_walk(resolver, domain)
        if names:
            print(f"  {Colors.BOLD}{Colors.BRIGHT_RED}[!!] {note}{Colors.RESET}")
            for n in names[:40]:
                print(f"      {n}")
            if len(names) > 40:
                print(f"      {Colors.DIM}... and {len(names) - 40} more{Colors.RESET}")
            findings.make(family="dns-nsec", title="NSEC zone walking possible",
                          severity="medium", target=domain,
                          evidence=f"{len(names)} names enumerated",
                          remediation="Switch the zone to NSEC3 (or whitelist), "
                                     "or accept public zone data exposure",
                          tool="dns")
        else:
            print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {note}")
        print()

    # --- reverse ---
    if getattr(args, 'reverse', False):
        print_subheader("REVERSE LOOKUP")
        a_records = found_records.get('A') or query_record(resolver, domain, 'A') or []
        if not a_records:
            print(f"  {Colors.DIM}[·] no A records to reverse-resolve{Colors.RESET}")
        for ip in a_records[:10]:
            ptrs = reverse_lookup(resolver, ip)
            if ptrs:
                for ptr in ptrs:
                    print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {ip:<18} → {ptr}")
            else:
                print(f"  {Colors.DIM}[·] {ip:<18} no PTR record{Colors.RESET}")

    # Summary
    print()
    print_summary("RECORDS FOUND", [
        (rtype, len(vals)) for rtype, vals in sorted(found_records.items())
    ] or [("None", "no records found")])

    if getattr(args, 'json', False):
        emit_json({"tool": "dns", "target": domain,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": found_records, "wildcards": wildcards})

    print_success("DNS enumeration completed")
