"""
SMB Enum Tool
enum4linux-style domain enumeration over SAMR/LSA (impacket optional)

Users, groups, password policy, domain SID - what leaks to a low-priv or
anonymous session. impacket is a heavy optional dep; without it the tool
reports exactly what to install.
"""

from datetime import datetime

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, kv, Colors, emit_json
)

from vantic.core import findings, store

META = {
    "name": "smbenum",
    "title": "SMB Enum",
    "category": "INTERNAL / AD",
    "description": "enum4linux-style domain enumeration",
    "risk": "intrusive",
    "examples": [
        "vantic smbenum 10.0.0.10",
        "vantic smbenum 10.0.0.10 --user jsmith --pass 'P@ss' --users --policy",
    ],
    "flow": [
        ("arg", "target", "Target IP (DC preferred)", None),
        ("opt", "--user", "Username (blank = anonymous)", ""),
        ("opt", "--pass", "Password", ""),
    ],
    "guard": {"target": "host"},
}


def add_arguments(parser):
    parser.add_argument('target', help='Target IP (domain controller)')
    parser.add_argument('--user', help='Username (anonymous if omitted)')
    parser.add_argument('--pass', dest='password', help='Password')
    parser.add_argument('--users', action='store_true', help='Enumerate domain users')
    parser.add_argument('--groups', action='store_true', help='Enumerate groups')
    parser.add_argument('--policy', action='store_true', help='Read password policy')
    parser.add_argument('--rids', type=int, default=500,
                        help='RID walk start (default 500)')
    parser.add_argument('--max-rids', type=int, default=500,
                        help='RID walk range (default 500)')


def run(args):
    target = args.target
    user = getattr(args, 'user', None)
    password = getattr(args, 'password', None)
    want_users = getattr(args, 'users', False)
    want_groups = getattr(args, 'groups', False)
    want_policy = getattr(args, 'policy', False)
    if not (want_users or want_groups or want_policy):
        want_users = want_groups = want_policy = True

    try:
        from impacket.smbconnection import SMBConnection
        from impacket.dcerpc.v5 import samr, lsad, lsarpc
    except ImportError:
        print_error("smbenum needs impacket (the one heavy optional dep):")
        print(f"      {Colors.CYAN}pip3 install impacket{Colors.RESET}")
        print_info("Lighter pre-auth SMB checks: vantic smb " + target)
        return

    print_header("SMB ENUM", target)
    kv("Session", f"{user or 'anonymous'}@{target}", Colors.BOLD)
    print()

    results = {'users': [], 'groups': [], 'policy': {}}

    try:
        conn = SMBConnection(target, target, None, 5)
        # Prefer 445; impacket auto-handles the session setup
        conn.login(user or '', password or '')
        dce = conn.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        samr_handle = samr.hSamrConnect(dce)['ServerHandle']
        domain = samr.hSamrLookupDomain(dce, samr_handle, 'Builtin')['DomainId']
        # Open the *account* domain (real users), not Builtin
        domains = samr.hSamrEnumerateDomainsInSamServer(
            dce, samr_handle)['Domains/Entries']
        acct_domain = None
        for d in domains:
            if str(d['Name']) != 'Builtin':
                acct_domain = samr.hSamrOpenDomain(
                    dce, samr_handle, 0x01 | 0x02,
                    samr.hSamrLookupDomain(dce, samr_handle, d['Name'])['DomainId']
                )['DomainHandle']
                results['domain'] = str(d['Name'])
                break
        dom = acct_domain or samr.hSamrOpenDomain(
            dce, samr_handle, 0x01 | 0x02, domain)['DomainHandle']

        if want_users:
            print_subheader("DOMAIN USERS")
            resp = samr.hSamrEnumerateUsersInDomain(dce, dom, 0)
            for item in resp['Buffer']['Buffer']:
                name = str(item['Name'])
                rid = item['RelativeId']
                desc = str(item.get('Description', ''))
                results['users'].append({'name': name, 'rid': rid, 'desc': desc})
            for u in results['users'][:60]:
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} "
                      f"{Colors.BOLD}{u['name']:<24}{Colors.RESET} "
                      f"{Colors.DIM}rid={u['rid']} {u['desc'][:30]}{Colors.RESET}")
            if len(results['users']) > 60:
                print(f"  {Colors.DIM}... and {len(results['users']) - 60} more{Colors.RESET}")
            if not user and results['users']:
                findings.make(family="smb-anon-enum",
                              title="Anonymous SAMR user enumeration",
                              severity="medium", target=target,
                              evidence=f"{len(results['users'])} users enumerated anonymously",
                              remediation="Restrict anonymous RPC (RestrictAnonymous=1)",
                              tool="smbenum")
            print()

        if want_groups:
            print_subheader("DOMAIN GROUPS")
            resp = samr.hSamrEnumerateAliasesInDomain(dce, dom)
            for item in resp['Buffer']['Buffer']:
                name = str(item['Name'])
                results['groups'].append(name)
            for g in results['groups'][:40]:
                print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {g}")
            print()

        if want_policy:
            print_subheader("PASSWORD POLICY")
            pol = samr.hSamrQueryInformationDomain2(
                dce, dom, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
            pinfo = pol['Buffer']
            min_len = pinfo['MinPasswordLength']
            history = pinfo['PasswordHistoryLength']
            props = pinfo['PasswordProperties']
            complexity = bool(props & 0x1)
            results['policy'] = {'min_length': min_len, 'history': history,
                                 'complexity': complexity}
            kv("Min length", str(min_len))
            kv("History", str(history))
            kv("Complexity", "required" if complexity else "off")
            if min_len < 8:
                findings.make(family="password-policy",
                              title="Weak domain password policy",
                              severity="medium", target=target,
                              evidence=f"minLen={min_len} history={history} "
                                       f"complexity={complexity}",
                              remediation="Raise minimum length to 14+ and keep complexity on",
                              tool="smbenum")
            print()

        dce.disconnect()
        conn.close()
    except Exception as e:
        print_error(f"SAMR enumeration failed: {e}")
        if not user:
            print_info("Anonymous enum is often blocked - try --user/--pass")

    print_summary("SMB ENUM", [
        ("Domain", results.get('domain', '-')),
        ("Users", len(results['users'])),
        ("Groups", len(results['groups'])),
        ("Policy", "read" if results['policy'] else "-"),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "smbenum", "target": target,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": results})

    print_success("SMB enum completed")
