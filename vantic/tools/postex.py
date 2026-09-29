"""
Post-Exploitation Audit Tool
Read-only privilege-escalation audit over SSH (paramiko) on an
AUTHORIZED unix target

Whitelisted commands only, `sudo -n` only (never hangs on a password),
5s timeout per command, everything in the audit trail. Never reads
private key contents (.ssh checks list existence/perms only).
"""

from datetime import datetime

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_summary, print_table, kv, Colors, emit_json,
    load_json_data
)

from vantic.core import findings, audit, store

META = {
    "name": "postex",
    "title": "Privesc Audit",
    "category": "POST-EXPLOITATION",
    "description": "Read-only unix privesc audit over SSH",
    "risk": "intrusive",
    "examples": [
        "vantic postex 10.0.0.20 -u operator",
        "vantic postex 10.0.0.20 -u operator --checks suid,cron,kernel",
    ],
    "flow": [
        ("arg", "target", "Target IP (authorized unix host)", None),
        ("opt", "-u", "SSH username", ""),
        ("opt", "-w", "Password wordlist or literal", ""),
    ],
    "guard": {"target": "host"},
}

# (id, category, severity, command, hit-criteria note)
CHECKS = [
    ("os", "system", "info",
     "uname -a; head -4 /etc/os-release 2>/dev/null", "kernel + distro"),
    ("identity", "system", "info",
     "id; hostname", "sudo/docker/lxd/disk group membership"),
    ("sudo-rights", "sudo", "high",
     "sudo -n -l 2>/dev/null", "NOPASSWD or wildcard commands"),
    ("sudo-version", "sudo", "medium",
     "sudo -V 2>/dev/null | head -1", "< 1.9.5p2 (CVE-2021-3156 candidate)"),
    ("suid", "filesystem", "high",
     "find / -xdev -type f -perm -4000 2>/dev/null | head -40",
     "non-default SUID paths"),
    ("sgid", "filesystem", "medium",
     "find / -xdev -type f -perm -2000 2>/dev/null | head -20", "unusual SGID"),
    ("world-writable-files", "filesystem", "medium",
     "find /etc /usr/local -xdev -type f -perm -0002 2>/dev/null | head -20",
     "writable config/scripts"),
    ("world-writable-dirs", "filesystem", "low",
     "find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -20",
     "missing sticky bit"),
    ("capabilities", "filesystem", "high",
     "getcap -r / 2>/dev/null | head -30", "cap_setuid/cap_sys_admin off-core"),
    ("cron", "scheduled", "high",
     "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d 2>/dev/null; crontab -l 2>/dev/null",
     "writable scripts called by root"),
    ("systemd-timers", "scheduled", "medium",
     "systemctl list-timers --all 2>/dev/null | head -15", "unusual root units"),
    ("writable-units", "scheduled", "high",
     "find /etc/systemd /lib/systemd -type f -writable 2>/dev/null | head -10",
     "any writable unit"),
    ("path-audit", "environment", "medium",
     "echo $PATH | tr ':' '\\n' | while read d; do [ -w \"$d\" ] && echo writable: $d; done",
     "writable dir early in PATH"),
    ("uid0-users", "accounts", "high",
     "awk -F: '$3==0 {print $1}' /etc/passwd", "root besides root"),
    ("key-file-perms", "accounts", "medium",
     "ls -l /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null; "
     "ls -la ~/.ssh /home/*/.ssh 2>/dev/null",
     "readable shadow/sudoers; loose .ssh perms (existence/perms ONLY)"),
    ("priv-groups", "accounts", "high",
     "getent group sudo wheel admin docker lxd disk 2>/dev/null",
     "docker/lxd/disk membership"),
    ("pkexec", "packages", "medium",
     "ls -l /usr/bin/pkexec 2>/dev/null; dpkg -s policykit-1 2>/dev/null | grep -i version",
     "unpatched polkit (CVE-2021-4034 candidate)"),
    ("nfs-exports", "filesystem", "medium",
     "cat /etc/exports 2>/dev/null", "no_root_squash / insecure"),
    ("sshd-posture", "services", "medium",
     "grep -Ei '^(permitrootlogin|passwordauthentication)' /etc/ssh/sshd_config 2>/dev/null",
     "PermitRootLogin yes / PasswordAuthentication yes"),
    ("mount-flags", "filesystem", "low",
     "findmnt -rn -o TARGET,OPTIONS 2>/dev/null | head -20",
     "writable mounts without nosuid/noexec"),
    ("sysctls", "system", "low",
     "sysctl kernel.kptr_restrict kernel.dmesg_restrict kernel.yama.ptrace_scope 2>/dev/null",
     "all-zero info disclosure"),
    ("root-processes", "services", "info",
     "ps auxww 2>/dev/null | awk '$1==\"root\"{print $11}' | sort -u | head -25",
     "unexpected root services"),
]

DEFAULT_SUID_PATHS = {'/usr/bin/su', '/usr/bin/sudo', '/usr/bin/passwd', '/usr/bin/mount',
                      '/usr/bin/umount', '/usr/bin/chsh', '/usr/bin/chfn', '/usr/bin/newgrp',
                      '/usr/bin/gpasswd', '/usr/bin/pkexec', '/usr/lib/openssh/ssh-keysign',
                      '/bin/su', '/bin/mount', '/bin/umount', '/bin/ping'}


def analyze(check_id, output):
    """Turn raw command output into findings-worthy lines."""
    hits = []
    if check_id == 'sudo-rights':
        if 'NOPASSWD' in output or '(ALL)' in output:
            hits.append('sudo rights include NOPASSWD or (ALL)')
    elif check_id == 'suid':
        for line in output.splitlines():
            path = line.strip()
            if path and path not in DEFAULT_SUID_PATHS and path.startswith('/'):
                hits.append(f'non-default SUID: {path}')
    elif check_id == 'uid0-users':
        users = [u for u in output.split() if u != 'root']
        if users:
            hits.append(f'UID-0 users besides root: {", ".join(users)}')
    elif check_id == 'world-writable-files':
        hits.extend(l.strip() for l in output.splitlines() if l.strip())
    elif check_id == 'capabilities':
        for line in output.splitlines():
            if 'cap_setuid' in line or 'cap_sys_admin' in line or 'cap_dac_override' in line:
                hits.append(line.strip())
    elif check_id == 'writable-units':
        hits.extend(l.strip() for l in output.splitlines() if l.strip())
    elif check_id == 'priv-groups':
        for grp in ('docker', 'lxd', 'disk', 'wheel'):
            for line in output.splitlines():
                if line.startswith(f'{grp}:') and len(line.split()) > 2:
                    hits.append(f'{grp} group has members')
                    break
    elif check_id == 'key-file-perms':
        for line in output.splitlines():
            if 'shadow' in line or 'sudoers' in line:
                parts = line.split()
                if len(parts) >= 2 and parts[0].startswith('-') and \
                        parts[1] != 'root':
                    hits.append(f'{parts[-1]} owned by {parts[1]}')
        if '-rw-r--r--' in output and 'shadow' in output:
            hits.append('/etc/shadow world-readable')
    elif check_id == 'nfs-exports':
        for line in output.splitlines():
            if 'no_root_squash' in line or 'insecure' in line:
                hits.append(line.strip())
    elif check_id == 'sshd-posture':
        if re_search('permitrootlogin yes', output):
            hits.append('sshd PermitRootLogin yes')
        if re_search('passwordauthentication yes', output):
            hits.append('sshd PasswordAuthentication yes')
    elif check_id == 'path-audit':
        hits.extend(l.strip() for l in output.splitlines() if 'writable:' in l)
    return hits


def re_search(pattern, text):
    import re
    return re.search(pattern, text, re.IGNORECASE) is not None


def kernel_cve_suggest(uname_line):
    """uname -r vs the curated kernel CVE list (candidate - verify manually)."""
    import re
    db = load_json_data("kernel_exploits.json") or []
    m = re.search(r'(\d+)\.(\d+)\.(\d+)', uname_line)
    if not m:
        return []
    version = tuple(int(g) for g in m.groups())
    out = []
    for entry in db:
        try:
            lo = tuple(int(x) for x in entry['min'].split('.'))
            hi = tuple(int(x) for x in entry['max'].split('.'))
            if lo <= version <= hi:
                out.append(entry)
        except (ValueError, KeyError):
            continue
    return out


def add_arguments(parser):
    parser.add_argument('target', help='Authorized target IP')
    parser.add_argument('-u', '--user', required=True, help='SSH username')
    parser.add_argument('-p', '--port', type=int, default=22)
    parser.add_argument('--pass', dest='password', help='Password (prompted if omitted)')
    parser.add_argument('--checks', help='Subset: suid,cron,kernel,... (default all)')
    parser.add_argument('--timeout', type=int, default=5, help='Per-command timeout')


def run(args):
    target = args.target
    user = args.user
    password = getattr(args, 'password', None) or ''
    cmd_timeout = getattr(args, 'timeout', 5)

    if not password:
        import getpass
        password = getpass.getpass(f"  SSH password for {user}@{target}: ")

    if not HAS_PARAMIKO:
        print_error("postex needs paramiko:")
        print(f"      {Colors.CYAN}pip3 install paramiko{Colors.RESET}")
        return

    wanted = None
    if getattr(args, 'checks', None):
        wanted = {c.strip() for c in args.checks.split(',')}

    print_header("PRIVESC AUDIT", f"{user}@{target}")
    kv("Checks", len(wanted) if wanted else f"{len(CHECKS)} (all)")
    print()

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(target, port=getattr(args, 'port', 22), username=user,
                       password=password, timeout=10, allow_agent=False,
                       look_for_keys=False, banner_timeout=15)
    except Exception as e:
        print_error(f"SSH connection failed: {e}")
        return

    results = []
    all_hits = []
    for check_id, category, severity, command, note in CHECKS:
        if wanted and check_id not in wanted:
            continue
        try:
            _stdin, stdout, stderr = client.exec_command(command,
                                                         timeout=cmd_timeout)
            output = stdout.read().decode(errors='replace')
            err = stderr.read().decode(errors='replace').strip()
        except Exception as e:
            results.append((check_id, category, 'error', str(e)))
            continue

        if not output.strip() and not err:
            results.append((check_id, category, 'empty', ''))
            continue

        hits = analyze(check_id, output)
        results.append((check_id, category, severity if hits else 'info', output))
        for hit in hits:
            all_hits.append((check_id, category, severity, hit))
        audit.log("postex-check", target=target, check=check_id,
                  hits=len(hits))

        # Print per check
        if hits:
            for hit in hits:
                color = getattr(Colors, 'BRIGHT_RED' if severity in ('high', 'critical')
                                else 'BRIGHT_YELLOW')
                print(f"  {color}[!]{Colors.RESET} [{check_id}] {hit}")
                findings.make(family=f"postex-{check_id}", title=hit,
                              severity=severity, target=target,
                              evidence=output[:300],
                              remediation=note, tool="postex")
        elif output.strip():
            first = output.strip().splitlines()[0][:72]
            print(f"  {Colors.DIM}[·] [{check_id:<17}] {first}{Colors.RESET}")

    # Kernel CVE suggestion (detection only)
    os_output = next((o for cid, _c, _s, o in results if cid == 'os'), '')
    if os_output:
        cves = kernel_cve_suggest(os_output.splitlines()[0] if os_output else '')
        if cves:
            print()
            for cve in cves:
                print(f"  {Colors.BRIGHT_MAGENTA}[?]{Colors.RESET} kernel candidate: "
                      f"{Colors.BOLD}{cve['id']}{Colors.RESET} {cve['title']} "
                      f"{Colors.DIM}(verify manually){Colors.RESET}")
                findings.make(family="kernel-cve",
                              title=f"Kernel in {cve['id']} range",
                              severity="high", target=target,
                              evidence=os_output.splitlines()[0],
                              remediation=f"{cve['title']} - patch the kernel "
                                          f"(candidate - verify manually)",
                              tool="postex")

    client.close()

    print()
    counts = {}
    for _cid, _cat, sev, _o in results:
        counts[sev] = counts.get(sev, 0) + 1
    print_summary("PRIVESC AUDIT", [
        ("Checks run", len(results)),
        ("With findings", len(all_hits)),
        ("Errors", counts.get('error', 0)),
    ])

    if getattr(args, 'json', False):
        emit_json({"tool": "postex", "target": target,
                   "started": datetime.now().isoformat(timespec='seconds'),
                   "results": [{"check": cid, "severity": sev, "output": out[:2000]}
                               for cid, _c, sev, out in results]})

    if store.is_active():
        store.record_target(target, 'host', group_name='postex')
    print_success("Privilege-escalation audit completed")
