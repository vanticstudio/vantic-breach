# Vantic Breach - Project Status

> **Every wall has a way in.**

**Version:** 3.0.0  
**Last Updated:** September 29, 2026  
**Status:** 🟢 Full-suite release - 57 tools, engagement platform, all core paths tested  
**Author:** Vantic  
**Tag:** Red Teaming Tool Application

> **Background:** the expansion plan lived in **[ROADMAP.md](ROADMAP.md)** and the
> internal-network research in **[RESEARCH_INTERNAL.md](RESEARCH_INTERNAL.md)** —
> both are now **implemented**. This file tracks the state of the shipped toolkit.

---

## 📍 Current Location

```
/Users/jakevolkanovski/Desktop/pentest/vantic-breach/
```

---

## ✅ What We Have (v3.0.0)

### Platform (`vantic/core/`)
- [x] **registry** — plugin discovery; every tool declares `META`; adding a tool = 1 file (`META` + `add_arguments` + `run`); failed imports never break startup
- [x] **store** — SQLite engagement database (`~/.vantic/engagements/<name>/data.db`): targets, services, findings, runs, checkpoints; WAL + thread-local connections
- [x] **guard** — scope enforcement (allow/deny CIDR·domain·host·URL; deny wins; hostnames verified by resolved records; allow-list semantics). Exit code 3 on refusal
- [x] **audit** — append-only JSONL per engagement (every run, argv, exit code, duration)
- [x] **findings** — Finding model, dedup fingerprints, CVSS v3.1 base calculator, shared severity bands
- [x] **net** — shared HTTP client: keep-alive connections, retry/backoff, Retry-After, per-host rate limiting, redirect capture with loop/hop caps
- [x] Global flags: `--json` (machine stdout / human stderr), `--quiet`, `--engagement NAME`, exit codes 0/1/2/3/4

### Engagement workflow
```
vantic engage new acme --client 'Acme Corp' --auth-ref 'PO-1234'
vantic engage scope --allow-cidr 10.0.0.0/24 --allow-domain acme.com --deny-host 10.0.0.1
vantic engage use acme        # guard + store + audit active
  ...run any tools...         # findings/services/runs recorded
vantic jobs                  # run history
vantic report --from-store --output report.html
vantic engage off            # standalone mode
```

### Tools — 57 across 11 categories

| Category | Tools |
|----------|-------|
| **RECONNAISSANCE** | dns (records·AXFR·mailsec·SRV·reverse-CIDR·NSEC walk·wildcards), subdomain (brute·passive CT/OSINT), whois, asn (Team Cymru + geo), takeover (CNAME dangling), osint, reconapi (Shodan InternetDB) |
| **DISCOVERY** | scan (TCP/UDP·banner), nmap, synscan (scapy, SYN/FIN/NULL/XMAS/ACK), arpsweep (+passive ARP cache), osfp (TTL/window/MSS), netmap, dnssweep (PTR + stale detection) |
| **INTERNAL / AD** | namesniff (passive LLMNR/NBT-NS + WPAD), nbtquery (NBSTAT), mdnsscan, smb (dialects·signing·anon shares), smbenum (SAMR, impacket), ldap (rootDSE + anon search, raw BER), kerbprobe (AS-REQ user enum), policy (lockout read), rdp (X.224/NLA + NTLM type2), winrm, ra_sweep (VNC/SSH/telnet/TV/AnyDesk), ntlm |
| **SERVICES** | enum (banners + protocol probes), smtp (VRFY/EXPN/RCPT), snmp (raw BER), nfs (portmap/mountd), redis, memcache, mqtt, vnc |
| **WEB ANALYSIS** | web (headers·CSP-deep·cookie-audit·XSS-context·SQLi-bool-diff), http, dir (soft-404 calibration·recursive·multi-wordlist·categories·redirect fix), crawler (robots/sitemap seeds), params (hidden param discovery), jwt, cors, graphql, checks (nuclei-lite templates), webauth (basic/form) |
| **CREDENTIALS** | creds (brute + spray, delay/jitter, stop-on-success, nsr), defaults (vendor default-cred audit), mailauth (IMAP/POP3/SMTP) |
| **GATEWAY / INFRA** | gateway (identify·admin·creds·DNS posture), upnp (SSDP + IGD read-only), dhcp (rogue detection) |
| **VULNERABILITIES** | vuln (TLS·Heartbleed·POODLE·cert audit·CVE hints) |
| **EXPLOITATION** | shell (9 languages) |
| **POST-EXPLOITATION** | postex (read-only privesc audit, 24 whitelisted checks, kernel CVE suggester) |
| **ANALYSIS & REPORTING** | sniff (tcpdump + presets), report v2 (exec summary, SVG charts, findings cards, print CSS), diff, jobs |

### Menu & GUI
- Two-level interactive menu: **categories → tools → guided prompts** (risk badges; tool names also typed directly)
- GUI: registry-driven forms for all 57 tools + "Extra args" field; runs the real CLI in a subprocess

---

## 🐛 Known Issues / Limits

1. **sniff** — live capture needs root (`sudo vantic sniff`); styled fallback otherwise
2. **web** — XSS/SQLi remain reflection/context/error-signature heuristics (boolean-differential added)
3. **rdp creds** — verifies X.224 reachability (use the `rdp` tool for posture)
4. **macOS CA store** — TLS checks fall back to unverified mode and say so
5. **kerbprobe / smbenum** — raw-DER parsing is heuristic; smbenum needs optional impacket
6. **Passive sources** — crt.sh is flaky by nature (45s timeout, single retry); HackerTarget 50/day
7. **postex** — requires paramiko + an authorized unix target with password auth

---

## 📦 Dependencies

Required: Python 3.9+ (stdlib-first design)

```bash
pip3 install paramiko dnspython   # core optional (creds, dns, subdomain...)
pip3 install scapy               # synscan, arpsweep, dhcp, osfp (root)
pip3 install impacket            # smbenum (heavy - only this tool needs it)
pip3 install ldap3              # policy (authenticated reads)
pip3 install pysmb              # smb --shares
```

---

## 🏗️ Architecture

```
vantic-breach/
├── vantic.py                     # CLI entry point
├── vantic-gui.py                 # GUI entry (also --cli-run router for frozen builds)
├── vantic/
│   ├── __init__.py               # version 3.0.0
│   ├── cli.py                    # registry-driven parser/dispatch, engage, menu
│   ├── gui.py                    # registry-driven GUI
│   ├── core/                     # platform
│   │   ├── registry.py           # plugin discovery + categories
│   │   ├── store.py              # SQLite engagement store
│   │   ├── audit.py              # JSONL audit trail
│   │   ├── guard.py              # scope enforcement (exit 3)
│   │   ├── findings.py           # Finding model + CVSS v3.1
│   │   └── net.py                # shared HTTP/socket helpers
│   ├── tools/                    # 57 tool modules (name == CLI subcommand)
│   │   ├── scan.py nmap.py dns.py subdomain.py ... shell.py report.py
│   ├── utils/__init__.py         # visual system + wordlist/data resolution
│   └── data/                     # JSON databases + check templates
│       ├── service_probes.json banner_cves.json kernel_exploits.json
│       ├── router_signatures.json
│       └── checks/*.json         # 12 bundled template checks
├── wordlists/                    # directories, subdomains, passwords + defaults_*
├── app/                          # packaged editions + build_mac.sh
└── *.md                          # README, QUICKSTART, BUILD, ROADMAP, RESEARCH_INTERNAL
```

**Adding a tool = 1 file**: `vantic/tools/<name>.py` with `META` + `add_arguments(parser)` + `run(args)`. The registry wires parser, dispatch, menu, guard, audit, store and GUI automatically.

---

## 🎨 Design Goals

- **Assessment discipline** — detect / enumerate / report on authorized targets; every check ends in a finding with remediation text (ROADMAP §1/§11)
- **One engine, many faces** — CLI, menu, GUI all run the same tool modules
- **Beginner-friendly** — two-level menu with guided prompts
- **Power-user ready** — full argparse surface, `--json` machine mode, exit codes
- **Professional reports** — exec summary, SVG severity charts, print-to-PDF stylesheet

---

## 📞 Contact

**Project:** Vantic Breach  
**Version:** 3.0.0  
**Author:** Vantic  
**Tagline:** Every wall has a way in.  
**License:** MIT

---

*Last updated: September 29, 2026*
