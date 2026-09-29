# Vantic Breach v3.0.0

> **Every wall has a way in.**

A full-suite authorized-engagement red teaming toolkit: **57 tools** across
recon → discovery → enumeration → assessment → reporting, with an
engagement platform (scope guard, findings store, audit trail) and three
front ends over one engine: a styled CLI, a two-level interactive menu,
and a point-and-click GUI.

**Red Teaming Tool Application** | **By Vantic**

---

## 1. Editions — pick your interface

| Edition | How to launch | What it is |
|---------|---------------|------------|
| **CLI** | `python3 vantic.py <tool> <args>` | Direct command-line access, scriptable, `--json` machine mode |
| **Interactive menu** | `python3 vantic.py` (no args) | Categories → tools → guided prompts, risk badges |
| **GUI** (source only) | `python3 vantic-gui.py` | Sidebar + auto-generated forms + live colored output + Stop |
| **Mac app** | double-click `app/Mac app/Vantic Breach CLI.app` | Opens Terminal with the interactive menu, ad-hoc signed |
| **Windows launcher** | double-click `app/Windows app/Vantic Breach CLI.bat` | Opens the same menu in a console |

All editions drive the **same 57 tool modules** — the GUI and menu are
generated from each tool's `META` declaration, so behavior can never drift
between interfaces.

## 2. Tools (57, by category)

| Category | Tools |
|----------|-------|
| **RECONNAISSANCE** | `dns` (records·AXFR·SPF/DMARC/DKIM·SRV·reverse-CIDR·NSEC walk·wildcards) · `subdomain` (brute + passive CT/OSINT) · `whois` · `asn` (Team Cymru + geo) · `takeover` (dangling CNAME) · `osint` · `reconapi` (Shodan InternetDB, keyless) |
| **DISCOVERY** | `scan` (TCP/UDP + banner) · `nmap` · `synscan` (scapy SYN/FIN/NULL/XMAS/ACK) · `arpsweep` (active + passive) · `osfp` · `netmap` · `dnssweep` (PTR + stale records) |
| **INTERNAL / AD** | `namesniff` (passive LLMNR/NBT-NS) · `nbtquery` (NBSTAT) · `mdnsscan` · `smb` (dialects/signing/anon shares) · `smbenum` (SAMR) · `ldap` (rootDSE) · `kerbprobe` (user enum) · `policy` (lockout) · `rdp` (X.224/NLA + NTLM) · `winrm` · `ra_sweep` (VNC/SSH/telnet/TV/AnyDesk) · `ntlm` |
| **SERVICES** | `enum` (banners + probes) · `smtp` (VRFY/EXPN/RCPT) · `snmp` · `nfs` · `redis` · `memcache` · `mqtt` · `vnc` |
| **WEB ANALYSIS** | `web` (headers·CSP·cookies·XSS context·SQLi diff) · `http` · `dir` (soft-404·recursive) · `crawler` · `params` · `jwt` · `cors` · `graphql` · `checks` (templates) · `webauth` |
| **CREDENTIALS** | `creds` (brute + spray) · `defaults` (vendor defaults) · `mailauth` |
| **GATEWAY / INFRA** | `gateway` · `upnp` (IGD read-only) · `dhcp` (rogue detection) |
| **VULNERABILITIES** | `vuln` (TLS·Heartbleed·POODLE·cert·CVE hints) |
| **EXPLOITATION** | `shell` (9 languages) |
| **POST-EXPLOITATION** | `postex` (read-only privesc audit) |
| **ANALYSIS & REPORTING** | `sniff` (presets) · `report` (exec summary + SVG charts) · `diff` · `jobs` |

Every tool: `vantic <tool> -h` for options. Full listing: run `vantic` and
choose `tools`.

## 3. The engagement platform

```bash
vantic engage new acme --client 'Acme Corp' --auth-ref 'PO-1234'
vantic engage scope --allow-cidr 10.0.0.0/24 --allow-domain acme.com --deny-host 10.0.0.1
vantic engage use acme

vantic scan 10.0.0.5 --top 100        # guard checks scope; store + audit record
vantic smb 10.0.0.10                # findings accumulate
vantic report --from-store --output report.html

vantic engage off                   # standalone mode (no enforcement)
```

- **Scope guard** — allow/deny entries; deny wins; hostnames verified by
  resolved records; out-of-scope runs exit with code **3**.
- **Store** — SQLite per engagement (`~/.vantic/engagements/<name>/`):
  targets, services, findings (dedup by fingerprint), run history.
- **Audit** — append-only JSONL: every run's argv, exit code, duration.
- **Exit codes** — 0 ok · 1 error · 2 usage · 3 scope refusal · 4 interrupted.

## 4. Quick start

```bash
# CLI
python3 vantic.py scan 127.0.0.1 -p 22,80,443 --banner
python3 vantic.py dns example.com --mailsec --srv
python3 vantic.py subdomain example.com --brute --passive
python3 vantic.py web http://example.com --headers --csp --cookie-audit
python3 vantic.py report --from-store --output report.html

# Machine mode (JSON on stdout, human output on stderr)
python3 vantic.py --json scan 127.0.0.1 -p 443

# Interactive menu (categories -> tools -> guided prompts)
python3 vantic.py

# GUI
python3 vantic-gui.py

# Everything else (apps, Windows, signing): → BUILD.md
```

Useful global flags: `--json`, `--quiet`, `--engagement NAME`, `-v`
verbose tracebacks, `--no-banner`, `--color never` (clean piped output).

## 5. Project map (what lives where)

```
vantic.py                  CLI entry → vantic.cli.main()
vantic-gui.py              GUI entry; also routes --cli-run for frozen exes
vantic/
├── cli.py                 registry-driven parser/dispatch, engage, two-level menu
├── core/
│   ├── registry.py        plugin discovery, categories, reserved names
│   ├── store.py          SQLite engagement store
│   ├── audit.py          JSONL audit trail
│   ├── guard.py          scope enforcement (exit code 3)
│   ├── findings.py       Finding model + CVSS v3.1 calculator
│   └── net.py            shared HTTP client (keep-alive, rate limit, retry)
├── gui.py                 GUI: forms generated from META flow specs
├── utils/__init__.py      THE visual system: Colors, banners, tables,
│                          ProgressBar/Spinner, wordlist + data resolvers
├── tools/*.py             57 modules (filename == CLI subcommand)
└── data/                  service_probes, banner_cves, kernel_exploits,
                          router_signatures, checks/*.json templates
wordlists/                 directories, subdomains, passwords, defaults_*
app/                       packaged editions + build_mac.sh + edition README
BUILD.md                   ★ full build pipeline: source → signed app
QUICKSTART.md              fast onboarding
STATUS.md                  current state of every subsystem
ROADMAP.md / RESEARCH_INTERNAL.md   the plans this release implements
```

## 6. Architecture rules (read before editing)

1. **One file per tool.** Each `vantic/tools/<name>.py` (name == the CLI
   subcommand) declares `META` + `add_arguments(parser)` + `run(args)`.
   The registry wires parser, dispatch, menu, guard, audit, store, GUI.
2. **All output goes through `vantic.utils`.** Header panels, key/value
   rows, bordered tables, progress bars, summary panels. Never bake ANSI
   codes into function *default arguments* — `Colors` is mutable
   (`--color never` blanks it at runtime); resolve `Colors.X` at call time.
   In `--json` mode stdout is the machine stream — print through the utils
   helpers (they route) or expect your output to land in JSON.
3. **Progress must be non-tty-safe.** `ProgressBar`/`Spinner` render only
   on a TTY — piped output stays clean.
4. **Wordlists/data go through `resolve_wordlist` / `resolve_datafile`** —
   they search cwd, app bundles, the package parent and `_MEIPASS`.
5. **Optional deps follow the try/except `HAS_X` pattern** — degrade
   gracefully with install hints, never crash.
6. **The GUI and menu never import tool code.** New capabilities enter
   through the `META["flow"]` + CLI argv surface only.

## 7. Adding a new tool (1 file)

Create `vantic/tools/<name>.py` with `META` (name/title/category/
description/risk/examples/flow/guard), `add_arguments(parser)`, and
`run(args)` — see `BUILD.md` §10 for a worked example. The registry picks
it up everywhere (parser, menu, GUI, guard, audit, store). Users can also
drop plugins into `~/.vantic/plugins/`.

## 8. Build & packaging

Everything about turning this source into applications — macOS bundle
anatomy, the one-click Windows exe, self-signing on both platforms
(`codesign -s -` / `New-SelfSignedCertificate` + `signtool`), and the
packaging gotchas we hit and fixed — lives in **[BUILD.md](BUILD.md)**.

Note: signing is **not** done with Wine (that runs Windows software); macOS
uses built-in `codesign`, Windows uses built-in PowerShell/signtool.

## 9. Dependencies

```bash
pip3 install paramiko dnspython   # creds, dns/subdomain (core optional)
pip3 install scapy                # synscan, arpsweep, dhcp, osfp (needs root)
pip3 install impacket            # smbenum only (heavy)
pip3 install ldap3               # policy only
pip3 install pysmb               # smb --shares only
```
Everything else is Python stdlib (tkinter included with python.org
installers). Missing optional deps degrade gracefully with install hints.

## 10. Testing discipline

Safe targets: `127.0.0.1`, your own lab, public reference domains
(`example.com`) for DNS/HTTP reads. Never scan or brute-force systems you
don't own or lack written authorization for — these tools are for
authorized red-team engagements. Every check is detect / enumerate /
report: findings carry severity, evidence and remediation text.

## 11. Handoff notes for AI assistants

- Start: this README → `STATUS.md` (state of every subsystem) →
  `BUILD.md` (packaging + §10 extension recipe) →
  `vantic/utils/__init__.py` (output conventions) →
  `ROADMAP.md` / `RESEARCH_INTERNAL.md` (the plans 3.0.0 implements).
- The interactive menu and GUI are generated from `META` — adding fields
  to `META["flow"]` updates both at once.
- Bundled apps (`app/`) contain **copies**; after edits rerun
  `app/build_mac.sh`. The Windows launcher is a plain `.bat`.
- Known limitations are listed honestly in `STATUS.md` → Known Issues.

## 12. License

MIT — free for personal and commercial use.

---

**Vantic Breach v3.0.0** | *Every wall has a way in.*
**Red Teaming Tool Application** | **By Vantic**
