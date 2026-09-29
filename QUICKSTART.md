# Vantic Breach — Quick Start

> **Every wall has a way in.**

## 🚀 Three ways in

**1. GUI (recommended for browsing the toolkit)**
```bash
python3 vantic-gui.py
```
Or double-click the packaged app: `app/Mac app/Vantic Breach CLI.app`

**2. Interactive menu (categories → tools → guided prompts)**
```bash
python3 vantic.py
```
Or double-click: `app/Mac app/Vantic Breach CLI.app`

**3. Direct CLI**
```bash
cd /Users/jakevolkanovski/Desktop/pentest/vantic-breach
python3 vantic.py scan 127.0.0.1 -p 22,80,443,5000
```

## 🎯 Common commands

```bash
python3 vantic.py scan 192.168.1.1 -p 1-1000 --banner   # port range + banners
python3 vantic.py nmap 192.168.1.0/24 -p 22,80,443       # subnet host discovery
python3 vantic.py dns example.com --mailsec --srv       # SPF/DMARC/DKIM + SRV
python3 vantic.py subdomain example.com --brute --passive
python3 vantic.py web http://example.com --headers --csp --cookie-audit
python3 vantic.py dir http://target --category admin,vcs # tagged path checks
python3 vantic.py vuln 192.168.1.1 --check all --cve    # + banner CVE hints
python3 vantic.py smb 192.168.1.10                        # dialects + signing
python3 vantic.py rdp 10.0.0.5 --tls --cert               # NLA + NTLM posture
python3 vantic.py creds ssh 10.0.0.5 -u admin -w wordlists/passwords.txt --spray
python3 vantic.py shell bash --lhost 10.0.0.5 --lport 4444
python3 vantic.py report --from-store --output report.html
```

Any tool: add `-h` for all options. Machine mode: `--json` (clean JSON on
stdout, human output on stderr). `--color never` strips ANSI for logs.

## 🧰 Engagements (scope + findings + audit)

```bash
python3 vantic.py engage new acme --client 'Acme' --auth-ref 'PO-1'
python3 vantic.py engage scope --allow-cidr 10.0.0.0/24 --allow-domain acme.com
python3 vantic.py engage use acme
#   ...run tools: findings/services/runs recorded; out-of-scope = exit 3
python3 vantic.py jobs              # run history
python3 vantic.py report --from-store --output report.html
python3 vantic.py engage off
```

## 🖥️ Windows edition

No build step — copy the project to a Windows machine, install Python
(tick "Add python.exe to PATH"), double-click `app/Windows app/Vantic Breach CLI.bat`.
Details in `app/README.md`.

## 📦 Optional dependencies

```bash
pip3 install -r requirements.txt   # paramiko, dnspython, scapy, ...
```
Missing deps degrade gracefully with install hints.

## 📁 Wordlists included

- `wordlists/directories.txt` — common web paths (dir default)
- `wordlists/subdomains.txt` — common subdomains
- `wordlists/passwords.txt` — default password list
- `wordlists/router_defaults.txt` + `defaults_{ssh,ftp,http,snmp,redis}.txt`
  — vendor default credentials (gateway / defaults tools)

## 📊 Report generation

```bash
# From an engagement store (findings + services + charts):
python3 vantic.py engage use acme
python3 vantic.py report --from-store --output report.html

# From a legacy scan export:
python3 vantic.py report --input vantic_scan_127.0.0.1_*.csv --output report.html
```
Reports include an executive summary, severity donut/bar charts (inline
SVG, offline) and a print-to-PDF stylesheet.

## 📚 Where to go deeper

- **DOCS.md** — the full tool catalog and architecture rules
- **BUILD.md** — packaging: from source to self-signed apps, both platforms
- **STATUS.md** — per-subsystem status + known issues
- **app/README.md** — the packaged editions
