# Vantic Breach — Build & Packaging Guide

> **Read this first.** This document is the complete, self-contained build
> manual for Vantic Breach, written for handoff: it assumes **zero** prior
> context with the project. It covers the full pipeline — from plain source
> code that is "not an application" all the way to a packaged, self-signed
> application on each platform.

**Project:** Vantic Breach — Red Teaming Tool Application
**Slogan:** *Every wall has a way in.* **Author:** Vantic
**Current version:** 2.1.0

---

## 0. Golden rules

1. **Source of truth is the repo root.** `vantic/` (the Python package),
   `vantic.py` (entry point), `wordlists/` (payload lists). Everything inside
   `app/` is a *package* of that source — never edit bundled copies directly;
   edit source and rebuild.
2. **One engine, many faces.** All interfaces (direct CLI, interactive menu,
   source-only GUI, packaged apps) run the same 13 tool modules through the
   same `argparse` command surface. No tool logic lives outside `vantic/tools/`.
3. **Everything is self-signed** (macOS: ad-hoc `codesign -s -`). Windows
   currently has no binary to sign — its launcher is a plain `.bat` script
   (§6). The signing recipe for a future Windows *binary* is in §7.
4. **Never let Python write `__pycache__` inside a signed bundle** — it
   breaks the code-signature seal. Launchers set
   `PYTHONDONTWRITEBYTECODE=1`. See §8 (Gotchas).
5. **Windows exes can only be built on Windows** (PyInstaller cannot
   cross-compile from macOS). Not needed today — §7 preserves the recipe.

---

## 1. Source-of-truth map

```
vantic-breach/                     ← project root
├── vantic.py                      CLI entry point (imports vantic.cli)
├── vantic-gui.py                  GUI entry (source-only edition; not packaged)
├── vantic/                        the Python package
│   ├── __init__.py                version/author/slogan constants
│   ├── cli.py                     registry-driven argparse + dispatch + two-level menu
│   ├── gui.py                     tkinter GUI (forms generated from META flow specs)
│   ├── core/                      platform layer
│   │   ├── registry.py            plugin discovery (name == filename), categories
│   │   ├── store.py               SQLite engagement store (~/.vantic/engagements/)
│   │   ├── audit.py               JSONL audit trail per engagement
│   │   ├── guard.py               scope enforcement (exit code 3)
│   │   ├── findings.py            Finding model + CVSS v3.1 calculator
│   │   └── net.py                 shared HTTP client (keep-alive, rate limit, retry)
│   ├── utils/__init__.py          visual system: Colors, banners, tables,
│   │                              ProgressBar, Spinner, wordlist/data resolvers
│   ├── tools/                     57 tool modules (filename == CLI subcommand)
│   │   ├── scan.py nmap.py dns.py subdomain.py whois.py asn.py
│   │   ├── takeover.py osint.py reconapi.py
│   │   ├── synscan.py arpsweep.py osfp.py netmap.py dnssweep.py
│   │   ├── namesniff.py nbtquery.py mdnsscan.py smb.py smbenum.py
│   │   ├── ldap.py kerbprobe.py policy.py rdp.py winrm.py ra_sweep.py ntlm.py
│   │   ├── enum.py smtp.py snmp.py nfs.py redis.py memcache.py mqtt.py vnc.py
│   │   ├── web.py http.py dir.py crawler.py params.py jwt.py cors.py
│   │   ├── graphql.py checks.py webauth.py
│   │   ├── creds.py defaults.py mailauth.py
│   │   ├── gateway.py upnp.py dhcp.py
│   │   ├── vuln.py shell.py postex.py
│   │   └── sniff.py report.py diff.py jobs.py
│   └── data/                      JSON databases + check templates
│       ├── service_probes.json   banner_cves.json kernel_exploits.json
│       ├── router_signatures.json
│       └── checks/*.json          bundled template checks (checks tool)
├── wordlists/
│   ├── directories.txt            default web paths (dir default)
│   ├── subdomains.txt             default subdomain list
│   ├── passwords.txt              default password list (creds)
│   ├── router_defaults.txt        vendor default creds (gateway/defaults)
│   └── defaults_{ssh,ftp,http,snmp,redis}.txt
├── app/                           packaged editions (this guide's output)
│   ├── Mac app/
│   │   └── Vantic Breach CLI.app  CLI edition — double-click → Terminal menu
│   ├── Windows app/
│   │   └── Vantic Breach CLI.bat  double-click launcher for the menu
│   ├── build_mac.sh               build + ad-hoc sign (§5)
│   └── README.md                  editions guide
├── README.md                      user + developer/AI guide
├── QUICKSTART.md                  fast onboarding
├── STATUS.md                      project status
├── ROADMAP.md                     expansion plan (implemented in 3.0.0)
├── RESEARCH_INTERNAL.md           internal-network research brief (implemented)
├── BUILD.md                       ← this file
└── requirements.txt               optional deps
```

### How the pieces connect

```
                ┌──────────────────────────────────────────┐
                │              vantic/tools/*              │
                │   57 modules, META + add_arguments + run │
                └───────────────┬──────────────────────────┘
                                │ discovered by
                ┌───────────────┴──────────────────────┐
                │        vantic/core/registry.py        │
                │  parser loops META · dispatch = run() │
                │  guard → audit → store wrap every run │
                └───────────────┬──────────────────────┘
                                │
              ┌─────────────────┴──────────────────┐
              │           vantic/cli.py            │
              │  argparse + engage + two-level menu │
              └───────┬───────────────────┬────────┘
                      │                   │
        python3 vantic.py <args>       vantic gui / vantic-gui.py
           (CLI + menu)                (GUI builds argv from META flow,
                      │                 spawns CLI in a subprocess)
              ┌───────┴──────────────────────┐
              │  app/Mac app/Vantic Breach CLI.app    (macOS bundle)
              │  app/Windows app/Vantic Breach CLI.bat (Windows launcher)
              └──────────────────────────────┘
```

The GUI never imports tool code either: its forms are generated from each
tool's `META["flow"]` spec (the same data the interactive menu uses), and it
spawns the CLI in a subprocess, so Stop = kill process and interfaces can
never drift.

---

## 2. What "an application" means on each platform

### macOS: an `.app` bundle
A macOS app is a directory named `Something.app` with this skeleton:

```
Vantic Breach CLI.app/
└── Contents/
    ├── Info.plist      identity card (name, ID, version — §4 step 4)
    ├── Resources/      (icons would go here; currently empty)
    └── MacOS/
        ├── launcher    the executable Finder runs (bash script)
        ├── vantic.py   CLI entry
        ├── vantic/     the whole Python package (copy)
        └── wordlists/  payload lists (copy)
```

Double-clicking runs `launcher`, which opens Terminal inside the bundle
directory running `vantic.py` → banner + interactive menu.

### Windows: a `.bat` launcher
No build, no binary. `Vantic Breach CLI.bat` resolves the project root (two
directories up from itself), finds Python (`py`, then `python`) and runs
`vantic.py` in a console window that stays open (`pause`). There is nothing
to compile and nothing to sign — batch files are scripts, not binaries.

---

## 3. From nothing to application — the pipeline at a glance

| Stage | macOS | Windows |
|-------|-------|---------|
| 1. Raw source | repo root only | repo root only |
| 2. Copy source into a container | `.app` bundle skeleton (§4) | project folder as-is |
| 3. Add a launcher | `Contents/MacOS/launcher` + `Info.plist` | `Vantic Breach CLI.bat` (shipped) |
| 4. Make it "an app" | Finder recognizes the bundle; ad-hoc `codesign` seal | Windows associates `.bat` with cmd.exe natively |
| 5. Verify | `codesign -v` + menu smoke test (§4 step 7) | double-click, menu appears |

---

## 4. macOS build — manual, command by command

`app/build_mac.sh` automates exactly these steps; run them by hand
only to understand each one. `$APP` = `app/Mac app/Vantic Breach CLI.app`.

### Step 1 — skeleton
```bash
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
```

### Step 2 — copy the source in
```bash
cp vantic.py "$APP/Contents/MacOS/"
rsync -a --exclude='__pycache__' vantic/ "$APP/Contents/MacOS/vantic/"
mkdir -p "$APP/Contents/MacOS/wordlists"
cp wordlists/*.txt "$APP/Contents/MacOS/wordlists/"
```
**Exclude `__pycache__`** — stale bytecode breaks signatures and hides edits.

### Step 3 — the launcher
```bash
cat > "$APP/Contents/MacOS/launcher" << 'EOF'
#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
osascript -e 'tell application "Terminal" to activate' \
          -e "tell application \"Terminal\" to do script \"PYTHONDONTWRITEBYTECODE=1 python3 '$DIR/vantic.py'\"" \
          > /dev/null 2>&1 &
exit 0
EOF
chmod +x "$APP/Contents/MacOS/launcher"
```
`PYTHONDONTWRITEBYTECODE=1` is not cosmetic — §8 Gotcha #2.

### Step 4 — Info.plist
```bash
cat > "$APP/Contents/Info.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>     <string>launcher</string>
    <key>CFBundleIdentifier</key>     <string>com.vantic.breach</string>
    <key>CFBundleName</key>           <string>Vantic Breach</string>
    <key>CFBundleDisplayName</key>    <string>Vantic Breach</string>
    <key>CFBundlePackageType</key>    <string>APPL</string>
    <key>CFBundleShortVersionString</key> <string>2.1.0</string>
    <key>CFBundleVersion</key>        <string>4</string>
    <key>LSMinimumSystemVersion</key> <string>10.15</string>
    <key>NSHighResolutionCapable</key> <true/>
</dict>
</plist>
EOF
```
`CFBundleExecutable` must match the launcher filename. Bump the version keys
together with `vantic/__init__.py`.

### Step 5 — scrub Finder metadata
```bash
find "$APP" -name '.DS_Store' -delete
xattr -cr "$APP"
```
Why: `codesign` refuses bundles carrying Finder xattrs/resource forks with
*"resource fork, Finder information, or similar detritus not allowed"*.

### Step 6 — self-sign (ad-hoc)
```bash
codesign --force --deep -s - "$APP"
```
`-s -` = sign with no identity = **ad-hoc**, macOS's native "self-signed".
`--force` overwrites, `--deep` covers nested code.

### Step 7 — verify + smoke test
```bash
codesign -dv "$APP"   # expect: flags=0x2(adhoc), Identifier=com.vantic.breach
codesign -v  "$APP"   # expect: silence = valid
PYTHONDONTWRITEBYTECODE=1 python3 "$APP/Contents/MacOS/vantic.py" -V
# expect: Vantic Breach v2.1.0 | by Vantic
```
(Always use `PYTHONDONTWRITEBYTECODE=1` when invoking bundled Python by hand,
or you will recreate Gotcha #2 on the spot — we did.)

---

## 5. macOS scripted build

```bash
cd app
./build_mac.sh          # full build + ad-hoc sign
./build_mac.sh --sign   # re-sign existing bundle only
```

`build_mac.sh`: resolve ROOT (two dirs up) → wipe + rebuild the bundle
(copy source, write Info.plist, write launcher) → `sign()` (.DS_Store delete,
`xattr -cr`, `codesign --force --deep -s -`) → print `codesign -dv` proof.

**After any source edit, rerun the full script** — bundles are copies.
**Prefer a full rebuild over `--sign`** after touching bundle contents by
hand: partial edits can leave metadata that only a clean rebuild scrubs
(§8 Gotcha #7).

---

## 6. Windows "build" — copy and double-click

There is no compile stage:

1. Install Python 3.8+ from python.org (**"Add python.exe to PATH"**).
2. Copy the entire `vantic-breach` folder to the machine.
3. Double-click `app\Windows app\Vantic Breach CLI.bat`.

The launcher: `cd /d "%~dp0..\.."` (project root) → try `py vantic.py` →
fallback `python vantic.py` → friendly install instructions if neither
exists → `pause` so the console stays open. Portable as-is: no installer,
no registry, no signing (scripts don't carry signatures). Windows SmartScreen
may show a one-time "unknown publisher" notice for downloaded scripts —
normal for all scripts.

---

## 7. Appendix — freezing the GUI into an EXE (future option)

The GUI exists as source (`python3 vantic-gui.py` / `vantic gui`). If a
double-clickable no-Python-required exe is ever wanted, build it **on
Windows** (never from macOS — PyInstaller can't cross-compile):

```bat
python -m pip install pyinstaller paramiko dnspython
python -m PyInstaller --noconfirm --onefile --windowed --name "VanticBreach" ^
  --paths "<project root>" ^
  --add-data "<project root>\wordlists;wordlists" ^
  --hidden-import vantic.cli --hidden-import vantic.gui ^
  "<project root>\vantic-gui.py"
```

Four load-bearing details learned while building this before:
1. `--windowed` (no console flash) means the spawned child has
   `sys.stdout=None` — `vantic-gui.py`'s `--cli-run` branch reopens fds 1/2.
2. The exe respawns **itself** with `--cli-run <tool args>` per run (the
   frozen exe has no interpreter to spawn) — that keeps Stop working.
3. `--add-data wordlists;wordlists` unpacks to `sys._MEIPASS/wordlists` at
   runtime — `vantic.utils.resolve_wordlist` already checks it first.
4. `--hidden-import vantic.cli vantic.gui` — their imports are lazy from
   `vantic-gui.py`; static analysis would miss them.

Self-sign a future exe in PowerShell:
```powershell
New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Vantic" `
  -KeyUsage DigitalSignature -CertStoreLocation Cert:\CurrentUser\My
Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
  Sort-Object NotBefore -Descending | Select-Object -First 1 |
  Format-List Subject, Thumbprint
Set-AuthenticodeSignature -FilePath ".\VanticBreach.exe" `
  -Certificate (Get-ChildItem Cert:\CurrentUser\My\<THUMBPRINT>)
```
Note: "Wine" has nothing to do with signing (it *runs* Windows software on
other systems). Signing = `codesign` (macOS, built in) /
PowerShell+`signtool` (Windows, built in). Self-signed exes always show
SmartScreen's "unknown publisher" once per machine — inherent, not a bug.

---

## 8. Gotchas we actually hit (learned the hard way)

| # | Symptom | Cause | Fix |
|---|---------|-------|-----|
| 1 | `codesign: resource fork, Finder information, or similar detritus not allowed` | Finder xattrs / .DS_Store inside bundle | `find "$APP" -name .DS_Store -delete; xattr -cr "$APP"` before signing |
| 1b | Same detritus error **even though sign() strips first** — intermittently | Desktop under iCloud sync (fileprovider) re-attaches xattrs between the strip and the signature | `build_mac.sh` sign() verifies + retries up to 3× (strip → sign → verify) |
| 2 | Signature invalid/missing after an app was **run** | Python wrote `__pycache__` into the signed bundle → seal mismatch | Launchers set `PYTHONDONTWRITEBYTECODE=1`; exclude caches in rsync; re-sign after bundle surgery |
| 3 | `--sign` after manual bundle edits still fails codesign | partial edits leave fresh metadata behind | prefer a full `build_mac.sh` rebuild over `--sign` |
| 4 | Tool can't find `wordlists/directories.txt` | wordlists live next to the package, not the script | `vantic.utils.resolve_wordlist` searches cwd, exe dir, package parent, `_MEIPASS` — don't bypass it |
| 5 | Edited source but the app behaves old | apps run **copies** of source | rerun `build_mac.sh` after edits |
| 6 | App "opens" but nothing happens | `python3` missing from PATH, or wrong cwd | launcher uses `$(dirname "$0")` absolute paths; test per §4 step 7 |

---

## 9. Release checklist (from zero, every time)

1. Bump `__version__` in `vantic/__init__.py` (+ Info.plist versions).
2. `python3 -m py_compile vantic.py vantic-gui.py vantic/cli.py vantic/utils/__init__.py vantic/tools/*.py`
3. CLI smoke: `python3 vantic.py scan 127.0.0.1 -p 5000` and
   `python3 vantic.py shell bash --lhost 10.0.0.5 --lport 4444`
4. Menu smoke: `printf 'q\n' | python3 vantic.py` → banner + menu + clean quit
5. GUI smoke (source edition): `python3 vantic-gui.py --smoke` → `GUI_SMOKE_OK`
6. macOS: `cd app && ./build_mac.sh` → `codesign -v` clean.
7. Windows: copy project, double-click the `.bat`, menu opens.
8. Update `STATUS.md` if tool status changed.

---

## 10. Extending the toolkit (for the incoming AI)

Adding a new tool touches exactly **one place**: create
`vantic/tools/<name>.py` (filename must equal the CLI subcommand) with:

```python
META = {
    "name": "ctlog",               # == filename stem
    "title": "CT Log Lookup",
    "category": "RECONNAISSANCE", # one of registry.CATEGORY_ORDER
    "description": "one-line summary",
    "risk": "safe",                # safe | intrusive | destructive
    "examples": ["vantic ctlog example.com"],
    "flow": [                      # menu + GUI prompts (shared spec)
        ("arg", "domain", "Domain", None),          # positional (None default = required)
        ("opt", "--fast", "Fast mode", ""),          # option with a value
        ("flag", "--json-out", "Extra JSON?", ),    # boolean flag
        ("sub", "mode", "Mode (a/b)", "a"),          # subcommand (add "choices")
    ],
    "guard": {"domain": "domain"}, # scope-guard arg mapping (optional)
    "choices": {"mode": ["a", "b"]},  # sub values (if using "sub")
}

def add_arguments(parser):          # argparse subparser
    parser.add_argument("domain")
    ...

def run(args):                     # execute
    ...
```

The registry wires it into argparse, dispatch, the two-level menu, the
scope guard, the audit log, the store and the GUI automatically. Print
through `vantic.utils` helpers (`print_header`, `kv`, `print_table`,
`ProgressBar`, `print_summary`) so output matches the house style and
survives `--color never` (never bake ANSI codes into default arguments —
resolve `Colors.*` at call time). Optional deps follow the try/except
`HAS_X` pattern. Users can also drop plugins into `~/.vantic/plugins/`.

Then rebuild (§9). The menu and GUI pick the tool up automatically.

### Testing without attacking anything
Safe targets: `127.0.0.1`, your own lab, public reference domains
(`example.com`) for DNS/HTTP reads. Never scan or brute-force systems you
don't own or lack written authorization for — the tools exist for authorized
red-team work; keep the testing discipline too.

---

*Vantic Breach 3.0.0 | Every wall has a way in. | By Vantic*