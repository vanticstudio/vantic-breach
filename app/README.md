# Vantic Breach — Application Editions

> **Every wall has a way in.** | Red Teaming Tool Application | By Vantic

Each platform folder contains exactly **one launchable item** — nothing else.
All editions run the same 13 tools; the engine lives in the project source
(`vantic/`, `vantic.py`, `wordlists/`).

```
app/
├── Mac app/
│   └── Vantic Breach CLI.app    ← double-click (Terminal + interactive menu)
├── Windows app/
│   └── Vantic Breach CLI.bat    ← double-click (console + interactive menu)
├── build_mac.sh                 ← rebuilds/re-signs the Mac app
└── README.md                    ← this file
```

## macOS

Double-click `Vantic Breach CLI.app`. Finder opens Terminal, the banner
prints, and the numbered menu appears (`q` quits).

- Built + **ad-hoc self-signed** (`codesign -s -`) — no Gatekeeper prompt for
  locally built copies.
- A downloaded copy gets one quarantine prompt; clear it with
  `xattr -dr com.apple.quarantine "Vantic Breach CLI.app"`.
- Rebuild after source edits: `cd app && ./build_mac.sh`

## Windows

Double-click `Vantic Breach CLI.bat`. A console opens with the same menu.

- One-time setup: install Python 3.8+ from python.org and tick
  **"Add python.exe to PATH"**, then copy this whole project folder over.
- The launcher tries `py`, then `python`, and prints install instructions if
  neither exists; the console stays open via `pause`.
- No build step and nothing to sign — a `.bat` is a script, not a binary.
- Optional deps: `pip install paramiko dnspython` (SSH creds / DNS enum).

## Anywhere

```bash
python3 vantic.py        # interactive menu
python3 vantic.py <tool> # direct CLI
python3 vantic-gui.py    # GUI edition (source only)
```

## Full build documentation

**[BUILD.md](../BUILD.md)** — the complete source-to-signed-application
pipeline for handoff, including the gotchas we hit and fixed (signature
seals vs `__pycache__`, Finder xattr "detritus", wordlist resolution inside
bundles, and the future Windows-exe freezing recipe).