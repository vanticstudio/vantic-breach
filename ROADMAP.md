# Vantic Breach — v2.x Expansion Roadmap

> **Every wall has a way in.** | Red Teaming Tool Application | By Vantic

**This document is the handoff brief.** It is written for an AI (or engineer)
taking over development of the Vantic Breach toolkit. It assumes zero prior
conversation: everything needed to plan and execute the expansion is here,
plus pointers into the existing docs.

**Companion reading (in this order):**
1. `README.md` — what the project is, architecture rules (§6), how to add a tool (§7)
2. `ROADMAP.md` — this file
3. `RESEARCH_INTERNAL.md` — research brief for the internal-network / RDP /
   gateway / authentication expansion (module specs, findings taxonomies,
   pitfalls, build order for that phase)
4. `BUILD.md` — source-to-signed-app pipeline, packaging gotchas
5. `STATUS.md` — current per-tool state and known issues
6. `vantic/utils/__init__.py` — the output system every tool must use

**Current state at handoff:** v2.1.0. Python 3.12, stdlib-first (urllib/socket),
optional deps `paramiko` + `dnspython` (graceful-fallback pattern). 13 working
tools: `scan`, `nmap`, `dns`, `subdomain`, `web`, `http`, `dir`, `creds`,
`vuln`, `shell`, `enum`, `sniff`, `report`. All verified against localhost and
public reference domains.

---

## 1. Mission and hard rules

**Mission:** grow Vantic Breach into a full authorized-engagement toolkit —
recon → enumeration → assessment → audit → professional reporting — while
keeping it a single coherent Python codebase that a beginner can run and a
professional can trust.

**Hard rules (non-negotiable, inherited from the project):**

1. **Authorized engagements only.** Every tool exists for systems the
   operator owns or has written authorization to test. §9 adds technical
   enforcement (scope guard).
2. **Assessment discipline.** All modules are detect / enumerate / report.
   No config changes on targets, no data destruction, no persistence,
   no stealth/evasion/anti-AV work, no credential-theft-from-endpoint
   tooling. Read-only audits (§7 postex) list weaknesses so they can be
   reported and fixed — that is the whole point.
3. **One engine, many faces.** Tools live in `vantic/tools/<name>.py` and
   expose `run(args)` taking an `argparse.Namespace`. The CLI surface is
   argparse subcommands in `vantic/cli.py`. The GUI never imports tool code —
   it builds argv and spawns the CLI.
4. **Output goes through `vantic/utils`.** `print_header`, `print_subheader`,
   `kv`, `print_table`, `print_summary`, `ProgressBar`, `Spinner`,
   `status_badge`. Never `print()` raw styled text from tools. Never bake
   ANSI codes into default arguments (resolve `Colors.*` at call time —
   `--color never` blanks them at runtime). Everything must be non-tty-safe.
5. **Wordlists via `resolve_wordlist(path, name)`** — it searches cwd, the
   executable's folder (app bundles), the package parent, and PyInstaller's
   `sys._MEIPASS`. Don't open wordlist files directly.
6. **Optional dependencies follow the try/except pattern** (`HAS_PARAMIKO`,
   `HAS_DNSPYTHON` in existing tools): degrade gracefully, print the install
   command, never crash.
7. **Test against `127.0.0.1`, your own lab, or public reference domains
   (`example.com`).** Never test scanning/brute-force against third-party
   systems.

**Extension touchpoints today (6):** tools module → `tools/__init__.py` →
`cli.py:build_parser()` → `cli.py:dispatch()` → `cli.py:FLOWS` (menu prompt) →
`gui.py:SPECS`. Wave 1's registry (§3.1) reduces this to 2 — see its spec.

**Effort legend:** S ≤ 1 day · M 1–3 days · L 3–5+ days.
**Priority:** P0 = next release · P1 = following release · P2 = backlog.

---

## 2. Build order (dependency-aware)

The waves are ordered so nothing blocks anything else:

```
WAVE 1 (P0) — foundation + force multipliers
  3.1 registry        3.2 scope/guard      3.3 store (SQLite)
  3.4 net helpers     3.5 audit log        3.6 --json/--quiet
  → then: passive, wildcard+DNS upgrades, probes engine, creds engine,
          dirbuster soft-404, postex, banner+JSON exports

WAVE 2 (P1) — breadth
  crawler → params → jwt → cors → graphql (web chain)
  synscan → osfp (needs scapy + root)
  smb, smtp, ldap, nfs, rdp, vnc, mqtt, redis, memcache (service enum)
  asn, whois, takeover (recon chain)
  findings/CVSS model → report v2 → jobs/resume

WAVE 3 (P2) — depth and polish
  dhcp, kerberos, recon-api (keyed), osint harvest, config/profiles,
  scan diff, PDF export, color depth, UDP payload probes, cache snoop,
  STARTTLS, sniff presets, subdomain permutations
```

---

## 3. Wave 1 — P0 modules and upgrades

### 3.1 `registry` — plugin system + auto-registration (M, P0)

Reduces the 6-touchpoint pattern to **2** (create the file; optionally add
GUI fields). Discover tools by scanning `vantic/tools/` via
`pkgutil.iter_modules` + optional `~/.vantic/plugins/` via
`importlib.util.spec_from_file_location`. A failed import disables that one
tool with a warning — it never crashes startup (Recon-ng's pattern).

Minimal contract every tool adopts (no framework class):

```python
META = {
    "name": "ctlog",              # subcommand; keep == filename
    "title": "CT Log Lookup",
    "category": "RECONNAISSANCE", # matches TOOL_CATEGORIES names
    "description": "Certificate-transparency subdomain discovery",
    "risk": "safe",               # 'safe' | 'intrusive' | 'destructive'
    "examples": ["vantic ctlog example.com"],
}

def add_arguments(parser):        # replaces the build_parser() block
    parser.add_argument("domain")

def run(args):                    # unchanged existing convention
    ...
```

- `build_parser()` loops the registry; `TOOL_CATEGORIES` is generated from
  `META["category"]`; epilog examples from `META["examples"]`.
- `dispatch()` becomes `mod.run(args)` after the scope guard — the elif chain
  dies.
- Menu `FLOWS`: default flow auto-prompts only required positionals;
  `META.get("flow")` can override.
- GUI `SPECS`: built-ins keep hand-tuned specs; plugins get auto-specs from
  `META.get("gui_fields")` or a single free-text args field.
- **Pitfalls:** plugin imports run top-level code — enforce
  "META + function defs only", catch everything per module, denylist reserved
  names (`report`, `gui`, `jobs`, `diff`). Keep `tools/__init__.py` imports
  for the frozen-EXE path (`--collect-submodules vantic.tools`); the `.app`
  copies source files so dynamic discovery is fine there.
- **Update `BUILD.md` §10 in the same change** when touchpoints drop from 6
  to 2, or future contributors re-add dead elif branches.

### 3.2 `guard` — scope & engagement enforcement (M, P0)

Engagement directories `~/.vantic/engagements/<name>/`; scope table of
in/out CIDRs, domains (wildcards), URLs; engagement metadata (client, dates,
authorization reference). Central `assert_allowed(tool_meta, args)` called in
`dispatch()` before every run.

**The load-bearing detail:** scope checks must verify **resolved A/AAAA
records**, not name strings — `sub.acme.com` (in scope) can CNAME to a CDN
you must not touch, and brute-forced hosts can point anywhere. Explicit
out-of-scope entries beat wildcard in-scope entries. Long scans re-resolve at
request time (DNS rebinding) or pin the validated IP. `--recursive` subdomain
walking stops at third-party registrable domains.

Exit code `3` = scope refusal (see §3.6).

### 3.3 `store` — SQLite data layer (L, P0)

One `data.db` per engagement (Recon-ng workspace pattern), plus a JSONL
audit-log sidecar. Tools dual-write: record to the store **and** keep their
existing CSV/JSON exports — zero breakage, incremental migration.

```sql
PRAGMA journal_mode=WAL;
CREATE TABLE engagements (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL,
  client TEXT, start_date TEXT, end_date TEXT, auth_ref TEXT, created_at TEXT NOT NULL);
CREATE TABLE scopes (id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('cidr','domain','url','host')),
  value TEXT NOT NULL, allowed INTEGER NOT NULL DEFAULT 1,
  UNIQUE(engagement_id, kind, value));
CREATE TABLE targets (id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id),
  kind TEXT CHECK (kind IN ('host','domain','url','service')),
  value TEXT NOT NULL, group_name TEXT,
  first_seen TEXT, last_seen TEXT, UNIQUE(engagement_id, kind, value));
CREATE TABLE services (id INTEGER PRIMARY KEY,
  target_id INTEGER NOT NULL REFERENCES targets(id),
  port INTEGER NOT NULL, protocol TEXT NOT NULL DEFAULT 'tcp',
  state TEXT DEFAULT 'open', service_name TEXT, banner TEXT,
  source_tool TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  UNIQUE(target_id, port, protocol));
CREATE TABLE findings (id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id),
  fingerprint TEXT NOT NULL,   -- sha256(family|target|port|instance-key) → dedup
  family TEXT NOT NULL, title TEXT NOT NULL,
  severity TEXT CHECK (severity IN ('info','low','medium','high','critical')),
  cvss_vector TEXT, cvss_score REAL,
  target_id INTEGER REFERENCES targets(id), port INTEGER,
  evidence TEXT, status TEXT DEFAULT 'open',
  tool TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  UNIQUE(engagement_id, fingerprint));
CREATE TABLE runs (id INTEGER PRIMARY KEY,
  engagement_id INTEGER REFERENCES engagements(id),
  tool TEXT NOT NULL, argv TEXT NOT NULL, started_at TEXT NOT NULL,
  finished_at TEXT, exit_code INTEGER, stats TEXT);
CREATE TABLE checkpoints (run_id INTEGER PRIMARY KEY REFERENCES runs(id),
  wordlist TEXT, offset INTEGER, updated_at TEXT);
CREATE TABLE notes (id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL, target_id INTEGER,
  body TEXT, created_at TEXT NOT NULL);
```

Schema evolution via `PRAGMA user_version` + staged migrations. Migration
path: dual-write → `report --engagement <name>` as alternative to `--input` →
`vantic import --csv old.csv --engagement x` backfills legacy files.

**Pitfall (critical):** a `sqlite3.Connection` is single-thread by default —
use thread-local connections or short-lived per-batch connections; set
`journal_mode=WAL` + `busy_timeout=5000`; wrap batch inserts in one
`executemany` transaction. The GUI's subprocess model coexists fine with WAL;
never share a connection across the spawn boundary. Checkpoint writes are
bounded (every N items, never per item); insert findings **before** bumping a
resume offset so a kill never loses results.

### 3.4 `net` — shared HTTP/socket helpers (M, P0)

One place for: a browser-realistic UA, timeouts, retry with backoff + cap,
`Retry-After` respect, a shared thread-safe token-bucket rate limiter, and
per-host concurrency semaphores. Every urllib-based tool (`web`, `http`,
`dir`, `subdomain`, new recon modules) uses it. Also: thread-local
`http.client.HTTPConnection/HTTPSConnection` pooling — urllib handshakes TLS
per request today; reuse gives ~3–5× over TLS (handle
`RemoteDisconnected`/`ConnectionResetError` with one reconnect — servers close
idle keep-alive sockets).

Flags added to `web`/`dir`: `--delay 0.2`, `--max-retries 2`, `--rate 50`.
Rolling 403/429/503 spike detection → back off + `print_warning` instead of
hammering (rate-triggered WAF blocks) — but a *single* probe returning 403
while neighbors don't is a **finding** (payload-triggered WAF signature), not
noise.

### 3.5 `audit` — command audit log (S, P0)

Append-only JSONL per engagement (`audit.jsonl`): timestamp, full argv,
engagement, guard verdict, exit code. One integration point in `dispatch()`
covers CLI + menu + GUI (the GUI spawns the CLI). This is the engagement
record — every auth attempt and probe lands in it and feeds `report`.

### 3.6 Global flags — `--json` / `--quiet` / exit codes (M, P0)

Global parent-parser flags added once, inherited by all subcommands.
`--json`: machine JSON to **stdout**, all human output routed to stderr
(utils helpers gain stream routing); the GUI's output pane depends on this
separation. Exit codes: 0 = success/no findings, 1 = error, 2 = argparse
usage, 3 = scope refusal, 4 = partial failure. Each tool emits one final JSON
doc (shape: `{"tool","target","started","results":[...]}`) so `report`,
`diff`, and `takeover` can consume any tool's output.

### 3.7 Wave-1 tool upgrades

| feature | tool | notes | flags | effort |
|---|---|---|---|---|
| Wildcard detection | `dns`, `subdomain` | Resolve 2–3 random labels against the domain's **authoritative NS** (not system resolver — ISP NXDOMAIN-hijack false positives); record wildcard IP set; suppress brute candidates whose IPs ⊆ wildcard set. Auto-run in `subdomain --brute`, opt-out `--no-wildcard` | `--wildcard` / `--no-wildcard` | M |
| Passive subdomain mode | `subdomain` | `--passive` pulls keyless sources (§10 cheat sheet), merges + dedupes, tags source attribution; per-source failure is never fatal | `--passive --sources crt.sh,otx` | L |
| Mail security audit | `dns` | SPF parse (`+all`/`?all` flags, 10-lookup limit, include expansion), DMARC (`p=none` flag), DKIM selector sweep | `--mailsec` | M |
| Reverse sweep on CIDR | `dns` | PTR sweep over expanded hosts, ThreadPool(50) + ProgressBar, hard-cap /24 unless `--force` | `--reverse-cidr 10.0.1.0/24` | S |
| SRV enumeration | `dns` | Standard service prefixes (`_ldap._tcp.dc._msdcs`, `_kerberos`, `_sip._tcp`, `_autodiscover._tcp`…) | `--srv` | S |
| NSEC zone walk | `dns` | Signed zones only; detect NSEC3 and report "walk impractical"; cap ~5,000 records, detect revisit-loops | `--walk` | M |
| Active probe engine | `enum` | Send protocol probes on open/silent ports — HTTP GET/OPTIONS, FTP `USER anonymous`+`FEAT`+`SYST`, SMTP `EHLO`+`VRFY`, TLS cert parse, SSH kex parse (§3.8 probes DB) | `--probes http,ftp,smtp,tls,ssh,auto` | M |
| Credential engine | `creds` | Spray vs brute distinction, `--delay`/`--jitter`, stop-on-success (`threading.Event` checked **inside** workers), `-e nsr` pre-pass (null / login==pass / reversed), per-service throttle defaults; lockout warning banner. Keep fresh-connection-per-attempt (dodges `MaxAuthTries`) | `--spray --delay 1 --jitter 0.3 --stop-on-success --null-first` | M |
| paramiko hygiene | `creds`, `postex` | `set_keepalive(30)`, explicit `banner_timeout`/`auth_timeout`, `auth_none` probe to report allowed auth types instead of 100 silent failures | `--keepalive 30` | S |
| Soft-404 + size filters | `dir` | Baseline nonexistent path pre-scan (status/size/word-count/body); filter via `difflib` similarity > 0.9; explicit `--filter-size/--filter-words`; `--auto-calibrate` | see §11 pitfalls | M |
| Recursive scanning | `dir` | On 200/301 directory hits enqueue one level deeper, depth+page capped | `--recursive --recursion-depth 2` | M |
| Fix `--follow-redirects` no-op | `dir` | Both branches build identical openers today — implement hop-capped redirect capture (custom `HTTPRedirectHandler`, visited-location loop detection) | bugfix | S |
| Multi-wordlist + categories | `dir`, `web` | Repeatable `-w`, merged + deduped; split hardcoded probe lists into tagged data files (admin/config/backup/vcs/cms) | `-w a.txt -w b.txt --category admin,vcs` | S |
| Banner grab on open ports | `scan`, `nmap` | recv 128 bytes after connect; turns port lists into service lists | `--banner` | S |
| SYN scan hook | `scan` | Delegate to `synscan` (§4) when root+scapy, else connect-scan fallback with warning | `--syn` | S |
| TLS cert audit | `vuln` | CN/SAN, expiry, self-signed, key size, chain | `--check cert` | S |
| Cookie attribute audit | `web`, `http` | Parse Set-Cookie: flag missing Secure/HttpOnly/SameSite, `SameSite=None` without Secure, `__Host-` violations, session-named cookies without HttpOnly | `--cookie-audit` | S |
| CSP deep parse | `web` | `unsafe-inline`/`unsafe-eval` in script-src, missing `default-src`, wildcards, absent `object-src`/`frame-ancestors` | `--csp-deep` | S |
| SQLi boolean-differential | `web` | Truthy vs falsy payload response diff (length/status) beyond error signatures | upgrade `--sqli` | M |
| XSS context awareness | `web` | Classify reflection context (raw HTML vs attribute vs `<script>` vs encoded); only flag unencoded contexts as findings | upgrade `--xss` | M |
| Kernel→CVE suggester data | `postex` | `vantic/data/kernel_exploits.json` (uname → known LPE candidates, "verify manually") | data file | S |

### 3.8 `probes` — service version detection, nmap `-sV` concept, curated (L, P0)

JSON DB `vantic/data/service_probes.json` following nmap-service-probes
semantics (NULL probe = banner already captured, `fallback` chain,
`softmatch`, `rarity`): ~40–60 entries covering SSH, HTTP, FTP, SMTP, IMAP,
POP3, MySQL, PostgreSQL, Redis, VNC, Telnet, RTSP. Consumed by
`enum --probes` and after any open-port result. **Honesty rule:** present
`product/` matches as authoritative only for covered services,
softmatch-style output otherwise — a curated DB will never approach nmap's.

### 3.9 `postex` — privilege-escalation audit, read-only (L, P0)

Runs the §8 checklist over paramiko `exec_command` on an **authorized unix
target**; each check is a `(id, command, parser, category, severity)` tuple
in a registry (`--checks suid,caps,cron,kernel` subsets work). Commands are
whitelisted, `sudo -n` only (never hangs on a password prompt), 5s timeout
per command, stderr captured, everything logged to the audit trail.
**Explicitly never reads private key contents** (`.ssh` checks list
existence/perms only). Auth reuses the creds SSHClient pattern. Kernel→CVE
output is "candidate — verify manually", detection only. Per-category tables
via `print_table`, final `print_summary`, JSON out.

---

## 4. Wave 2 — P1 modules

### Recon chain

| module | CLI | what it does | effort | deps |
|---|---|---|---|---|
| `whois` | `whois <domain> [--raw] [--contacts]` | Port-43 chain: whois.iana.org → TLD server → registrar; parse registrant/org/registrar/expiry; flag soon-expiry + privacy-protected | M | stdlib socket |
| `asn` | `asn <domain\|IP\|ASN> [--prefixes] [--geo] [--reverse]` | Team Cymru ASN (whois.cymru.com batch or TXT `origin.<ip>.origin.asn.cymru.com` reusing dnspython) → sibling prefixes; ip-api.com free tier (45/min, HTTP-only, batch 100/POST) for geo; hands CIDRs to reverse sweep | M | dnspython (opt) |
| `takeover` | `takeover --input subs.json [--probe] [--threads N]` | CNAME chain walk → dangling detection (CNAME + terminal NXDOMAIN/no A) → provider fingerprint (s3, azurewebsites, cloudfront, github.io, herokuapp, netlify, fastly, shopify, zendesk, intercom, webflow…) → optional HTTP body confirmation ("NoSuchBucket", "There isn't a GitHub Pages site here"). Confidence: HIGH = dangling+fingerprint, LOW = body-match only | L | stdlib |

### Web chain (feeds each other: `crawler → params → web`)

| module | CLI | what it does | effort |
|---|---|---|---|
| `crawler` | `crawler <url> --depth 3 --max-pages 200 --forms` | Same-origin BFS (scheme+host+port normalized before every enqueue — a redirect to a third-party host is an open-redirect *finding*, never a crawl target); seeds from robots.txt Disallow + sitemap; parses `<a href>`, `<form action>` + input names, JS string URLs; emits dedup'd `{url, method, params[], source}` | M |
| `params` | `params <url> -w params.txt --method get,post,json` | Arjun-style hidden parameter discovery: batch candidate names per request; reflection markers (reliable) + content-length anomaly vs a 2-request stabilized baseline (dynamic content like CSRF tokens adds per-request jitter — measure it first) | M |
| `jwt` | `jwt <token-or-file> --audit --none --secrets` | Offline parse + audit: exp/nbf/iat, missing exp, long-lived, missing aud/iss, kid metacharacters, jku/x5u external URLs, empty signature. Opt-in active: alg-none variants (`none,None,NONE,nOnE`), HMAC secret dictionary via stdlib hmac + wordlist. RS256→HS256 confusion = detect+flag (P2: needs `cryptography`) | M |
| `cors` | `cors <url> --origin evil.example --null` | Origin matrix: attacker origin, `null`, subdomain-parent + suffix variants, arbitrary reflection. HIGH = arbitrary origin echoed + credentials allowed; flag `ACAO:*` with credentials as config error | S |
| `graphql` | `graphql <url> --introspect --batch --suggestions` | Endpoint discovery (`/graphql`, `/api/graphql`, `/graphiql`, `/playground`…); introspection → schema summary table; GET-borne mutations; JSON-array batching accepted (enables brute force); "Did you mean" field-suggestion leakage; missing depth/complexity limits (capped deep query) | M |
| `checks` | `checks <url> --templates dir --severity high,medium` | Nuclei-lite template engine — see §5.3 | L |

### Network/service chain

| module | CLI | what it does | effort | deps |
|---|---|---|---|---|
| `synscan` | `synscan <target> --mode syn,null,fin,xmas,ack --ping-icmp --ping-tcpack 80 --rate` | scapy `sr1(IP/TCP(flags=S))`: SYN\|ACK→open, RST→closed, ICMP/timeout→filtered. `os.geteuid()` guard up front ("rerun with sudo"); special-case loopback → connect scan (scapy can't SYN-scan 127.0.0.1); cap workers ~50, rate-limit sends (`sr1` in many threads drops packets); reuse port_scanner result shape | M | scapy (opt) |
| `osfp` | `osfp <target> --port 22` | TTL guess (64=Linux, 128=Windows, 255=Cisco/BSD) + window size + DF/MSS + TCP-options ordering → "best-effort OS guess + confidence" (label it as such; nmap -O is authoritative) | M | scapy (opt) |
| `smb` | `smb <target> --port 445 --shares --info` | Anonymous/null session: share list, anonymously-readable shares, dialect (NT1 = SMB1 legacy), signing/encryption flags. pysmb for SMB1 null sessions (smbprotocol is SMB2+-only) | M | pysmb (opt) |
| `smtp` | `smtp <target> --vrfy --expn --users users.txt --delay 1` | VRFY/EXPN/RCPT user enumeration; interpret 250/251/252=exists, 550/551/553=no, 502=disabled; verbatim response logging | S | stdlib |
| `ldap` | `ldap <target> --port 389 --rootdse --search` | Anonymous bind → rootDSE (namingContexts, SASL mechanisms) → depth-1 anonymous search; LDAPS via stdlib ssl | S | ldap3 (opt) |
| `nfs` | `nfs <target> --port 111` | Raw ONC RPC/XDR: portmapper DUMP → mountd EXPORT list; flag `no_root_squash`/`insecure`; discover-only | M | stdlib |
| `rdp` | `rdp <target> --port 3389 --negotiate --ntlm-info` | X.224 connection-request + negotiate response flags (SSL/HYBRID=NLA) → NTLM SSP NEGOTIATE → disclosed NetBIOS name/domain/OS; upgrades `creds rdp` from reachability to protocol detection | S-M | stdlib |
| `vnc` | `vnc <target> --display 0` | RFB version exchange → security types; type 1 = "no authentication" flag | S | stdlib |
| `mqtt` | `mqtt <target> --port 1883 --sample 15` | Anonymous CONNECT → CONNACK rc=0x00 = anonymous allowed; 10–15s subscribe sample of `#`/`$SYS/#` (read-only snapshot); broker version | M | raw / paho-mqtt (opt) |
| `redis` | `redis <target> --port 6379 --sample 50` | Raw RESP: PING, INFO, DBSIZE, CONFIG GET (never SET), SCAN sample; unauth + version + exposure verdict — one of the highest-hit internal findings | S | stdlib |
| `memcache` | `memcache <target> --port 11211 --udp` | `version\r\n` + `stats\r\n` on TCP and UDP; no-auth + version + item counts | S | stdlib |

### Platform

| feature | notes | effort |
|---|---|---|
| `findings` model + CVSS | Finding dataclass, dedup fingerprint, CVSS v3.1 base calculator (~150 lines, stdlib); v4.0 = store/display the vector, don't compute. Severity bands shared by both: 0.1–3.9 Low, 4.0–6.9 Medium, 7.0–8.9 High, 9.0–10 Critical. Always render score **and** vector together | M |
| report v2 | Executive summary (engagement metadata, scope, top-5 risks, severity distribution), finding cards (severity chip, CVSS badge, `<details>` evidence collapse), per-host drilldown, **inline-SVG charts** (donut via stroke-dasharray, bars via `<rect>` — zero CDN, offline), `@media print` stylesheet | L |
| jobs + resume | Background job registry + cooperative kill (`threading.Event` checked by ProgressBar loops); dir/creds checkpoint `(wordlist, offset)` every N items; `vantic jobs list/kill <id>`, `--resume <run_id>` | M |
| banner→CVE matcher | Curated `vantic/data/banner_cves.json` (OpenSSH, vsftpd 2.3.4, ProFTPD, Redis, MySQL, Apache/nginx versions); implement the currently-unused `--cve` flag; detect & report only | M |
| sniff presets | BPF presets (`http/dns/smb/creds`) + live protocol counter table | S |
| UDP payload probes | Per-port payloads (SNMP GET, DNS CHAOS, NTP, Redis PING, memcached `version`) to resolve open\|filtered ambiguity | M |

---

## 5. Wave 3 — P2 backlog

| item | notes |
|---|---|
| `dhcp` | scapy BOOTP DISCOVER broadcast → capture OFFERs; multiple differing servers = rogue-DHCP candidate (detect only); root required |
| `kerberos` | AS-REQ bogus user → error-code distinguishes valid users (P2, raw) |
| `recon-api` | One module for keyed sources (Shodan/Censys/VT); keys from `~/.vantic/apikeys.json` or env; Shodan InternetDB (`internetdb.shodan.io/<ip>`) is **keyless** — ship that as the default; enforce documented budgets in-code (`~/.vantic/usage.json` counter, never burn the last N calls) |
| `osint` | theHarvester-lite, keyless only: crt.sh SAN emails, OTX, GitHub/paste link patterns (print links, don't scrape search engines) |
| config/profiles | `~/.vantic/config.toml` via stdlib `tomllib` (read-only — write = emit a template); precedence one line: `CLI > env (VANTIC_*) > --profile > [tools.X] > [defaults] > argparse default`; merge only keys the user didn't explicitly set (`argparse.SUPPRESS` sentinel); `vantic config show --effective` prints the resolved table |
| `diff` | `vantic diff <run_a> <run_b>` — SQL over services/findings → new/lost ports, changed banners; first user of the plugin registry |
| PDF export | `reportlab` optional dep (pure-Python wheel, fits the optional-deps pattern); do NOT use WeasyPrint (needs Pango/Cairo system libs — breaks bundle portability), wkhtmltopdf (deprecated), or headless Chrome (huge external binary). Zero-dep path that always works: `@media print` stylesheet + "open HTML → Print → Save as PDF" |
| color depth | Honor `NO_COLOR`, `CLICOLOR_FORCE`, `TERM=dumb`; 256-color/truecolor detection via `COLORTERM` |
| subdomain permutations | Alterations of found hosts (num-swap, prefix/suffix glue, year suffixes) — the amass "alterations" trick, capped like `--recursive` |
| cache snoop | Non-recursive (`RD=0`) queries against open resolvers; niche, ~30 LOC |
| STARTTLS grading | Negotiate STARTTLS on SMTP/IMAP/POP3/FTP then regrade TLS (reuse `check_ssl`) |
| `--ping-ports` / SYN ping | Configurable host-discovery port list in `nmap` |

---

## 6. Data sources cheat sheet (keyless unless noted)

| source | gives | endpoint | reality |
|---|---|---|---|
| crt.sh | CT-log subdomains + SAN emails | `https://crt.sh/?q=%25.<domain>&output=json` | flakiest source: 502/504, multi-second hangs — timeout 45s, 2 retries, disk-cache a day; `name_value` can be newline-separated with `*.` entries |
| HackerTarget | subdomain→IP, PTR, whois | `https://api.hackertarget.com/hostsearch/?q=<domain>` | **50/day per IP**; over-limit returns HTTP 200 with body `API count exceeded` — check the body, not the status |
| AlienVault OTX | passive DNS, URLs, emails | `https://otx.alienvault.com/api/v1/indicators/domain/<domain>/passive_dns` | lenient; datacenter IPs occasionally 403; responses can be huge |
| Wayback CDX | historical URLs → subdomains | `http://web.archive.org/cdx/search/cdx?url=*.example.com&output=json&fl=original&collapse=urlkey&limit=5000` | 429s with long Retry-After; always pass `limit` + `collapse`; honor Retry-After once, then skip |
| RapidDNS | passive DNS dump | `https://rapiddns.io/subdomain/<domain>?full=1` | blocks scripted UAs — browser UA required |
| Anubis | subdomain DB | `https://jonlu.ca/anubis/subdomains/<domain>` | availability inconsistent — try/except |
| urlscan.io | hostnames from scans | `https://urlscan.io/api/v1/search/?q=domain:<domain>&size=100` | stick to v1 search |
| Cert Spotter | CT issuances | `https://api.certspotter.com/v1/issuances?domain=<domain>&include_subdomains=true&expand=dns_names` | ~100/hour keyless, paginate via `after_id` |
| Shodan InternetDB | per-IP ports/hostnames/vulns | `https://internetdb.shodan.io/<ip>` | keyless, daily refresh, single IPs only |
| Team Cymru | ASN/prefix/country per IP | whois port 43 batch (`begin…end`) or TXT `origin.<ip>.origin.asn.cymru.com` | batch per 100 IPs or use the DNS route |
| ip-api.com | geo/ISP/org | `http://ip-api.com/json/<ip>`, batch POST /batch (100) | 45/min, HTTP-only on free tier |
| RDAP | netblock ownership | `https://rdap.arin.net/registry/ip/<ip>` (auto-redirects) | generous, be polite |
| Shodan API (keyed) | org/ASN search | `api.shodan.io/shodan/host/search` | free: 100 credits/month |
| Censys (keyed) | host/cert search | `search.censys.io/api/v2/hosts/search` (Basic auth) | free: 250/month — spend carefully |
| VirusTotal (keyed) | passive DNS | `www.virustotal.com/api/v3/domains/<domain>/subdomains` | free: 500/day but **4/min** |

---

## 7. Service enumeration cheat sheet

| service | port(s) | probe | good result looks like | method |
|---|---|---|---|---|
| SSH | 22, 2222 | connect + read | `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13` | raw |
| SMB | 445, 139 | negotiate + anon IPC$ | share list, dialect, signing=off, null session | pysmb + raw |
| SNMP | 161/udp | BER GET sysDescr.0 | `Linux fw01 5.15.0-70-generic` | raw BER (~60 lines, no pysnmp needed) |
| SMTP | 25, 587, 465 | `EHLO`, `VRFY root`, `EXPN all` | `250-STARTTLS`, `252 root` | raw |
| IMAP | 143, 993 | `a1 CAPABILITY` | `* CAPABILITY IMAP4rev1 STARTTLS` | raw |
| POP3 | 110, 995 | `CAPA` | `+OK UIDL TOP STLS` | raw |
| LDAP | 389, 636 | anon bind + rootDSE | `namingContexts: DC=corp,DC=local` | ldap3 |
| NFS | 111, 2049 | portmap DUMP → mountd EXPORT | `/export *(rw,no_root_squash)` | raw RPC/XDR |
| RDP | 3389 | X.224 negotiate + NTLM SSP | `PROTOCOL_HYBRID`, NetBIOS/domain disclosed | raw |
| VNC | 5900+d | RFB version → security types | type `[1]` = **no auth** | raw |
| MQTT | 1883, 8883 | CONNECT → CONNACK; SUB `#` | rc `0x00`, `$SYS/broker/version` | raw / paho-mqtt |
| Redis | 6379 | `PING`, `INFO`, `DBSIZE`, `SCAN` | `+PONG`, `redis_version:7.2.4` | raw RESP |
| Memcached | 11211 tcp+udp | `version\r\n`, `stats\r\n` | `VERSION 1.6.22`, `curr_items 4821` | raw |
| MySQL | 3306 | greeting parse | `8.0.36` + auth plugin | raw |
| MSSQL | 1433, 1434/udp | UDP `\x02` (SSRP) | server + instance + version | raw |
| PostgreSQL | 5432 | minimal StartupMessage | `R:` auth code (0 = trust!) | raw |
| FTP | 21 | `USER anonymous`, `FEAT`, `SYST` | `230 Login successful` | raw / ftplib |
| DNS | 53 | CHAOS TXT `version.bind` | `BIND 9.18.24` | dnspython |
| HTTP(S) | 80, 443, 8080, 8443 | GET /, OPTIONS, robots, `.git/HEAD`, `.env` | Server header, 200s | urllib |

---

## 8. Privilege-escalation audit checklist (postex, read-only)

Exact commands run over paramiko `exec_command` on an authorized unix target;
`--sudo` prefixes `sudo -n` only. Hit-criteria in the last column.

| # | check | command | flags a finding |
|---|---|---|---|
| 1 | OS/kernel | `uname -a; cat /etc/os-release \| head -4` | feeds kernel→CVE suggester |
| 2 | identity | `id; hostname` | sudo/docker/lxd/disk group membership |
| 3 | sudo rights | `sudo -n -l` | `(ALL) NOPASSWD:`, wildcard commands (`find`, `vim`, `env`) |
| 4 | sudo version | `sudo -V \| head -1` | < 1.9.5p2 → CVE-2021-3156 candidate |
| 5 | SUID | `find / -xdev -type f -perm -4000` | non-default paths; setuid `python`/`bash`/`env` |
| 6 | SGID | `find / -xdev -type f -perm -2000` | unusual SGID |
| 7 | world-writable files | `find / -xdev -type f -perm -0002` | anything under `/etc`, cron/systemd scripts |
| 8 | world-writable dirs | `find / -xdev -type d -perm -0002 ! -perm -1000` | missing sticky on PATH-adjacent dirs |
| 9 | capabilities | `getcap -r /` | `cap_setuid`/`cap_sys_admin` on non-core binaries |
| 10 | cron | `cat /etc/crontab; ls -la /etc/cron.d; crontab -l` | writable scripts, root tasks calling user-writable files |
| 11 | systemd timers | `systemctl list-timers --all` | unusual/root unit names |
| 12 | writable units | `find /etc/systemd /lib/systemd -type f -writable` | any hit |
| 13 | PATH audit | per-dir `[ -w "$d" ]` loop | writable dir early in PATH |
| 14 | UID-0 users | `awk -F: '$3==0 {print $1}' /etc/passwd` | anything besides `root` |
| 15 | key file perms | `ls -l /etc/passwd /etc/shadow /etc/sudoers` | readable shadow/sudoers |
| 16 | priv groups | `getent group sudo wheel admin docker lxd disk` | docker/lxd/disk membership (report only) |
| 17 | pkexec | `ls -l /usr/bin/pkexec; dpkg -s policykit-1 \| grep -i version` | unpatched polkit → CVE-2021-4034 candidate |
| 18 | NFS exports | `cat /etc/exports` | `no_root_squash`/`insecure` |
| 19 | sshd posture | `grep -Ei '^(permitrootlogin\|passwordauthentication)' /etc/ssh/sshd_config` | `PermitRootLogin yes`, `PasswordAuthentication yes` |
| 20 | .ssh presence | `ls -la ~/.ssh /home/*/.ssh` | loose perms — **existence/perms only, never read keys** |
| 21 | kernel→CVE | local: `uname -r` vs `data/kernel_exploits.json` | Dirty Pipe 5.8–5.16.11, Dirty COW ≤4.8.3, CVE-2023-0386, CVE-2024-1086 — "candidate, verify manually" |
| 22 | mount flags | `findmnt -rn -o TARGET,OPTIONS` | writable mount without `nosuid/noexec` hosting binaries |
| 23 | sysctls | `sysctl kernel.kptr_restrict kernel.dmesg_restrict kernel.yama.ptrace_scope` | all-zero → info disclosure |
| 24 | root processes | `ps auxww \| awk '$1=="root"{print $11,$12}'` | unexpected root services |

---

## 9. Check-template system (`checks` module, nuclei-lite)

JSON templates (stdlib `json`, no PyYAML), one matcher group, GET/POST only,
no DSL expressions in v1. Bundled under `vantic/data/checks/*.json` (resolved
like wordlists; `--templates <dir>` overrides). This converts the web tool's
hardcoded payload/signature lists into data.

```json
{
  "id": "missing-x-frame-options",
  "info": {"name": "X-Frame-Options missing", "severity": "low",
           "tags": ["headers", "misconfig"]},
  "request": {"method": "GET", "path": "/", "headers": {}, "body": null},
  "match": {
    "condition": "and",
    "matchers": [
      {"type": "status", "value": [200, 403]},
      {"type": "header", "name": "X-Frame-Options", "absent": true}
    ]
  }
}
```

Matcher types (six covers 90% of real checks): `status` (int list), `header`
(name + contains/value/absent), `word` (string list, part: body|header,
case_insensitive), `regex` (stdlib re, part-scoped), `size` (bytes ±
tolerance), `not_match` (inverted — kills soft-404s). `path` supports
`{{FUZZ}}` with an optional wordlist. Engine = ThreadPoolExecutor over
templates, same as_completed + `ProgressBar.interrupt()` loop as dirbuster.

---

## 10. Master pitfalls list (merge of all research)

**HTTP/scanning**
- Soft-404s are the #1 dir-fuzz false positive: baseline two random
  nonexistent paths pre-scan; filter via body similarity > 0.9 + word-count
  deltas, never raw size alone. Decompress gzip before measuring (never send
  `Accept-Encoding: br` — no stdlib brotli).
- Distinguish rate-triggered WAF blocks (rolling 403/429/503 spike → back
  off) from payload-triggered (single probe 403 among clean neighbors → that
  probe is a **finding**).
- urllib handshakes TLS per request — thread-local keep-alive connections
  give ~3–5× over TLS. Handle server-side idle closes with one reconnect.
- Custom redirect handler: hop cap (~10), visited-location loop detection,
  record first-hop `Location` (auto-following hides open redirects).
- Param heuristics break on dynamic content (CSRF, timestamps): stabilize
  with two identical baselines, measure per-request jitter, trust reflection
  markers over size deltas.

**DNS**
- Wildcard detection must query the domain's **authoritative NS** — ISP
  resolvers hijack NXDOMAIN and some zones wildcard only at depth ≥ 1.
- crt.sh is the flakiest source (502/504, hangs): timeout 45s, 2 retries,
  disk-cache. HackerTarget signals quota exhaustion as **HTTP 200 body
  text**. Wayback needs `limit=` + `collapse=urlkey` and Retry-After honor.
- TXT-heavy answers can truncate over UDP — retry over TCP
  (`resolver.use_tcp = True`).

**Raw network**
- SYN/ARP/DHCP all need root (macOS BPF is root-only); guard with
  `os.geteuid()` and degrade gracefully. scapy can't SYN-scan loopback —
  special-case it. Cap `sr1` thread pools (~50) and rate-limit sends.
- Connect-scan "open" ≠ live service (SYN proxies complete then RST) —
  verify with a banner/probe before reporting. UDP no-reply = open|filtered;
  payload probes + 3× retry + throttle required.
- Reuse one dnspython `Resolver` (thread-safe for resolve); don't rebuild
  per query.

**Credentials**
- sshd `MaxAuthTries` (6) and `MaxStartups` (10:30:100) kill careless
  brute force — fresh-connection-per-attempt is correct, keep it; add
  delay/jitter; stop-on-success via `threading.Event` checked **inside**
  workers. Spray (one password × many users) is the low-lockout pattern;
  brute (many passwords × one user) risks lockout — warn.
- If password auth is disabled, `auth_none` reveals allowed types — report
  that instead of silent failures.

**Platform**
- SQLite + ThreadPoolExecutor: thread-local or per-batch connections, WAL +
  busy_timeout, `executemany` transactions. Never share a connection across
  the GUI's spawn boundary.
- Plugin imports execute top-level code — enforce META + defs only, catch
  per module, denylist reserved names.
- Config precedence: merge config only into keys the user didn't explicitly
  set (sentinel defaults), or argparse defaults silently override config.
- `--json` mode: machine output to stdout, human output to stderr, flush per
  line — the GUI parses stdout.
- Crawler/param scope: normalize scheme+host+port before every enqueue; a
  third-party redirect is a finding, never a crawl target.

---

## 11. Safety rails and out-of-scope statement

**In, always:** enumerate, detect, assess, report. Read-only audit checks on
authorized targets. Verbatim logging of every probe for the engagement record.

**Out, always:** stealth/evasion/anti-AV techniques, persistence or
self-hiding payloads, credential-dumping-from-endpoint tooling, destructive
actions on targets (`CONFIG SET`-class writes), DDoS, anything targeting
systems outside declared scope. The kernel→CVE and banner→CVE matchers emit
"candidate — verify manually" for authorized remediation, never weaponized
payload delivery. If a future maintainer asks "should vantic do X", the test
is: *would a pentest report include this finding and how to fix it?* If yes,
it fits. If it only makes sense to hide from defenders, it doesn't.

---

## 12. Suggested execution sequence for the incoming AI

1. Read `README.md` §6–7 (architecture rules + touchpoints), skim
   `vantic/utils/__init__.py`, run the §9 checklist in `BUILD.md`.
2. **Week 1:** `store` (SQLite schema above) + `audit` + global `--json` —
   smallest foundation, immediately useful.
3. **Week 2:** `net` helpers (rate limit/retry/keep-alive) + `guard` (scope) +
   wire into `dispatch()`.
4. **Week 3:** `registry` + convert 2–3 existing tools to META contract
   (start with `diff`-shaped simple ones) + update `BUILD.md` §10.
5. **Weeks 4–6 (parallelizable):** `passive` + wildcard detection +
   `--mailsec`/`--srv`/`--reverse-cidr` (recon wave) · soft-404 + recursive +
   redirect-fix in `dir` (web wave) · creds engine upgrade (creds wave).
6. **Weeks 7–9:** `crawler` → `params` → `jwt`/`cors`/`graphql` (web chain) ·
   `redis`/`snmp`/`smb`/`vnc` (service wave — stdlib ones first).
7. **Week 10+:** `findings`/CVSS → report v2 (SVG charts) → jobs/resume →
   Wave-3 backlog by priority.

Every PR: compile check, smoke tests (`scan 127.0.0.1`, menu `q`, GUI
`--smoke`), rebuild bundles via `app/build_mac.sh`, update `STATUS.md`.

---

*Vantic Breach 2.1.0 → 2.x | Every wall has a way in. | By Vantic*