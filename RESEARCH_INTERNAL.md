# Vantic Breach — Research Brief: Internal Network, RDP, Gateway & Authentication Assessment

> **Every wall has a way in.** | Red Teaming Tool Application | By Vantic

**What this is:** the research deliverable for the *internal* expansion of
Vantic Breach — assessing Windows estates with RDP exposed, internal network
enumeration, gateway/router auditing, and disciplined authentication testing.
It is written for the AI that will **build** these modules (not for an end
user): every section says what a technique **is**, what **assessment value**
it has (i.e., the finding it produces for the report), and **how to build
it** inside this codebase.

**Read first:** `README.md` (§6 architecture rules) · `ROADMAP.md` (§1 hard
rules, §3 platform foundation — this brief assumes the registry, scope guard,
SQLite store, audit log and `--json` from Wave 1) · `BUILD.md` (packaging).

**The one rule, restated:** detect / enumerate / report, on authorized
targets, with everything logged. Techniques below are ordered by what a
pentest *report* needs — every check ends in a finding with severity,
evidence and a remediation sentence. If a capability's only use is hiding
from defenders or accessing systems outside declared scope, it does not go in
the toolkit (see `ROADMAP.md` §11).

---

## Part 1 — Internal network enumeration

### 1.1 Techniques: what each is, what it's for

| Technique | What it is | Assessment value (report finding) | Auth needed? | Python path |
|---|---|---|---|---|
| ARP sweep | L2 broadcast `who-has` per IP in a CIDR | Host inventory that finds hosts dropping ICMP; MAC↔IP pairs; OUI vendor mapping (Apple/Cisco/Synology; VMware `00:50:56`/`00:0C:29`, Hyper-V `00:15:5D` = hypervisor detection) | Raw socket privileges | scapy `srp()` (opt) → stdlib fallback: passive OS ARP-cache read (`arp -a`, `/proc/net/arp`) |
| NBNS/NetBIOS node status | UDP/137 NBSTAT query | nbtscan behavior: hostname, `<03>` = logged-on username leak, `<20>` file server, `<1B>/<1D>` browser roles, MAC | No (often firewall-blocked) | Pure stdlib: UDP socket + `struct`, 12-byte NBNS header + 1st-level name encoding (~200 lines) |
| mDNS/Bonjour | Multicast DNS UDP/5353, DNS-SD PTR (`_smb`, `_http`, `_ipp`, `_rdp`, `_airplay`…) | Non-Windows/IoT inventory: Macs, printers, TVs, shadow IT; hostname+service+TXT (model info) | No | stdlib UDP multicast + minimal DNS parser (or optional dnspython) |
| SMB negotiate probe | TCP/445 + SMB1 `NT LM 0.12` / SMB2 NEGOTIATE | Dialect matrix (SMB1? 2.0.2/2.1/3.0/3.1.1?), signing bits, encryption-capable | No | Raw handcrafted frames (~stdlib) — exactly nmap `smb-protocols` |
| SMB signing check | `SecurityMode` in negotiate response | **"Signing not required" → NTLM relay exposure on the segment** — the single most valuable SMB finding | No | Same probe |
| Anonymous/guest shares | Null/guest session on IPC$ → `NetShareEnumAll` | Anonymous share access finding; share names reveal layout (SYSVOL = DC, print$, admin shares) | No (legacy/misconfigured/NAS) | pysmb or smbprotocol (opt) |
| Null session (history) | Legacy SMB1 anonymous IPC$ | Mostly dead on modern Windows; live on legacy/Samba/NAS → "legacy anonymous configuration" finding | No | pysmb anonymous connect |
| enum4linux heritage | rpcclient-style ops on `\pipe\samr/lsarpc/srvsvc` | Users, groups, shares, **password policy** (min length/history/complexity), domain name + SID | Anonymous sometimes; normally yes | impacket (opt, heavy — import-guarded) |
| LDAP rootDSE + depth-1 | Anonymous bind, base `""` search | DC fingerprint without creds (dnsHostName, defaultNamingContext, SASL mechs); depth-1 returning objects = "anonymous LDAP enumeration" misconfig | No | ldap3 (opt) or ~150-line stdlib BER encoder |
| Kerberos AS-REQ username enum | AS-REQ without preauth per candidate to KDC:88 | Error 5 = no user, error 6 = exists+preauth, **AS-REP returned = pre-auth not required → ASREPRoast exposure finding**; zero lockout interaction (no passwords submitted) | No | Stdlib DER builder (~300 lines) or impacket kerberos module |
| LLMNR/NBT-NS audit (passive) | Join 224.0.0.252:5355 / UDP 137, listen + log name→source-IP | Evidence clients leak unresolvable-name queries → the Responder/poisoning exposure class, **without building a poisoner** | No | Pure stdlib listener + benign WPAD DNS check |
| Traceroute | UDP probes + ICMP time-exceeded | Segmentation findings (does VLAN B traffic traverse a firewall hop?) | Usually root | scapy → fallback: parse system `traceroute` |
| Stale DNS cross-check | PTR sweep vs live-host results | Records pointing at dead IPs = scavenging finding | No | dnspython / `gethostbyaddr` |

### 1.2 Modules to build

| Module | CLI | Implementation notes | Effort | P | Deps |
|---|---|---|---|---|---|
| `arpsweep` | `arpsweep --cidr 10.0.5.0/24 [--iface en0] [--passive] [--timeout 1] [--json]` | Expand CIDR, ARP who-has per host (rate ~10/s), IP/MAC + OUI vendor table. `--passive` = OS cache only (unprivileged). Degrade with `print_warning` when not root. **Must pass the whole CIDR through the scope guard** — broadcast sweeps can't be scoped per-reply | M | P0 | scapy opt |
| `smbprobe` | `smbprobe <target\|file:targets.txt> [--dialects] [--signing] [--smb1] [--guest] [--anon-shares]` | Two-stage: raw TCP/445 negotiate prober (dialect list + SecurityMode bits + encryption flag), then `--anon-shares` via pysmb/smbprotocol with guest-flag detection. All read-only. Plain TCP connect first to distinguish "SMB1 off" from "filtered" | M | P0 | pysmb/smbprotocol opt |
| `namesniff` | `namesniff [--llmnr] [--nbns] [--wpad-check <domain>] [--duration 300] [--json]` | Passive LLMNR + NBT-NS listeners on worker threads, name→source-IP log, summary "X clients leaked N queries in T minutes". `--wpad-check` = one benign DNS query for `wpad.<domain>`. **Never sends a response — listens only** | S | P0 | stdlib |
| `nbtquery` | `nbtquery <target\|cidr> [--timeout 2]` | Stdlib NBSTAT; parse name-table type codes (00/03/20/1B/1D) + trailing MAC; note firewall-silent-drop vs explicit ICMP-unreachable (the distinction is itself a firewall finding) | S | P1 | stdlib |
| `mdnsscan` | `mdnsscan [--active] [--passive] [--types _smb,_http,_ipp] [--duration 120]` | Active PTR/SRV/TXT queries or passive announcement listen; inventory table hostname→IP→services→TXT hints; flags non-corporate devices (shadow IT / flat-network evidence) | S | P1 | dnspython opt |
| `ldapprobe` | `ldapprobe <dc> [--port 389] [--anon] [--depth 0\|1] [--base <dn>]` | Anonymous bind + rootDSE via kv rows; `--depth 1` reports the ACL result ("denied" = healthy baseline; "returned N objects" = finding). ldap3 if present, else stdlib BER | S/M | P1 | ldap3 opt |
| `netmap` | `netmap [--arp-cache] [--routes] [--gateway] [--trace <target>]` | Pure stdlib "what does this box see": ARP cache + routes + default gateway + OUI annotations + traceroute; one-screen segment summary feeding segmentation findings | M | P1 | scapy opt |
| `smbenum` | `smbenum <target> [--user u --pass p] [--rids] [--groups] [--policy] [--lsa]` | The enum4linux port: SAMR EnumDomains/Users (RID walk), GetDomainPasswordInfo (policy), LSA QueryInformationPolicy (domain SID). Anonymous mode first — what leaks without creds is itself a finding. Needs impacket's RPC layer — the one justified heavy optional dep | L | P2 | impacket opt |
| `kerbprobe` | `kerbprobe <kdc\|domain> --users usernames.txt [--dc-ip ip]` | Stdlib DER AS-REQ builder; classify error matrix; rate ~20/s; **no lockout interaction — state this in tool help**; output confirmed-principals table + JSON | M | P2 | stdlib |
| `dnssweep` | `dnssweep --cidr 10.0.5.0/24 [--dns <server>]` | PTR sweep diffed against live-host results → stale-DNS finding | S | P2 | dnspython opt |

### 1.3 Internal findings taxonomy

| Finding | Severity | Evidence | Remediation (report text) |
|---|---|---|---|
| SMB signing not required | High | per-host SecurityMode bits | Enforce "Digitally sign communications (always)" via GPO |
| SMBv1 enabled | High/Critical | SMB1 negotiate accepted | Disable SMB1 features, verify by re-scan |
| Anonymous/guest share access | Medium (High if sensitive shares) | share list via null/guest | Disable guest logons; `RestrictAnonymous(SAM)` = 1 |
| Null-session RPC enumeration | Medium | SAMR/LSA outputs obtained anonymously | Restrict anonymous RPC pipes |
| LLMNR enabled | High | passive capture: names + source IPs | "Turn off multicast name resolution" GPO |
| NBT-NS enabled | Medium/High | passive UDP/137 queries | Disable NetBIOS over TCP/IP |
| WPAD resolvable | Medium/High | `wpad.<domain>` answered | Disable WPAD; reserve `wpad` in DNS |
| Kerberos pre-auth not required | High | AS-REP returned without PA-ENC-TIMESTAMP | Re-enable pre-authentication on affected accounts |
| Username enumeration possible | Medium | error-code matrix 5 vs 6 | Inherent NTLM-era behavior — note + KDC hardening |
| Anonymous LDAP returns data | Medium | depth-1 anonymous result counts | Remove Anonymous Logon from Pre-Win2000 Compatible Access |
| Flat network / no segmentation | Medium/High | reachability matrix + traceroute | Segment by function with VLANs/ACLs |
| Stale DNS records | Low/Medium | A/PTR → dead IPs | Enable DNS scavenging |
| Logged-on username leak via NBNS | Low/Medium | `<03>` names per host | Disable Messenger/NetBIOS services |
| Unmanaged/shadow devices | Medium | mDNS/NBNS/OUI inventory | Enroll or quarantine per policy |
| Weak password policy (SAMR read) | Medium | min length/history/complexity | Raise to ≥14 chars via Default Domain Policy |

### 1.4 Internal pitfalls

- **SMB dialect quirks:** SMB1-disabled hosts RST on SMB1-only negotiate but answer SMB2 on a fresh connection — plain TCP connect first, one dialect probe per connection. SMB 3.1.1 rejects wildcard `SMB 2.???` without the preauth-integrity negotiate context. Guest detection lives in session-setup `SessionFlags`, not negotiate.
- **LLMNR listening:** multicast join is unprivileged; UDP/137 may already be bound (macOS NetBIOS, nmbd) — use `SO_REUSEADDR` or report the limitation. Switch IGMP-snooping may not forward LLMNR to your port — note listener position as evidence quality.
- **scapy:** loopback has no ARP layer — always expose `--iface`; macOS BPF needs root; every L2 module needs an unprivileged degraded mode.
- **Windows firewall:** domain profile blocks UDP/137 inbound on workstations — NBNS timeouts ≠ "no NetBIOS"; corroborate with namesniff + LDAP/SMB.
- **DC-less networks:** workgroups have no LDAP/Kerberos — detect absence fast and degrade to SMB+mDNS+NBNS.
- **impacket size:** pulls pyasn1/pyOpenSSL/cryptography — keep import-guarded; smbprobe+ldapprobe deliver 70% of the value without it.
- **Kerberos noise:** no-password queries never lock out, but keep rate limits and full audit logging — engaged DCs audit these queries, and the report should show exactly what was sent.

---

## Part 2 — RDP and remote-access assessment

### 2.1 What RDP assessment is, and why it works pre-auth

Every RDP connection begins with an X.224 handshake that **negotiates the
security protocol before any credentials are touched** — so an assessment
tool can fingerprint posture, information disclosure and crypto support with
no login. That is what makes RDP auditing safe and cheap: it's a handshake
you're already allowed to start by pointing a client at the port.

**Wire sequence (TCP):** TPKT (`03 00 <len>`) + COTP Connection Request +
`cookie: mstshash=…` + optional RDP Negotiation Request (`02 <flags> 00 08 00
<requested-protocols LE>`). Server answers: legacy plain CC (pre-Vista), a
Negotiation Response (selected protocol), or Negotiation Failure (code).

**Protocol flags:** `0x1` SSL-only, `0x2` HYBRID (NLA/CredSSP), `0x4` RDSTLS,
`0x8` HYBRID_EX (Restricted Admin era). **Failure codes:** 1
SSL_REQUIRED_BY_SERVER, 2 SSL_NOT_ALLOWED_BY_SERVER (GPO forces RDP Security
Layer), 3 SSL_CERT_NOT_ON_SERVER, 4 INCONSISTENT_FLAGS,
5 HYBRID_REQUIRED_BY_SERVER (NLA enforced), 6 SSL_WITH_USER_AUTH_REQUIRED.

| Check | Detail | Risk meaning / finding | Stdlib-only? |
|---|---|---|---|
| Negotiation posture | Send NEG_REQ 0x0000000B (SSL+HYBRID+HYBRID_EX), then SSL-only variants | **HYBRID enforced** = protected (pre-auth RCE class blocked); **SSL-only accepted** = NLA not required, pre-auth session path reachable = High; **native RDP layer accepted** = RC4-era, weakest = Critical-to-High; **HYBRID_EX advertised** = modern stack | Yes (~60 lines) |
| NTLM SSP disclosure | After HYBRID: TLS → TSRequest with bare NTLM Type1 → parse Type2 (ServerChallenge, flags, Version, AV_PAIRs) | Pre-auth disclosure of NetBIOS/FQDN host, **AD domain**, OS build (`10.0.14393`=2016, `17763`=2019, `19041`=Win10, `20348`=2022, `26100`=Win11/2025, `6.1.7601`=Win7/2008R2) — the version is the primary legacy-stack signal. Exactly nmap `rdp-ntlm-info` | Yes (~120 lines, flat TLV) |
| TLS versions on 3389 | TLS happens before CredSSP even on NLA servers — pinned handshakes always work | TLS 1.0/1.1 enabled = legacy posture = Medium; TLS1.2+ only = pass | Yes (ssl module version pinning) |
| Certificate inspection | `getpeercert(binary_form=True)` + small DER walk | Default RDP cert is self-signed, CN=`<hostname>` — expected (Info). Findings: expired, key <2048, SHA-1 signature, **same cert/serial across hosts** = provisioning misconfig | Yes (~80-line DER walk) |
| Legacy encryption levels | rdp-enum-encryption model: level enum (40/56/128-bit RC4, FIPS) | "Low/Medium" accepted = 40/56-bit RC4 era = Critical-era posture | Partial (~+80 lines) |
| Legacy-stack context | Combine: plain CC + SSL-only + old NTLM version + legacy levels | "**Unpatched legacy RDP stack exposed, NLA not enforced — CVE-2019-0708-class pre-auth RCE risk context**" = Critical finding routed to remediation. **Flagging only — never crash-based verification (ms12-020-style probes are intrusive; default off per §11)** | Yes |

### 2.2 Modules to build

| Module | CLI | Notes | Effort | P | Deps |
|---|---|---|---|---|---|
| `rdp` | `rdp <targets> --negotiate --ntlm-info --tls --cert --ports 3389,3390 [--adjacent]` | One reusable `x224_negotiate(sock, req_flags)` helper (~60 lines); layered checks each reconnect (servers tolerate ~1 conn/3s — serialize with backoff, never two sessions per host or you shadow a real user's session); NTLM parse = flat TLV; TLS via `ssl` pinning; cert via DER walker. Full stdlib | M (2–3d) | P1 | none |
| `winrm` | `winrm <targets> --ports 5985,5986 --auth-types` | HTTP GET `/wsman` → 401 + `WWW-Authenticate: Negotiate/Kerberos/Basic` + `Server: Microsoft-HTTPAPI/2.0` = presence + accepted auth planes. Presence/auth-type report only — no auth attempts | S (½d) | P2 | stdlib |
| `ra-sweep` | `ra-sweep <targets> [--vnc --ssh-banner --telnet --tva]` | RFB security types (type 1 = no auth = Critical); SSH banner (`OpenSSH_for_Windows_x.y` vs `OpenSSH_9.x` = version-age finding); telnet banner = deprecated flag; TeamViewer 5938/5939 + AnyDesk 7070/6568 open = "third-party remote access detected — flag for review" | S (1d) | P2 | stdlib |

Later (creds-engine phase): `rdp --cred-check` produces exactly **one**
sequential CredSSP Type3 per credential (impacket `rdp_check.py` is the
model, not a dependency). Refusal rules in Part 4 apply verbatim.

### 2.3 RDP hardening audit checklist

| Check | Verify from probe | Finding text |
|---|---|---|
| NLA required? | SSL-only request → failure 5 / SSL not selected = enforced; SSL actually selected = not | "NLA not enforced — pre-auth RDP session path exposed (RCE-class risk context)" |
| RDP Security Layer permitted? | failure 2 / legacy exchange succeeds | "Server permits legacy RDP Security Layer (RC4-era)" |
| Encryption level | legacy level enum | "40/56-bit RC4 encryption levels accepted" |
| TLS versions | pinned handshakes | "TLS 1.0/1.1 enabled on 3389" |
| Cert health | DER parse | expired / weak / SHA-1 / hostname-in-CN / serial-collision |
| Restricted Admin | HYBRID_EX in NEG_RSP | info — capable, actual mode needs auth |
| OS/version context | NTLM Version + Product_Version | "Legacy stack (6.1.7601 era) with NLA off — CVE-2019-0708-class exposure, Critical" |
| Domain disclosure | AV_PAIRs | "RDP pre-auth discloses internal hostname/domain" |
| Internet exposure | scope + RD Gateway markers (`/remote`, `/Rpc` on 443) | "RDP/RD Gateway reachable from untrusted network scope" |
| Idle/session limits | **Not probeable pre-auth** | "Requires post-auth phase — don't guess" |

### 2.4 RDP pitfalls

- XP/2003 return plain CC (don't misread as "no RDP"); failure 3 comes from Core/container builds; code 5 = "NLA required", not "broken".
- CredSSP-hardened servers (2018 EncryptionOracleRemediation) refuse CredSSP without TLS 1.2+ — request TLS before CredSSP or you'll emit false "legacy" signals.
- NLA-on servers still leak NTLM Type2 info — don't skip info checks when NLA is on.
- RD Gateway fronting: back-end RDP answers the gateway only; probe 443 for RDG markers before declaring back-end status.
- Validate on TPKT `03 00` magic, never on "TCP connect succeeded" (SYN-proxy false positives).
- OpenSSL 3 refuses RC4/TLS<1.2 clientside — report "untestable (client TLS stack)" distinctly from "disabled".
- Serialize connections per host (~1 conn/3s) — a second concurrent session can shadow an active user's session.
- pyrdp is a capture/MITM tool — read as protocol reference only, never a dependency (out of scope per §11).

---

## Part 3 — Gateway & router assessment

### 3.1 What it is, what it's for

Auditing gateways/switches/APs the operator administers or is authorized to
test: identify the device (four channels: HTTP banner/realm/title, UPnP
device XML, mDNS TXT, SSH/telnet banner), assess its management planes,
enumerate what it exposes, and report misconfigurations. Router audits are a
standard deliverable: the findings below are exactly what an ISP/customer
router assessment contains.

| Technique | What it is | Assessment value | Auth needed? | Python path |
|---|---|---|---|---|
| Mgmt-port banner sweep | connect+read on 80/443/8080/8443, 22, 23, 161/u, 1900/u, 7547, 49000/49152 (TR-064) | Which management planes are enabled; device/firmware ID feeding the planned banner→CVE matcher | No | reuse `service_enum.grab_banner` + `port_scanner` |
| HTTP identity fingerprint | Server header, WWW-Authenticate realm ("Broadband Router" = strong vendor signal), `<title>`, meta generator | Vendor/model guess; admin-on-HTTP = finding | No | urllib + html.parser |
| SSH algorithm audit | Banner + `Transport.start_client()` → `get_security_options()` | Dropbear = embedded; old OpenSSH = old firmware; weak KEX (`diffie-hellman-group1-sha1`, 3des-cbc) = finding; **identical vendor host keys across devices** = finding | No (handshake only) | paramiko (opt, existing HAS_PARAMIKO pattern) |
| Default-credential audit | Vendor-matched default pairs vs Basic auth / login form / SSH | **Default credentials active = Critical**; only pairs matching the identified vendor (≤ ~10 tries) | No — that's the audit's point | urllib Basic header / paramiko (reuse creds fresh-conn pattern) |
| UPnP SSDP discovery | M-SEARCH multicast to 239.255.255.250:1900, parse LOCATION device XML | Device inventory (friendlyName/manufacturer/model/firmware); UPnP enabled at all | No | raw UDP multicast + urllib + xml.etree (~300 LOC stdlib) |
| IGD read-only actions | SOAP `WANIPConnection:1#GetExternalIPAddress` / `#GetStatusInfo` / `#GetGenericPortMappingEntry` index loop (stops on 713/714) | **NAT port-mapping inventory** — which forwards exist (high report value); reads only, never `AddPortMapping` | No | raw HTTP + hand-built SOAP |
| WAN-side UPnP probe | External-vantage SSDP/HTTP to WAN IP | WAN-facing UPnP responding = Critical (LAN probes can't see this) | No | raw, run from external host |
| SNMP on gear | BER GET sysDescr/sysObjectID/sysName with public/private | Open SNMP = High; sysObjectID → vendor/model; firmware from sysDescr; capped walks: ifTable, ARP (ipNetToMedia), routes | Community (public = the finding) | raw BER (~60 LOC, planned snmp module) |
| Open-resolver test | Recursive query for a public domain against LAN/WAN IP | Recursion enabled on WAN = Medium/High | No | dnspython (opt) / raw DNS builder |
| Rogue-DHCP listen | BOOTP DISCOVER broadcast, collect OFFERs | Multiple differing servers = rogue-DHCP candidate (Critical) | No (root) | scapy (planned `dhcp` module) |
| TR-069/CWMP | HTTP GET WAN:7547 (+ LAN 49000/49152) | CWMP WAN-exposed = High (the 2016 mass-router-incident vector); detect & report only | No | raw/urllib |
| WPS status | WSC IEs in beacons (monitor mode) or admin-UI manual check | WPS enabled = Medium | No | sniffed captures / manual |
| Vendor static names | Resolve `routerlogin.net`, `fritz.box`, `tplinkwifi.net`, `dlinkrouter.local`, `router.asus.com`, `openwrt.lan` against the gateway resolver | Vendor confirmation without touching the device | No | socket/dnspython |

### 3.2 Modules to build

| Module | CLI | Notes | Effort | P | Deps |
|---|---|---|---|---|---|
| `gateway` | `gateway <target> [--all\|--ident\|--admin\|--mgmt\|--dns] [--creds --cred-list router_defaults.txt] [--wan-probe --wan-ip <ip>]` | Pipeline: identify → web-admin assess → cred audit (opt-in, vendor-filtered, stop-on-success) → DNS posture → telnet/SSH audit. Each phase emits findings to the store (families: `gateway-creds`, `gateway-admin-http`, `gateway-upnp`…). `--wan-probe` warns/refuses from RFC1918 space — WAN checks need true external vantage (document the vantage in the audit log) | M | P1 | paramiko/dnspython opt |
| `upnp` | `upnp [--cidr 192.168.1.0/24\|--host <ip>] [--igd-read] [--timeout 4]` | SSDP discover → LOCATION XML parse → device table → `--igd-read` runs the read-only IGD action set. Comment-blocks the write-action code paths (postex-whitelist discipline) | S/M | P1 | stdlib |
| `wordlists/router_defaults.txt` | TSV `# vendor<TAB>model<TAB>user<TAB>pass` | Seed from public default-cred databases (routerpasswords/cirt.net-style) + vendor manuals; identification phase filters to matching vendor rows | S | P0 (data) | — |
| `vantic/data/router_signatures.json` | consumed by `gateway --ident` | Server-header/realm/title → vendor+model rules; same shape as the planned `banner_cves.json` | S | P1 | — |

### 3.3 Gateway findings taxonomy

| Finding | Severity | Evidence | Remediation |
|---|---|---|---|
| Default credentials active | Critical | successful pair + verbatim log | Rotate admin password |
| Admin interface reachable from WAN | Critical | external-vantage response | Restrict admin to LAN |
| WAN-facing UPnP responds | Critical | external SSDP reply | Disable UPnP or WAN discovery |
| Rogue DHCP server | Critical | second OFFER (IP, MAC) | Locate and remove |
| SNMP public readable | High | sysDescr/sysName dump | ACL communities / disable v1/v2c |
| Telnet enabled | High | port 23 banner | Disable telnet, use SSH |
| TR-069 WAN-exposed | High | external 7547 response | Filter at WAN edge |
| Admin UI on plain HTTP | Medium/High | 200 without redirect/HSTS | Enforce HTTPS + HSTS |
| NAT mappings enumerable | Medium | IGD mapping list | Restrict UPnP |
| WAN open resolver | Medium | external recursive reply | Disable external recursion |
| Weak SSH KEX/ciphers | Medium | security-options listing | Update firmware |
| WPS enabled | Medium | WSC IE / admin check | Disable WPS |
| Ancient/EoL banner (RomPager < 4.07 = Misfortune Cookie class) | Medium | banner + CVE matcher | Update firmware |
| Admin cookie missing flags | Low/Medium | Set-Cookie capture | Set flags |
| version.bind disclosure | Low | CHAOS TXT | Suppress version |

### 3.4 Gateway pitfalls

- **SSDP on macOS:** bind with `SO_REUSEADDR`+`SO_REUSEPORT`, set `IP_MULTICAST_IF` (macOS otherwise routes multicast out the default interface → zero responses on multi-homed machines), `IP_MULTICAST_LOOP=0`, ~4s listen, cap responses; first run trips the macOS firewall prompt.
- **Fragile router web UIs:** GET the login page first (session cookie/CSRF often required before POST accepts); `Connection: close`, `Accept-Encoding: identity`, no HEAD; success detection is per-vendor (redirect vs Set-Cookie vs re-rendered form); `CERT_NONE` fallback for universal self-signed; some ancient gear only speaks TLS 1.0 — lower the context floor deliberately. Router httpds are weak CPUs — serial requests, ≤1/s.
- **WAN testing needs external vantage:** NAT hairpin invalidates LAN probes of the WAN IP; CGNAT means WAN IP ≠ router IP — confirm via IGD GetExternalIPAddress first.
- **Scope:** SSDP multicast touches every UPnP device on the segment — the guard must require the whole CIDR in scope. SNMP GETs against third-party gear are unauthorized access even though read-only.
- **SNMP:** no-reply = open|filtered (2s timeout, 2 retries — report filtered, not closed); cap walk depth (full walks have wedged fragile firmware); never SET.
- **DNS:** many servers don't answer version.bind (absence ≠ no server — info only).

---

## Part 4 — Authentication testing discipline ("bypassing passwords", honestly)

### 4.1 Taxonomy — what each technique is, and the toolkit's verdict

| Technique | Definition | Authorized use | Lockout/risk profile | Verdict |
|---|---|---|---|---|
| Default credentials | Vendor factory accounts never rotated | First pass on appliances, routers, IoT, DBs | None — creds are *valid*; lockout math irrelevant | **Implement** (`defaults` mode + data files) |
| Password spraying | One password × many usernames, spaced across the lockout window | Finding weak-password accounts without per-user pileup | Lowest of the guessing family: ≤1 bad attempt/user/window | **Implement** (creds v2 round scheduler) |
| Targeted brute force | Wordlist × one explicitly-authorized account | RoE-named shared/svc account | Highest — attempts pile on one counter | **Limited**: `--targeted` flag, size cap, loud warning |
| Credential stuffing | Breached combo lists replayed | Almost none in authorized work | Severe; trips smart lockout and fraud tooling | **Refuse** by default (only with explicit client authorization + client-supplied list) |
| Password reuse | One *known* password against other in-scope services | Lateral-movement verification after a valid find | Low if throttled | **Limited**: manual flag, single password |
| Offline hash cracking | Cracking dumped hashes | n/a — dumping is banned (§11) | — | **Refuse** (hard boundary) |
| Lockout probing | N−1 attempts on a *test* account to measure the threshold | Calibrating spray safety when policy read is unavailable | Intrusive; consumes counter space | **Limited**: opt-in `--probe-lockout`, test accounts only |

Key fact the tool must encode: **`badPwdCount` is invisible to the tester**
(only readable via LDAP with valid creds, accurate only on the PDC emulator)
→ play blind, never spend more guesses than the worst-case budget.

### 4.2 Lockout math and safe rates

AD defaults: threshold 5–10 (0 = disabled — itself a finding), observation
window ~10–30 min, auto-unlock ~30 min. PSOs can override per group.

- Safe spray rule: per-user attempts per window ≤ **threshold − 2**.
- Conservative default: **1 password per user per day**, rounds ≥ 3h apart.
- `round_time ≈ users × delay × (1 + jitter)`; simplest correct policy = full
  user sweep with delay, then sleep ≥ window before the next password.
- Spray = **password-major order** (outer loop passwords, inner users) — the
  opposite of the current user-major brute loop.

| Service | Lockout behavior | Safe rate | Watch for |
|---|---|---|---|
| AD/LDAP | badPwdCount, blind | 1 pwd/user/day, gap ≥ window | never spray service accounts; disabled accounts poison counts |
| SSH | `MaxAuthTries` (6) disconnects per connection, usually no persistent lockout | 1 password/conn, ≤4 pwds/conn, 5–10 conn/min, threads ≤2 | `SSHException` on disconnect ≠ auth failure — retryable, don't count |
| FTP | vendor 421/530 lockouts | ≤5 attempts/min/account | `421` = throttled → back off; anonymous FTP is a separate finding |
| HTTP Basic/Form | none standard; fail2ban/WAF on top | 1–2 req/s, threads ≤2 | 401 = continue; 403/429 burst = anti-brute → abort round |
| SMTP AUTH | throttle codes | 1 attempt/2–5 s, port 587 not 25 | `454/429/503` = throttle |
| IMAP/POP3 | server-dependent `BYE` | ≤5 attempts/min | `BYE` = pause |
| SNMP | none (UDP) | 20–50 pps | timeouts ≠ failures; retransmit once |
| Redis | none | instant | no-auth INFO is the finding |
| AzureAD/SSO | **smart lockout** (ML, IP-familiarity) | treat as out of bounds | defeating smart lockout = evasion (§11). Detecting and reporting "smart lockout present" is the finding |

### 4.3 Modules to build

| Module | CLI | Notes | Effort | P | Deps |
|---|---|---|---|---|---|
| `creds` v2 (existing) | `creds <svc> <target> --users U --passwords P --spray --delay 30 --jitter 0.25 --stop-on-success --threads 2` | Round scheduler: spray = password-major; `--stop-on-success` kills the round, logs the pair, asks before continuing; replace fixed `max_workers=10` with service-aware caps (≤2 for lockout-able services); every attempt → audit log | M | P0 | paramiko (SSH) |
| `defaults` | `defaults <target> [--service ssh,ftp,http,snmp,mysql,redis]` | Builds candidate set from `defaults_<service>.txt` files, feeds the creds v2 engine; stop-on-success per service | S | P0 | — |
| `webauth` | `webauth <url> [--mode basic,digest,form] --users U --passwords P` | Basic/digest: success keyed on 401→2xx/30x transition + realm fingerprint. Form: GET login page → extract CSRF field (name varies — `csrfmiddlewaretoken`/`_token`/`csrf_token`) → POST with per-session cookie jar; success = status + body-diff vs failed baseline + redirect target | M/L | P1 | stdlib |
| `ntlm` | `ntlm <url>` | One request; `WWW-Authenticate: NTLM <b64>` → decode type2 → AV_PAIR walk → NetBIOS/DNS domain, forest, OS hint. **Read-only — never constructs a Type3** | S | P1 | stdlib |
| `mailauth` | `mailauth <target> --proto imap|pop3|smtp` | stdlib imaplib/poplib/smtplib; creds v2 scheduler; throttle-aware | S | P2 | stdlib |
| `policy` | `policy <dc> --user U --password P [--proto ldap,samr]` | Read-only policy read: minPwdLength, lockoutThreshold/Duration/ObservationWindow, PSOs → outputs the **spray budget** the creds engine consumes | L | P2 | needs valid creds; ldap3/impacket opt |

**Default-credential data files** (header comment in each: "Compiled from
vendor documentation and public advisory references; pairs are defaults as
shipped — verify against vendor docs before engagement"): `defaults_ssh.txt`
(~50), `defaults_ftp.txt` (~40), `defaults_http_admin.txt` (~150–200,
routerpasswords/cirt.net-style), `defaults_iot.txt` (~60, cameras/DVRs/printers),
`defaults_cisco.txt` (~30), `defaults_scada.txt` (~80, ICS-CERT advisories),
`defaults_mysql.txt`/`_postgres.txt`/`_mssql.txt` (~15–20 each, vendor docs),
`defaults_redis.txt` (~10), `defaults_snmp.txt` (~30 community strings).

### 4.4 Auth findings taxonomy

| Finding | Severity | Evidence | Remediation |
|---|---|---|---|
| Valid default credentials on service X | High (Critical at network edge/admin) | exact user:pass, host:port, timestamp, mode (audit log) | Rotate credentials; disable default accounts |
| Spray success (common password on real account) | High | round, password, username, service | Complexity + MFA; rotate |
| No lockout policy evidence | Medium | spray log + volume math | Enable lockout, threshold 5–10 |
| Weak password policy (policy read) | Medium (High if minLen <8, history 0) | attribute dump + source | Raise min length/history; PSO for privileged accounts |
| User enumeration via differential | Low–Medium | request/response pair | Uniform responses, constant-time paths |
| NTLM disclosure | Info–Low (Medium if forest disclosed) | type2 AV_PAIR contents | Prefer Kerberos-first; disable NTLM where unused |
| No-auth access (Redis INFO, SNMP public, anonymous FTP) | High | unauthenticated command + response excerpt | Enable auth / change communities / ACL |
| Anti-brute present | Info (positive note) | ban signal + timestamp | Keep; tune to alert, not just ban |

### 4.5 Auth pitfalls

- **403 vs 401:** Basic-auth testing keys on 401 (retry semantics); 403 after N requests = anti-brute ban, not "wrong password" — miscounting poisons results *and* the lockout budget. Form apps often return 200 with the login re-rendered — use baseline body-diff, never status alone.
- **CSRF churn:** token is per-session, often single-use — fetch fresh token + cookie jar per attempt or every attempt fails ("all locked" false conclusion).
- **NTLM:** the type2 blob appears only on the first 401; AV_PAIRs start after the fixed 32-byte header; post-2012 servers omit the OS pair. Detection never constructs a Type3.
- **Timing side-channels:** valid-username paths hit DB/bcrypt (tens–hundreds of ms slower) — only claim enumeration with n≥20 samples + known-good/known-bad controls, framed as "possible". Jitter the toolkit's own delays so *its* timing isn't a clean oracle against defender monitoring.
- **IP bans mid-spray:** fail2ban kills remaining rounds silently — detect, abort the round, log the ban as a finding; **never** rotate IPs/proxies (that's evasion, §11).
- **Blast radius:** never spray service/shared accounts (one lockout = production outage); lockout noise pollutes SIEM — the report should state expected log volume up front so blue-team alerts aren't mistaken for incidents.
- **Blast radius (RDP):** lockouts are domain-wide; parallel attempts against one account on different hosts cross the threshold instantly; a successful RDP logon kicks an existing user's session ("another user signed in") — real user disruption, another reason RDP cred-check is off by default.

---

## Part 5 — Build order for these modules

Assuming ROADMAP Wave 1 (registry, guard, store, audit, `--json`) is done:

1. **`namesniff`** (S, stdlib, passive-only) and **`smbprobe`** (M) — the
   two highest-value internal findings (LLMNR exposure, SMB signing/SMBv1)
   with the least dependency burden.
2. **`creds` v2 + `defaults` + data files** — the lockout-aware engine plus
   `router_defaults`/`defaults_*` gets instant value across every service.
3. **`rdp`** (M, full stdlib) + **`arpsweep`** (M) — pre-auth posture and host
   inventory; both degrade gracefully without root.
4. **`gateway` + `upnp` + `router_signatures.json`** — gateway audit rides on
   rdp/arpsweep/creds pieces.
5. **`ntlm` + `webauth`** (auth surface round).
6. **`ldapprobe`, `nbtquery`, `mdnsscan`, `netmap`, `winrm`, `ra-sweep`**.
7. **`kerbprobe`, `smbenum`, `policy`, `mailauth`, `dnssweep`** (heavier
   optional-dep territory).

Every module: scope-guard hook, audit-log integration, findings → store,
`print_table`/`print_summary` output, `--json` export, graceful
optional-dep fallbacks, and the §11 boundary test — *would a pentest report
contain this finding and how to fix it?*

---

*Vantic Breach 2.1.0 → 2.x | Every wall has a way in. | By Vantic*