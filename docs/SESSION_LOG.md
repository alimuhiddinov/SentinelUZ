# SentinelUZ — Session Log
# Newest first. Append-only — never overwrite existing entries.

---

## Phase 4A — Events Enhancement + Status Workflow + Query Language
Date: 2026-04-07
Status: Complete

### Files Created
- `edr_server/edr_app/query_parser.py` — Query language parser (field:value AND/OR/NOT syntax) for events and alerts
- `edr_server/edr_app/management/commands/demo_setup.py` — Viva demo setup/teardown management command
- `edr_server/edr_app/templates/edr_app/endpoint_events.html` — Unified events feed with slide panel, query bar, SVG chart
- `edr_server/edr_app/templates/edr_app/help_center.html` — 9-section help center with TOC, process tree example, compliance
- `docs/Demo_Script.md` — 8-minute Bloody Wolf demo script for viva
- `docs/Viva_Quick_Reference.md` — Key numbers and architecture facts
- `docs/Integration_Test_Report.md` — 20-test integration test report
- `edr_server/edr_app/migrations/0013_signature.py` — Signature model migration
- `edr_server/edr_app/migrations/0014_*.py` — Status field, indexes, remove is_acknowledged

### Files Modified
- `edr_server/edr_app/models.py` — Added Signature model (12 fields, MITRE mapping), replaced is_acknowledged BooleanField with status CharField (5 states), added assigned_to/false_positive_reason/closed_at, added compound indexes on Event and SuspiciousActivity
- `edr_server/edr_app/utils.py` — Added SIGNATURES dict (6 detection types with plain English), _create_signature() helper called after each alert creation in match_iocs()
- `edr_server/edr_app/views.py` — Rewrote dashboard() with annotations, added dashboard_stats_api(), alert_signatures(), signature_events(), endpoint_events(), endpoint_events_api() (query/CSV/date range), help_center(), _event_summary()
- `edr_server/edr_app/urls.py` — Added 7 new URL patterns (dashboard stats, signatures, events, help)
- `edr_server/edr_app/admin.py` — Registered SignatureAdmin
- `edr_server/edr_app/templates/edr_app/alert_detail.html` — Added GIB-style right panel (3-state: signatures→events→JSON), session auth fix
- `edr_server/edr_app/templates/edr_app/alerts.html` — Added CSS-only tooltip icons for severity and IOC
- `edr_server/edr_app/templates/edr_app/base.html` — Added Help & Docs and Events nav links
- `edr_server/edr_app/templates/edr_app/dashboard.html` — Complete redesign: stat cards, severity bar, endpoint table, recent alerts, quick actions, auto-refresh
- `edr_server/edr_app/templates/edr_app/ioc_manager.html` — Rewritten: stat boxes, 2-col layout, auto-detect upload, safety badges

### Features Added
- **Signature model**: 6 detection types with plain English explanations and MITRE ATT&CK mapping
- **Alert detail right panel**: 3-state drill-down (signatures→events→raw JSON) with syntax highlighting
- **Endpoint events page**: Unified telemetry feed with tabs, SVG volume chart, slide panel for raw data
- **Query language**: field:value AND/OR/NOT syntax for filtering events and alerts
- **CSV export**: Export up to 5000 events as CSV from events API
- **Status workflow**: 5-state alert lifecycle (open→acknowledged→false_positive/in_incident→closed)
- **Dashboard redesign**: Stat cards, severity bar, annotated endpoint table, recent alerts, auto-refresh
- **IoC Manager redesign**: TI stats, sync button, custom IOC upload, exclusion rules with safety badges
- **Help center**: 9 sections with sticky TOC, process tree example, compliance checklists, printable reference
- **Demo setup**: Management command for Bloody Wolf simulation

### Key Decisions Made
- Replaced is_acknowledged BooleanField with status CharField to support full alert lifecycle
- Query parser uses __icontains on raw_data TextField (not JSONField) for broad text search
- Session auth for all API calls (no separate token needed from browser)

### Commit
f84224c — Phase 4A: Events enhancement

---

## Phase 3 Session 3.1 — Base Template + Navigation + Fonts
Date: 2026-04-06
Status: Complete

### Files Created
- `edr_server/edr_app/context_processors.py` — Global stats context processor (active endpoints, critical count, TI IP/hash counts) for top stats bar on every page

### Files Modified
- `edr_server/edr_server/settings.py` — Registered `edr_app.context_processors.edr_stats` in TEMPLATES context_processors
- `edr_server/edr_app/templates/edr_app/base.html` — Complete rewrite: dark theme (#0a0e17), 160px fixed sidebar, 48px stats bar, Inter + JetBrains Mono fonts, 55+ CSS variables, severity badges, .mono/.hash classes, 30s auto-refresh JS, table sort, timeAgo(), copyHash(), showToast()
- `edr_server/edr_app/templates/edr_app/dashboard.html` — New layout with status dots (online pulse animation, offline gray), mono classes on hostnames/IPs
- `edr_server/edr_app/templates/edr_app/alerts.html` — Severity badges (badge-critical/high/medium/low), IoC matched column, relative timestamps with data-iso, 10 columns
- `edr_server/edr_app/templates/edr_app/processes.html` — SHA256 hash display with click-to-copy, LOLBin/CHAIN badges, parent name column, mono on PID/path
- `edr_server/edr_app/templates/edr_app/ports.html` — Mono classes on all IP/port/PID fields, custom state badges (established/listening/other)
- `edr_server/edr_app/templates/edr_app/device_detail.html` — Full dark theme redesign with all mono/hash/badge classes, alerts section added
- `edr_server/edr_app/templates/edr_app/vulnerabilities.html` — Severity badges, mono on CVE IDs/hostnames, confidence score colour coding
- `edr_server/edr_app/templates/edr_app/logs.html` — Custom dark filter form, pagination without DataTables, level colour coding
- `edr_server/edr_app/templates/edr_app/login.html` — Standalone dark login page (no base.html dependency, own Inter font import)

### Features Added
- **Dark theme**: Complete EDR-style dark UI (#0a0e17 page, #111827 surfaces, #1a2234 elevated)
- **Two-font system**: Inter for all UI text (400/500/600), JetBrains Mono for technical data (hashes, IPs, PIDs, paths)
- **Sidebar navigation**: 160px fixed left, 9 nav items, active state with left accent border, SVG icons
- **Top stats bar**: Active endpoints, CRITICAL count (red when >0), TI records loaded — via context processor
- **Severity colour system**: 55+ CSS variables — CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=blue with matching bg/border variants
- **CSS classes**: `.badge-critical/high/medium/low`, `.mono` (monospace technical data), `.hash` (click-to-copy SHA256), `.status-dot` (online/offline)
- **Auto-refresh**: 30s interval on /alerts/, /processes/, /ports/ — fetch + DOMParser replaces #main-content only
- **Table sort**: Click any column header to sort ascending/descending (numeric-aware)
- **Utility JS**: `timeAgo()` relative timestamps, `copyHash()` clipboard with toast, `showToast()` notifications
- **Context processor**: `edr_stats()` provides global stats to every template without per-view duplication

### Key Decisions Made
- **Removed Bootstrap/jQuery/DataTables entirely**: Pure vanilla CSS + JS reduces page load, eliminates dark-theme conflicts, removes 4 CDN dependencies
- **Context processor over per-view data**: Avoids duplicating TI/alert count queries in every view function
- **Auto-refresh via DOMParser**: Only replaces #main-content innerHTML, preserving sidebar and stats bar state
- **Standalone login.html**: Does not extend base.html — avoids showing sidebar/stats bar to unauthenticated users
- **SVG icons inline**: No Font Awesome or Bootstrap Icons CDN — 7 inline SVGs in sidebar for zero external requests

### Test Results
- Django system check: Pass — 0 issues
- Template syntax validation: Pass — all 9 templates load without errors
- Context processor import: Pass

### Known Issues / Future Work
- Auto-refresh resets scroll position on content update
- Stats bar TI count displays raw number (not formatted as "209k" — needs template filter)
- Process tree and IoC Manager pages not yet created (Sessions 3.2, 3.4)

### Commit
Pending (uncommitted changes)

---

## Phase 2 Session 6 — Windows Service + Self-Elevating Installer
Date: 2026-04-05
Status: Complete

### Files Created
- `edr_client/include/service_manager.h` — ServiceManager class with RAII ScHandleGuard, static methods, std::atomic stop flag
- `edr_client/src/service_manager.cpp` — Full Windows Service lifecycle: install/uninstall/start/stop, UAC elevation, SCM dispatcher
- `dist/README.txt` — One-page deployment guide for IT managers

### Files Modified
- `edr_client/src/main.cpp` — Extracted `RunMonitoringLoop()` + `GetExeDirectory()`, added argc/argv, 6 command flags, smart no-args installer with 3 cases
- `edr_client/CMakeLists.txt` — Added service_manager.cpp/.h, linked advapi32, shell32, user32

### Features Added
- **Windows Service**: SentinelUZAgent service with SERVICE_AUTO_START, runs monitoring loop via ServiceMain
- **Self-elevating installer**: double-click exe detects state, shows MessageBox, requests UAC via ShellExecuteExW("runas"), installs + starts
- **5 command modes**: `--service` (SCM entry), `--install`, `--uninstall`, `--status`, `--console` (debug)
- **Responsive stop**: 100ms sleep chunks instead of blocking 30s, service responds to stop within ~100ms
- **Config path resolution**: `GetExeDirectory()` so service finds config.ini (CWD = System32)
- **RAII ScHandleGuard**: all SC_HANDLE values auto-closed

### Key Decisions Made
- **Console subsystem preserved**: service works from console exe, keeps --status/--console output visible
- **std::atomic<bool> over volatile bool**: correct cross-thread semantics for stop flag
- **Binary path quoting**: CreateServiceW gets quoted path to handle spaces in install location
- **dist/ package**: exe + config.ini + libwinpthread DLL + README.txt

### Test Results
- Build: Pass — clean compile, no errors, all targets built
- dist/ packaging: Pass — exe copied, README created

### Known Issues / Future Work
- Service mode std::cout goes nowhere (harmless)
- Manual testing required (Tests A-D in plan) — UAC elevation cannot be automated
- No Windows Event Log writing from service (stretch)

### Commit
Pending (uncommitted changes)

---

## Phase 2 Session 5 — Static Linking + dist/ Package
Date: 2026-04-05
Status: Complete

### Files Modified
- `edr_client/CMakeLists.txt` — Added static linking flags for libgcc, libstdc++, pthread; added strip post-build

### Features Added
- **Static linking**: `-static-libgcc -static-libstdc++` + static pthread linking for portable binary
- **Binary stripping**: post-build strip command reduces exe size
- **dist/ directory**: deployable package with edr_client.exe, libwinpthread-1.dll, config.ini

### Key Decisions Made
- **libwinpthread-1.dll still needed**: MinGW's pthread implementation requires this DLL even with static linking
- **Build dir**: build2/ (not build/) to avoid conflicts

### Commit
Pending (uncommitted changes)

---

## Phase 2 Session 4 — Exclusion Rules
Date: 2026-04-04
Status: Complete

### Files Created
- `edr_server/edr_app/migrations/0010_exclusionrule.py` — ExclusionRule model migration
- `docs/Phase2_Session4_ExclusionRules_Reference.md` — Reference documentation

### Files Modified
- `edr_server/edr_app/models.py` — Added ExclusionRule model with 4 match modes, expires_at, admin FK
- `edr_server/edr_app/utils.py` — Added `_load_exclusion_rules()`, `_is_excluded()`, integrated into `match_iocs()`
- `edr_server/edr_app/admin.py` — Registered ExclusionRule in Django admin

### Features Added
- **ExclusionRule model**: 4 match modes (NAME_ONLY, NAME_AND_PATH, HASH_ONLY, ALL) — Pyramid of Pain approach
- **Exclusion filtering**: `_is_excluded()` checks each process against active rules before IoC matching
- **Temporary exclusions**: `expires_at` field for time-limited allowlisting
- **Admin panel**: ExclusionRule manageable via Django admin

### Key Decisions Made
- **Pyramid of Pain approach**: match modes ordered by specificity (hash > path+name > name)
- **Fresh load each call**: exclusion rules loaded each `match_iocs()` — no stale cache risk

### Commit
Pending (uncommitted changes)

---

## Phase 2 Session 3 — Network Connection Scanning + IP IoC Matching
Date: 2026-04-03
Status: Complete

### Files Created
- `edr_server/edr_app/migrations/0009_port_local_ip_port_local_port_port_remote_ip_and_more.py` — Port model extended fields

### Files Modified
- `edr_client/src/port_scanner.cpp` — Replaced netstat parsing with `GetExtendedTcpTable` API, added UDP scanning
- `edr_client/include/port_info.h` — Added localIp, localPort, remoteIp, remotePort, owningPid, owningPath fields
- `edr_client/src/network_client.cpp` — New JSON payload format with network[] array (localIp, remoteIp, etc.)
- `edr_server/edr_app/models.py` — Added local_ip, local_port, remote_ip, remote_port to Port model
- `edr_server/edr_app/views.py` — upload_data() handles new network connection format
- `edr_server/edr_app/utils.py` — match_iocs() checks remote_ip against TI IP blacklist

### Features Added
- **GetExtendedTcpTable**: native Windows API for TCP connections with owning PID
- **UDP scanning**: GetExtendedUdpTable for UDP connections
- **IP IoC matching**: all remote IPs checked against 209k+ TI IP blacklist
- **MALICIOUS_IP alert type**: CRITICAL severity when connection to blacklisted IP detected

### Key Decisions Made
- **Native API over netstat**: GetExtendedTcpTable is faster and more reliable than parsing netstat output
- **Full replace strategy**: all network connections replaced each scan cycle (not delta)

### Commit
Pending (uncommitted changes)

---

## Phase 2 Session 2 — SHA256 Hashing, LOLBin Detection, Delta Detection
Date: 2026-04-02
Status: Complete

### Files Modified
- `edr_client/src/process_scanner.cpp` — Added SHA256 via BCrypt, LOLBin detection (17 tools), delta detection (new PIDs only), parent PID chain, suspicious chain detection
- `edr_client/include/process_info.h` — Added sha256Hash, isLolbin, isSuspiciousChain, parentPid, parentName fields
- `edr_client/src/network_client.cpp` — Updated JSON payload to include new process fields
- `edr_server/edr_app/models.py` — Added parent_pid, sha256_hash, is_lolbin, is_suspicious_chain, parent_name to Process
- `edr_server/edr_app/utils.py` — match_iocs() checks for KNOWN_ATTACK_TOOLS, SUSPICIOUS_CHAIN, LOLBIN_DETECTED, RANSOMWARE_PRECURSOR

### Features Added
- **SHA256 hashing**: BCrypt API, skips files >50MB, hex-encoded output
- **LOLBin detection**: 17 living-off-the-land binaries flagged (cmd, powershell, certutil, etc.)
- **Suspicious parent-child chains**: Office/browser spawning LOLBin → HIGH alert
- **Delta detection**: only new PIDs sent (~95% bandwidth reduction)
- **Ransomware precursor detection**: vssadmin, wbadmin, bcdedit, cipher, diskshadow

### Key Decisions Made
- **50MB hash limit**: skip large files to avoid scan delays
- **Delta over full snapshot**: dramatically reduces upload size; terminated PIDs sent separately

### Commit
Pending (uncommitted changes)

---

## Phase 2 Session 1 — Config Reader + Auth Token
Date: 2026-04-01
Status: Complete

### Files Created
- `edr_client/include/config_reader.h` — ConfigReader struct with server URL, token, port, interval, hostname
- `edr_client/src/config_reader.cpp` — INI file parser supporting [server] and [agent] sections
- `edr_client/config.ini` — Default configuration file

### Files Modified
- `edr_client/src/main.cpp` — Loads config from config.ini, passes to NetworkClient
- `edr_client/src/network_client.cpp` — Added Token auth header, accepts ConfigReader in constructor

### Features Added
- **INI config reader**: parses config.ini with url, token, port, interval_seconds, hostname
- **Auto hostname**: resolves Windows computer name if hostname=auto
- **Token authentication**: Authorization: Token header sent with all API requests

### Key Decisions Made
- **INI format**: simple, no external dependencies, easy for IT managers to edit
- **config.ini must be beside exe**: resolved relative to working directory (later fixed to exe directory in Session 6)

### Commit
Pending (uncommitted changes)

---

## Phase 1 — IoC Engine, TI Feeds, Alert Grouping, Docker
Date: 2026-03-30
Status: Complete

### Files Created
- `edr_server/edr_app/management/commands/sync_ti_feeds.py` — 4 TI feed sync command (IPsum, Feodo, MalwareBazaar, ThreatFox)
- `edr_server/edr_app/migrations/0008_suspiciousactivity_event_count_and_more.py` — SuspiciousActivity extended fields
- `docker-compose.yml` — PostgreSQL + Django one-command deployment

### Files Modified
- `edr_server/edr_app/models.py` — Added ThreatIntelIP, ThreatIntelHash, extended SuspiciousActivity (severity, ioc_matched, event_count, last_seen)
- `edr_server/edr_app/utils.py` — Added match_iocs(), _create_or_update_alert(), 30-min TI cache, KNOWN_ATTACK_TOOLS, RANSOMWARE_PRECURSORS
- `edr_server/edr_app/views.py` — Added health_check(), transaction.atomic() in upload_data(), match_iocs() call

### Features Added
- **IoC matching engine**: hash match, attack tool detection, suspicious chains, ransomware precursors, IP blacklist
- **TI feed sync**: 4 free feeds (IPsum 209k IPs, Feodo C2s, MalwareBazaar hashes, ThreatFox mixed)
- **Targeted mode**: MalwareBazaar signatures for NetSupport, Ajina, LockBit, BlackCat, Rhysida
- **Alert deduplication**: 3-day window, event_count increment, ioc_matched key
- **Health endpoint**: GET /api/health/ with TI stats
- **Docker deployment**: docker-compose.yml with PostgreSQL 15

### Key Decisions Made
- **30-minute TI cache**: balance between freshness and DB query load
- **3-day dedup window**: prevents alert flood during persistent threats
- **event_count field**: tracks recurrence without creating duplicate rows

### Commit
c699343 — Phase 1 complete: IoC engine, TI feeds, ransomware detection, Docker, health endpoint

---

## Phase 0 — Initial Scaffold
Date: 2026-03-28
Status: Complete

### Files Created
- Full Django project structure (edr_server/)
- Full C++ agent structure (edr_client/)
- All base models: Client, Process, Port, SuspiciousActivity, Vulnerability, VulnerabilityMatch, Log, WindowsEventLog, Command
- All base views: dashboard, device_detail, processes, ports, alerts, vulnerabilities, logs
- All base API endpoints: upload_data, upload_logs, pending_commands
- All base templates: dashboard.html, device_detail.html, processes.html, ports.html, alerts.html, etc.
- C++ agent: process scanning (CreateToolhelp32Snapshot), basic port scanning, behavior monitor, network client (WinHTTP), log collector

### Features Added
- **Django backend**: models, views, serializers, URLs, templates, admin
- **C++ agent**: process enumeration, network scanning, behavior detection, HTTP client, log collection
- **Web dashboard**: device list, process table, port table, alert table, vulnerability table, log viewer

### Commit
d2f0be9 — Initial commit - SentinelUZ EDR System
