# SentinelUZ EDR — Implementation Summary
# Last updated: 2026-04-07 after Phase 4D

## System Overview

SentinelUZ is a lightweight EDR system that deploys a C++ Windows agent to collect process, network, and behavioral telemetry from endpoints, sends it to a Django backend every 30 seconds, and matches it against 209k+ threat intelligence indicators to surface alerts on a web dashboard. Built for mid-size Uzbek organizations needing PP-167/PQ-153 compliance without enterprise EDR costs ($50k+).

## Architecture

- **C++ Agent** → Scans processes + TCP/UDP connections, computes SHA256 hashes, detects LOLBins and suspicious parent-child chains, sends delta telemetry via WinHTTP, runs as Windows Service (SentinelUZAgent)
- **Django Backend** → Ingests telemetry at `/api/upload/`, stores in PostgreSQL, runs detection pipeline, serves dashboard
- **Detection Engine** → `match_iocs()` checks processes against TI hash/IP sets, known attack tools, LOLBin rules, ransomware precursors; `_is_excluded()` filters allowlisted processes
- **Web Dashboard** → Django templates + vanilla JS, dark theme (#0a0e17), Inter + JetBrains Mono fonts, 160px sidebar nav, severity colour-coded badges, 30s auto-refresh

## Data Flow

1. Agent scans running processes every 30s (delta: new PIDs only) with SHA256, LOLBin flags, parent-child chains
2. Agent scans TCP/UDP connections via `GetExtendedTcpTable` with owning process info
3. Agent POSTs JSON to `POST /api/upload/` (hostname + processes + terminatedPids + network + alerts)
4. Django `upload_data()` stores new processes, deletes terminated PIDs, replaces all network connections
5. `analyze_vulnerabilities(client)` matches process/service names against CVE database
6. `match_iocs(client)` checks all processes against TI hash set + known attack tools + LOLBin rules + ransomware precursors
7. `match_iocs()` checks all network connections against TI IP blacklist (209k+ IPs)
8. Alerts created/grouped via `_create_or_update_alert()` with 3-day dedup window + event_count
9. Dashboard renders alerts sorted by `last_seen`, grouped by `event_count`, auto-refreshes every 30s

## Django Models

| Model | Key Fields | Purpose |
|---|---|---|
| Client | hostname, ip_address, auth_token, last_seen, is_active | Registered endpoint |
| Process | client(FK), pid, name, path, sha256_hash, parent_pid, parent_name, is_lolbin, is_suspicious_chain | Process telemetry (delta) |
| Port | client(FK), local_ip, local_port, remote_ip, remote_port, protocol, state, process_name, process_id | Network connections (full replace) |
| SuspiciousActivity | client(FK), type, severity, description, ioc_matched, event_count, last_seen | Alerts with dedup grouping |
| Vulnerability | cve_id, severity, affected_software, affected_versions | CVE database entries |
| VulnerabilityMatch | vulnerability(FK), client(FK), match_type, confidence_score | Process/port/service CVE matches |
| Log | client(FK), level, message, source | Agent operational logs |
| WindowsEventLog | client(FK), source, provider, level, event_id, message | Windows event logs |
| Command | client(FK), command, args, executed, response | Remote commands to agent |
| ThreatIntelIP | ip_address, source, threat_type, is_active | Blacklisted IPs from TI feeds |
| ThreatIntelHash | sha256_hash, malware_name, source, is_active | Malware hashes from TI feeds |
| ExclusionRule | process_name, process_path, sha256_hash, match_mode, is_active, expires_at | Allowlist rules (4 modes) |
| Report | report_type, filename, file_path, generated_by, generated_at, record_count, filters_applied, file_size_bytes | Saved report archive |

## API Endpoints

| Method + URL | View | Purpose |
|---|---|---|
| `POST /api/upload/` | `upload_data()` | Agent telemetry ingestion + IoC matching |
| `POST /api/logs/upload/` | `upload_logs()` | Agent operational logs |
| `POST /api/logs/windows/` | `upload_windows_logs()` | Windows event logs (token auth) |
| `POST /api/commands/pending/` | `pending_commands()` | Agent fetches unexecuted commands |
| `GET /api/health/` | `health_check()` | Returns TI stats + endpoint count |
| `GET /dashboard/` | `dashboard()` | Main dashboard (active/inactive clients) |
| `GET /device/<id>/` | `device_detail()` | Per-device processes, ports, alerts, vulns |
| `GET /processes/` | `processes()` | All processes table |
| `GET /ports/` | `ports()` | All network connections table |
| `GET /alerts/` | `alerts()` | All alerts sorted by last_seen |
| `GET /vulnerabilities/` | `vulnerabilities()` | All CVE matches with confidence scores |
| `GET /logs/` | `logs()` | Windows event logs with filters + pagination |

## Detection Logic

- **Hash match** → `proc.sha256_hash in hash_set` → CRITICAL
- **Known attack tool** → name contains mimikatz/psexec/bloodhound/etc. (16 tools) → CRITICAL
- **Suspicious chain** → Office/browser spawned LOLBin (`is_suspicious_chain=True`) → HIGH
- **LOLBin alone** → `is_lolbin=True` without suspicious parent → LOW
- **Ransomware precursor** → vssadmin/wbadmin/bcdedit/cipher/diskshadow → CRITICAL if chain, HIGH otherwise
- **Malicious IP** → `conn.remote_ip in ip_set` → CRITICAL
- All checks skip excluded processes via `_is_excluded()`

## C++ Agent Capabilities

- **Collects**: PID, name, path, command line, parent PID/name, SHA256, LOLBin flag, suspicious chain flag, modules, CPU, memory, TCP/UDP connections (local/remote IP:port, state, owning process)
- **Sends**: JSON with hostname, processes[], terminatedPids[], network[], ports[], alerts[]
- **Delta detection**: only new PIDs sent (~95% bandwidth reduction); terminated PIDs sent for server cleanup
- **SHA256**: BCrypt API, skips files >50MB
- **LOLBins**: 17 tools (cmd, powershell, certutil, wmic, bitsadmin, vssadmin, etc.)
- **Suspicious parents**: 8 apps (WINWORD, EXCEL, POWERPNT, CHROME, FIREFOX, MSEDGE, IEXPLORE, OUTLOOK)
- **Modes**: `--service` (SCM), `--install`, `--uninstall`, `--status`, `--console`, no-args (smart installer)
- **Config**: `config.ini` with server URL, token, port, interval, hostname

## Frontend Design System

- **Theme**: Dark (#0a0e17 background, #111827 surfaces, #1a2234 elevated)
- **Fonts**: Inter (UI text: 400/500/600) + JetBrains Mono (technical data: hashes, IPs, PIDs, paths)
- **Layout**: 160px fixed sidebar + 48px top stats bar + main content area
- **Sidebar nav**: Dashboard, Alerts, Processes, Network, Vulnerabilities, Event Logs
- **Stats bar**: active endpoints count, CRITICAL alert count, TI records loaded (via `context_processors.edr_stats`)
- **Severity badges**: CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=blue — each with matching bg/border
- **Data classes**: `.mono` (JetBrains Mono for IPs/PIDs/ports/paths), `.hash` (click-to-copy SHA256 display)
- **Status dots**: green pulse animation for online, gray for offline
- **Auto-refresh**: 30s interval on alerts/processes/ports pages via fetch + DOMParser (updates #main-content only)
- **Utilities**: `timeAgo()` relative timestamps, `copyHash()` clipboard, `showToast()` notifications, JS table sort
- **No external dependencies**: Bootstrap, jQuery, DataTables all removed — pure vanilla CSS + JS

## Exclusion Rules

| Match Mode | Matches On | Use Case |
|---|---|---|
| `NAME_ONLY` | Process name (case-insensitive) | Broad exclusion for known-safe tool |
| `NAME_AND_PATH` | Name + path prefix | Exclude only from expected location |
| `HASH_ONLY` | SHA256 exact match | Pin to specific binary version |
| `ALL` | Name + path + hash | Strictest — all three must match |

- Supports `expires_at` for temporary exclusions
- Managed via Django admin panel
- Loaded fresh each `match_iocs()` call

## TI Feeds

| Source | Records | Provides |
|---|---|---|
| IPsum (stamparm/ipsum) | ~209k IPs | Multi-source aggregated blacklist |
| Feodo Tracker (abuse.ch) | ~1k IPs | C2 server IPs |
| MalwareBazaar (abuse.ch) | ~1k hashes/day | Recent malware SHA256 hashes |
| ThreatFox (abuse.ch) | Variable | Mixed IoCs (IPs + hashes, 24h) |

- Targeted mode: NetSupport, Ajina, LockBit, BlackCat, Rhysida signatures
- Sync: `python manage.py sync_ti_feeds [--targeted]`
- Cache: module-level Python set, 30-minute TTL

## Alert Lifecycle

1. `match_iocs()` runs inside `upload_data()` after every agent telemetry upload
2. `_create_or_update_alert()` checks for existing alert with same `(client, ioc_matched, type)` within 3-day window
3. If match found: `event_count += 1`, `last_seen` updated (no duplicate row)
4. If no match: new `SuspiciousActivity` created with `event_count=1`
5. Dedup keys: `tool:<name>`, `chain:<parent>:<child>`, `lolbin:<name>`, `ransomware:<name>`, `ip:<addr>`, or raw SHA256
6. Dashboard shows alerts sorted by `last_seen` desc, severity color-coded with badge-critical/high/medium/low

## Phase Status

- Phase 0: Complete — Initial Django + C++ scaffold, basic models, dashboard
- Phase 1: Complete — IoC engine, 209k IPs, 1348 hashes, alert grouping, Docker, health endpoint
- Phase 2 Session 1: Complete — config.ini reader, auth token
- Phase 2 Session 2: Complete — SHA256, LOLBin (17 tools), delta detection, parent PID chain
- Phase 2 Session 3: Complete — GetExtendedTcpTable, IP IoC matching against 209k blacklist
- Phase 2 Session 4: Complete — ExclusionRule model, Pyramid of Pain exclusions, admin panel
- Phase 2 Session 5: Complete — Static linking (libgcc/libstdc++/pthread), dist/ package
- Phase 2 Session 6: Complete — Windows Service (SentinelUZAgent), self-elevating UAC installer, 5 command modes
- Phase 3 Session 3.1: Complete — Dark theme, sidebar nav, Inter+JetBrains Mono, severity badges, auto-refresh, context processor
- Phase 3 Session 3.2: PENDING — Process tree visualisation
- Phase 3 Session 3.3: PENDING — Alerts panel redesign (cards)
- Phase 3 Session 3.4: PENDING — IoC Manager page
- Phase 3 Session 3.5: PENDING — Dashboard overview redesign
- Phase 3 Session 3.6: PENDING — Help & Documentation Center
- Phase 4: PENDING — Data retention management command
- Phase 5: PENDING — Integration testing + Bloody Wolf demo

## Known Limitations

- No automated response (kill process, isolate endpoint) — detection only
- No Linux agent — Windows-only
- SQLite in development; PostgreSQL requires Docker
- TI cache is per-process (not shared across Django workers)
- Auto-refresh replaces #main-content innerHTML — scroll position resets on refresh
- Agent `_popen()` command execution has no sandboxing
- Service mode `std::cout` output goes nowhere (harmless but invisible)
- No ioc_manager.html or process_tree.html templates yet
