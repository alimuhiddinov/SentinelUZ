# SentinelUZ — BISP Final Year Project
# Westminster International University in Tashkent
# Module: 6BUIS007C-n | Deadline: 10 April 2026

## Project Summary
Lightweight EDR (Endpoint Detection & Response) system for mid-size
Uzbek organizations. Target users: IT managers with no security
background who need basic endpoint visibility to comply with PP-167
and PQ-153 regulations.
GitHub: https://github.com/alimuhiddinov/SentinelUZ

## Repository Structure
- edr_client/     → C++ Windows agent (process + network telemetry)
- edr_server/     → Django 4.2 + DRF backend + web dashboard
- docker-compose.yml → one-command deployment

## CRITICAL: Real App Structure
- Django app name is: edr_app (NOT dashboard)
- App path: edr_server/edr_app/
- Models: edr_server/edr_app/models.py
- Views: edr_server/edr_app/views.py
- Utils: edr_server/edr_app/utils.py
- URLs: edr_server/edr_app/urls.py
- Templates: edr_server/edr_app/templates/edr_app/

## Existing Models (DO NOT recreate)
- Client: hostname, ip_address, last_seen, auth_token, is_active
- Process: client(FK), pid, name, path, command_line, timestamp, version
- Port: client(FK), port_number, protocol, state, process_name,
  process_id, service_name, service_version, timestamp
- SuspiciousActivity: client(FK), type, description, process_name,
  process_id, timestamp
- Vulnerability: cve_id, description, severity, published_date,
  affected_software, affected_versions
- VulnerabilityMatch: vulnerability(FK), client(FK), match_type,
  process(FK), port(FK), confidence_score, timestamp
- Log: client(FK), level, message, timestamp, source
- WindowsEventLog: client(FK), source, provider, level, event_id,
  message, timestamp
- Command: client(FK), command, args, executed, executed_at, response

## Models Added (migrations applied)
Added to Process: parent_pid, sha256_hash, is_lolbin,
  is_suspicious_chain, parent_name
Added to SuspiciousActivity: severity, ioc_matched, event_count,
  first_seen, last_seen
New: ThreatIntelIP (ip_address, source, threat_type, is_active)
New: ThreatIntelHash (sha256_hash, malware_name, source, is_active)
New: ExclusionRule (match_type, name, path, sha256_hash, reason)

## Existing API Endpoints (DO NOT recreate)
POST /api/upload/              → receives processes+ports+alerts
POST /api/logs/upload/         → upload logs
POST /api/logs/windows/        → upload Windows event logs
POST /api/commands/pending/    → agent fetches pending commands
GET  /dashboard/               → main dashboard
GET  /device/<id>/             → per-device detail
GET  /processes/               → all processes
GET  /ports/                   → all ports
GET  /alerts/                  → all alerts
GET  /vulnerabilities/         → all vuln matches
GET  /logs/                    → Windows event logs

## Endpoints to ADD
GET  /api/health/              → {"status":"ok"}
POST /api/auth/login/          → returns token for agent
GET  /ioc-manager/             → new page
GET  /process-tree/            → new page

## Tech Stack
Backend:   Python 3.8+, Django 4.2, DRF, PostgreSQL
Database:  PostgreSQL 15 (Docker), Django ORM only — no raw SQL
Frontend:  Django templates + vanilla JS + dark CSS (NO React/Vue)
Agent:     C++17, MinGW-w64, CMake, nlohmann/json, WinHTTP, CryptoAPI
TI Feeds:  IPsum, abuse.ch Feodo, MalwareBazaar, ThreatFox (all free)
Deploy:    Docker Compose

## Code Rules
- Python: snake_case, Django ORM only
- Secrets: .env + python-decouple, never hardcoded
- C++: RAII for all Windows handles
- Frontend: vanilla JS only, no frameworks
- API responses: {"status":"ok","data":[]} or
  {"status":"error","message":"..."}

## What is NOT built yet
- Process tree visualisation (Phase 3 Session 3.2)
- Alerts panel card redesign (Phase 3 Session 3.3)
- ioc_manager.html template (Phase 3 Session 3.4)
- Dashboard overview stat cards (Phase 3 Session 3.5)
- Help & Documentation Center (Phase 3 Session 3.6)
- Data retention management command (Phase 4)
- Integration testing + Bloody Wolf demo (Phase 5)

## EXPLICITLY OUT OF SCOPE — never suggest
- ML/AI-based detection
- Automated response (kill process, isolate endpoint)
- Linux agent
- Multi-tenancy / MSSP
- Payment processing
- React, Vue, Angular, jQuery
- Elasticsearch
- Email/Telegram notifications

## Demo for Viva (April 18-30)
Bloody Wolf attack simulation on 2 VirtualBox Windows 10 VMs:
fake doc → cmd.exe → powershell.exe →
outbound C2 connection to blacklisted IP →
SentinelUZ fires alert with full process chain

## Business Context
- Market: mid-size Uzbek orgs (healthcare, education, govt)
- Laws: PP-167 (May 2023), PQ-153 (April 2025)
- Pricing: Free/10 endpoints, $600/yr/50, $1500/yr/200
- Key threats: Bloody Wolf (NetSupport RAT), Ajina.Banker
- Gap: Enterprise EDR $50k+, Wazuh too complex

## Current Phase Status
- Phase 0: Complete — Initial Django + C++ scaffold, base models, dashboard
- Phase 1: Complete — IoC engine, 209k IPs, 1348 hashes,
  alert grouping (event_count, 3-day window), Docker, health endpoint
- Phase 2 Session 1: Complete — config.ini reader, auth token
- Phase 2 Session 2: Complete — SHA256, LOLBin (17 tools),
  delta detection, parent PID chain
- Phase 2 Session 3: Complete — GetExtendedTcpTable,
  IP IoC matching against 209k blacklist
- Phase 2 Session 4: Complete — ExclusionRule model,
  Pyramid of Pain exclusions, admin panel
- Phase 2 Session 5: Complete — static linking (libgcc/libstdc++/pthread), dist/ package
- Phase 2 Session 6: Complete — Windows Service (SentinelUZAgent),
  self-elevating UAC installer, 5 command modes
- Phase 3 Session 3.1: Complete — Dark theme, sidebar nav,
  Inter+JetBrains Mono fonts, severity badges, auto-refresh,
  context processor, removed Bootstrap/jQuery/DataTables
- Phase 3 Session 3.2: Complete — process tree (process_tree.html,
  process_tree view, API-first loading, threats-only default,
  DocumentFragment rendering, CSS border tree lines)
- Phase 3 Session 3.3: Complete — Event model (6 types, M2M to
  SuspiciousActivity, correlation_id), alerts card layout,
  alert_detail.html (5-tab investigation workspace),
  5 alert API endpoints (detail, events, context, network,
  acknowledge), process_injection alerts flushed
- Phase 3 Session 3.4: PENDING — IoC Manager page
- Phase 3 Session 3.5: PENDING — Dashboard overview redesign
- Phase 3 Session 3.6: PENDING — Help & Documentation Center
- Phase 4: PENDING — Data retention command
- Phase 5: PENDING — Integration testing + Bloody Wolf demo

## Key Technical Decisions Made
- Alert deduplication: 3-day window, event_count field
- Delta detection: only new PIDs sent each scan (~95% reduction)
- TI cache: 30-minute module-level Python set cache
- ExclusionRule: 4 match modes (NAME_ONLY/NAME_AND_PATH/
  HASH_ONLY/ALL) — Pyramid of Pain approach
- Database: SQLite local, PostgreSQL via Docker
- Build: always prefix PATH="/c/msys64/ucrt64/bin:$PATH"
- Build dir: edr_client/build2/ (not build/)
- config.ini must be copied to build2/ after each build
- Frontend: Django templates + vanilla JS — confirmed final
  NO React, NO Vue, NO jQuery, NO Bootstrap
- Frontend UX: based on CrowdStrike Falcon, SentinelOne
  Singularity, Group-IB Huntpoint design patterns
  Key rules: dark by default, colour encodes severity only,
  sidebar nav, numbers first, expandable context in place,
  search always visible, process tree not table for processes

## Files Changed Since Initial Commit
- edr_server/edr_app/models.py — ThreatIntelIP, ThreatIntelHash,
  ExclusionRule, extended Process + SuspiciousActivity fields
- edr_server/edr_app/utils.py — match_iocs(), _create_or_update_alert(),
  _load_exclusion_rules(), _is_excluded(), 30-min TI cache
- edr_server/edr_app/views.py — upload_data() with transaction.atomic(),
  health_check(), network connection handling
- edr_server/edr_app/management/commands/sync_ti_feeds.py — 4 feeds
- edr_client/src/config_reader.cpp — INI parser
- edr_client/src/process_scanner.cpp — SHA256, LOLBin, delta, parent PID
- edr_client/src/port_scanner.cpp — GetExtendedTcpTable
- edr_client/src/network_client.cpp — auth header, new JSON payload
- edr_client/src/main.cpp — config loading, delta-aware scan loop
- .claude/skills/frontend.md — EDR-specific UX system
  (research-based: Falcon, SentinelOne, Huntpoint patterns)
- .claude/commands/build-agent.md — compile with MSYS2 PATH prefix
- .claude/commands/run-agent.md — end-to-end test command
- .claude/commands/generate-token.md — DRF token for agent
- docs/Phase2_Session4_ExclusionRules_Reference.md — generated
- edr_client/include/service_manager.h — Windows Service class
- edr_client/src/service_manager.cpp — SCM lifecycle, UAC elevation
- dist/README.txt — deployment guide
- .claude/skills/documenter.md — session documentation skill
- docs/IMPLEMENTATION_SUMMARY.md — living system reference
- docs/SESSION_LOG.md — chronological build history
- edr_server/edr_app/context_processors.py — global stats for stats bar
- edr_server/edr_app/templates/edr_app/base.html — dark theme, sidebar,
  Inter+JetBrains Mono, auto-refresh, removed Bootstrap/jQuery/DataTables

## Skill Usage Rules
- ANY frontend/template/CSS/JS work: Use skill: frontend
  (this skill encodes EDR UX patterns, do not deviate from it)
- ANY Django/API/model work: Use skill: backend
- ANY C++ agent work: Use skill: cpp-agent
- ANY detection/TI/alert logic: Use skill: security
- END of every session / "document" / "phase done": Use skill: documenter
  (updates IMPLEMENTATION_SUMMARY, SESSION_LOG, CLAUDE.md phase status)

## Deadlines
- Report: April 10, 2026
- Viva: Late April 2026