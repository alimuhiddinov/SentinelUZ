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

## Models to ADD (migrations needed)
Add to Process: parent_pid, sha256_hash, is_lolbin,
  is_suspicious_chain, parent_name
Add to SuspiciousActivity: severity, ioc_matched
New: ThreatIntelIP (ip_address, source, threat_type, is_active)
New: ThreatIntelHash (sha256_hash, malware_name, source, is_active)

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
- ThreatIntelIP and ThreatIntelHash models
- sync_ti_feeds management command
- IoC matching engine in utils.py
- parent_pid, sha256_hash, is_lolbin fields on Process
- severity, ioc_matched fields on SuspiciousActivity
- SHA256 hashing in C++ agent
- config.ini reader in C++ agent
- GetExtendedTcpTable network connections in C++ agent
- LOLBin + parent-child detection in C++ agent
- docker-compose.yml
- .env file
- /api/health/ endpoint
- ioc_manager.html template
- process_tree.html template
- Auto-refresh on dashboard

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