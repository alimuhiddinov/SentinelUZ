# SentinelUZ — Endpoint Detection and Response

> **"Your endpoints, our vigilance."**

SentinelUZ is a lightweight EDR platform built for organisations
in Uzbekistan that need real-time endpoint threat detection without
enterprise pricing. It monitors Windows endpoints for malware,
lateral movement, and suspicious process behaviour, sending alerts
to a central web dashboard for analyst review.

Built as a BSc Business Information Systems final-year project at
Westminster International University in Tashkent (WIUT).

---

## What it does

Every SentinelUZ agent runs silently on a Windows endpoint and
reports back to the central server every 30 seconds. The server
analyses the telemetry, matches it against a threat intelligence
database, and raises alerts when something looks wrong.

An analyst logs into the web dashboard, reviews the alerts,
investigates the timeline of events on any affected endpoint, and
takes action — adding an exclusion or marking the alert as a
false positive.

---

## Detection capabilities

| Detection type | Description |
|---|---|
| Hash match | SHA-256 of running processes checked against MalwareBazaar and ThreatFox threat intel feeds |
| Known attack tools | 16 offensive tools detected by name: Mimikatz, Cobalt Strike, BloodHound, PsExec, Rubeus, and others |
| Suspicious process chain | 8 suspicious parents (Word, Excel, Outlook, browsers) spawning any of 17 LOLBins triggers an alert |
| LOLBin abuse | 17 living-off-the-land binaries: cmd, powershell, certutil, mshta, regsvr32, rundll32, wscript, and others |
| Malicious IP match | Outbound connections checked against IPsum, Feodo Tracker, and ThreatFox IP blacklists |
| Alert deduplication | Matching alerts within a 3-day window are grouped and increment an event counter instead of creating duplicates |

---

## Architecture

```
Windows Endpoint          Central Server (Django)
─────────────────         ──────────────────────────────
SentinelUZ Agent    ───►  REST API  ──►  PostgreSQL
(C++ service)             │              (events, alerts,
│                       │               processes)
│ reports:              │
├─ running processes    ▼
├─ network connections  Alert Engine
├─ file hashes          │
└─ system events        ▼
                        Web Dashboard
                        (Owner / IT Manager)
```

**Agent:** C++ Windows service, runs as SYSTEM, reports every 30 seconds
**Server:** Django 4.2, PostgreSQL 15, Docker Compose
**Dashboard:** Role-based web UI — Owner and IT Manager

---

## Tech stack

| Component | Technology |
|---|---|
| Agent | C++17, Windows API, WinHTTP |
| Backend | Python 3.11, Django 4.2, Django REST Framework |
| Database | PostgreSQL 15 |
| Threat intel | MalwareBazaar, ThreatFox, IPsum, Feodo Tracker |
| Frontend | Django templates, vanilla JS |
| Deployment | Docker Compose (2 containers: Django + PostgreSQL) |

---

## Quick start

### Prerequisites
- Docker Desktop
- Windows machine for the agent (or use the demo data)

### 1. Clone and configure

```bash
git clone https://github.com/alimuhiddinov/SentinelUZ.git
cd SentinelUZ
cp edr_server/.env.example edr_server/.env
# Edit edr_server/.env with your values
```

### 2. Start the server

```bash
docker compose up --build -d
docker compose exec django python manage.py migrate
docker compose exec django python manage.py createsuperuser
```

### 3. Load threat intelligence

```bash
docker compose exec django python manage.py sync_ti_feeds
```

### 4. Open dashboard
http://localhost:8000

### 5. Install agent on Windows endpoint

Build the agent with CMake (MinGW-w64), then configure `config.ini` with the server URL and auth token:

```ini
[server]
url=http://your-server-ip:8000
token=your-auth-token
```

Install as a Windows service (run as Administrator):
```
edr_client.exe --install
```

The agent installs as a Windows service and starts automatically.

---

## User roles

| Permission | Owner | IT Manager |
|---|:---:|:---:|
| View dashboard and alerts | ✅ | ✅ |
| View endpoint events | ✅ | ✅ |
| Acknowledge alerts | ✅ | ✅ |
| Add exclusions | ✅ | ✅ |
| Manage IoC rules | ✅ | ✅ |
| Manage company and users | ✅ | ❌ |
| Sync threat intel feeds | ✅ | ❌ |

Owner = staff or superuser. IT Manager = any other authenticated user.

---

## Project structure

```
SentinelUZ/
├── edr_server/              # Django backend
│   ├── edr_app/             # Main application
│   │   ├── models.py        # 19 models (endpoints, alerts, TI, incidents)
│   │   ├── views.py         # API endpoints + dashboard views
│   │   ├── utils.py         # IoC matching, alert engine
│   │   ├── urls.py          # URL routing
│   │   ├── templates/       # Dashboard HTML templates
│   │   └── management/      # sync_ti_feeds, cleanup_old_data
│   ├── edr_server/          # Django project settings
│   └── Dockerfile
├── edr_client/              # C++ Windows agent
│   ├── src/
│   │   ├── main.cpp         # Entry point, service modes
│   │   ├── process_scanner.cpp   # Process enumeration, SHA-256, LOLBin detection
│   │   ├── port_scanner.cpp      # Network connection enumeration
│   │   ├── network_client.cpp    # HTTP reporting to server
│   │   ├── config_reader.cpp     # INI configuration parser
│   │   └── service_manager.cpp   # Windows service lifecycle
│   └── CMakeLists.txt
├── docker-compose.yml
└── edr_server/.env.example
```

---

## Limitations

- Windows agent only (Linux agent is future work)
- No memory forensics or kernel-level hooks
- Static TI matching — no behavioural ML classifier
- Single-tenant — one organisation per deployment

---

## Future development

- Linux agent (C++ cross-platform build)
- Memory scanning with YARA
- ML-based anomaly detection
- MITRE ATT&CK technique tagging on alerts
- Multi-tenant SaaS architecture

---

## Testing

```bash
docker compose exec django python manage.py test --verbosity=2
```

111 tests · 19 models · 20 migrations

---

*BSc Business Information Systems · Westminster International University in Tashkent · 2026*
