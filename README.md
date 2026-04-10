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
reports back to the central server every few seconds. The server
analyses the telemetry, matches it against a threat intelligence
database, and raises alerts when something looks wrong.

A security analyst logs into the web dashboard, reviews the alerts,
investigates the timeline of events on any affected endpoint, and
takes action — isolating the machine, adding an exclusion, or
marking the alert as a false positive.

---

## Detection capabilities

| Detection type | Description |
|---|---|
| Hash match | SHA-256 of running processes checked against 264,109 known malware hashes |
| Known attack tools | 16 offensive tools detected by name: Mimikatz, Cobalt Strike, BloodHound, PsExec, and others |
| Suspicious process chain | 8 parent-child process pairs flagged: Word spawning cmd, PowerShell spawning net, and similar |
| LOLBin abuse | Living-off-the-land binaries used maliciously: certutil, mshta, regsvr32, wscript |
| Network anomaly | Beacon-like outbound connections, connections to known malicious IPs |
| Delta scoring | Cumulative risk score per endpoint — alert fires when score crosses threshold |

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
                        (Admin / Analyst / Viewer)
```

**Agent:** C++ Windows service, runs as SYSTEM, reports every 30 seconds
**Server:** Django 4.2, PostgreSQL 15, Redis + Celery, Docker Compose
**Dashboard:** Role-based web UI — Admin, Analyst, Viewer

---

## Tech stack

| Component | Technology |
|---|---|
| Agent | C++17, Windows API, WinHTTP |
| Backend | Python 3.12, Django 4.2, Django REST Framework |
| Database | PostgreSQL 15 |
| Task queue | Redis 7 + Celery 5 |
| Threat intel | MalwareBazaar (264,109 hashes), 16 LOLBin signatures |
| Frontend | Django templates, vanilla JS |
| Deployment | Docker Compose (4 containers) |

---

## Quick start

### Prerequisites
- Docker Desktop
- Windows machine for the agent (or use the demo data)

### 1. Clone and configure

```bash
git clone https://github.com/alimuhiddinov/SentinelUZ.git
cd SentinelUZ
cp .env.example .env
# Edit .env with your values
```

### 2. Start the server

```bash
docker compose up --build -d
docker compose exec edr_server python manage.py migrate
docker compose exec edr_server python manage.py createsuperuser
```

### 3. Load threat intelligence

```bash
docker compose exec edr_server python manage.py update_ti_feeds
```

### 4. Open dashboard
http://localhost:8000

### 5. Install agent on Windows endpoint

Build the agent or download from Releases, then run as Administrator:
```
SentinelUZAgent.exe --server http://your-server-ip:8000 --install
```

The agent installs as a Windows service and starts automatically.

---

## User roles

| Permission | Admin | Analyst | Viewer |
|---|:---:|:---:|:---:|
| View dashboard and alerts | ✅ | ✅ | ✅ |
| View endpoint events | ✅ | ✅ | ✅ |
| Acknowledge alerts | ✅ | ✅ | ❌ |
| Mark false positive | ✅ | ✅ | ❌ |
| Add exclusions | ✅ | ❌ | ❌ |
| Manage endpoints | ✅ | ❌ | ❌ |
| Manage users | ✅ | ❌ | ❌ |
| View threat intel database | ✅ | ✅ | ❌ |

---

## Project structure

```
SentinelUZ/
├── edr_server/          # Django backend
│   ├── alerts/          # Alert models, views, scoring engine
│   ├── endpoints/       # Endpoint registration and management
│   ├── events/          # Process, network, file event ingestion
│   ├── threat_intel/    # TI database and feed sync
│   ├── accounts/        # User auth and roles
│   └── owner/           # Company and licence management
├── edr_client/          # C++ Windows agent
│   ├── src/
│   │   ├── collector/   # Process, network, file collectors
│   │   ├── reporter/    # HTTP reporting to server
│   │   └── service/     # Windows service wrapper
│   └── CMakeLists.txt
├── docker-compose.yml
└── .env.example
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
- Mobile push notifications

---

## Testing

```bash
docker compose exec edr_server python manage.py test --verbosity=2
```

111 tests · 16 models · 20 migrations

---

*BSc Business Information Systems · Westminster International University in Tashkent · 2026*
