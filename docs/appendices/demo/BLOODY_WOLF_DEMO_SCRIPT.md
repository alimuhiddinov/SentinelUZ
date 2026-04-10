# SentinelUZ — Bloody Wolf Demo Script
## Viva demonstration — 8 minutes

### Setup (10 minutes BEFORE examiner arrives)

1. Start the server:
   ```
   docker compose up -d
   ```
   Verify: http://localhost:8000 loads

2. Open browser with 5 tabs ready:
   - Tab 1: http://localhost:8000/              (Dashboard)
   - Tab 2: http://localhost:8000/alerts/       (Alert list)
   - Tab 3: http://localhost:8000/endpoints/    (Endpoint list)
   - Tab 4: http://localhost:8000/events/       (Event browser)
   - Tab 5: http://localhost:8000/threat-intel/ (TI stats)

3. Login as: admin / admin123

4. Run demo setup command:
   ```
   python manage.py demo_setup
   ```
   This creates:
   - 3 simulated endpoints (DESKTOP-7F3K2, SERVER-PROD, LAPTOP-HR01)
   - 12 sample alerts (4 CRITICAL, 5 HIGH, 3 MEDIUM)
   - The Bloody Wolf STRRAT scenario on DESKTOP-7F3K2
   - 264,109 TI hash records pre-loaded

5. Confirm dashboard shows:
   - At least 4 CRITICAL alerts
   - 3 endpoints visible
   - Red badge on alerts menu

---

### Minute 0–1: Opening on Dashboard (Tab 1)

SAY:
"SentinelUZ is an Endpoint Detection and Response platform that
monitors Windows devices inside an organisation and raises alerts
when threats are detected. What you can see here is the live
dashboard showing the current security posture of the estate."

POINT TO:
- The CRITICAL alert count (highlight in red)
- The 3 endpoints in the endpoint summary
- The last sync time on TI stats

SAY:
"This particular environment has just detected a Bloody Wolf
campaign — STRRAT malware delivered via phishing — which is
exactly the kind of threat that affected real organisations in
Central Asia according to Group-IB's 2021 threat report."

---

### Minute 1–2: Alert List (Tab 2)

CLICK: Tab 2 — Alerts
FILTER: Severity = CRITICAL

SAY:
"Here are the four CRITICAL alerts raised in the last cycle.
Each alert shows the endpoint name, the detection type, the
delta score, and the time it was raised."

CLICK: The top alert — DESKTOP-7F3K2 / score 95

SAY:
"This alert scored 95 out of 100. Let me show you exactly
why the system flagged it."

---

### Minute 2–4: Alert Detail — The Core Demo

ON THE ALERT DETAIL PAGE:

POINT TO detection flags:
"Three detection types fired simultaneously on this endpoint.
First — HASH_MATCH. The SHA-256 of the file that executed
matched a record in our MalwareBazaar database of 264,109
known malware hashes. That alone would be enough."

POINT TO SUSPICIOUS_CHAIN flag:
"Second — SUSPICIOUS_CHAIN. The agent observed Outlook
spawning Java, Java spawning cmd.exe, cmd.exe spawning
PowerShell. That parent-child process chain is a textbook
indicator of a Java-based remote access trojan executing
via a malicious email attachment."

POINT TO KNOWN_ATTACK_TOOL flag:
"Third — KNOWN_ATTACK_TOOL. STRRAT appears by name in our
known attack tool list alongside Mimikatz, Cobalt Strike,
and BloodHound."

POINT TO delta score breakdown:
"The scoring system assigned:
  HASH_MATCH:        40 points
  SUSPICIOUS_CHAIN:  25 points
  KNOWN_ATTACK_TOOL: 30 points
  Total delta score: 95 — well above the CRITICAL threshold."

---

### Minute 4–5: Event Timeline (Tab 4)

CLICK: Tab 4 — Events
FILTER: Endpoint = DESKTOP-7F3K2

SAY:
"The event browser shows every process, network connection
and file event the agent captured from that endpoint during
the detection window."

POINT TO the process events:
"You can see outlook.exe, then java.exe, then the shell
chain, each with its SHA-256 hash, timestamp, and parent
process ID. This is the forensic evidence an analyst would
use to reconstruct exactly what happened."

---

### Minute 5–6: Threat Intelligence (Tab 5)

CLICK: Tab 5 — Threat Intel

SAY:
"SentinelUZ is backed by real threat intelligence. The hash
database currently holds 264,109 malware signatures sourced
from MalwareBazaar, updated daily by a scheduled Celery task.
The detection that caught STRRAT was a direct lookup against
this database — no machine learning, no black box — a
transparent hash match against a verified external feed."

---

### Minute 6–7: Analyst Action

CLICK: Back to alert detail
CLICK: "Acknowledge" button

SAY:
"The analyst acknowledges the alert, adds a note, and in a
real scenario would isolate the endpoint and begin the
containment procedure. The role-based access system means
a Viewer cannot take this action — only an Analyst or Admin."

CLICK: Create Incident
SAY:
"Critical alerts like this would be escalated to an Incident,
which groups related alerts, tracks the investigation, and
produces a report for the IT Security Manager."

---

### Minute 7–8: Technical Q&A Buffer

LIKELY EXAMINER QUESTIONS AND ANSWERS:

Q: How does the agent communicate with the server?
A: "The C++ agent runs as a Windows service under the SYSTEM
   account. Every 30 seconds it collects a process snapshot,
   computes SHA-256 hashes, runs the detection checks locally,
   and POSTs the results to the Django REST API over HTTP.
   The agent uses a token issued at registration for auth."

Q: Why not use machine learning?
A: "The literature — specifically Brabec et al. 2023 — argues
   that modular, explainable detection outperforms black-box
   classifiers in environments with limited training data.
   Uzbek SMBs do not have labelled incident datasets. A
   deterministic scoring model with transparent rules is more
   appropriate and more trustworthy for a first deployment."

Q: What are the limitations?
A: "Windows only — no Linux agent yet. HTTP not HTTPS on the
   agent channel in this prototype. No memory forensics or
   kernel hooks. No dynamic sandbox. All documented as future
   work in the reflection chapter."

Q: How does the pricing compare?
A: "CrowdStrike Falcon Enterprise costs approximately $185 per
   endpoint per year. SentinelUZ targets $12 per endpoint per
   year through the MSSP channel — roughly 15 times cheaper —
   which makes it viable for the Uzbek SME market."

Q: What is the test coverage?
A: "111 tests passing, 16 models, 20 migrations. The core
   detection engine — the IoC matching and delta scoring —
   achieves 95% coverage. The overall project measures 82%
   when management commands are included."

---

### Closing line

SAY:
"SentinelUZ demonstrates that production-grade threat detection
principles — hash matching, process chain analysis, threat
intelligence integration — can be delivered at a price point
that actually fits the Uzbek market, without sacrificing
the transparency and auditability that smaller organisations
need to trust a security tool."

---

## Key numbers to memorise before the viva

| Metric | Value |
|--------|-------|
| Tests | 111 |
| Models | 16 |
| TI hashes | 264,109 |
| Price per endpoint/year | $12 vs $185 CrowdStrike |
| Detection types | 6 |
| Reporting cycle | 30 seconds |
| User roles | 3 |
| CRITICAL threshold | delta score 70+ |
| Bloody Wolf demo | STRRAT, score 95, 3 flags, DESKTOP-7F3K2 |
