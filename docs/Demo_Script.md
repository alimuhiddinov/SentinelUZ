# SentinelUZ Viva Demo Script
## Bloody Wolf Attack Chain Simulation
## Duration: ~8 minutes

---

## Pre-Demo Setup (15 minutes before)

1. Start Django server:
   ```
   cd C:\Dev\SentinelUZ\edr_server
   python manage.py runserver
   ```

2. Verify health endpoint:
   Open: http://localhost:8000/api/health/
   Expected: `{"status":"ok","stats":{"threat_intel_ips":~209000,"threat_intel_hashes":~1348}}`

3. Verify agent running: `services.msc` → SentinelUZAgent = Running

4. Open browser tabs:
   - Tab 1: http://localhost:8000/dashboard/
   - Tab 2: http://localhost:8000/alerts/
   - Tab 3: (alert detail — open after alert fires)
   - Tab 4: http://localhost:8000/events/
   - Tab 5: http://localhost:8000/ioc-manager/
   - Tab 6: http://localhost:8000/help/
   - Tab 7: http://localhost:8000/api/health/

---

## Demo Narrative

### Opening (30 seconds)
"I'll demonstrate SentinelUZ detecting the Bloody Wolf attack pattern — a campaign documented by Group-IB that targeted Uzbek government agencies, medical facilities, and financial institutions in 2024. The attack chain starts with a phishing email that opens a command prompt from Microsoft Word, then downloads a remote access tool using certutil.exe. SentinelUZ detects this chain in real-time."

### Show Dashboard (45 seconds)
"This is the main dashboard. You can see the endpoint is Online — the agent runs as a Windows Service reporting every 30 seconds. The TI counter shows 209,000 blacklisted IPs and 1,348 malware hashes loaded, including 1,000 NetSupport RAT hashes from Bloody Wolf."

### Trigger Simulation

**Step 1 — LOLBin chain** (PowerShell as Admin):
```powershell
Start-Process cmd.exe -ArgumentList '/c powershell.exe -Command "Write-Host Simulation"'
```
Expected: SUSPICIOUS_CHAIN (HIGH) alert within 30 seconds.

**Step 2 — C2 connection** (add demo IP):
```
python manage.py demo_setup
```
Expected: BLACKLISTED_IP alert within 30 seconds.

### Show Alert Firing (2 minutes)
Switch to Alerts tab. "Within 30 seconds, SentinelUZ detected and classified the threat. The SUSPICIOUS_CHAIN alert at HIGH severity. Let me open the investigation workspace."

Click [Investigate].

### Show Alert Detail (3 minutes)
"The Overview tab gives a plain English explanation designed for IT managers — they don't need to know what T1059 means, they need to know what happened and what to do."

Click Process Chain tab: "The process tree shows the attack chain. Amber PIDs match the Group-IB Huntpoint interface."

Click Detections panel (right): "Each detection has plain English explanation. Clicking shows raw telemetry events, and clicking an event shows full JSON — what CERT-UZ needs for forensics."

### Show Endpoint Events (30 seconds)
"The raw telemetry feed — every process creation, network connection, and detection. The evidence trail PP-167 requires."

### Show IoC Manager (30 seconds)
"209,000 blacklisted IPs from four public feeds, plus 1,348 malware hashes specific to Uzbek threats."

### Closing (30 seconds)
"SentinelUZ addresses the gap from my literature review — no existing solution provides genuine EDR capability, PP-167 compliance, Uzbek-specific TI, and accessibility for SMBs. At $12/endpoint/year versus $185 for CrowdStrike, with <10 minute deployment versus days for Wazuh."

---

## Post-Demo Cleanup

```
python manage.py demo_setup --teardown
```

---

## Key Viva Questions

- Why Django over Flask? → Admin panel, ORM, DRF, battle-tested
- Why C++ for agent? → Direct Windows API access, <5MB memory, no runtime dependency
- Why not Wazuh? → 16GB RAM requirement, Elastic stack complexity, days to deploy
- What is a LOLBin? → Legitimate Windows tool misused by attackers (17 monitored)
- How does delta detection work? → Only new PIDs sent (~95% write reduction)
- What is Pyramid of Pain? → ExclusionRule match modes from easy-to-spoof to hard-to-spoof
- Why not automated kill? → Risk of killing legitimate processes, out of scope for v1
- How handle 200 endpoints? → PostgreSQL, bulk_create, 30-min TI cache
- Why plain English over MITRE? → Target users are IT managers, not SOC analysts
- What does PP-167 require? → Endpoint monitoring, incident detection, audit trail, TI
