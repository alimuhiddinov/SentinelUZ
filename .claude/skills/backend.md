# SentinelUZ Backend Skill

## CRITICAL: Real app structure
- Django app name: edr_app (NOT dashboard, NOT sentinel)
- App path: edr_server/edr_app/
- Models: edr_server/edr_app/models.py
- Views: edr_server/edr_app/views.py
- Utils: edr_server/edr_app/utils.py (analyze_vulnerabilities + match_iocs)
- URLs: edr_server/edr_app/urls.py
- Templates: edr_server/edr_app/templates/edr_app/
- Management commands: edr_server/edr_app/management/commands/

## Current Models (ALL EXIST — do not recreate)

### Client
hostname, ip_address, last_seen(auto_now), auth_token(unique),
is_active

### Process (extended — all fields exist)
client(FK), pid, name, path, command_line, timestamp, version,
parent_pid, sha256_hash(max_length=64), is_lolbin, is_suspicious_chain,
parent_name

### Port (extended — includes network connection fields)
client(FK), port_number, protocol, state, process_name, process_id,
timestamp, service_name, service_version,
local_ip, local_port, remote_ip, remote_port

### SuspiciousActivity (extended — all fields exist)
client(FK), type, description, process_name, process_id, timestamp,
severity(CRITICAL/HIGH/MEDIUM/LOW, default='LOW'),
ioc_matched(max_length=255), score, event_count(default=1),
last_seen(auto_now)
Index on: (client, ioc_matched, type)

### ThreatIntelIP
ip_address(unique, GenericIPAddressField), source, threat_type,
added_date(auto), is_active(default=True)
Index on: ip_address

### ThreatIntelHash
sha256_hash(unique, max_length=64), malware_name, source,
added_date(auto), is_active(default=True)
Index on: sha256_hash

### ExclusionRule
process_name, process_path(max_length=500), sha256_hash(max_length=64),
match_mode (NAME_ONLY/NAME_AND_PATH/HASH_ONLY/ALL, default='NAME_AND_PATH'),
reason(TextField), added_by(FK User, SET_NULL), expires_at(nullable),
is_active(default=True), created_at(auto)
Indexes on: (process_name, is_active), (sha256_hash, is_active)
Admin registered with safety_level computed property.
_is_excluded() called in match_iocs() before alert creation.

### Vulnerability
cve_id(unique), description, severity(CRITICAL/HIGH/MEDIUM/LOW),
published_date, last_modified_date, affected_software, affected_versions

### VulnerabilityMatch
vulnerability(FK), client(FK), match_type(PROCESS/PORT/SERVICE),
process(FK nullable), port(FK nullable), confidence_score, timestamp
unique_together: (vulnerability, client, process), (vulnerability, client, port)

### Log
client(FK), level(INFO/WARNING/ERROR/DEBUG), message, timestamp, source

### WindowsEventLog
client(FK), source, provider, level(Information/Warning/Error/Critical/Verbose),
event_id, message, timestamp, created_at
Indexes on: -timestamp, source, level

### Command
client(FK), command, args, created_at, executed, executed_at, response

## Existing API endpoints — DO NOT recreate
POST /api/upload/              → upload_data() — main telemetry ingestion
POST /api/logs/upload/         → upload_logs()
POST /api/logs/windows/        → upload_windows_logs()
POST /api/commands/pending/    → pending_commands()
GET  /api/health/              → health_check() — returns status + TI stats
GET  /dashboard/               → dashboard()
GET  /device/<id>/             → device_detail()
GET  /processes/               → processes()
GET  /ports/                   → ports()
GET  /alerts/                  → alerts()
GET  /vulnerabilities/         → vulnerabilities()
GET  /logs/                    → logs()

## Endpoints to ADD
POST /api/auth/login/ → POST {username,password} returns DRF token
GET  /ioc-manager/   → new template page
GET  /process-tree/  → new template page

## Current utils.py — DO NOT replace, extend only

### analyze_vulnerabilities(client) — EXISTS, works
Matches processes and ports against Vulnerability records via NVD data.

### match_iocs(client) — EXISTS, works
Full IoC matching engine with these features:

1. **30-minute TI cache** (_ti_cache module-level dict):
   Loads ThreatIntelIP and ThreatIntelHash into Python sets.
   Refreshes when _ti_cache['loaded_at'] > 30 minutes old.

2. **Exclusion rules** (Pyramid of Pain approach):
   _load_exclusion_rules() — loads active, non-expired ExclusionRule records.
   _is_excluded(proc, exclusions) — checks process against all rules
   by match_mode (NAME_ONLY, NAME_AND_PATH, HASH_ONLY, ALL).
   Excluded processes are skipped before any alert creation.

3. **Alert types generated** (in priority order):
   - HASH_MATCH (CRITICAL) — sha256 matches TI hash database
   - KNOWN_ATTACK_TOOL (CRITICAL) — process name contains known tool name
   - SUSPICIOUS_CHAIN (HIGH) — Office/browser spawned LOLBin
   - RANSOMWARE_PRECURSOR (CRITICAL/HIGH) — vssadmin, wbadmin, bcdedit, etc.
   - LOLBIN_DETECTED (LOW) — LOLBin without suspicious parent
   - MALICIOUS_IP (CRITICAL) — Port.remote_ip matches TI IP database

4. **IP matching** against Port.remote_ip:
   Filters out 0.0.0.0, *, 127.0.0.1, empty strings.
   Checks remaining remote IPs against the cached ip_set.

### _create_or_update_alert() — 3-day dedup with event_count
- Looks for existing alert with same (client, ioc_matched, type)
  within a 3-day window (last_seen >= now - 3 days)
- If found: increments event_count, updates last_seen (auto_now)
- If not found: creates new SuspiciousActivity record
- Returns True if new alert created, False if existing updated

## Alert deduplication
Same client + same ioc_matched + same type within 3-day window =
increment event_count on existing alert (not create new one).
This dramatically reduces alert noise for recurring detections.

## Severity rules
CRITICAL: sha256 matches TI hash, known attack tool, ransomware
          precursor with suspicious parent, malicious IP connection
HIGH:     suspicious chain (Office/browser → LOLBin), ransomware
          precursor without suspicious parent
MEDIUM:   (reserved for future use)
LOW:      LOLBin detected without suspicious parent

## Call order in upload_data() view
Within transaction.atomic():
  1. Handle terminated PIDs (delta detection)
  2. Create new Process records
  3. Replace Port/network connection records
  4. Create SuspiciousActivity from agent-side alerts
  5. analyze_vulnerabilities(client)
  6. match_iocs(client)

## TI feed management command
File: edr_server/edr_app/management/commands/sync_ti_feeds.py
Command: python manage.py sync_ti_feeds

Feed sources:
  IPsum → GET https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt
    Skip lines starting with #, split on \t, take index [0] as IP
    Source label: 'ipsum'

  Feodo → GET https://feodotracker.abuse.ch/downloads/ipblocklist.csv
    Skip rows where row[0].startswith('#'), IP is column 0
    Source label: 'feodo'

  MalwareBazaar → POST https://mb-api.abuse.ch/api/v1/
    Body: query=get_recent&selector=time
    Response: data[i].sha256_hash, data[i].signature
    Source label: 'malwarebazaar'

  ThreatFox → POST https://threatfox-api.abuse.ch/api/v1/
    Body JSON: {"query":"get_iocs","days":1}
    Response: data[i].ioc_value, data[i].ioc_type
    Hash: ioc_type == 'sha256_hash'
    IP: ioc_type == 'ip:port' → extract IP before ':'
    Source label: 'threatfox'

Use bulk_create(ignore_conflicts=True) for performance.
Wrap each feed in try/except — one failure must not stop others.
requests timeout=30 for all calls.
Log counts: "IPsum: +N IPs added"

## API response format — always use this shape
Success: {"status": "ok", "data": [...]}
Error:   {"status": "error", "message": "..."}

## Code rules
- Django ORM only — no raw SQL ever
- Secrets in .env + python-decouple, never hardcoded
- bulk_create(ignore_conflicts=True) for all batch inserts
- select_related() on all FK traversals in list views
- Always add db_index=True on fields used in filter/lookup

## Requirements (in requirements.txt)
python-decouple==3.8
psycopg2-binary==2.9.9
