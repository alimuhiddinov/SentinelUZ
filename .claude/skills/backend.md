# SentinelUZ Backend Skill

## CRITICAL: Real app structure
- Django app name: edr_app (NOT dashboard, NOT sentinel)
- App path: edr_server/edr_app/
- Models: edr_server/edr_app/models.py
- Views: edr_server/edr_app/views.py
- Utils: edr_server/edr_app/utils.py (analyze_vulnerabilities lives here)
- URLs: edr_server/edr_app/urls.py
- Templates: edr_server/edr_app/templates/edr_app/
- Management commands: edr_server/edr_app/management/commands/

## Existing models — DO NOT recreate
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

## Models to ADD via new migration
Add fields to Process model:
  parent_pid = models.IntegerField(null=True, blank=True)
  sha256_hash = models.CharField(max_length=64, blank=True, null=True)
  is_lolbin = models.BooleanField(default=False)
  is_suspicious_chain = models.BooleanField(default=False)
  parent_name = models.CharField(max_length=255, blank=True, null=True)

Add fields to SuspiciousActivity model:
  severity = models.CharField(max_length=20, default='MEDIUM',
    choices=[('CRITICAL','Critical'),('HIGH','High'),
             ('MEDIUM','Medium'),('LOW','Low')])
  ioc_matched = models.CharField(max_length=255, blank=True, null=True)

New models to create:
  ThreatIntelIP: ip_address(unique), source, threat_type,
    added_date(auto), is_active(default=True)
    Index on: ip_address
  ThreatIntelHash: sha256_hash(unique, max_length=64), malware_name,
    source, added_date(auto), is_active(default=True)
    Index on: sha256_hash

## Existing API endpoints — DO NOT recreate
POST /api/upload/              → upload_data() — main telemetry ingestion
POST /api/logs/upload/         → upload_logs()
POST /api/logs/windows/        → upload_windows_logs()
POST /api/commands/pending/    → pending_commands()
GET  /dashboard/               → dashboard()
GET  /device/<id>/             → device_detail()
GET  /processes/               → processes()
GET  /ports/                   → ports()
GET  /alerts/                  → alerts()
GET  /vulnerabilities/         → vulnerabilities()
GET  /logs/                    → logs()

## Endpoints to ADD
GET  /api/health/    → simple {"status":"ok","version":"1.0"}
POST /api/auth/login/ → POST {username,password} returns DRF token
GET  /ioc-manager/   → new template page
GET  /process-tree/  → new template page

## Existing utils.py — DO NOT replace
analyze_vulnerabilities(client) already exists and works.
ADD new function alongside it: match_iocs(client)
ADD helper: _create_alert_deduped(client, type, severity, desc, ioc)

## IoC matching logic to add to utils.py
def match_iocs(client):
    ip_set = set(ThreatIntelIP.objects.filter(
        is_active=True).values_list('ip_address', flat=True))
    hash_set = set(ThreatIntelHash.objects.filter(
        is_active=True).values_list('sha256_hash', flat=True))
    for proc in Process.objects.filter(client=client):
        if proc.sha256_hash and proc.sha256_hash in hash_set:
            _create_alert_deduped(client,'HASH_MATCH','CRITICAL',
                f'Malware hash: {proc.name}', proc.sha256_hash, proc)
        if proc.is_suspicious_chain:
            _create_alert_deduped(client,'SUSPICIOUS_CHAIN','MEDIUM',
                f'Suspicious chain: {proc.parent_name} -> {proc.name}',
                'suspicious_chain', proc)
    for port in Port.objects.filter(client=client):
        if port.process_name:
            pass  # remote IP check added when network events model added

def _create_alert_deduped(client, alert_type, severity,
                           description, ioc_matched, process=None):
    from django.utils import timezone
    from datetime import timedelta
    exists = SuspiciousActivity.objects.filter(
        client=client, ioc_matched=ioc_matched,
        timestamp__gte=timezone.now()-timedelta(hours=1)
    ).exists()
    if not exists:
        SuspiciousActivity.objects.create(
            client=client, type=alert_type, severity=severity,
            description=description, ioc_matched=ioc_matched,
            process_name=process.name if process else '',
            process_id=process.pid if process else None,
            timestamp=timezone.now()
        )

## Call match_iocs in upload_data() view
After existing analyze_vulnerabilities(client) call, add:
    from .utils import match_iocs
    match_iocs(client)

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

## Severity rules
CRITICAL: sha256 matches MalwareBazaar or ThreatFox hash
HIGH:     remote_ip matches Feodo or IPsum
MEDIUM:   is_suspicious_chain = True
LOW:      is_lolbin = True, no suspicious parent

## Alert deduplication
Same client + same ioc_matched within 1 hour = skip creation

## API response format — always use this shape
Success: {"status": "ok", "data": [...]}
Error:   {"status": "error", "message": "..."}

## Code rules
- Django ORM only — no raw SQL ever
- Secrets in .env + python-decouple, never hardcoded
- bulk_create(ignore_conflicts=True) for all batch inserts
- select_related() on all FK traversals in list views
- Always add db_index=True on fields used in filter/lookup

## Requirements to add to requirements.txt
apscheduler==3.10.4
python-decouple==3.8
psycopg2-binary==2.9.9