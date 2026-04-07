# Skill File Conflict Resolution
# Audit date: 2026-04-05
# Files audited: frontend.md, backend.md, cpp-agent.md

═══════════════════════════════════════════
CONFLICT REPORT
═══════════════════════════════════════════

## 1. COLOUR CONFLICTS
NONE — only frontend.md defines CSS variables.

## 2. LAYOUT CONFLICTS
NONE — only frontend.md defines layout structure.

## 3. COMPONENT CONFLICTS
NONE — only frontend.md defines visual components.

## 4. RULE CONFLICTS

### CONFLICT #1: Alert Deduplication Window
- backend.md line 99:  `timestamp__gte=timezone.now()-timedelta(hours=1)`
- backend.md line 153: "Same client + same ioc_matched within 1 hour = skip"
- ACTUAL implementation (utils.py): 3-day window with event_count field
- CLAUDE.md confirms: "Alert deduplication: 3-day window, event_count field"
- WINNER: backend.md is STALE — actual implementation (3-day + event_count)
  is the authoritative decision. backend.md needs update.

## 5. NAMING CONFLICTS
NONE — all files use edr_app, Client, Process, Port, SuspiciousActivity.

═══════════════════════════════════════════
STALENESS ISSUES (not conflicts, but outdated content)
═══════════════════════════════════════════

### backend.md lines 29-49: "Models to ADD"
These models ALREADY EXIST with migrations applied:
- Process extended fields: parent_pid, sha256_hash, is_lolbin,
  is_suspicious_chain, parent_name — DONE
- SuspiciousActivity: severity, ioc_matched — DONE
  ALSO added but not in backend.md: event_count, first_seen, last_seen
- ThreatIntelIP, ThreatIntelHash — DONE
- ExclusionRule — DONE (not mentioned in backend.md at all)

### backend.md lines 70-108: "IoC matching logic to add"
match_iocs() ALREADY EXISTS in utils.py with a more complete
implementation than what backend.md describes:
- 30-minute module-level TI cache (not per-call DB query)
- _create_or_update_alert() with 3-day dedup + event_count
- _load_exclusion_rules() + _is_excluded() for Pyramid of Pain
- IP IoC matching against Port.remote_ip

### backend.md line 167: apscheduler in requirements
Not currently used. sync_ti_feeds is a management command,
not a scheduled task via apscheduler.

═══════════════════════════════════════════
AUTHORITATIVE CSS VARIABLES FOR base.html :root
(merged from all skill files — frontend.md is sole authority)
═══════════════════════════════════════════

:root {
  /* ── Backgrounds ── */
  --bg-page:        #0a0e17;
  --bg-surface:     #111827;
  --bg-elevated:    #1a2234;
  --bg-selected:    #1e3a5f;

  /* ── Borders ── */
  --border-subtle:  #1e2d3d;
  --border-default: #2d3f55;
  --border-bright:  #3d5278;

  /* ── Text ── */
  --text-primary:   #e2e8f0;
  --text-secondary: #94a3b8;
  --text-muted:     #64748b;
  --text-inverse:   #0a0e17;

  /* ── Severity ── */
  --critical:        #ef4444;
  --critical-bg:     #2d1515;
  --critical-border: #7f1d1d;

  --high:            #f97316;
  --high-bg:         #2d1a0e;
  --high-border:     #7c2d12;

  --medium:          #eab308;
  --medium-bg:       #2d2600;
  --medium-border:   #713f12;

  --low:             #3b82f6;
  --low-bg:          #0f1c35;
  --low-border:      #1e3a8a;

  /* ── Status ── */
  --status-online:  #22c55e;
  --status-offline: #475569;
  --status-warning: #f59e0b;

  /* ── Accent ── */
  --accent:         #60a5fa;
  --accent-hover:   #93c5fd;

  /* ── Threat Intel indicators ── */
  --ioc-match:      #ef4444;
  --ioc-bg:         #2d1515;
  --lolbin:         #f97316;
  --lolbin-bg:      #2d1a0e;
  --suspicious:     #a855f7;
  --suspicious-bg:  #1e1030;

  /* ── Typography scale ── */
  --text-xs:   11px;
  --text-sm:   13px;
  --text-base: 15px;
  --text-lg:   18px;
  --text-xl:   24px;
  --text-2xl:  32px;
}

═══════════════════════════════════════════
AUTHORITY HIERARCHY
═══════════════════════════════════════════

1. frontend.md  → ALL UI decisions (CSS, layout, components, JS)
2. backend.md   → ALL model/API/Django decisions
3. cpp-agent.md → ALL C++ agent decisions
4. security.md  → ALL detection logic decisions (does not exist yet)

When files conflict, the domain owner wins.
When a skill file conflicts with CLAUDE.md, CLAUDE.md wins
(it reflects actual implemented decisions).
