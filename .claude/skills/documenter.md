---
name: documenter
description: >
  Use this skill at the END of every phase session to
  automatically document what was built. Trigger: any time
  a session ends, a feature is completed, or the user says
  "document this session" / "update docs" / "phase done".
  Also use when generating implementation summaries,
  progress reports, or review documents.
---

# SentinelUZ — Session Documentation Skill

═══════════════════════════════════════════
WHEN TO USE THIS SKILL
═══════════════════════════════════════════

Automatically trigger documentation after:
- Any phase session completes
- Any significant feature is added
- Any bug is fixed that changes behaviour
- User says: "document", "update docs", "phase done",
  "what did we build", "summarise this session"

═══════════════════════════════════════════
DOCUMENTATION TARGETS — ALWAYS UPDATE ALL
═══════════════════════════════════════════

After every session, update ALL of these:

1. docs/IMPLEMENTATION_SUMMARY.md — what exists right now
2. docs/SESSION_LOG.md — chronological build history
3. CLAUDE.md — phase status section only

Never skip any of the three. They serve different purposes:
- IMPLEMENTATION_SUMMARY = current state snapshot (for review)
- SESSION_LOG = history of what was built when (for report)
- CLAUDE.md = operational context for next Claude Code session

═══════════════════════════════════════════
DOCUMENT 1 — IMPLEMENTATION_SUMMARY.md
═══════════════════════════════════════════

Location: docs/IMPLEMENTATION_SUMMARY.md

This is a LIVING document — overwrite it completely
each time. It always reflects current state only.
No history here — SESSION_LOG handles history.

Structure (keep scannable, no paragraphs):

# SentinelUZ EDR — Implementation Summary
# Last updated: [date] after [Phase X Session Y]

## System Overview
[2-3 sentences: what it is, who uses it, what it does]

## Architecture
[One-line description of each layer]
- C++ Agent → [what it does]
- Django Backend → [what it does]
- Detection Engine → [what it does]
- Web Dashboard → [what it does]

## Data Flow
[Numbered steps, one line each, full chain]
1. Agent scans every 30s → collects processes + TCP connections
2. ...

## Django Models
[Table format]
| Model | Key Fields | Purpose |
|---|---|---|
| Client | hostname, ip, last_seen | Registered endpoints |
| Process | pid, name, sha256, is_lolbin... | Process telemetry |
| ... | ... | ... |

## API Endpoints
[Table format]
| Method + URL | View | Purpose |
|---|---|---|
| POST /api/upload/ | upload_data() | Agent telemetry ingestion |
| ... | ... | ... |

## Detection Logic
[Bullet list, one line per check]
- Hash match → ThreatIntelHash set → CRITICAL alert
- IP match → ThreatIntelIP set → HIGH alert
- ...

## C++ Agent Capabilities
[Bullet list]
- Collects: [list]
- Sends: [JSON structure summary]
- Modes: [--install, --uninstall, --service, --status, --console]

## Exclusion Rules
[Table: match mode | safety level | description]

## TI Feeds
[Table: source | records | what it provides]

## Alert Lifecycle
[Numbered steps]
1. match_iocs() runs after each upload_data()
2. ...

## Phase Status
[Copy from CLAUDE.md phase status]

## Known Limitations
[Bullet list — honest, for report use]

═══════════════════════════════════════════
DOCUMENT 2 — SESSION_LOG.md
═══════════════════════════════════════════

Location: docs/SESSION_LOG.md

This is an APPEND-ONLY document — never overwrite,
only add new entries at the top (newest first).

Entry format for each session:

---
## [Phase X Session Y] — [Session Name]
Date: [today's date]
Status: Complete

### Files Created
- path/to/file.py — [one line: what it does]

### Files Modified
- path/to/file.py — [one line: what changed]

### Features Added
- [Feature name]: [one sentence description]
- [Feature name]: [one sentence description]

### Key Decisions Made
- [Decision]: [why this approach was chosen]

### Test Results
- [Test name]: [Pass/Fail — one line result]

### Known Issues / Future Work
- [Issue or limitation if any]

### Commit
[git commit hash if available, or "pending"]
---

═══════════════════════════════════════════
DOCUMENT 3 — CLAUDE.md UPDATE
═══════════════════════════════════════════

After each session, update ONLY the phase status
section in CLAUDE.md:
- Change PENDING to Complete for finished sessions
- Add one-line summary of what was built next to status
- Never change other sections of CLAUDE.md

═══════════════════════════════════════════
HOW TO RUN THIS SKILL
═══════════════════════════════════════════

At the END of any session, run:

  Use skill: documenter

  Document Phase [X] Session [Y] — [Session Name].

  Read these files to understand what was built:
    [list the files that were created or modified]

  Then:
  1. Update docs/IMPLEMENTATION_SUMMARY.md (full overwrite)
  2. Append new entry to docs/SESSION_LOG.md
  3. Update phase status in CLAUDE.md

  Be specific — include actual field names, function names,
  file paths, and line counts. This document is used for
  report writing and viva preparation.

═══════════════════════════════════════════
REVIEW OUTPUT FORMAT
═══════════════════════════════════════════

After updating all 3 documents, print this summary
to the terminal so the developer can do a fast review:

════════════════════════════════════════════
SESSION COMPLETE — [Phase X Session Y]
════════════════════════════════════════════

BUILT:
  [Feature 1] — [one line]
  [Feature 2] — [one line]
  [Feature 3] — [one line]

FILES:
  Created:  [count] files
  Modified: [count] files
  Key new file: [most important new file]

DETECTION COVERAGE:
  [Only if detection logic changed]
  Alerts can now fire for: [list new alert types]

TEST RESULTS:
  [Test A] — passed
  [Test B] — passed
  [Test C] — failed: [reason] → [fix applied]

DOCS UPDATED:
  docs/IMPLEMENTATION_SUMMARY.md
  docs/SESSION_LOG.md
  CLAUDE.md phase status

NEXT SESSION:
  Phase [X] Session [Y+1] — [Next session name]
  Start with: Use skill: documenter + Use skill: [domain skill]

COMMIT:
  git add docs/ CLAUDE.md
  git commit -m "docs: Phase [X] Session [Y] complete"
  git push
════════════════════════════════════════════

═══════════════════════════════════════════
BACKFILL — RUN ONCE TO CATCH UP
═══════════════════════════════════════════

Since this skill is being added after Phase 2 is complete,
run this once to backfill all existing documentation:

  Use skill: documenter

  Backfill all documentation for completed phases.

  Read these files to understand what was built:
    CLAUDE.md
    edr_server/edr_app/models.py
    edr_server/edr_app/utils.py
    edr_server/edr_app/views.py
    edr_server/edr_app/urls.py
    edr_client/src/main.cpp
    edr_client/src/service_manager.cpp
    edr_client/src/process_scanner.cpp
    edr_client/src/port_scanner.cpp
    edr_client/src/network_client.cpp
    edr_client/src/config_reader.cpp
    edr_server/edr_app/management/commands/sync_ti_feeds.py

  Create docs/IMPLEMENTATION_SUMMARY.md reflecting
  current state of all completed phases (0 through 2).

  Create docs/SESSION_LOG.md with one entry per
  completed phase session (Phase 0 through Phase 2 S6),
  backfilled from CLAUDE.md and actual file contents.

  Update CLAUDE.md phase status to mark all completed
  sessions as Complete.

  Print the full review summary to terminal.

After this one-time backfill, use the skill at the
end of every future session going forward.
