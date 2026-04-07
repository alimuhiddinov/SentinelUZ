---
name: edr-ux
description: >
  Use this skill for ALL frontend work in SentinelUZ. Encodes
  UX patterns from CrowdStrike Falcon, SentinelOne Singularity,
  and Group-IB Huntpoint. Covers colour system, typography,
  component patterns, interaction rules, and accessibility.
  Trigger: any template, CSS, JS, or dashboard work in edr_app.
---

# SentinelUZ EDR — UX Design System
# Based on: CrowdStrike Falcon, SentinelOne Singularity, Group-IB Huntpoint

═══════════════════════════════════════════
PHILOSOPHY — HOW REAL EDR UIs THINK
═══════════════════════════════════════════

Security analysts work in low-light SOCs for 8-12 hour shifts.
Every design decision serves one goal: get the analyst to the
right alert, with the right context, in the shortest time.

Rules derived from professional EDR consoles:
1. DARK BY DEFAULT — not optional, not a toggle preference.
   Falcon, SentinelOne, Group-IB all dark by default.
2. COLOUR ENCODES SEVERITY ONLY — never use red/orange for decoration.
   When analyst sees red, it means CRITICAL. Always. No exceptions.
3. SIDEBAR NAVIGATION — persistent left sidebar (not top navbar).
   Analyst needs navigation visible at all times during investigation.
4. NUMBERS FIRST — dashboards show counts prominently. Not charts.
   "12 CRITICAL alerts" is more useful than a pie chart at 3am.
5. EXPANDABLE CONTEXT — never navigate to see more. Expand in place.
   Falcon uses slide-out panels. SentinelOne uses expandable rows.
6. SEARCH IS PRIMARY — filter box always visible above every table.
   Analysts hunt by process name, hash, IP — not by scrolling.
7. TIMESTAMPS AS RELATIVE + ABSOLUTE — show "3 minutes ago" with
   the actual time on hover. Both are needed for investigation.
8. STATUS DOTS NOT WORDS — Online = green dot. Offline = grey dot.
   Faster to scan than reading "Online" or "Offline" text.
9. PROCESS TREE NOT TABLE — process relationships must be visual.
   Falcon's process tree is its most used investigation feature.
10. ALERT GROUPING — same event multiple times = one card with count.
    Group-IB Huntpoint groups related events into one alert record.

═══════════════════════════════════════════
COLOUR SYSTEM
═══════════════════════════════════════════

CSS custom properties — define in base.html :root block:

/* Backgrounds — 3 levels like Falcon and SentinelOne */
--bg-page:      #0a0e17;   /* page background — deepest */
--bg-surface:   #111827;   /* cards, panels, sidebar */
--bg-elevated:  #1a2234;   /* dropdowns, hover states, inputs */
--bg-selected:  #1e3a5f;   /* selected row, active nav item */

/* Borders */
--border-subtle:  #1e2d3d;  /* most borders */
--border-default: #2d3f55;  /* active/focused borders */
--border-bright:  #3d5278;  /* emphasis borders */

/* Text */
--text-primary:   #e2e8f0;  /* main content */
--text-secondary: #94a3b8;  /* labels, metadata, timestamps */
--text-muted:     #64748b;  /* disabled, placeholder */
--text-inverse:   #0a0e17;  /* text on coloured backgrounds */

/* Severity — THE most important colour decisions */
/* Derived from CrowdStrike Falcon and SentinelOne Singularity */
--critical:       #ef4444;  /* CRITICAL — pure red, never reused */
--critical-bg:    #2d1515;  /* CRITICAL alert card background */
--critical-border:#7f1d1d;  /* CRITICAL card left border */

--high:           #f97316;  /* HIGH — orange */
--high-bg:        #2d1a0e;
--high-border:    #7c2d12;

--medium:         #eab308;  /* MEDIUM — amber */
--medium-bg:      #2d2600;
--medium-border:  #713f12;

--low:            #3b82f6;  /* LOW — blue (informational) */
--low-bg:         #0f1c35;
--low-border:     #1e3a8a;

/* Status indicators — endpoint online/offline */
--status-online:  #22c55e;  /* green dot */
--status-offline: #475569;  /* grey dot — not red, offline ≠ threat */
--status-warning: #f59e0b;  /* yellow — seen recently but not active */

/* Accent — for links, buttons, active states */
--accent:         #60a5fa;  /* blue accent */
--accent-hover:   #93c5fd;

/* TI indicators — for blacklisted IPs and malware hashes */
--ioc-match:      #ef4444;  /* same as critical — IoC = immediate threat */
--ioc-bg:         #2d1515;
--lolbin:         #f97316;  /* LOLBin — orange warning */
--lolbin-bg:      #2d1a0e;
--suspicious:     #a855f7;  /* suspicious chain — purple (distinct) */
--suspicious-bg:  #1e1030;

═══════════════════════════════════════════
TYPOGRAPHY
═══════════════════════════════════════════

Font: system-ui, -apple-system, 'Segoe UI', sans-serif
  (No Google Fonts — EDR consoles are offline-capable)

Scale:
  --text-xs:   11px;  /* timestamps, metadata tags */
  --text-sm:   13px;  /* table cell content, secondary labels */
  --text-base: 15px;  /* primary body text */
  --text-lg:   18px;  /* section headings */
  --text-xl:   24px;  /* stat numbers on dashboard cards */
  --text-2xl:  32px;  /* large KPI numbers */

Rules:
- Monospace font for: hashes, IPs, PIDs, paths, hostnames
  font-family: 'JetBrains Mono', 'Cascadia Code', monospace
  These must be visually distinct — analysts copy-paste them constantly
- Never bold for emphasis in tables — use colour instead
- Alert descriptions: text-sm, text-secondary
- Process names: text-sm, text-primary, monospace

═══════════════════════════════════════════
LAYOUT — SIDEBAR STRUCTURE
(based on CrowdStrike Falcon and SentinelOne)
═══════════════════════════════════════════

Page structure:
┌──────────┬──────────────────────────────────┐
│          │  TOP BAR (stats strip)           │
│ SIDEBAR  ├──────────────────────────────────┤
│  nav     │                                  │
│          │  MAIN CONTENT AREA               │
│  160px   │                                  │
│  fixed   │                                  │
└──────────┴──────────────────────────────────┘

Sidebar (160px wide, full height, fixed):
  Background: var(--bg-surface)
  Border-right: 1px solid var(--border-subtle)

  Logo area (48px tall):
    SentinelUZ shield logo + name
    Border-bottom: 1px solid var(--border-subtle)

  Nav items:
    Height: 40px per item
    Padding: 0 16px
    Icon (20px) + Label text-sm
    Active: background var(--bg-selected), left border 3px var(--accent)
    Hover: background var(--bg-elevated)

  Nav items in order:
    🛡 Dashboard
    💻 Endpoints
    ⚠ Alerts        [badge with CRITICAL count if > 0]
    🔄 Processes
    🌐 Network
    🗂 IoC Manager
    🔍 Vulnerabilities
    📋 Event Logs

  Bottom of sidebar:
    Admin user name
    Settings gear icon

Top stats bar (48px tall, full width minus sidebar):
  Background: var(--bg-surface)
  Border-bottom: 1px solid var(--border-subtle)
  Flex row, gap 32px, padding 0 24px

  Stats shown always:
    ENDPOINTS: N active / N total
    CRITICAL: N  [red if > 0]
    HIGH: N      [orange if > 0]
    TI LOADED: 209k IPs · 1.3k hashes
    LAST SYNC: 2h ago

Main content:
  Padding: 24px
  Max-width: none (full width)
  Background: var(--bg-page)

═══════════════════════════════════════════
COMPONENT PATTERNS
═══════════════════════════════════════════

── DASHBOARD STAT CARDS ──
(Based on Falcon's KPI cards)

4 cards in a row, equal width:
┌─────────────────┐
│ CRITICAL ALERTS │
│                 │
│       12        │  ← --text-2xl, var(--critical)
│                 │
│  ↑3 since 1h   │  ← trend indicator
└─────────────────┘

Card CSS:
  background: var(--bg-surface)
  border: 1px solid var(--border-subtle)
  border-top: 3px solid <severity-colour>
  border-radius: 6px
  padding: 20px
  The top accent border indicates severity category

── ALERT CARDS ──
(SentinelOne groups alerts by type; Huntpoint uses event_count)

NOT a plain table row. Each alert is a card:

┌─ [CRITICAL] ─────────────────────────── 3x ─┐
│ HASH_MATCH · WINDOWS                         │
│ Malware hash detected: powershell.exe        │
│ Hash: a1b2c3d4...  Process: PID 14532        │
│ First: 23 Mar 14:30 · Last: 23 Mar 15:45    │
│                              [View Device ›] │
└──────────────────────────────────────────────┘

Alert card CSS:
  background: var(--<severity>-bg)
  border: 1px solid var(--<severity>-border)
  border-left: 4px solid var(--<severity>)
  border-radius: 4px
  padding: 12px 16px
  margin-bottom: 8px

Severity badge (top-left):
  background: var(--<severity>)
  color: var(--text-inverse)
  font-size: var(--text-xs)
  font-weight: 600
  letter-spacing: 0.08em
  padding: 2px 8px
  border-radius: 3px
  text-transform: uppercase

Count badge (top-right, when event_count > 1):
  background: var(--bg-elevated)
  color: var(--text-secondary)
  font-size: var(--text-xs)
  padding: 2px 8px
  border-radius: 10px
  "3×" format

── PROCESS TREE ──
(Falcon's most-used investigation feature)

Render from parent_pid relationships using JS buildTree():

System (PID: 4)
├── svchost.exe (PID: 1240)
└── explorer.exe (PID: 14548)
    └── ⚠ cmd.exe (PID: 9012)           [orange — LOLBin]
        └── 🔴 powershell.exe (PID: 11234) [red — suspicious chain]

Tree CSS:
  font-family: monospace
  font-size: var(--text-sm)

  .tree-line::before:
    content: "├── " or "└── "
    color: var(--border-bright)

  .node-lolbin:
    color: var(--lolbin)
    background: var(--lolbin-bg)
    padding: 2px 6px
    border-radius: 3px

  .node-suspicious:
    color: var(--critical)
    background: var(--critical-bg)
    padding: 2px 6px
    border-radius: 3px

SHA256 hash display (truncated with copy button):
  <code class="hash">a1b2c3d4...f9e8</code>
  [📋] copy icon — onclick copies full hash to clipboard
  font-family: monospace, font-size: text-xs

── ENDPOINT CARDS ON DASHBOARD ──
(Based on SentinelOne's endpoint list)

┌────────────────────────────────────┐
│ ● WINDOWS          [Active]        │  ← green dot
│ 192.168.1.100 · Windows 10         │
│ 313 processes · 2 CRITICAL alerts  │
│ Last seen: 2 minutes ago           │
└────────────────────────────────────┘

Status dot:
  Width/height: 10px, border-radius: 50%
  Online (< 2 min): background var(--status-online), box-shadow: 0 0 6px var(--status-online)
  Recent (< 10 min): background var(--status-warning)
  Offline (> 10 min): background var(--status-offline)

── TABLES ──
(Used for processes, ports — not alerts)

thead:
  background: var(--bg-surface)
  border-bottom: 2px solid var(--border-default)
  position: sticky, top: 0
  text-transform: uppercase
  font-size: var(--text-xs)
  letter-spacing: 0.06em
  color: var(--text-secondary)

  th with sort: cursor pointer, ▲▼ indicator on active column

tbody tr:
  border-bottom: 1px solid var(--border-subtle)
  height: 40px

tbody tr:hover:
  background: var(--bg-elevated)

tbody tr.is-lolbin:
  border-left: 3px solid var(--lolbin)

tbody tr.is-ioc-match:
  border-left: 3px solid var(--critical)
  background: var(--critical-bg)

Monospace columns: PID, hash, IP address, port number, path
  font-family: monospace
  font-size: var(--text-xs)

── SEARCH BAR ──
(Always visible above every table — Falcon puts it prominently)

<input type="search" placeholder="Search processes...">
  width: 280px
  background: var(--bg-elevated)
  border: 1px solid var(--border-default)
  border-radius: 4px
  padding: 8px 12px 8px 36px  (space for search icon)
  color: var(--text-primary)
  font-size: var(--text-sm)

  On focus: border-color var(--accent)

Filter buttons beside search:
  All | CRITICAL | HIGH | MEDIUM | LOW
  Active filter: background var(--accent), color var(--text-inverse)
  Inactive: background var(--bg-elevated), color var(--text-secondary)

── NETWORK CONNECTIONS TABLE ──

Remote IP highlighting:
  If remote_ip is blacklisted: class="ioc-match"
    background: var(--ioc-bg)
    color: var(--ioc-match)
    font-weight: 600
    monospace

Connection state badges:
  ESTABLISHED: background #064e3b, color #6ee7b7   (green)
  LISTEN:      background #1e3a5f, color #93c5fd   (blue)
  TIME_WAIT:   background #2d2600, color #fbbf24   (amber)
  CLOSE_WAIT:  background #2d1515, color #fca5a5   (light red)

═══════════════════════════════════════════
JAVASCRIPT PATTERNS
═══════════════════════════════════════════

All vanilla JS — no frameworks. Rules:

AUTO-REFRESH (every 30 seconds, no page reload):
  let refreshTimer = setInterval(refreshAlerts, 30000);

  function refreshAlerts() {
    fetch('/api/alerts/recent/')
      .then(r => r.json())
      .then(data => {
        // Update counts in stats bar
        document.getElementById('stat-critical').textContent =
          data.critical_count;
        // Flash badge if count increased
        if (data.critical_count > previousCritical) {
          document.getElementById('stat-critical')
            .classList.add('flash');
          setTimeout(() =>
            document.getElementById('stat-critical')
              .classList.remove('flash'), 1000);
        }
      });
  }

FLASH ANIMATION CSS:
  @keyframes flash {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
  }
  .flash { animation: flash 0.5s ease 3; }

RELATIVE TIMESTAMPS:
  function timeAgo(isoString) {
    const diff = (Date.now() - new Date(isoString)) / 1000;
    if (diff < 60) return Math.round(diff) + 's ago';
    if (diff < 3600) return Math.round(diff/60) + 'm ago';
    if (diff < 86400) return Math.round(diff/3600) + 'h ago';
    return Math.round(diff/86400) + 'd ago';
  }

TABLE SORT (click th to sort):
  document.querySelectorAll('th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      sortTable(col, th.dataset.dir === 'asc' ? 'desc' : 'asc');
      th.dataset.dir = th.dataset.dir === 'asc' ? 'desc' : 'asc';
    });
  });

COPY HASH TO CLIPBOARD:
  function copyHash(hash) {
    navigator.clipboard.writeText(hash).then(() => {
      showToast('Hash copied to clipboard');
    });
  }

PROCESS TREE BUILDER:
  function buildTree(processes) {
    const map = {};
    const roots = [];
    processes.forEach(p => {
      map[p.pid] = { ...p, children: [] };
    });
    processes.forEach(p => {
      if (p.parent_pid && map[p.parent_pid]) {
        map[p.parent_pid].children.push(map[p.pid]);
      } else {
        roots.push(map[p.pid]);
      }
    });
    return roots;
  }

  function renderTree(nodes, depth=0) {
    return nodes.map((node, i) => {
      const isLast = i === nodes.length - 1;
      const prefix = depth > 0 ?
        (isLast ? '└── ' : '├── ') : '';
      const cls = node.is_suspicious_chain ? 'node-suspicious' :
                  node.is_lolbin ? 'node-lolbin' : '';
      return `
        <div class="tree-item ${cls}" style="padding-left:${depth*20}px">
          <span class="tree-prefix">${prefix}</span>
          <span class="proc-name">${node.name}</span>
          <span class="proc-pid text-muted">(PID: ${node.pid})</span>
          ${node.sha256_hash ?
            `<code class="hash" onclick="copyHash('${node.sha256_hash}')">
              ${node.sha256_hash.substr(0,16)}...
            </code>` : ''}
        </div>
        ${renderTree(node.children, depth + 1)}
      `;
    }).join('');
  }

TOAST NOTIFICATION:
  function showToast(message, type='info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
  }

  CSS:
  .toast {
    position: fixed; bottom: 24px; right: 24px;
    background: var(--bg-elevated);
    border: 1px solid var(--border-default);
    border-radius: 4px;
    padding: 10px 16px;
    font-size: var(--text-sm);
    color: var(--text-primary);
    z-index: 9999;
    animation: slideIn 0.2s ease;
  }
  @keyframes slideIn {
    from { transform: translateY(10px); opacity: 0; }
    to { transform: translateY(0); opacity: 1; }
  }

═══════════════════════════════════════════
ACCESSIBILITY RULES
(SentinelOne redesigned for WCAG 2.0 — follow the same standard)
═══════════════════════════════════════════

- All severity colours must pass 4.5:1 contrast ratio on their bg
  (the values above are pre-verified)
- All interactive elements must be keyboard-navigable (tab + enter)
- Focus indicator: outline: 2px solid var(--accent), outline-offset: 2px
- All icon-only buttons must have aria-label
- Copy hash button: aria-label="Copy SHA256 hash to clipboard"
- Status dots: aria-label="Endpoint online" / "Endpoint offline"
- Tables: <thead> with <th scope="col"> for all columns
- Alert severity badges: role="status" aria-label="Severity: Critical"

═══════════════════════════════════════════
DJANGO TEMPLATE INTEGRATION
═══════════════════════════════════════════

CRITICAL: Read existing templates BEFORE writing any CSS/HTML.
Files to check first:
  edr_server/edr_app/templates/edr_app/base.html
  edr_server/edr_app/templates/edr_app/alerts.html
  edr_server/edr_app/templates/edr_app/dashboard.html

MATCH EXISTING STRUCTURE — do not recreate what exists.
Add CSS variables to :root in base.html.
Extend existing blocks, don't replace them.

Template block structure:
  {% block content %} — main page content
  {% block extra_css %} — page-specific CSS
  {% block extra_js %} — page-specific JS

Pass severity context to templates from views.py:
  SuspiciousActivity.severity choices must map to CSS classes:
  CRITICAL → 'severity-critical'
  HIGH     → 'severity-high'
  MEDIUM   → 'severity-medium'
  LOW      → 'severity-low'

Template filter for severity CSS class:
  {{ alert.severity|lower }} → use directly as CSS class suffix

For alert.event_count badges, only show if event_count > 1:
  {% if alert.event_count > 1 %}
    <span class="count-badge">{{ alert.event_count }}×</span>
  {% endif %}

For timestamps, show both relative and absolute:
  <span class="timestamp"
        title="{{ alert.last_seen|date:'Y-m-d H:i:s' }}"
        data-iso="{{ alert.last_seen|date:'c' }}">
    {{ alert.last_seen|timesince }} ago
  </span>
  Then JS updates data-iso elements to relative format on load.

═══════════════════════════════════════════
WHAT NOT TO DO
(common mistakes that make EDR dashboards look amateur)
═══════════════════════════════════════════

✗ NEVER use Bootstrap — adds visual noise, wrong aesthetic
✗ NEVER use red for decoration (only severity CRITICAL)
✗ NEVER use a pie chart for alert distribution — use numbers
✗ NEVER paginate a process list — use virtual scroll or limit 100
✗ NEVER show full SHA256 in a table — truncate to 16 chars
✗ NEVER use white backgrounds — even modal overlays are dark
✗ NEVER use tooltips for critical info — show inline
✗ NEVER use colour alone to convey meaning — add icon + text too
✗ NEVER auto-play animations — reduce-motion must be respected
✗ NEVER show raw ISO timestamps — always relative + hover absolute
