# SentinelUZ Viva Quick Reference

## Key Numbers
| Metric | Value |
|--------|-------|
| TI IPs loaded | 208,926+ |
| TI hashes loaded | 1,348+ |
| LOLBins monitored | 17 |
| Suspicious parents | 8 (Office + browsers) |
| Alert dedup window | 3 days |
| TI cache lifetime | 30 minutes |
| Delta detection savings | ~95% write reduction |
| Agent memory | <5MB |
| Deploy time | <10 minutes |
| Price | $12/endpoint/year |
| vs CrowdStrike | $185/endpoint/year (15x more expensive) |
| vs Kaspersky | $30-50/endpoint/year (no genuine EDR) |
| vs Wazuh | Free but 16GB RAM + 250GB storage |
| Data retention (raw) | 48 hours |
| Data retention (events) | 7-30 days |
| Data retention (alerts) | Forever |
| Development period | 2026-03-22 to 2026-04-07 |

## Architecture Facts
| Item | Value |
|------|-------|
| Django app name | `edr_app` (NOT dashboard) |
| Main model | `Client` (NOT Endpoint) |
| Build dir | `edr_client/build2/` (NOT build/) |
| Service name | `SentinelUZAgent` |
| Detection engine | `utils.py` → `match_iocs()` |
| TI cache | Module-level dict, 30-min expiry |
| Bloody Wolf TI | 1,000 NetSupport RAT hashes |
| Alert dedup | `_create_or_update_alert()` → 3-day window |
| Exclusion modes | NAME_ONLY, NAME_AND_PATH, HASH_ONLY, ALL |
| Signature model | 6 detection types, plain English + MITRE |

## Detection Types (Signatures)
| SIG ID | Alert Type | Severity | MITRE |
|--------|-----------|----------|-------|
| SIG-007 | HASH_MATCH | CRITICAL | T1204 |
| SIG-005 | KNOWN_ATTACK_TOOL | CRITICAL | T1105 |
| SIG-010 | SUSPICIOUS_CHAIN | HIGH | T1059 |
| SIG-008 | RANSOMWARE_PRECURSOR | CRITICAL | T1490 |
| SIG-006 | BLACKLISTED_IP | HIGH | T1071 |
| SIG-001 | LOLBIN_DETECTED | LOW | T1059 |

## Pages
| URL | Purpose |
|-----|---------|
| /dashboard/ | Main overview with stat cards |
| /alerts/ | Alert cards with severity |
| /alerts/<id>/ | 5-tab investigation + right panel |
| /events/ | Raw telemetry feed |
| /ioc-manager/ | TI management + exclusions |
| /help/ | 9-section documentation |
| /api/health/ | Health check endpoint |
