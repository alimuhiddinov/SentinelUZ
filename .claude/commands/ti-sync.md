Run threat intelligence feed synchronization.

Execute: cd edr_server && python manage.py sync_ti_feeds

If the command does not exist yet, create it at:
edr_server/edr_app/management/commands/sync_ti_feeds.py

After running report:
- New IPs added to ThreatIntelIP
- New hashes added to ThreatIntelHash
- Any feeds that failed with error reason
- Total time taken