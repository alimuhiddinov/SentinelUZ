---
Run the SentinelUZ EDR agent for testing.

Prerequisites:
- Django server must be running: cd edr_server && python manage.py runserver
- config.ini must have correct server URL and token
- edr_client/build2/edr_client.exe must exist (run /build-agent first)

Steps:
1. Check Django is running: curl -s http://localhost:8000/api/health/
2. Check config.ini has token filled in
3. Run: edr_client/build2/edr_client.exe
4. Watch output for first 3 scan cycles
5. Check dashboard: http://localhost:8000/dashboard/
6. Check processes: http://localhost:8000/processes/
7. Check alerts: http://localhost:8000/alerts/

Expected output on startup:
- Config loaded: server URL, masked token, interval
- "EDR Client started"
- "Scanning processes..."
- "Sent data to server"

If connection fails: check token in config.ini matches
token from: python manage.py shell -c
"from rest_framework.authtoken.models import Token;
print(Token.objects.first().key)"
---
