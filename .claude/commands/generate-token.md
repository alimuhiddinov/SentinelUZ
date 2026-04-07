---
Generate an auth token for the C++ agent to use.

Run in edr_server/:
python manage.py shell -c "
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
user = User.objects.get(username='admin')
token, created = Token.objects.get_or_create(user=user)
print('Token:', token.key)
print('Add this to edr_client/config.ini under [server]:')
print('token=' + token.key)
"

After getting the token:
1. Open edr_client/config.ini
2. Replace the empty token= line with token=<printed value>
3. Save the file
4. Rebuild: /build-agent
---
