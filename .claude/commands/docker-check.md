Check Docker deployment health and fix issues.

1. docker-compose ps
2. docker-compose logs django --tail=30
3. docker-compose logs postgres --tail=15
4. curl -s http://localhost:8000/api/health/

If django not starting:
  docker-compose exec django python manage.py migrate
If postgres not starting:
  Check volume permissions
If connection refused:
  Check ALLOWED_HOSTS and .env DATABASES setting

Fix then: docker-compose up -d to verify.