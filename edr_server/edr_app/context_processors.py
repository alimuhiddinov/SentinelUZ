from django.utils import timezone
from datetime import timedelta


def edr_stats(request):
    """Global stats for the top stats bar on every page."""
    if not request.user.is_authenticated:
        return {}

    from .models import Client, SuspiciousActivity, ThreatIntelIP, ThreatIntelHash

    now = timezone.now()
    two_min_ago = now - timedelta(minutes=2)

    active_count = Client.objects.filter(last_seen__gte=two_min_ago).count()
    total_endpoints = Client.objects.count()
    critical_count = SuspiciousActivity.objects.filter(severity='CRITICAL').count()
    ti_ip_count = ThreatIntelIP.objects.filter(is_active=True).count()
    ti_hash_count = ThreatIntelHash.objects.filter(is_active=True).count()

    return {
        'stats_active_endpoints': active_count,
        'stats_total_endpoints': total_endpoints,
        'stats_critical_count': critical_count,
        'stats_ti_ip_count': ti_ip_count,
        'stats_ti_hash_count': ti_hash_count,
    }
