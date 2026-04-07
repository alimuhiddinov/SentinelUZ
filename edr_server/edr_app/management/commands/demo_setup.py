import subprocess
from django.core.management.base import BaseCommand
from edr_app.models import ThreatIntelIP
from edr_app.utils import _ti_cache


class Command(BaseCommand):
    help = 'Setup or teardown viva demonstration data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--teardown', action='store_true',
            help='Remove demo data instead of adding',
        )
        parser.add_argument(
            '--ip', type=str, default='',
            help='Specific IP to add as demo C2',
        )

    def handle(self, *args, **options):
        if options['teardown']:
            deleted = ThreatIntelIP.objects.filter(source='viva_demo').delete()
            _ti_cache['loaded_at'] = None
            self.stdout.write(self.style.SUCCESS(f'Demo data removed: {deleted}'))
            return

        ip = options.get('ip', '')
        if not ip:
            try:
                result = subprocess.run(
                    ['netstat', '-n'], capture_output=True, text=True, timeout=10)
                for line in result.stdout.split('\n'):
                    if 'ESTABLISHED' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            ip = parts[2].rsplit(':', 1)[0]
                            break
            except Exception as e:
                self.stderr.write(f'netstat failed: {e}')

        if ip:
            obj, created = ThreatIntelIP.objects.get_or_create(
                ip_address=ip,
                defaults={
                    'source': 'viva_demo',
                    'threat_type': 'DEMO_C2_SERVER',
                    'is_active': True,
                },
            )
            _ti_cache['loaded_at'] = None
            self.stdout.write(self.style.SUCCESS(
                f'{"Added" if created else "Already exists"}: {ip} as demo C2'))
        else:
            self.stdout.write(self.style.WARNING(
                'No active connection found. Use --ip to specify one.'))

        self.stdout.write('Demo ready. Run with --teardown to clean up.')
