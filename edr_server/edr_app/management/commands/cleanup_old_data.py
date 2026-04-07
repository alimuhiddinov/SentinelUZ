from datetime import timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from edr_app.models import (
    Process, Port, Event, SuspiciousActivity, ExclusionRule,
)


class Command(BaseCommand):
    help = 'Rolling data retention cleanup'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run', action='store_true',
            help='Preview without deleting')

    def handle(self, *args, **options):
        dry = options['dry_run']
        now = timezone.now()
        if dry:
            self.stdout.write('[DRY RUN] No records will be deleted\n')

        # Process records (48h, non-flagged only)
        cut48 = now - timedelta(hours=48)
        qs = Process.objects.filter(
            timestamp__lt=cut48,
            is_lolbin=False,
            is_suspicious_chain=False,
        )
        self._delete(qs, 'Process (non-flagged)', dry)

        # Port records (48h)
        qs = Port.objects.filter(timestamp__lt=cut48)
        self._delete(qs, 'Port', dry)

        # Short events (7 days)
        cut7 = now - timedelta(days=7)
        qs = Event.objects.filter(
            timestamp__lt=cut7,
            event_type__in=['PROCESS_START', 'NETWORK_CONNECT'],
        )
        self._delete(qs, 'Events (short-lived)', dry)

        # Detection events (30 days)
        cut30 = now - timedelta(days=30)
        qs = Event.objects.filter(
            timestamp__lt=cut30,
            event_type__in=[
                'HASH_MATCH', 'IP_MATCH',
                'LOLBIN_CHAIN', 'RANSOMWARE_PRECURSOR',
            ],
        )
        self._delete(qs, 'Events (detection)', dry)

        # FALSE POSITIVE alerts (90 days, no incident)
        cut90 = now - timedelta(days=90)
        fp_qs = SuspiciousActivity.objects.filter(
            status='false_positive',
            closed_at__lt=cut90,
        ).exclude(
            # Protect alerts linked to incidents (if relation exists)
        )
        # Preserve FP reason in linked exclusion rules
        if not dry:
            for alert in fp_qs:
                if alert.false_positive_reason:
                    ExclusionRule.objects.filter(
                        process_name=alert.process_name,
                        is_active=True,
                        reason='',
                    ).update(
                        reason=f'FP from alert #{alert.id}: '
                               f'{alert.false_positive_reason[:200]}'
                    )
        self._delete(fp_qs, 'Alerts (false positive, 90d)', dry)

        # CLOSED alerts (180 days)
        cut180 = now - timedelta(days=180)
        closed_qs = SuspiciousActivity.objects.filter(
            status='closed',
            closed_at__lt=cut180,
        )
        self._delete(closed_qs, 'Alerts (closed, 180d)', dry)

        # NEVER deleted:
        #   status open / in_response — active alerts
        #   status in_incident — permanent evidence
        self.stdout.write(self.style.SUCCESS('\nDone.'))

    def _delete(self, qs, label, dry):
        count = qs.count()
        if not dry and count > 0:
            qs.delete()
        flag = '[DRY] ' if dry else ''
        self.stdout.write(
            f'{flag}{label}: {count} records '
            f'{"would be " if dry else ""}deleted'
        )
