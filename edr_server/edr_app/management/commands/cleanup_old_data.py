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

        # FALSE POSITIVE alerts — delete after 90 days
        # ONLY if not linked to any incident
        fp_cutoff = now - timedelta(days=90)
        fp_qs = SuspiciousActivity.objects.filter(
            status='false_positive',
            closed_at__lt=fp_cutoff,
            incidents__isnull=True,
        )
        # Preserve FP reason in linked exclusion rules before deleting
        for alert in fp_qs:
            if alert.false_positive_reason:
                rules = ExclusionRule.objects.filter(
                    process_name=alert.process_name,
                    is_active=True,
                )
                for rule in rules:
                    if not rule.reason:
                        rule.reason = (
                            f"Auto-created from FP "
                            f"alert #{alert.id}: "
                            f"{alert.false_positive_reason[:200]}")
                        rule.save()
        count_fp = fp_qs.count()
        if not dry:
            fp_qs.delete()
        self.stdout.write(
            f'{"[DRY] " if dry else ""}FP alerts deleted: {count_fp}')

        # CLOSED alerts — delete after 180 days
        # ONLY if not linked to any incident
        closed_cutoff = now - timedelta(days=180)
        closed_qs = SuspiciousActivity.objects.filter(
            status='closed',
            closed_at__lt=closed_cutoff,
            incidents__isnull=True,
        )
        count_closed = closed_qs.count()
        if not dry:
            closed_qs.delete()
        self.stdout.write(
            f'{"[DRY] " if dry else ""}Closed alerts deleted: {count_closed}')

        # NEVER AUTO-DELETE:
        # status='open'          — active, being worked
        # status='acknowledged'  — active, being worked
        # status='in_incident'   — incident demands permanence
        # incidents__isnull=False — ANY incident link = protected
        #
        # The .filter(incidents__isnull=True) in both
        # querysets above is the ONLY protection mechanism.
        # It means: even a false_positive or closed alert
        # is immune to deletion if it has an incident linked.
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
