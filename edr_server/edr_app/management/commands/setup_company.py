from django.core.management.base import BaseCommand
from django.contrib.auth.models import User


class Command(BaseCommand):
    help = 'Create initial company and license setup'

    def add_arguments(self, parser):
        parser.add_argument(
            '--name', default='My Organisation',
            help='Company name')
        parser.add_argument(
            '--tier', default='professional',
            choices=['free', 'professional', 'enterprise'])
        parser.add_argument(
            '--months', type=int, default=12)

    def handle(self, *args, **options):
        from datetime import date, timedelta
        from edr_app.models import Company, License, Client

        if Company.objects.exists():
            self.stdout.write(self.style.WARNING(
                'Company already exists. Use /owner/company/ to manage.'))
            return

        company = Company.objects.create(
            name=options['name'], is_active=True)
        self.stdout.write(self.style.SUCCESS(
            f'Created company: {company.name}'))

        end_date = date.today() + timedelta(days=30 * options['months'])
        owner = User.objects.filter(is_superuser=True).first()
        tier = options['tier']
        max_ep = License.TIER_LIMITS.get(tier, 10)

        lic = License.objects.create(
            company=company,
            tier=tier,
            valid_from=date.today(),
            valid_until=end_date,
            max_endpoints=max_ep,
            is_active=True,
            created_by=owner,
        )
        self.stdout.write(self.style.SUCCESS(
            f'License: {lic.get_tier_display()} '
            f'({max_ep} endpoints) until {end_date}'))

        updated = Client.objects.filter(
            company__isnull=True).update(company=company)
        self.stdout.write(f'Linked {updated} existing endpoints.')
