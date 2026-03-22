import requests
from django.core.management.base import BaseCommand
from edr_app.models import ThreatIntelIP, ThreatIntelHash


class Command(BaseCommand):
    help = 'Sync threat intelligence feeds (IPsum, Feodo, MalwareBazaar, ThreatFox)'

    TARGETED_SIGNATURES = [
        'NetSupport',
        'Ajina',
        'LockBit',
        'BlackCat',
        'Rhysida',
    ]

    def add_arguments(self, parser):
        parser.add_argument(
            '--targeted',
            action='store_true',
            help='Also fetch MalwareBazaar hashes for Uzbekistan-relevant signatures',
        )

    def handle(self, *args, **options):
        from decouple import config
        api_key = config('ABUSE_CH_API_KEY', default='')

        ip_count = 0
        hash_count = 0

        # Feed 1 — IPsum
        try:
            self.stdout.write('Fetching IPsum...')
            resp = requests.get(
                'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
                timeout=30,
            )
            resp.raise_for_status()
            ips = []
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('\t')
                if parts:
                    ips.append(ThreatIntelIP(ip_address=parts[0], source='ipsum'))
            created = ThreatIntelIP.objects.bulk_create(ips, ignore_conflicts=True)
            n = len(created)
            ip_count += n
            self.stdout.write(self.style.SUCCESS(f'IPsum: +{n} IPs added'))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f'IPsum failed: {e}'))

        # Feed 2 — Feodo Tracker
        try:
            self.stdout.write('Fetching Feodo Tracker...')
            resp = requests.get(
                'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
                timeout=30,
            )
            resp.raise_for_status()
            ips = []
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(',')
                if parts:
                    ips.append(ThreatIntelIP(
                        ip_address=parts[0],
                        source='feodo',
                        threat_type='c2_server',
                    ))
            created = ThreatIntelIP.objects.bulk_create(ips, ignore_conflicts=True)
            n = len(created)
            ip_count += n
            self.stdout.write(self.style.SUCCESS(f'Feodo: +{n} IPs added'))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f'Feodo failed: {e}'))

        # Feed 3 — MalwareBazaar
        try:
            self.stdout.write('Fetching MalwareBazaar...')
            resp = requests.post(
                'https://mb-api.abuse.ch/api/v1/',
                data='query=get_recent&selector=time',
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Auth-Key': api_key,
                },
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            hashes = []
            if data.get('query_status') == 'ok':
                for item in data.get('data', []):
                    hashes.append(ThreatIntelHash(
                        sha256_hash=item['sha256_hash'],
                        malware_name=item.get('signature') or '',
                        source='malwarebazaar',
                    ))
            created = ThreatIntelHash.objects.bulk_create(hashes, ignore_conflicts=True)
            n = len(created)
            hash_count += n
            self.stdout.write(self.style.SUCCESS(f'MalwareBazaar: +{n} Hashes added'))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f'MalwareBazaar failed: {e}'))

        # Feed 4 — ThreatFox
        try:
            self.stdout.write('Fetching ThreatFox...')
            resp = requests.post(
                'https://threatfox-api.abuse.ch/api/v1/',
                json={'query': 'get_iocs', 'days': 1},
                headers={
                    'Content-Type': 'application/json',
                    'Auth-Key': api_key,
                },
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            tf_ips = []
            tf_hashes = []
            if data.get('query_status') == 'ok':
                for item in data.get('data', []):
                    ioc_type = item.get('ioc_type', '')
                    ioc_value = item.get('ioc_value', '')
                    if ioc_type == 'sha256_hash':
                        tf_hashes.append(ThreatIntelHash(
                            sha256_hash=ioc_value,
                            malware_name=item.get('malware', ''),
                            source='threatfox',
                        ))
                    elif ioc_type == 'ip:port':
                        ip = ioc_value.split(':')[0]
                        tf_ips.append(ThreatIntelIP(
                            ip_address=ip,
                            source='threatfox',
                            threat_type='malware_c2',
                        ))
            created_ips = ThreatIntelIP.objects.bulk_create(tf_ips, ignore_conflicts=True)
            created_hashes = ThreatIntelHash.objects.bulk_create(tf_hashes, ignore_conflicts=True)
            ni = len(created_ips)
            nh = len(created_hashes)
            ip_count += ni
            hash_count += nh
            self.stdout.write(self.style.SUCCESS(f'ThreatFox: +{ni} IPs, +{nh} Hashes added'))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f'ThreatFox failed: {e}'))

        # Feed 5 — MalwareBazaar Targeted (only with --targeted flag)
        if options['targeted']:
            targeted_count = 0
            for sig in self.TARGETED_SIGNATURES:
                try:
                    self.stdout.write(f'Fetching MalwareBazaar targeted: {sig}...')
                    resp = requests.post(
                        'https://mb-api.abuse.ch/api/v1/',
                        data=f'query=get_siginfo&signature={sig}&limit=1000',
                        headers={
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'Auth-Key': api_key,
                        },
                        timeout=60,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    hashes = []
                    if data.get('query_status') == 'ok':
                        for item in data.get('data', []):
                            hashes.append(ThreatIntelHash(
                                sha256_hash=item['sha256_hash'],
                                malware_name=sig,
                                source='malwarebazaar_targeted',
                            ))
                    created = ThreatIntelHash.objects.bulk_create(
                        hashes, ignore_conflicts=True,
                    )
                    n = len(created)
                    targeted_count += n
                    self.stdout.write(self.style.SUCCESS(
                        f'  {sig}: +{n} hashes added'
                    ))
                except Exception as e:
                    self.stderr.write(self.style.ERROR(
                        f'  {sig} failed: {e}'
                    ))
            hash_count += targeted_count
            self.stdout.write(self.style.SUCCESS(
                f'MalwareBazaar Targeted: +{targeted_count} hashes total'
            ))

        self.stdout.write(self.style.SUCCESS(
            f'Sync complete. IPs: +{ip_count} total, Hashes: +{hash_count} total'
        ))
