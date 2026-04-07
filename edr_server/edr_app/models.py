from django.db import models
from django.utils import timezone
import threading
import uuid

# Create your models here.

class Client(models.Model):
    hostname = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    last_seen = models.DateTimeField(auto_now=True)
    auth_token = models.CharField(max_length=255, unique=True, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    # Command handling
    _pending_command = None
    _command_response = None
    _command_event = None
    
    def queue_command(self, command):
        self._pending_command = command
        self._command_response = None
        self._command_event = threading.Event()
    
    def get_pending_command(self):
        command = self._pending_command
        self._pending_command = None
        return command
    
    def set_command_response(self, response):
        self._command_response = response
        if self._command_event:
            self._command_event.set()
    
    def wait_for_response(self, timeout=5):
        if self._command_event and self._command_event.wait(timeout):
            response = self._command_response
            self._command_response = None
            self._command_event = None
            return response
        return None
    
    def execute_command(self, command):
        self.queue_command(command)
        return self.wait_for_response()
    
    def __str__(self):
        return f"{self.hostname} ({self.ip_address})"

class Command(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='commands')
    command = models.CharField(max_length=255)
    args = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    executed = models.BooleanField(default=False)
    executed_at = models.DateTimeField(null=True, blank=True)
    response = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.command} ({self.client.hostname})"

class Process(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='processes')
    pid = models.IntegerField()
    name = models.CharField(max_length=255)
    path = models.CharField(max_length=1024)
    command_line = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    version = models.CharField(max_length=50, blank=True, null=True)
    parent_pid = models.IntegerField(null=True, blank=True)
    sha256_hash = models.CharField(max_length=64, blank=True, null=True)
    is_lolbin = models.BooleanField(default=False)
    is_suspicious_chain = models.BooleanField(default=False)
    parent_name = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.name} (PID: {self.pid})"

class Port(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='ports')
    port_number = models.IntegerField()
    protocol = models.CharField(max_length=10)
    state = models.CharField(max_length=20)
    process_name = models.CharField(max_length=255)
    process_id = models.IntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)
    service_name = models.CharField(max_length=100, blank=True, null=True)
    service_version = models.CharField(max_length=50, blank=True, null=True)
    local_ip = models.GenericIPAddressField(null=True, blank=True)
    local_port = models.IntegerField(null=True, blank=True)
    remote_ip = models.GenericIPAddressField(null=True, blank=True)
    remote_port = models.IntegerField(null=True, blank=True)

    def __str__(self):
        return f"{self.protocol}:{self.port_number} ({self.state})"

class SuspiciousActivity(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='activities')
    type = models.CharField(max_length=100)
    description = models.TextField()
    process_name = models.CharField(max_length=255, blank=True)
    process_id = models.IntegerField(null=True, blank=True)
    timestamp = models.DateTimeField()
    severity = models.CharField(
        max_length=20,
        choices=[('CRITICAL', 'Critical'), ('HIGH', 'High'),
                 ('MEDIUM', 'Medium'), ('LOW', 'Low')],
        default='LOW'
    )
    ioc_matched = models.CharField(max_length=255, blank=True, null=True)
    score = models.IntegerField(default=0)
    event_count = models.IntegerField(default=1)
    last_seen = models.DateTimeField(auto_now=True)
    events = models.ManyToManyField('Event', blank=True, related_name='alerts')
    correlation_id = models.CharField(max_length=64, blank=True, null=True, db_index=True,
                                      help_text='Groups related alerts from same attack chain')

    ALERT_STATUS = [
        ('open',           'Open'),
        ('in_response',    'In Response'),
        ('false_positive', 'False Positive'),
        ('in_incident',    'In Incident'),
        ('closed',         'Closed'),
    ]
    status = models.CharField(max_length=20, choices=ALERT_STATUS, default='open', db_index=True)
    false_positive_reason = models.TextField(blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    assigned_to = models.ForeignKey(
        'auth.User', on_delete=models.SET_NULL,
        null=True, blank=True, related_name='assigned_alerts')

    class Meta:
        ordering = ['-last_seen']
        indexes = [
            models.Index(fields=['client', 'ioc_matched', 'type']),
            models.Index(fields=['severity', 'last_seen'], name='alert_sev_ts_idx'),
            models.Index(fields=['client', 'last_seen'], name='alert_client_ts_idx'),
            models.Index(fields=['last_seen'], name='alert_ts_idx'),
            models.Index(fields=['status'], name='alert_status_idx'),
        ]

    def __str__(self):
        return f"{self.type} - {self.description[:50]}"

    @property
    def is_acknowledged(self):
        return self.status in ('in_response', 'in_incident', 'false_positive', 'closed')

    def can_mark_false_positive(self):
        if hasattr(self, 'incidents') and self.incidents.exists():
            refs = ', '.join(i.reference for i in self.incidents.all()[:3])
            return False, f"Alert is linked to {refs}. Remove it from the incident before marking as false positive."
        return True, ""

    def can_delete(self):
        if self.status in ('open', 'in_response', 'in_incident'):
            return False
        if hasattr(self, 'incidents') and self.incidents.exists():
            return False
        return True

class Vulnerability(models.Model):
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]

    cve_id = models.CharField(max_length=20, unique=True)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='MEDIUM')
    published_date = models.DateTimeField()
    last_modified_date = models.DateTimeField()
    affected_software = models.CharField(max_length=255, default='Unknown')
    affected_versions = models.CharField(max_length=255, default='*')
    related_processes = models.ManyToManyField(Process, related_name='vulnerabilities', blank=True)
    related_ports = models.ManyToManyField(Port, related_name='vulnerabilities', blank=True)

    def __str__(self):
        return self.cve_id

class VulnerabilityMatch(models.Model):
    MATCH_TYPE_CHOICES = [
        ('PROCESS', 'Process Match'),
        ('PORT', 'Port Match'),
        ('SERVICE', 'Service Match'),
    ]

    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    match_type = models.CharField(max_length=20, choices=MATCH_TYPE_CHOICES)
    process = models.ForeignKey(Process, on_delete=models.CASCADE, null=True, blank=True)
    port = models.ForeignKey(Port, on_delete=models.CASCADE, null=True, blank=True)
    confidence_score = models.FloatField(default=0.0)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [
            ('vulnerability', 'client', 'process'),
            ('vulnerability', 'client', 'port'),
        ]

    def __str__(self):
        return f"{self.vulnerability.cve_id} - {self.match_type} - {self.confidence_score}"

class Log(models.Model):
    LOG_LEVELS = [
        ('INFO', 'Info'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('DEBUG', 'Debug'),
    ]
    
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='logs')
    level = models.CharField(max_length=10, choices=LOG_LEVELS, default='INFO')
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    source = models.CharField(max_length=255, help_text="Source of the log (e.g., component name)")

    def __str__(self):
        return f"[{self.level}] {self.client.hostname}: {self.message[:50]}"

    class Meta:
        ordering = ['-timestamp']

class WindowsEventLog(models.Model):
    LOG_LEVELS = [
        ('Information', 'Information'),
        ('Warning', 'Warning'),
        ('Error', 'Error'),
        ('Critical', 'Critical'),
        ('Verbose', 'Verbose'),
    ]

    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    source = models.CharField(max_length=255)  # Application, System, Security
    provider = models.CharField(max_length=255)
    level = models.CharField(max_length=20, choices=LOG_LEVELS)
    event_id = models.CharField(max_length=50)
    message = models.TextField()
    timestamp = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['source']),
            models.Index(fields=['level']),
        ]

    def __str__(self):
        return f"{self.source} - {self.event_id} - {self.timestamp}"


class ThreatIntelIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    source = models.CharField(max_length=50)
    threat_type = models.CharField(max_length=100, blank=True)
    added_date = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        indexes = [models.Index(fields=['ip_address'])]

    def __str__(self):
        return f"{self.ip_address} ({self.source})"


class ThreatIntelHash(models.Model):
    sha256_hash = models.CharField(max_length=64, unique=True)
    malware_name = models.CharField(max_length=255, blank=True)
    source = models.CharField(max_length=50)
    added_date = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        indexes = [models.Index(fields=['sha256_hash'])]

    def __str__(self):
        return f"{self.sha256_hash[:16]}... ({self.malware_name})"


class ExclusionRule(models.Model):
    MATCH_MODES = [
        ('NAME_ONLY', 'Name Only'),
        ('NAME_AND_PATH', 'Name + Path'),
        ('HASH_ONLY', 'SHA256 Hash Only'),
        ('ALL', 'Name + Path + Hash'),
    ]

    process_name = models.CharField(
        max_length=255, blank=True,
        help_text='e.g. explorer.exe'
    )
    process_path = models.CharField(
        max_length=500, blank=True,
        help_text='e.g. C:\\Windows\\System32\\'
    )
    sha256_hash = models.CharField(
        max_length=64, blank=True,
        help_text='Full SHA256 hex string'
    )
    match_mode = models.CharField(
        max_length=20,
        choices=MATCH_MODES,
        default='NAME_AND_PATH'
    )
    reason = models.TextField(
        blank=True,
        help_text='Why this process is excluded'
    )
    added_by = models.ForeignKey(
        'auth.User',
        on_delete=models.SET_NULL,
        null=True, blank=True
    )
    expires_at = models.DateTimeField(
        null=True, blank=True,
        help_text='Leave blank for permanent exclusion'
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['process_name', 'is_active']),
            models.Index(fields=['sha256_hash', 'is_active']),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.process_name} ({self.match_mode})'

    def is_expired(self):
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False


class Event(models.Model):
    EVENT_TYPES = [
        ('PROCESS_START',        'Process Started'),
        ('NETWORK_CONNECT',      'Network Connection'),
        ('HASH_MATCH',           'Malware Hash Detected'),
        ('IP_MATCH',             'Blacklisted IP Connection'),
        ('LOLBIN_CHAIN',         'LOLBin Process Chain'),
        ('RANSOMWARE_PRECURSOR', 'Ransomware Precursor Tool'),
    ]

    client     = models.ForeignKey('Client', on_delete=models.CASCADE, related_name='events')
    event_type = models.CharField(max_length=30, choices=EVENT_TYPES, db_index=True)
    process    = models.ForeignKey('Process', null=True, blank=True, on_delete=models.SET_NULL, related_name='events')
    port       = models.ForeignKey('Port', null=True, blank=True, on_delete=models.SET_NULL, related_name='events')
    timestamp  = models.DateTimeField(auto_now_add=True, db_index=True)
    raw_data   = models.TextField(default='{}', help_text='JSON-encoded event data')

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['event_type', 'timestamp'], name='event_type_ts_idx'),
            models.Index(fields=['client', 'timestamp'], name='event_client_ts_idx'),
            models.Index(fields=['timestamp'], name='event_ts_idx'),
        ]

    def __str__(self):
        return f"{self.event_type} on {self.client.hostname} at {self.timestamp:%Y-%m-%d %H:%M:%S}"

    @property
    def display_name(self):
        return dict(self.EVENT_TYPES).get(self.event_type, self.event_type)


class Signature(models.Model):

    MITRE_TACTICS = [
        ('execution',        'Execution'),
        ('defense_evasion',  'Defense Evasion'),
        ('command_control',  'Command and Control'),
        ('discovery',        'Discovery'),
        ('lateral_movement', 'Lateral Movement'),
        ('impact',           'Impact'),
        ('persistence',      'Persistence'),
    ]

    SEVERITY_LEVELS = [
        ('LOW',      'Low'),
        ('MEDIUM',   'Medium'),
        ('HIGH',     'High'),
        ('CRITICAL', 'Critical'),
    ]

    alert = models.ForeignKey(
        'SuspiciousActivity', on_delete=models.CASCADE,
        related_name='signatures', null=True, blank=True)
    events = models.ManyToManyField(
        'Event', related_name='signatures', blank=True)
    sig_id = models.CharField(max_length=20, default='SIG-000')
    name = models.CharField(max_length=200)
    plain_title = models.CharField(max_length=200)
    plain_explanation = models.TextField()
    plain_action = models.TextField()
    mitre_id = models.CharField(max_length=20, blank=True)
    mitre_tactic = models.CharField(
        max_length=30, choices=MITRE_TACTICS, blank=True)
    severity = models.CharField(
        max_length=10, choices=SEVERITY_LEVELS, default='LOW')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.sig_id}: {self.plain_title}"

    @property
    def mitre_url(self):
        if self.mitre_id:
            base = self.mitre_id.replace('.', '/')
            return f"https://attack.mitre.org/techniques/{base}/"
        return ""


class Incident(models.Model):
    STATUS_CHOICES = [
        ('open',        'Open'),
        ('in_progress', 'In Progress'),
        ('resolved',    'Resolved'),
        ('closed',      'Closed'),
    ]
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH',     'High'),
        ('MEDIUM',   'Medium'),
        ('LOW',      'Low'),
    ]

    number = models.PositiveIntegerField(unique=True, editable=False)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open', db_index=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='HIGH')
    created_by = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, related_name='created_incidents')
    assigned_to = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_incidents')
    alerts = models.ManyToManyField('SuspiciousActivity', related_name='incidents', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['number']),
        ]

    def save(self, *args, **kwargs):
        if not self.number:
            last = Incident.objects.order_by('-number').first()
            self.number = (last.number + 1) if last else 1
        super().save(*args, **kwargs)
        self._update_severity()

    def _update_severity(self):
        sev_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        alert_sevs = list(self.alerts.values_list('severity', flat=True))
        for sev in sev_order:
            if sev in alert_sevs:
                if self.severity != sev:
                    Incident.objects.filter(pk=self.pk).update(severity=sev)
                return

    @property
    def reference(self):
        return f"INC-{self.number:04d}"

    @property
    def time_open(self):
        end = self.resolved_at or timezone.now()
        delta = end - self.created_at
        hours = int(delta.total_seconds() / 3600)
        if hours < 24:
            return f"{hours}h open"
        return f"{delta.days}d open"

    def __str__(self):
        return f"{self.reference}: {self.title}"


class IncidentActivity(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='activities')
    user = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=100)
    detail = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.incident.reference}: {self.action}"


class IncidentComment(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True)
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']


class Report(models.Model):
    REPORT_TYPES = [
        ('events',     'Events Report'),
        ('alerts',     'Alerts Report'),
        ('incidents',  'Incidents Report'),
        ('compliance', 'PP-167 Compliance Report'),
    ]

    report_type = models.CharField(max_length=20, choices=REPORT_TYPES)
    filename = models.CharField(max_length=255)
    file_path = models.CharField(max_length=500, blank=True)
    generated_by = models.ForeignKey(
        'auth.User', on_delete=models.SET_NULL, null=True, blank=True)
    generated_at = models.DateTimeField(auto_now_add=True)
    record_count = models.IntegerField(default=0)
    filters_applied = models.TextField(default='{}', blank=True)
    file_size_bytes = models.IntegerField(default=0)

    class Meta:
        ordering = ['-generated_at']
        indexes = [
            models.Index(fields=['report_type', 'generated_at']),
        ]

    @property
    def filters_dict(self):
        import json
        try:
            return json.loads(self.filters_applied or '{}')
        except (json.JSONDecodeError, TypeError):
            return {}

    @property
    def file_size_display(self):
        b = self.file_size_bytes
        if b < 1024:
            return f"{b} B"
        elif b < 1024**2:
            return f"{b/1024:.1f} KB"
        return f"{b/1024**2:.1f} MB"
