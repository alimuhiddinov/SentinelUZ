from django.contrib import admin
from .models import (
    Client, Process, Port, SuspiciousActivity, Vulnerability,
    ThreatIntelIP, ThreatIntelHash, ExclusionRule, Event, Signature,
    Incident, IncidentActivity, IncidentComment, WindowsEventLog,
)

# Register your models here.

@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = ('hostname', 'ip_address', 'last_seen')
    search_fields = ('hostname', 'ip_address')

@admin.register(Process)
class ProcessAdmin(admin.ModelAdmin):
    list_display = ('client', 'pid', 'name', 'timestamp')
    list_filter = ('client',)
    readonly_fields = ('client', 'pid', 'name', 'timestamp')

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

@admin.register(Port)
class PortAdmin(admin.ModelAdmin):
    list_display = ('client', 'port_number', 'protocol', 'state', 'timestamp')
    list_filter = ('client', 'protocol', 'state')
    readonly_fields = ('client', 'port_number', 'protocol', 'state', 'timestamp')

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

@admin.register(SuspiciousActivity)
class SuspiciousActivityAdmin(admin.ModelAdmin):
    list_display = ('client', 'type', 'description', 'timestamp')
    list_filter = ('client', 'type')

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('cve_id', 'severity', 'published_date')
    list_filter = ('severity',)
    search_fields = ('cve_id', 'description')

@admin.register(ThreatIntelIP)
class ThreatIntelIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'source', 'threat_type', 'is_active', 'added_date')
    list_filter = ('source', 'is_active')
    search_fields = ('ip_address',)

@admin.register(ThreatIntelHash)
class ThreatIntelHashAdmin(admin.ModelAdmin):
    list_display = ('sha256_hash', 'malware_name', 'source', 'is_active', 'added_date')
    list_filter = ('source', 'is_active')
    search_fields = ('sha256_hash', 'malware_name')


@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ['event_type', 'client', 'timestamp', 'process', 'port']
    list_filter = ['event_type', 'client']
    search_fields = ['event_type', 'client__hostname']
    readonly_fields = ['timestamp', 'raw_data']
    ordering = ['-timestamp']


@admin.register(Signature)
class SignatureAdmin(admin.ModelAdmin):
    list_display = ['sig_id', 'plain_title', 'mitre_id', 'mitre_tactic', 'severity', 'created_at']
    list_filter = ['severity', 'mitre_tactic']
    search_fields = ['sig_id', 'plain_title', 'mitre_id']
    readonly_fields = ['created_at']


class IncidentActivityInline(admin.TabularInline):
    model = IncidentActivity
    extra = 0
    readonly_fields = ['user', 'action', 'detail', 'timestamp']


class IncidentCommentInline(admin.TabularInline):
    model = IncidentComment
    extra = 0
    readonly_fields = ['author', 'created_at']


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ['reference', 'title', 'status', 'severity', 'created_by', 'created_at']
    list_filter = ['status', 'severity']
    search_fields = ['title', 'description']
    readonly_fields = ['number', 'created_at', 'updated_at']
    inlines = [IncidentActivityInline, IncidentCommentInline]


@admin.register(WindowsEventLog)
class WindowsEventLogAdmin(admin.ModelAdmin):
    list_display = ['source', 'level', 'event_id', 'client', 'timestamp']
    list_filter = ['source', 'level']

    def get_model_perms(self, request):
        """Hide from admin index. Deprecated model."""
        return {}


@admin.register(ExclusionRule)
class ExclusionRuleAdmin(admin.ModelAdmin):
    list_display = [
        'process_name', 'process_path', 'match_mode',
        'safety_level', 'reason', 'added_by',
        'expires_at', 'is_active', 'created_at'
    ]
    list_filter = ['match_mode', 'is_active']
    search_fields = ['process_name', 'process_path',
                     'sha256_hash', 'reason']
    list_editable = ['is_active']
    readonly_fields = ['created_at', 'added_by']

    fieldsets = (
        ('Match Criteria', {
            'fields': ('match_mode', 'process_name',
                       'process_path', 'sha256_hash'),
            'description': (
                'NAME_AND_PATH is recommended. '
                'NAME_ONLY can be spoofed by attackers '
                'who name their malware after legitimate processes.'
            )
        }),
        ('Details', {
            'fields': ('reason', 'expires_at', 'is_active')
        }),
        ('Audit', {
            'fields': ('added_by', 'created_at'),
            'classes': ('collapse',)
        }),
    )

    def safety_level(self, obj):
        levels = {
            'NAME_ONLY':     'LOW — name can be spoofed',
            'NAME_AND_PATH': 'MEDIUM — recommended',
            'HASH_ONLY':     'HIGH — exact match',
            'ALL':           'HIGHEST — strictest',
        }
        return levels.get(obj.match_mode, '?')
    safety_level.short_description = 'Safety Level'

    def save_model(self, request, obj, form, change):
        if not obj.pk:
            obj.added_by = request.user
        super().save_model(request, obj, form, change)

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        recent = Process.objects.exclude(
            sha256_hash=''
        ).exclude(
            sha256_hash__isnull=True
        ).values(
            'name', 'path', 'sha256_hash'
        ).distinct()[:20]

        if recent:
            hash_list = '\n'.join([
                f"{p['name']} — {p['sha256_hash'][:16]}..."
                for p in recent
            ])
            form.base_fields['sha256_hash'].help_text = (
                f'Optional. Leave blank to match by '
                f'name/path only.\n'
                f'Recently seen process hashes:\n{hash_list}'
            )
        return form
