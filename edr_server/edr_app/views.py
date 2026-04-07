from django.shortcuts import render, get_object_or_404, redirect
from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view, permission_classes, authentication_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.http import require_POST
from django.conf import settings
from django.utils import timezone
from datetime import timedelta, datetime
import requests
import json
import os
from .models import (
    Client, Process, Port, SuspiciousActivity, Vulnerability,
    VulnerabilityMatch, Log, WindowsEventLog,
    ThreatIntelIP, ThreatIntelHash, ExclusionRule, Event, Signature,
    Incident, IncidentActivity, IncidentComment, Report,
)
from .serializers import (
    ClientSerializer, ProcessSerializer, PortSerializer,
    SuspiciousActivitySerializer, VulnerabilitySerializer, LogSerializer, WindowsEventLogSerializer
)
from .utils import analyze_vulnerabilities, match_iocs, _ti_cache
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.http import HttpResponse, JsonResponse
from django.core.paginator import Paginator
from django.db import transaction
from django.contrib import messages

REPORTS_DIR = os.path.join(settings.BASE_DIR, 'reports_archive')
os.makedirs(REPORTS_DIR, exist_ok=True)


def _save_report_record(report_type, filename, filters, record_count,
                         request=None, content=b''):
    """Save report metadata and file to reports archive."""
    file_path = os.path.join(REPORTS_DIR, filename)
    if content:
        with open(file_path, 'wb') as f:
            f.write(content)
    file_size = (os.path.getsize(file_path)
                 if os.path.exists(file_path) else 0)
    user = request.user if request and request.user.is_authenticated else None
    Report.objects.create(
        report_type=report_type,
        filename=filename,
        file_path=file_path,
        generated_by=user,
        record_count=record_count,
        filters_applied=json.dumps(filters),
        file_size_bytes=file_size,
    )


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    from .models import ThreatIntelIP, ThreatIntelHash, Client
    return Response({
        "status": "ok",
        "version": "1.0",
        "timestamp": timezone.now().isoformat(),
        "app": "SentinelUZ EDR",
        "stats": {
            "threat_intel_ips": ThreatIntelIP.objects.filter(
                is_active=True).count(),
            "threat_intel_hashes": ThreatIntelHash.objects.filter(
                is_active=True).count(),
            "active_endpoints": Client.objects.filter(
                is_active=True).count(),
        }
    })


def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return redirect('login')

@login_required
def dashboard(request):
    from django.db.models import Count, Q, Max

    now = timezone.now()
    two_min_ago = now - timedelta(minutes=2)
    twenty_four_h_ago = now - timedelta(hours=24)

    total_endpoints = Client.objects.count()
    active_endpoints = Client.objects.filter(last_seen__gte=two_min_ago).count()
    critical_alerts = SuspiciousActivity.objects.filter(
        severity='CRITICAL', status='open').count()
    alerts_24h = SuspiciousActivity.objects.filter(
        timestamp__gte=twenty_four_h_ago).count()
    ti_total = (ThreatIntelIP.objects.filter(is_active=True).count() +
                ThreatIntelHash.objects.filter(is_active=True).count())
    open_incidents = Incident.objects.filter(
        status__in=['open', 'in_progress']).count()

    endpoints = Client.objects.annotate(
        process_count=Count('processes', distinct=True),
        critical_count=Count('activities', filter=Q(
            activities__severity='CRITICAL',
            activities__status='open'), distinct=True),
        alert_count=Count('activities', filter=Q(
            activities__status='open'), distinct=True),
    ).order_by('-last_seen')

    recent_alerts = SuspiciousActivity.objects.select_related(
        'client').order_by('-last_seen')[:5]

    severity_qs = SuspiciousActivity.objects.filter(
        status='open').values('severity').annotate(count=Count('id'))
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for row in severity_qs:
        severity_counts[row['severity']] = row['count']

    last_checkin = Client.objects.aggregate(last=Max('last_seen'))['last']

    context = {
        'active_endpoints': active_endpoints,
        'total_endpoints': total_endpoints,
        'critical_alerts': critical_alerts,
        'alerts_24h': alerts_24h,
        'ti_total': ti_total,
        'open_incidents': open_incidents,
        'endpoints': endpoints,
        'recent_alerts': recent_alerts,
        'severity_counts': severity_counts,
        'last_checkin': last_checkin,
        'two_min_ago': two_min_ago,
    }
    return render(request, 'edr_app/dashboard.html', context)


@login_required
def dashboard_stats_api(request):
    from django.db.models import Count, Q, Max

    now = timezone.now()
    two_min_ago = now - timedelta(minutes=2)
    twenty_four_h_ago = now - timedelta(hours=24)

    active_endpoints = Client.objects.filter(last_seen__gte=two_min_ago).count()
    total_endpoints = Client.objects.count()
    critical_alerts = SuspiciousActivity.objects.filter(
        severity='CRITICAL', status='open').count()
    alerts_24h = SuspiciousActivity.objects.filter(
        timestamp__gte=twenty_four_h_ago).count()
    ti_total = (ThreatIntelIP.objects.filter(is_active=True).count() +
                ThreatIntelHash.objects.filter(is_active=True).count())
    open_incidents = Incident.objects.filter(
        status__in=['open', 'in_progress']).count()

    endpoints_qs = Client.objects.annotate(
        process_count=Count('processes', distinct=True),
        critical_count=Count('activities', filter=Q(
            activities__severity='CRITICAL',
            activities__status='open'), distinct=True),
        alert_count=Count('activities', filter=Q(
            activities__status='open'), distinct=True),
    ).order_by('-last_seen')

    endpoints_data = []
    for ep in endpoints_qs:
        endpoints_data.append({
            'id': ep.id,
            'hostname': ep.hostname,
            'ip_address': ep.ip_address,
            'is_online': ep.last_seen >= two_min_ago if ep.last_seen else False,
            'last_seen': ep.last_seen.isoformat() if ep.last_seen else None,
            'process_count': ep.process_count,
            'critical_count': ep.critical_count,
            'alert_count': ep.alert_count,
        })

    recent = []
    for a in SuspiciousActivity.objects.select_related('client').order_by('-last_seen')[:5]:
        recent.append({
            'id': a.id,
            'type': a.type,
            'severity': a.severity,
            'hostname': a.client.hostname,
            'ioc_matched': a.ioc_matched or '',
            'event_count': a.event_count,
            'last_seen': a.last_seen.isoformat() if a.last_seen else None,
        })

    severity_qs = SuspiciousActivity.objects.filter(
        status='open').values('severity').annotate(count=Count('id'))
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for row in severity_qs:
        severity_counts[row['severity']] = row['count']

    last_checkin = Client.objects.aggregate(last=Max('last_seen'))['last']

    return JsonResponse({
        'active_endpoints': active_endpoints,
        'total_endpoints': total_endpoints,
        'critical_alerts': critical_alerts,
        'alerts_24h': alerts_24h,
        'ti_total': ti_total,
        'open_incidents': open_incidents,
        'endpoints': endpoints_data,
        'recent_alerts': recent,
        'severity_counts': severity_counts,
        'last_checkin': last_checkin.isoformat() if last_checkin else None,
    })


@login_required
def device_detail(request, device_id):
    client = get_object_or_404(Client, id=device_id)
    
    # Get recent data, excluding PID 0
    processes = Process.objects.filter(client=client).exclude(pid=0).order_by('-timestamp')[:50]
    ports = Port.objects.filter(client=client).order_by('-timestamp')[:50]
    alerts = SuspiciousActivity.objects.filter(client=client).order_by('-last_seen')[:20]
    logs = Log.objects.filter(client=client).order_by('-timestamp')[:100]
    
    # Analyze vulnerabilities
    analyze_vulnerabilities(client)
    vulnerability_matches = VulnerabilityMatch.objects.filter(client=client).order_by('-confidence_score')
    
    # Group vulnerabilities by type
    process_vulnerabilities = vulnerability_matches.filter(match_type='PROCESS')
    service_vulnerabilities = vulnerability_matches.filter(match_type='SERVICE')
    port_vulnerabilities = vulnerability_matches.filter(match_type='PORT')
    
    clients = Client.objects.all().order_by('hostname')

    context = {
        'client': client,
        'processes': processes,
        'ports': ports,
        'alerts': alerts,
        'process_vulnerabilities': process_vulnerabilities,
        'service_vulnerabilities': service_vulnerabilities,
        'port_vulnerabilities': port_vulnerabilities,
        'logs': logs,
        'clients': clients,
    }
    return render(request, 'edr_app/device_detail.html', context)

@login_required
def processes(request):
    processes = Process.objects.select_related('client').exclude(pid=0).order_by('-timestamp')
    clients = Client.objects.all().order_by('hostname')
    return render(request, 'edr_app/processes.html', {
        'processes': processes,
        'clients': clients,
    })

@login_required
def process_tree(request, device_id):
    client = get_object_or_404(Client, id=device_id)
    processes = Process.objects.filter(client=client).exclude(pid=0).order_by('parent_pid', 'pid')

    processes_json = json.dumps([{
        'pid':                 p.pid,
        'parent_pid':          p.parent_pid,
        'name':                p.name,
        'path':                p.path or '',
        'sha256_hash':         p.sha256_hash or '',
        'is_lolbin':           p.is_lolbin,
        'is_suspicious_chain': p.is_suspicious_chain,
        'parent_name':         p.parent_name or '',
        'command_line':        p.command_line or '',
    } for p in processes])

    return render(request, 'edr_app/process_tree.html', {
        'client':          client,
        'processes_json':  processes_json,
        'process_count':   processes.count(),
        'lolbin_count':    processes.filter(is_lolbin=True).count(),
        'suspicious_count': processes.filter(is_suspicious_chain=True).count(),
    })

@login_required
def ports(request):
    ports = Port.objects.select_related('client').order_by('-timestamp')
    clients = Client.objects.all().order_by('hostname')
    return render(request, 'edr_app/ports.html', {
        'ports': ports,
        'clients': clients,
    })

@login_required
def alerts(request):
    from .query_parser import apply_query

    status_filter = request.GET.get('status', 'open')
    query_str = request.GET.get('query', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    page = int(request.GET.get('page', 1))
    per_page = 50

    qs = SuspiciousActivity.objects.select_related('client').prefetch_related('incidents').order_by('-last_seen')

    if status_filter and status_filter != 'all':
        qs = qs.filter(status=status_filter)

    if date_from:
        qs = qs.filter(last_seen__gte=date_from + 'T00:00:00Z')
    if date_to:
        qs = qs.filter(last_seen__lte=date_to + 'T23:59:59Z')

    if query_str:
        qs, _ = apply_query(qs, query_str, mode='alerts')

    total = qs.count()
    start = (page - 1) * per_page
    alerts_page = qs[start:start + per_page]
    has_more = (start + per_page) < total

    # If AJAX request, return JSON
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        data = []
        for a in alerts_page:
            inc = a.incidents.first()
            data.append({
                'id': a.id,
                'type': a.type,
                'severity': a.severity,
                'status': a.status,
                'description': a.description[:120],
                'process_name': a.process_name or '',
                'process_id': a.process_id,
                'ioc_matched': a.ioc_matched or '',
                'event_count': a.event_count,
                'hostname': a.client.hostname if a.client else '',
                'timestamp': a.timestamp.isoformat() if a.timestamp else None,
                'last_seen': a.last_seen.isoformat() if a.last_seen else None,
                'score': a.score,
                'incident_ref': inc.reference if inc else None,
                'incident_id': inc.id if inc else None,
            })
        return JsonResponse({
            'alerts': data, 'total': total, 'page': page,
            'per_page': per_page, 'has_more': has_more,
        })

    context = {'alerts': alerts_page, 'total': total}
    return render(request, 'edr_app/alerts.html', context)

@login_required
def alert_process_context(request, alert_id):
    """Return process chain context for an alert (JSON)."""
    alert = get_object_or_404(SuspiciousActivity, id=alert_id)
    client = alert.client
    flagged_pid = alert.process_id

    if not flagged_pid:
        # Try to get from linked events
        proc_event = alert.events.filter(process__isnull=False).first()
        if proc_event:
            flagged_pid = proc_event.process.pid

    if not flagged_pid:
        return JsonResponse({'processes': [], 'flagged_pid': None})

    all_processes = Process.objects.filter(client=client)

    # Collect ancestors (up 3 levels) + flagged + children
    pids_to_include = {flagged_pid}

    current_pid = flagged_pid
    for _ in range(3):
        proc = all_processes.filter(pid=current_pid).first()
        if proc and proc.parent_pid:
            pids_to_include.add(proc.parent_pid)
            current_pid = proc.parent_pid
        else:
            break

    children = all_processes.filter(parent_pid=flagged_pid).values_list('pid', flat=True)
    pids_to_include.update(children)

    processes = all_processes.filter(pid__in=pids_to_include).order_by('parent_pid', 'pid')

    data = []
    for p in processes:
        item = {
            'pid':        p.pid,
            'parent_pid': p.parent_pid,
            'name':       p.name,
            'flagged':    p.pid == flagged_pid,
        }
        if p.is_lolbin:
            item['lolbin'] = True
        if p.is_suspicious_chain:
            item['suspicious'] = True
        if p.sha256_hash:
            item['hash_short'] = p.sha256_hash[:16]
            item['hash_full'] = p.sha256_hash
        if p.path:
            item['path'] = p.path
        if p.command_line:
            item['cmd'] = p.command_line
        data.append(item)

    return JsonResponse({
        'processes':   data,
        'flagged_pid': flagged_pid,
        'alert_type':  alert.type,
        'ioc':         alert.ioc_matched or '',
    })

@login_required
def alert_detail(request, alert_id):
    alert = get_object_or_404(
        SuspiciousActivity.objects.select_related('client'), id=alert_id)
    related_alerts = []
    if alert.correlation_id:
        related_alerts = SuspiciousActivity.objects.filter(
            correlation_id=alert.correlation_id
        ).exclude(id=alert_id).order_by('-timestamp')[:10]
    return render(request, 'edr_app/alert_detail.html', {
        'alert': alert,
        'related_alerts': related_alerts,
        'event_count': alert.events.count(),
        'client': alert.client,
    })

@login_required
def alert_events_api(request, alert_id):
    from .models import Event
    alert = get_object_or_404(SuspiciousActivity, id=alert_id)
    events = alert.events.select_related('process', 'port').order_by('timestamp')
    data = []
    for e in events:
        item = {
            'id': e.id,
            'event_type': e.event_type,
            'display_name': e.display_name,
            'timestamp': e.timestamp.isoformat(),
            'raw_data': json.loads(e.raw_data) if e.raw_data else {},
        }
        if e.process:
            item['process'] = {
                'pid': e.process.pid, 'name': e.process.name,
                'path': e.process.path or '',
                'parent_pid': e.process.parent_pid,
                'is_lolbin': e.process.is_lolbin,
                'is_suspicious_chain': e.process.is_suspicious_chain,
            }
        if e.port:
            item['port'] = {
                'remote_ip': e.port.remote_ip or '',
                'remote_port': e.port.remote_port,
                'state': e.port.state or '',
                'process_name': e.port.process_name or '',
            }
        data.append(item)
    return JsonResponse({'events': data, 'event_count': len(data), 'alert_id': alert_id})

@login_required
def alert_network_context(request, alert_id):
    alert = get_object_or_404(SuspiciousActivity, id=alert_id)
    window_start = alert.timestamp - timedelta(minutes=2)
    window_end = alert.last_seen + timedelta(minutes=2)

    ports = list(Port.objects.filter(
        client=alert.client,
        timestamp__gte=window_start,
        timestamp__lte=window_end,
    ).order_by('-timestamp')[:50])

    if alert.process_id:
        pid_ports = list(Port.objects.filter(
            client=alert.client, process_id=alert.process_id,
        ).order_by('-timestamp')[:20])
        seen = {p.id for p in ports}
        for p in pid_ports:
            if p.id not in seen:
                ports.append(p)
                seen.add(p.id)
        ports = ports[:50]

    ip_set = _ti_cache.get('ips') or set()
    data = [{
        'remote_ip': p.remote_ip or '', 'remote_port': p.remote_port,
        'local_ip': p.local_ip or '', 'local_port': p.local_port,
        'state': p.state or '', 'process_id': p.process_id,
        'process_name': p.process_name or '',
        'timestamp': p.timestamp.isoformat(),
        'is_blacklisted': (p.remote_ip or '') in ip_set,
    } for p in ports]

    return JsonResponse({'connections': data, 'count': len(data)})

@login_required
def alert_acknowledge(request, alert_id):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    alert = get_object_or_404(SuspiciousActivity, id=alert_id)
    alert.status = 'in_response'
    alert.save(update_fields=['status'])
    return JsonResponse({'status': 'ok'})

@login_required
def vulnerabilities(request):
    # Get all vulnerability matches with related data
    vulnerabilities = VulnerabilityMatch.objects.select_related(
        'vulnerability', 'client', 'process', 'port'
    ).order_by('-timestamp')

    # Convert confidence scores from 0-1 to 0-100
    for vuln in vulnerabilities:
        vuln.confidence_score = vuln.confidence_score * 100

    context = {
        'vulnerabilities': vulnerabilities,
    }
    return render(request, 'edr_app/vulnerabilities.html', context)

def logs(request):
    """Deprecated — redirects to Endpoint Events."""
    return redirect('endpoint_events')

@staff_member_required
def view_logs(request):
    # Get filter parameters
    level = request.GET.get('level', '')
    client_id = request.GET.get('client', '')
    date_str = request.GET.get('date', '')

    # Start with all logs
    logs = Log.objects.select_related('client').all().order_by('-timestamp')

    # Apply filters
    if level:
        logs = logs.filter(level=level)
    if client_id:
        logs = logs.filter(client_id=client_id)
    if date_str:
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
            logs = logs.filter(timestamp__date=date)
        except ValueError:
            pass

    # Pagination
    paginator = Paginator(logs, 50)  # Show 50 logs per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'logs': page_obj,
        'log_levels': Log.LOG_LEVELS,
        'clients': Client.objects.all(),
        'selected_level': level,
        'selected_client': client_id,
        'selected_date': datetime.strptime(date_str, '%Y-%m-%d') if date_str else None,
    }
    return render(request, 'edr_app/logs.html', context)

@staff_member_required
def download_logs(request):
    # Get filter parameters
    level = request.GET.get('level', '')
    client_id = request.GET.get('client', '')
    date_str = request.GET.get('date', '')

    # Start with all logs
    logs = Log.objects.select_related('client').all().order_by('-timestamp')

    # Apply filters
    if level:
        logs = logs.filter(level=level)
    if client_id:
        logs = logs.filter(client_id=client_id)
    if date_str:
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
            logs = logs.filter(timestamp__date=date)
        except ValueError:
            pass

    # Create the HttpResponse object with CSV header
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="logs.csv"'

    # Create CSV writer
    writer = csv.writer(response)
    writer.writerow(['Timestamp', 'Client', 'Level', 'Source', 'Message'])

    # Write data
    for log in logs:
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.client.hostname,
            log.level,
            log.source,
            log.message
        ])

    return response

@api_view(['POST'])
@csrf_exempt
@permission_classes([AllowAny])
def upload_logs(request):
    try:
        # Parse JSON data
        try:
            data = json.loads(request.body) if isinstance(request.body, bytes) else request.data
        except json.JSONDecodeError:
            return Response(
                {'error': 'Invalid JSON data'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get hostname from data
        hostname = data.get('hostname')
        if not hostname:
            return Response(
                {'error': 'Hostname is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get or create client
        client, created = Client.objects.get_or_create(
            hostname=hostname,
            defaults={'ip_address': request.META.get('REMOTE_ADDR', '0.0.0.0')}
        )

        # Update client's last_seen timestamp
        client.last_seen = timezone.now()
        client.save()

        # Process logs
        logs_data = data.get('logs', [])
        if not logs_data:
            return Response(
                {'error': 'No logs provided'},
                status=status.HTTP_400_BAD_REQUEST
            )

        for log_data in logs_data:
            if not all(key in log_data for key in ['level', 'message', 'source']):
                continue

            Log.objects.create(
                client=client,
                level=log_data['level'],
                message=log_data['message'],
                source=log_data['source'],
                timestamp=timezone.now()
            )

        return Response({'status': 'success'})
    except Exception as e:
        print(f"Error in upload_logs: {str(e)}")  # Add logging for debugging
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])  # Allow any client to upload data
def upload_data(request):
    try:
        # Parse JSON data
        try:
            data = json.loads(request.body) if isinstance(request.body, bytes) else request.data
        except json.JSONDecodeError:
            return Response(
                {'error': 'Invalid JSON data'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get hostname from data
        hostname = data.get('hostname')
        if not hostname:
            return Response(
                {'error': 'Hostname is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate required data
        if not any(key in data for key in ['processes', 'ports', 'alerts']):
            return Response(
                {'error': 'At least one of processes, ports, or alerts is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get or create client
        client, created = Client.objects.get_or_create(
            hostname=hostname,
            defaults={'ip_address': request.META.get('REMOTE_ADDR', '0.0.0.0')}
        )

        # Update client's last_seen timestamp
        client.last_seen = timezone.now()
        client.save()

        with transaction.atomic():
            # Handle terminated processes
            if 'terminatedPids' in data:
                terminated = data['terminatedPids']
                if terminated:
                    Process.objects.filter(client=client, pid__in=terminated).delete()

            # Process the reported processes (delta: only new ones)
            if 'processes' in data:
                for proc_data in data['processes']:
                    if not all(key in proc_data for key in ['pid', 'name']):
                        continue
                    Process.objects.create(
                        client=client,
                        pid=proc_data['pid'],
                        name=proc_data['name'],
                        path=proc_data.get('path', ''),
                        command_line=proc_data.get('commandLine', ''),
                        parent_pid=proc_data.get('parent_pid'),
                        parent_name=proc_data.get('parentName', ''),
                        sha256_hash=proc_data.get('sha256', ''),
                        is_lolbin=proc_data.get('isLolbin', False),
                        is_suspicious_chain=proc_data.get('isSuspiciousChain', False),
                    )

            # Process network connections (new format) or ports (legacy)
            network_data = data.get('network', data.get('ports', []))
            if network_data:
                Port.objects.filter(client=client).delete()
                for conn in network_data:
                    local_port = conn.get('localPort', conn.get('port', 0))
                    if not conn.get('protocol'):
                        continue
                    Port.objects.create(
                        client=client,
                        port_number=local_port,
                        protocol=conn['protocol'],
                        state=conn.get('state', ''),
                        process_name=conn.get('processName', ''),
                        process_id=conn.get('pid', 0),
                        local_ip=conn.get('localIp'),
                        local_port=local_port,
                        remote_ip=conn.get('remoteIp'),
                        remote_port=conn.get('remotePort'),
                    )

            # Analyze vulnerabilities and match IoCs within the same transaction
            analyze_vulnerabilities(client)
            match_iocs(client)

        return Response({'status': 'success'})
    except Exception as e:
        print(f"Error in upload_data: {str(e)}")  # Add logging for debugging
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def upload_windows_logs(request):
    """Endpoint for clients to upload Windows logs"""
    print(f"Received request at: {request.path}")
    print(f"Request method: {request.method}")
    print(f"Raw request data: {request.data}")
    
    try:
        # Get client IP address
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip_address = x_forwarded_for.split(',')[0]
        else:
            ip_address = request.META.get('REMOTE_ADDR')
            
        print(f"Client IP: {ip_address}")

        # Parse request data
        data = request.data
        if isinstance(data, str):
            data = json.loads(data)
            
        # Extract hostname and log data
        if isinstance(data, dict):
            hostname = data.get('hostname')
            log_data = data.get('data')
        else:
            return Response({'error': 'Invalid request format'}, status=status.HTTP_400_BAD_REQUEST)
            
        print(f"Parsed hostname: {hostname}")
        print(f"Log data: {log_data}")
            
        if not hostname:
            return Response({'error': 'Hostname is required'}, status=status.HTTP_400_BAD_REQUEST)
            
        if not log_data:
            return Response({'error': 'Log data is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Get or create client
        client, created = Client.objects.get_or_create(
            hostname=hostname,
            defaults={'ip_address': ip_address}
        )
        
        # Update client info
        client.ip_address = ip_address
        client.last_seen = timezone.now()
        client.save()
        
        print(f"Client {'created' if created else 'updated'}: {client}")
        
        # Process log data
        try:
            if isinstance(log_data, list):
                for log in log_data:
                    WindowsEventLog.objects.create(
                        client=client,
                        level=log.get('level', 'INFO'),
                        message=log.get('message', ''),
                        source=log.get('source', ''),
                        event_id=log.get('event_id', ''),
                        provider=log.get('provider', ''),
                        timestamp=log.get('timestamp', timezone.now())
                    )
            elif isinstance(log_data, dict):
                WindowsEventLog.objects.create(
                    client=client,
                    level=log_data.get('level', 'INFO'),
                    message=log_data.get('message', ''),
                    source=log_data.get('source', ''),
                    event_id=log_data.get('event_id', ''),
                    provider=log_data.get('provider', ''),
                    timestamp=log_data.get('timestamp', timezone.now())
                )
        except Exception as e:
            print(f"Error processing log data: {str(e)}")
            print(f"Log data was: {log_data}")
            return Response({'error': f'Error processing log data: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({'status': 'success'})
            
    except Exception as e:
        import traceback
        print(f"Error in upload_windows_logs: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
class ClientViewSet(viewsets.ModelViewSet):
    queryset = Client.objects.all()
    serializer_class = ClientSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=['post'])
    def report(self, request, pk=None):
        try:
            client = self.get_object()
            data = request.data

            # Update client's last_seen timestamp
            client.last_seen = timezone.now()
            client.save()

            # Process the reported processes
            if 'processes' in data:
                # First validate all process data
                valid_processes = []
                for proc_data in data['processes']:
                    if all(key in proc_data for key in ['pid', 'name']):
                        valid_processes.append(proc_data)
                
                # Only delete old processes if we have valid new data
                if valid_processes:
                    Process.objects.filter(client=client).delete()  # Clear old processes
                    for proc_data in valid_processes:
                        Process.objects.create(
                            client=client,
                            pid=proc_data['pid'],
                            name=proc_data['name'],
                            path=proc_data.get('path', ''),
                            command_line=proc_data.get('commandLine', '')
                        )
                        # Check for vulnerabilities
                        self.check_process_vulnerabilities(proc_data['name'])

            # Process the reported ports
            if 'ports' in data:
                for port_data in data['ports']:
                    Port.objects.create(
                        client=client,
                        port_number=port_data['port'],
                        protocol=port_data['protocol'],
                        state=port_data['state'],
                        process_name=port_data['processName'],
                        process_id=port_data['pid']
                    )

            # Analyze vulnerabilities
            analyze_vulnerabilities(client)

            return Response({'status': 'success'})
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def check_process_vulnerabilities(self, process_name):
        try:
            # Query NVD API
            headers = {
                'apiKey': settings.NVD_API_KEY
            }
            params = {
                'keywordSearch': process_name
            }
            response = requests.get(
                settings.NVD_API_URL,
                headers=headers,
                params=params
            )
            
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulnerabilities', []):
                    cve = vuln.get('cve', {})
                    
                    # Create or update vulnerability
                    vulnerability, created = Vulnerability.objects.get_or_create(
                        cve_id=cve.get('id'),
                        defaults={
                            'description': cve.get('descriptions', [{}])[0].get('value', ''),
                            'severity': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseSeverity', 'UNKNOWN'),
                            'published_date': timezone.now(),
                            'last_modified_date': timezone.now()
                        }
                    )

        except Exception as e:
            print(f"Error checking vulnerabilities: {str(e)}")


    @action(detail=True, methods=['post'])
    def logs(self, request, pk=None):
        """
        Endpoint for receiving logs from a client
        """
        client = self.get_object()
        data = request.data
        
        # Create log entry
        log = Log.objects.create(
            client=client,
            level=data.get('level', 'INFO'),
            message=data.get('message', ''),
            source=data.get('source', '')
        )
        
        return Response(LogSerializer(log).data, status=status.HTTP_201_CREATED)

@login_required
def ioc_manager(request):
    from django.db.models import Count, Max

    ip_stats = ThreatIntelIP.objects.filter(
        is_active=True
    ).values('source').annotate(
        count=Count('id'),
        last_updated=Max('added_date')
    ).order_by('-count')

    hash_stats = ThreatIntelHash.objects.filter(
        is_active=True
    ).values('source').annotate(
        count=Count('id'),
        last_updated=Max('added_date')
    ).order_by('-count')

    ip_total = ThreatIntelIP.objects.filter(is_active=True).count()
    hash_total = ThreatIntelHash.objects.filter(is_active=True).count()

    recent_detections = SuspiciousActivity.objects.filter(
        ioc_matched__isnull=False
    ).exclude(
        ioc_matched=''
    ).select_related('client').order_by('-last_seen')[:20]

    exclusion_rules = ExclusionRule.objects.filter(
        is_active=True
    ).select_related('added_by').order_by('-created_at')

    exclusion_count = exclusion_rules.count()

    last_sync = ThreatIntelIP.objects.order_by('-added_date').values_list(
        'added_date', flat=True
    ).first()
    last_sync_hash = ThreatIntelHash.objects.order_by('-added_date').values_list(
        'added_date', flat=True
    ).first()
    if last_sync_hash and (not last_sync or last_sync_hash > last_sync):
        last_sync = last_sync_hash

    has_name_only = exclusion_rules.filter(match_mode='NAME_ONLY').exists()

    context = {
        'ip_stats': ip_stats,
        'hash_stats': hash_stats,
        'ip_total': ip_total,
        'hash_total': hash_total,
        'total_ti': ip_total + hash_total,
        'recent_detections': recent_detections,
        'exclusion_rules': exclusion_rules,
        'exclusion_count': exclusion_count,
        'last_sync': last_sync,
        'has_name_only': has_name_only,
    }
    return render(request, 'edr_app/ioc_manager.html', context)


@login_required
@require_POST
def sync_ti_feeds_view(request):
    from django.core.management import call_command
    from io import StringIO
    import re
    try:
        out = StringIO()
        call_command('sync_ti_feeds', stdout=out)
        output = out.getvalue()

        ip_match = re.search(r'IPs: \+(\d+) total', output)
        hash_match = re.search(r'Hashes: \+(\d+) total', output)
        added_ips = int(ip_match.group(1)) if ip_match else 0
        added_hashes = int(hash_match.group(1)) if hash_match else 0

        new_total = (ThreatIntelIP.objects.filter(is_active=True).count() +
                     ThreatIntelHash.objects.filter(is_active=True).count())

        return JsonResponse({
            'status': 'ok',
            'added_ips': added_ips,
            'added_hashes': added_hashes,
            'total': new_total,
            'output': output,
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)


@login_required
@require_POST
def ioc_add(request):
    import re

    ioc_type = request.POST.get('type', 'ip')
    raw_values = request.POST.get('values', '')
    source = request.POST.get('source', 'manual').strip()
    threat_type = request.POST.get('threat_type', '').strip()

    lines = [l.strip() for l in raw_values.splitlines() if l.strip()]

    added = skipped = invalid = 0

    if ioc_type == 'ip':
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        valid = [l for l in lines if ip_pattern.match(l)]
        invalid = len(lines) - len(valid)

        objs = [ThreatIntelIP(
            ip_address=ip,
            source=source or 'manual',
            threat_type=threat_type or 'custom',
        ) for ip in valid]
        result = ThreatIntelIP.objects.bulk_create(objs, ignore_conflicts=True)
        added = len(result)
        skipped = len(valid) - added
    else:
        hash_pattern = re.compile(r'^[a-fA-F0-9]{64}$')
        valid = [l.lower() for l in lines if hash_pattern.match(l)]
        invalid = len(lines) - len(valid)

        objs = [ThreatIntelHash(
            sha256_hash=h,
            source=source or 'manual',
            malware_name=threat_type or 'custom',
        ) for h in valid]
        result = ThreatIntelHash.objects.bulk_create(objs, ignore_conflicts=True)
        added = len(result)
        skipped = len(valid) - added

    return JsonResponse({
        'status': 'ok',
        'added': added,
        'skipped': skipped,
        'invalid': invalid,
    })


@login_required
@require_POST
def exclusion_delete(request, rule_id):
    rule = get_object_or_404(ExclusionRule, id=rule_id)
    rule.delete()
    return JsonResponse({'status': 'ok'})


@login_required
def help_center(request):
    return render(request, 'edr_app/help_center.html')


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def alert_action(request, alert_id):
    alert = get_object_or_404(SuspiciousActivity, id=alert_id)
    action = request.data.get('action', '')
    reason = request.data.get('reason', '')

    if action == 'in_response':
        if alert.status == 'open':
            alert.status = 'in_response'
    elif action == 'false_positive':
        ok, msg = alert.can_mark_false_positive()
        if not ok:
            return Response({'error': msg}, status=400)
        if not reason.strip():
            return Response({'error': 'Reason required'}, status=400)
        alert.status = 'false_positive'
        alert.false_positive_reason = reason
        alert.closed_at = timezone.now()
    elif action == 'close':
        alert.status = 'closed'
        alert.closed_at = timezone.now()
    elif action == 'reopen':
        if alert.status not in ('false_positive', 'closed'):
            return Response({'error': 'Can only reopen FP or closed'}, status=400)
        alert.status = 'open'
        alert.closed_at = None
    elif action == 'in_incident':
        alert.status = 'in_incident'
    else:
        return Response({'error': f'Unknown action: {action}'}, status=400)

    alert.save()
    return Response({
        'alert_id': alert_id,
        'status': alert.status,
        'closed_at': alert.closed_at.isoformat() if alert.closed_at else None,
        'suggest_exclusion': action == 'false_positive' and bool(alert.process_name),
        'process_name': alert.process_name or '',
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def alert_counts(request):
    from django.db.models import Count
    counts_qs = SuspiciousActivity.objects.values('status').annotate(n=Count('id'))
    result = {r['status']: r['n'] for r in counts_qs}
    result['all'] = sum(result.values())
    return Response(result)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def alert_bulk_action(request):
    ids = request.data.get('alert_ids', [])
    action = request.data.get('action', '')
    reason = request.data.get('reason', '')
    if not ids:
        return Response({'error': 'No alert_ids'}, status=400)
    alerts_qs = SuspiciousActivity.objects.filter(id__in=ids)
    updated = 0
    errors = []
    for alert in alerts_qs:
        if action == 'in_response' and alert.status == 'open':
            alert.status = 'in_response'
            alert.save()
            updated += 1
        elif action == 'false_positive':
            ok, msg = alert.can_mark_false_positive()
            if ok and reason.strip():
                alert.status = 'false_positive'
                alert.false_positive_reason = reason
                alert.closed_at = timezone.now()
                alert.save()
                updated += 1
            else:
                errors.append(f"Alert {alert.id}: {msg or 'reason required'}")
        elif action == 'close':
            alert.status = 'closed'
            alert.closed_at = timezone.now()
            alert.save()
            updated += 1
    return Response({'updated': updated, 'errors': errors})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def exclusion_create(request):
    name = request.data.get('process_name', '').strip()
    mode = request.data.get('match_mode', '')
    path = request.data.get('process_path', '').strip()
    hash_ = request.data.get('sha256_hash', '').strip()
    reason = request.data.get('reason', '').strip()

    if not name or not reason:
        return Response({'error': 'Process name and reason required'}, status=400)
    if mode == 'NAME_AND_PATH' and not path:
        return Response({'error': 'Path required for Name+Path mode'}, status=400)
    if mode in ('HASH_ONLY', 'ALL') and not hash_:
        return Response({'error': 'Hash required for this mode'}, status=400)

    rule = ExclusionRule.objects.create(
        process_name=name, process_path=path, sha256_hash=hash_,
        match_mode=mode, reason=reason, added_by=request.user, is_active=True,
    )
    from .utils import _ti_cache
    _ti_cache['loaded_at'] = None

    return Response({
        'id': rule.id, 'process_name': rule.process_name, 'match_mode': rule.match_mode,
    }, status=201)


# ── Incident views ──

def _log_activity(incident, user, action, detail=''):
    IncidentActivity.objects.create(
        incident=incident, user=user, action=action, detail=detail)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def incident_create(request):
    title = request.data.get('title', '').strip()
    desc = request.data.get('description', '')
    alert_ids = request.data.get('alert_ids', [])
    if not title:
        return Response({'error': 'Title required'}, status=400)

    inc = Incident(title=title, description=desc, created_by=request.user)
    inc.save()

    if alert_ids:
        alerts_qs = SuspiciousActivity.objects.filter(id__in=alert_ids)
        inc.alerts.set(alerts_qs)
        alerts_qs.update(status='in_incident')
        _log_activity(inc, request.user, 'Created',
                       f'Created with {len(alert_ids)} alert(s)')
    else:
        _log_activity(inc, request.user, 'Created', 'Created with no alerts')

    return Response({
        'id': inc.id, 'reference': inc.reference, 'title': inc.title,
    }, status=201)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def incident_add_alert(request, incident_id):
    inc = get_object_or_404(Incident, id=incident_id)
    alert_id = request.data.get('alert_id')
    if not alert_id:
        return Response({'error': 'alert_id required'}, status=400)
    alert = get_object_or_404(SuspiciousActivity, id=alert_id)
    inc.alerts.add(alert)
    alert.status = 'in_incident'
    alert.save(update_fields=['status'])
    _log_activity(inc, request.user, 'Alert added',
                   f'Alert #{alert_id} added')
    return Response({'status': 'ok'})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def incident_status(request, incident_id):
    inc = get_object_or_404(Incident, id=incident_id)
    new_status = request.data.get('status', '')
    valid = [c[0] for c in Incident.STATUS_CHOICES]
    if new_status not in valid:
        return Response({'error': f'Invalid status: {new_status}'}, status=400)
    old = inc.status
    inc.status = new_status
    if new_status in ('resolved', 'closed') and not inc.resolved_at:
        inc.resolved_at = timezone.now()
    elif new_status in ('open', 'in_progress'):
        inc.resolved_at = None
    inc.save()
    _log_activity(inc, request.user, 'Status changed',
                   f'{old} → {new_status}')
    return Response({'status': inc.status, 'resolved_at': inc.resolved_at.isoformat() if inc.resolved_at else None})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def incident_comment(request, incident_id):
    inc = get_object_or_404(Incident, id=incident_id)
    body = request.data.get('body', '').strip()
    if not body:
        return Response({'error': 'Comment body required'}, status=400)
    comment = IncidentComment.objects.create(incident=inc, author=request.user, body=body)
    _log_activity(inc, request.user, 'Comment added', body[:100])
    return Response({'id': comment.id, 'body': comment.body, 'author': request.user.username,
                     'created_at': comment.created_at.isoformat()}, status=201)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def incident_list_api(request):
    status_filter = request.GET.get('status', '')
    qs = Incident.objects.select_related('created_by', 'assigned_to').order_by('-created_at')
    if status_filter and status_filter != 'all':
        qs = qs.filter(status=status_filter)
    data = []
    for inc in qs[:100]:
        data.append({
            'id': inc.id, 'reference': inc.reference, 'title': inc.title,
            'status': inc.status, 'severity': inc.severity,
            'alert_count': inc.alerts.count(), 'time_open': inc.time_open,
            'created_at': inc.created_at.isoformat(),
            'created_by': inc.created_by.username if inc.created_by else '',
        })
    return Response(data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def incident_detail_api(request, incident_id):
    inc = get_object_or_404(Incident.objects.select_related('created_by', 'assigned_to'), id=incident_id)
    alerts_data = []
    for a in inc.alerts.select_related('client').order_by('-last_seen'):
        alerts_data.append({
            'id': a.id, 'type': a.type, 'severity': a.severity,
            'status': a.status, 'hostname': a.client.hostname if a.client else '',
            'description': a.description[:120], 'last_seen': a.last_seen.isoformat() if a.last_seen else None,
        })
    activities_data = []
    for act in inc.activities.all()[:50]:
        activities_data.append({
            'action': act.action, 'detail': act.detail,
            'user': act.user.username if act.user else '', 'timestamp': act.timestamp.isoformat(),
        })
    comments_data = []
    for c in inc.comments.all():
        comments_data.append({
            'id': c.id, 'body': c.body, 'author': c.author.username if c.author else '',
            'created_at': c.created_at.isoformat(),
        })
    return Response({
        'id': inc.id, 'reference': inc.reference, 'title': inc.title,
        'description': inc.description, 'status': inc.status, 'severity': inc.severity,
        'created_by': inc.created_by.username if inc.created_by else '',
        'assigned_to': inc.assigned_to.username if inc.assigned_to else '',
        'created_at': inc.created_at.isoformat(),
        'updated_at': inc.updated_at.isoformat(),
        'resolved_at': inc.resolved_at.isoformat() if inc.resolved_at else None,
        'time_open': inc.time_open, 'alerts': alerts_data,
        'activities': activities_data, 'comments': comments_data,
    })


@login_required
def incidents_page(request):
    return render(request, 'edr_app/incidents.html')


@login_required
def incident_detail_page(request, incident_id):
    inc = get_object_or_404(Incident, id=incident_id)
    return render(request, 'edr_app/incident_detail.html', {'incident': inc})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def alert_signatures(request, alert_id):
    """Return signatures for an alert grouped by tactic."""
    alert = get_object_or_404(SuspiciousActivity, id=alert_id)
    signatures = alert.signatures.all().prefetch_related('events')

    tactic_order = [
        'execution', 'defense_evasion', 'command_control',
        'impact', 'persistence', 'discovery', 'lateral_movement',
    ]
    grouped = {}
    for sig in signatures:
        tactic = sig.mitre_tactic or 'other'
        if tactic not in grouped:
            grouped[tactic] = []
        grouped[tactic].append({
            'id': sig.id,
            'sig_id': sig.sig_id,
            'plain_title': sig.plain_title,
            'plain_explanation': sig.plain_explanation,
            'plain_action': sig.plain_action,
            'mitre_id': sig.mitre_id,
            'mitre_tactic': sig.mitre_tactic,
            'mitre_url': sig.mitre_url,
            'severity': sig.severity,
            'event_count': sig.events.count(),
        })

    result = []
    for tactic in tactic_order:
        if tactic in grouped:
            result.append({
                'tactic': tactic,
                'tactic_display': tactic.replace('_', ' ').title(),
                'signatures': grouped[tactic],
            })
    for tactic, sigs in grouped.items():
        if tactic not in tactic_order:
            result.append({
                'tactic': tactic,
                'tactic_display': tactic.replace('_', ' ').title(),
                'signatures': sigs,
            })

    return Response({
        'alert_id': alert_id,
        'tactic_count': len(result),
        'sig_count': signatures.count(),
        'tactics': result,
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def signature_events(request, sig_id):
    """Return events for a specific signature."""
    sig = get_object_or_404(Signature, id=sig_id)
    events = sig.events.all().order_by('timestamp')

    data = []
    for evt in events:
        raw = {}
        try:
            raw = json.loads(evt.raw_data) if isinstance(evt.raw_data, str) else (evt.raw_data or {})
        except (json.JSONDecodeError, TypeError):
            pass
        data.append({
            'id': evt.id,
            'event_type': evt.event_type,
            'event_type_display': evt.display_name,
            'timestamp': evt.timestamp.isoformat() if evt.timestamp else None,
            'raw_data': raw,
            'summary': _event_summary(evt, raw),
        })

    return Response({
        'sig_id': sig.id,
        'plain_title': sig.plain_title,
        'mitre_id': sig.mitre_id,
        'events': data,
    })


def _event_summary(event, raw):
    """One-line plain English summary of an event."""
    if event.event_type == 'PROCESS_START':
        return f"Process created: {raw.get('name', 'unknown')} (PID {raw.get('pid', '?')})"
    elif event.event_type == 'NETWORK_CONNECT':
        return f"Network connection: {raw.get('remote_ip', '?')}:{raw.get('remote_port', '?')}"
    elif event.event_type == 'HASH_MATCH':
        return f"Malware hash matched: {raw.get('name', raw.get('process_name', 'unknown'))}"
    elif event.event_type == 'IP_MATCH':
        return f"Blacklisted IP: {raw.get('remote_ip', '?')}"
    elif event.event_type == 'LOLBIN_CHAIN':
        return f"LOLBin chain: {raw.get('chain', 'unknown chain')}"
    elif event.event_type == 'RANSOMWARE_PRECURSOR':
        return f"Ransomware tool: {raw.get('name', raw.get('process_name', 'unknown'))}"
    return event.display_name


@login_required
def endpoint_events(request):
    """Endpoint events feed page."""
    clients = Client.objects.all().order_by('hostname')
    return render(request, 'edr_app/endpoint_events.html', {'clients': clients})


@login_required
def endpoint_events_api(request):
    """Returns paginated Event records for the events feed."""
    import csv as csv_mod
    from .query_parser import apply_query

    query_str = request.GET.get('query', '').strip()
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    fmt = request.GET.get('format', 'json')
    tab = request.GET.get('tab', 'all')
    event_type = request.GET.get('event_type', '')
    client_id = request.GET.get('client_id', '')
    page = int(request.GET.get('page', 1))
    per_page = 50

    qs = Event.objects.select_related('client', 'process', 'port')

    # Date range: explicit dates win over hours
    if date_from or date_to:
        if date_from:
            qs = qs.filter(timestamp__gte=date_from + 'T00:00:00Z')
        if date_to:
            qs = qs.filter(timestamp__lte=date_to + 'T23:59:59Z')
    else:
        hours = int(request.GET.get('hours', 24))
        cutoff = timezone.now() - timedelta(hours=hours)
        qs = qs.filter(timestamp__gte=cutoff)

    if query_str:
        qs, _ = apply_query(qs, query_str, mode='events')

    if tab == 'alerts':
        qs = qs.filter(alerts__severity__in=['HIGH', 'CRITICAL']).distinct()
    elif tab == 'suspicious':
        qs = qs.filter(event_type__in=[
            'HASH_MATCH', 'IP_MATCH', 'LOLBIN_CHAIN', 'RANSOMWARE_PRECURSOR',
        ])

    if event_type:
        qs = qs.filter(event_type=event_type)
    if client_id:
        qs = qs.filter(client_id=client_id)

    qs = qs.order_by('-timestamp')
    total = qs.count()

    # CSV export
    if fmt == 'csv':
        import io
        buffer = io.StringIO()
        filename = f"events_{timezone.now().strftime('%Y%m%d_%H%M%S')}.csv"
        writer = csv_mod.writer(buffer)
        writer.writerow(['Timestamp', 'Event Type', 'Hostname', 'Summary', 'Detail', 'Linked Alert'])
        row_count = 0
        for evt in qs[:5000]:
            raw = {}
            try:
                raw = json.loads(evt.raw_data) if isinstance(evt.raw_data, str) else (evt.raw_data or {})
            except (json.JSONDecodeError, TypeError):
                pass
            linked = evt.alerts.filter(severity__in=['HIGH', 'CRITICAL']).first()
            writer.writerow([
                evt.timestamp.strftime('%Y-%m-%d %H:%M:%S') if evt.timestamp else '',
                evt.event_type,
                evt.client.hostname if evt.client else '',
                _event_summary(evt, raw),
                raw.get('path', raw.get('chain', '')),
                linked.id if linked else '',
            ])
            row_count += 1
        csv_bytes = buffer.getvalue().encode('utf-8')
        filters = {}
        if date_from:
            filters['date_from'] = date_from
        if date_to:
            filters['date_to'] = date_to
        if query_str:
            filters['query'] = query_str
        _save_report_record('events', filename, filters, row_count,
                            request=request, content=csv_bytes)
        response = HttpResponse(csv_bytes, content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

    # JSON pagination
    start = (page - 1) * per_page
    events = qs[start:start + per_page]

    data = []
    for evt in events:
        raw = {}
        try:
            raw = json.loads(evt.raw_data) if isinstance(evt.raw_data, str) else (evt.raw_data or {})
        except (json.JSONDecodeError, TypeError):
            pass

        badges = []
        if evt.event_type == 'HASH_MATCH':
            badges = ['MALWARE']
        elif evt.event_type == 'IP_MATCH':
            badges = ['C2']
        elif evt.event_type == 'LOLBIN_CHAIN':
            badges = ['LOLBIN', 'CHAIN']
        elif evt.event_type == 'RANSOMWARE_PRECURSOR':
            badges = ['RANSOMWARE']
        elif evt.event_type == 'PROCESS_START':
            if raw.get('is_lolbin'):
                badges.append('LOLBIN')

        linked_alert = evt.alerts.filter(severity__in=['HIGH', 'CRITICAL']).first()

        data.append({
            'id': evt.id,
            'event_type': evt.event_type,
            'event_type_display': evt.display_name,
            'timestamp': evt.timestamp.isoformat() if evt.timestamp else None,
            'hostname': evt.client.hostname if evt.client else '',
            'title': _event_summary(evt, raw),
            'detail': raw.get('path', raw.get('chain', '')),
            'badges': badges,
            'raw_data': raw,
            'linked_alert_id': linked_alert.id if linked_alert else None,
        })

    # Tab counts (use same base date filter)
    if date_from or date_to:
        all_qs = Event.objects.all()
        if date_from:
            all_qs = all_qs.filter(timestamp__gte=date_from + 'T00:00:00Z')
        if date_to:
            all_qs = all_qs.filter(timestamp__lte=date_to + 'T23:59:59Z')
    else:
        hours_val = int(request.GET.get('hours', 24))
        all_qs = Event.objects.filter(timestamp__gte=timezone.now() - timedelta(hours=hours_val))

    counts = {
        'all': all_qs.count(),
        'alerts': all_qs.filter(alerts__severity__in=['HIGH', 'CRITICAL']).distinct().count(),
        'suspicious': all_qs.filter(event_type__in=[
            'HASH_MATCH', 'IP_MATCH', 'LOLBIN_CHAIN', 'RANSOMWARE_PRECURSOR',
        ]).count(),
    }

    # Event type distribution
    from django.db.models import Count as DjCount
    dist_qs = all_qs.values('event_type').annotate(cnt=DjCount('id')).order_by('-cnt')
    distribution = [{'type': r['event_type'], 'count': r['cnt']} for r in dist_qs]

    # Volume chart (24h by hour)
    chart = []
    now = timezone.now()
    for i in range(23, -1, -1):
        hour_start = now - timedelta(hours=i + 1)
        hour_end = now - timedelta(hours=i)
        count = Event.objects.filter(
            timestamp__gte=hour_start, timestamp__lt=hour_end,
        ).count()
        chart.append({'hour': hour_end.strftime('%H:%M'), 'count': count})

    return JsonResponse({
        'events': data,
        'total': total,
        'page': page,
        'per_page': per_page,
        'has_more': (start + per_page) < total,
        'tab_counts': counts,
        'chart': chart,
        'distribution': distribution,
    })


# ─── Reports ────────────────────────────────────────────────

@login_required
def reports_page(request):
    """Reports archive page."""
    report_type = request.GET.get('type', '')
    reports = Report.objects.all()
    if report_type:
        reports = reports.filter(report_type=report_type)
    return render(request, 'edr_app/reports.html', {
        'reports': reports,
        'report_types': Report.REPORT_TYPES,
        'selected_type': report_type,
    })


@login_required
def report_download(request, report_id):
    """Download a saved report file."""
    report = get_object_or_404(Report, id=report_id)
    if not report.file_path or not os.path.exists(report.file_path):
        return HttpResponse('Report file not found.', status=404)
    with open(report.file_path, 'rb') as f:
        content = f.read()
    response = HttpResponse(content, content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{report.filename}"'
    return response


@login_required
@require_POST
def report_delete(request, report_id):
    """Delete a report record and its file."""
    report = get_object_or_404(Report, id=report_id)
    if report.file_path and os.path.exists(report.file_path):
        os.remove(report.file_path)
    report.delete()
    return JsonResponse({'status': 'ok'})


@login_required
def compliance_report(request):
    """Generate PP-167 compliance report CSV."""
    import csv as csv_mod
    import io
    from django.db.models import Avg, F

    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')

    now = timezone.now()
    if date_from:
        period_start = datetime.strptime(date_from, '%Y-%m-%d').replace(
            hour=0, minute=0, second=0)
        period_start = timezone.make_aware(period_start)
    else:
        period_start = now - timedelta(days=30)
    if date_to:
        period_end = datetime.strptime(date_to, '%Y-%m-%d').replace(
            hour=23, minute=59, second=59)
        period_end = timezone.make_aware(period_end)
    else:
        period_end = now

    # Gather stats
    total_endpoints = Client.objects.filter(is_active=True).count()
    total_events = Event.objects.filter(
        timestamp__gte=period_start, timestamp__lte=period_end).count()

    alerts_in_period = SuspiciousActivity.objects.filter(
        timestamp__gte=period_start, timestamp__lte=period_end)
    critical_count = alerts_in_period.filter(severity='CRITICAL').count()
    high_count = alerts_in_period.filter(severity='HIGH').count()
    medium_count = alerts_in_period.filter(severity='MEDIUM').count()
    low_count = alerts_in_period.filter(severity='LOW').count()
    fp_count = alerts_in_period.filter(status='false_positive').count()

    incidents_in_period = Incident.objects.filter(
        created_at__gte=period_start, created_at__lte=period_end)
    incidents_created = incidents_in_period.count()
    incidents_resolved = incidents_in_period.filter(
        status__in=['resolved', 'closed']).count()

    # Mean time to acknowledge (alerts that moved beyond 'open')
    acked = alerts_in_period.exclude(status='open').filter(
        closed_at__isnull=False)
    if acked.exists():
        from django.db.models import ExpressionWrapper, DurationField
        mtta_seconds = acked.annotate(
            ack_time=ExpressionWrapper(
                F('closed_at') - F('timestamp'),
                output_field=DurationField())
        ).aggregate(avg=Avg('ack_time'))['avg']
        mtta_hours = round(mtta_seconds.total_seconds() / 3600, 1) if mtta_seconds else 'N/A'
    else:
        mtta_hours = 'N/A'

    # Mean time to resolve (incidents)
    resolved = incidents_in_period.filter(resolved_at__isnull=False)
    if resolved.exists():
        from django.db.models import ExpressionWrapper, DurationField
        mttr_seconds = resolved.annotate(
            res_time=ExpressionWrapper(
                F('resolved_at') - F('created_at'),
                output_field=DurationField())
        ).aggregate(avg=Avg('res_time'))['avg']
        mttr_hours = round(mttr_seconds.total_seconds() / 3600, 1) if mttr_seconds else 'N/A'
    else:
        mttr_hours = 'N/A'

    ti_ips = ThreatIntelIP.objects.filter(is_active=True).count()
    ti_hashes = ThreatIntelHash.objects.filter(is_active=True).count()

    # Check continuous monitoring (any gaps > 6h without events?)
    continuous = 'Yes' if total_events > 0 else 'No'

    # Build CSV
    buffer = io.StringIO()
    writer = csv_mod.writer(buffer)

    # Section 1: Summary
    writer.writerow(['PP-167 Compliance Report — SentinelUZ EDR'])
    writer.writerow([])
    writer.writerow(['Metric', 'Value'])
    writer.writerow(['Report Period Start', period_start.strftime('%Y-%m-%d')])
    writer.writerow(['Report Period End', period_end.strftime('%Y-%m-%d')])
    writer.writerow(['Total Endpoints Monitored', total_endpoints])
    writer.writerow(['Total Events Recorded', total_events])
    writer.writerow(['CRITICAL Alerts Detected', critical_count])
    writer.writerow(['HIGH Alerts Detected', high_count])
    writer.writerow(['MEDIUM Alerts Detected', medium_count])
    writer.writerow(['LOW Alerts Detected', low_count])
    writer.writerow(['False Positives Identified', fp_count])
    writer.writerow(['Incidents Created', incidents_created])
    writer.writerow(['Incidents Resolved', incidents_resolved])
    writer.writerow(['Mean Time to Acknowledge (hours)', mtta_hours])
    writer.writerow(['Mean Time to Resolve (hours)', mttr_hours])
    writer.writerow(['Threat Intelligence Coverage (IPs)', ti_ips])
    writer.writerow(['Threat Intelligence Coverage (Hashes)', ti_hashes])
    writer.writerow(['PP-167 Monitoring Continuous', continuous])
    writer.writerow([])

    # Section 2: Alert Detail
    writer.writerow(['--- Alert Detail ---'])
    writer.writerow([
        'Alert ID', 'Timestamp', 'Severity', 'Type', 'Status',
        'Process Name', 'Description', 'IoC Matched', 'Hostname',
    ])
    detail_count = 0
    for a in alerts_in_period.select_related('client').order_by('-timestamp'):
        writer.writerow([
            a.id,
            a.timestamp.strftime('%Y-%m-%d %H:%M:%S') if a.timestamp else '',
            a.severity,
            a.type,
            a.status,
            a.process_name or '',
            a.description[:200],
            a.ioc_matched or '',
            a.client.hostname if a.client else '',
        ])
        detail_count += 1

    writer.writerow([])
    writer.writerow([
        'Report generated by SentinelUZ EDR. '
        'Continuous monitoring in compliance with PP-167 '
        '(Presidential Resolution, 31 May 2023) and '
        'PQ-153 (Cabinet Resolution, 30 April 2025).'
    ])

    csv_bytes = buffer.getvalue().encode('utf-8')
    filename = f"compliance_pp167_{period_start.strftime('%Y%m%d')}_{period_end.strftime('%Y%m%d')}.csv"
    record_count = detail_count + 1  # summary + detail rows
    filters = {'date_from': period_start.strftime('%Y-%m-%d'),
               'date_to': period_end.strftime('%Y-%m-%d')}
    _save_report_record('compliance', filename, filters, record_count,
                        request=request, content=csv_bytes)

    response = HttpResponse(csv_bytes, content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response
