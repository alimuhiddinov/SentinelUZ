from .models import (
    Process, Port, Vulnerability, VulnerabilityMatch,
    SuspiciousActivity, ThreatIntelIP, ThreatIntelHash,
    ExclusionRule, Event,
)
from django.utils import timezone
from django.db import IntegrityError
from datetime import timedelta
import re
import json
import hashlib

KNOWN_ATTACK_TOOLS = [
    'mimikatz', 'pwdump', 'procdump', 'lazagne',
    'ghostpack', 'psexec', 'bloodhound', 'cobalt',
    'metasploit', 'meterpreter', 'empire', 'cobaltstrike',
    'hacktools', 'sharphound', 'rubeus', 'certify',
]

RANSOMWARE_PRECURSORS = [
    'vssadmin.exe',   # deletes shadow copies
    'wbadmin.exe',    # deletes Windows backups
    'bcdedit.exe',    # disables boot recovery
    'cipher.exe',     # file encryption
    'diskshadow.exe', # shadow copy manipulation
]

SIGNATURES = {
    'HASH_MATCH': {
        'sig_id': 'SIG-007',
        'name': 'Known Malware Execution',
        'plain_title': 'Known malware file detected',
        'plain_explanation': (
            'A running process matched a file in our malware database. '
            'The SHA256 fingerprint of this file exactly matches a known '
            'malicious program. This is a confirmed detection — not a false positive.'
        ),
        'plain_action': (
            '1. Act immediately.\n'
            '2. Stop the process if it is still running.\n'
            '3. Disconnect the device from the network.\n'
            '4. Do not restart the computer — this may destroy forensic evidence.\n'
            '5. Contact CERT-UZ: cert.uz'
        ),
        'mitre_id': 'T1204',
        'mitre_tactic': 'execution',
        'severity': 'CRITICAL',
    },
    'KNOWN_ATTACK_TOOL': {
        'sig_id': 'SIG-005',
        'name': 'Known Attack Tool Detected',
        'plain_title': 'Hacking tool detected on this device',
        'plain_explanation': (
            'A process was detected whose name matches a known offensive security '
            'or hacking tool. These tools are sometimes used by IT teams legitimately, '
            'but their presence on a non-security workstation is a strong indicator of compromise.'
        ),
        'plain_action': (
            '1. Identify who is running this tool and why.\n'
            '2. If no legitimate reason exists, treat as a security incident.\n'
            '3. Check the process chain in the Process Chain tab.\n'
            '4. Isolate the device if origin is unclear.'
        ),
        'mitre_id': 'T1105',
        'mitre_tactic': 'command_control',
        'severity': 'CRITICAL',
    },
    'SUSPICIOUS_CHAIN': {
        'sig_id': 'SIG-010',
        'name': 'Suspicious Process Chain',
        'plain_title': 'Suspicious process chain detected',
        'plain_explanation': (
            'A chain of suspicious processes was detected — one application launched '
            'another in a pattern commonly seen in attacks. For example, Word opening a '
            'command prompt which then opens PowerShell is the exact pattern used in the '
            'Bloody Wolf campaign targeting Uzbek organisations in 2024.'
        ),
        'plain_action': (
            '1. Review the full chain in the Process Chain tab.\n'
            '2. If the chain started from an Office application or browser, a malicious '
            'document or website may have triggered this.\n'
            '3. Check if the user opened any unexpected email attachments recently.\n'
            '4. Consider isolating the device.'
        ),
        'mitre_id': 'T1059',
        'mitre_tactic': 'execution',
        'severity': 'HIGH',
    },
    'RANSOMWARE_PRECURSOR': {
        'sig_id': 'SIG-008',
        'name': 'Ransomware Precursor Activity',
        'plain_title': 'Ransomware warning sign detected',
        'plain_explanation': (
            'A tool that ransomware uses to prepare an attack was detected. This includes '
            'tools that delete Windows backups (vssadmin, wbadmin) or disable system recovery '
            '(bcdedit). Ransomware attackers delete backups immediately before encrypting files '
            'to prevent recovery without paying.'
        ),
        'plain_action': (
            '1. Act immediately — this may indicate an active ransomware attack.\n'
            '2. Disconnect the device from the network.\n'
            '3. Check other devices on the same network for similar alerts.\n'
            '4. Contact CERT-UZ: cert.uz\n'
            '5. Do not pay any ransom without expert advice.'
        ),
        'mitre_id': 'T1490',
        'mitre_tactic': 'impact',
        'severity': 'CRITICAL',
    },
    'BLACKLISTED_IP': {
        'sig_id': 'SIG-006',
        'name': 'C2 Communication Detected',
        'plain_title': 'Connection to known attacker server',
        'plain_explanation': (
            'A network connection was made to an IP address known to be used by attackers. '
            'This IP appears in threat intelligence databases as a command-and-control server '
            '— a server attackers use to control malware on infected machines.'
        ),
        'plain_action': (
            '1. This is a serious indicator — the device may already be compromised.\n'
            '2. Identify which process made the connection (shown in the Network tab).\n'
            '3. If the connection is ESTABLISHED, disconnect from network immediately.\n'
            '4. Contact CERT-UZ: cert.uz'
        ),
        'mitre_id': 'T1071',
        'mitre_tactic': 'command_control',
        'severity': 'HIGH',
    },
    'LOLBIN_DETECTED': {
        'sig_id': 'SIG-001',
        'name': 'LOLBin Execution',
        'plain_title': 'Dual-use system tool detected',
        'plain_explanation': (
            'A Windows system tool that is often misused by attackers (called a LOLBin — '
            'Living off the Land Binary) was detected running. These tools are legitimate '
            'and present on every Windows computer, but attackers use them because antivirus '
            'software cannot block them. The tool running alone is a LOW severity observation '
            '— the concern increases if it was launched by an unexpected application.'
        ),
        'plain_action': (
            '1. Check what launched this tool (visible in Process Chain tab).\n'
            '2. If launched by Microsoft Office, a browser, or email client, '
            'escalate to HIGH severity immediately.\n'
            '3. If launched by a legitimate admin task, consider adding an exclusion rule.'
        ),
        'mitre_id': 'T1059',
        'mitre_tactic': 'execution',
        'severity': 'LOW',
    },
}

_ti_cache = {'ips': None, 'hashes': None, 'loaded_at': None}


def _get_correlation_id(client, process, timestamp):
    """Generate a correlation ID grouping alerts from the same process tree within 5 minutes."""
    root_pid = process.pid if process else 0
    if process and process.parent_pid:
        current = process
        for _ in range(5):
            parent = Process.objects.filter(client=client, pid=current.parent_pid).first()
            if parent:
                root_pid = parent.pid
                current = parent
            else:
                break
    bucket = int(timestamp.timestamp() / 300)
    key = f"{client.id}:{root_pid}:{bucket}"
    return hashlib.md5(key.encode()).hexdigest()[:16]


def _create_or_update_alert(client, alert_type, severity, description, ioc_key, proc):
    """Create a new alert or increment event_count on an existing one.
    Returns the alert object (existing or new)."""
    cutoff = timezone.now() - timedelta(days=3)
    existing = SuspiciousActivity.objects.filter(
        client=client,
        ioc_matched=ioc_key,
        type=alert_type,
        last_seen__gte=cutoff,
    ).order_by('-last_seen').first()

    if existing:
        existing.event_count += 1
        existing.save(update_fields=['event_count', 'last_seen'])
        return existing

    now = timezone.now()
    alert = SuspiciousActivity.objects.create(
        client=client,
        type=alert_type,
        severity=severity,
        description=description,
        process_name=proc.name if proc else '',
        process_id=proc.pid if proc else None,
        ioc_matched=ioc_key,
        timestamp=now,
        correlation_id=_get_correlation_id(client, proc, now),
    )
    return alert


def _load_exclusion_rules():
    """Load active, non-expired exclusion rules."""
    from django.db.models import Q
    return list(
        ExclusionRule.objects.filter(
            is_active=True
        ).filter(
            Q(expires_at__isnull=True) |
            Q(expires_at__gt=timezone.now())
        )
    )


def _is_excluded(proc, exclusions):
    """Check if a process matches any exclusion rule."""
    proc_name_lower = proc.name.lower() if proc.name else ''
    proc_path = proc.path or ''
    proc_hash = proc.sha256_hash or ''

    for rule in exclusions:
        if rule.match_mode == 'HASH_ONLY':
            if proc_hash and proc_hash == rule.sha256_hash:
                return True

        elif rule.match_mode == 'NAME_AND_PATH':
            name_match = (proc_name_lower == rule.process_name.lower())
            path_match = (proc_path.startswith(rule.process_path)
                          if rule.process_path else True)
            if name_match and path_match:
                return True

        elif rule.match_mode == 'ALL':
            name_match = (proc_name_lower == rule.process_name.lower())
            path_match = (proc_path.startswith(rule.process_path)
                          if rule.process_path else True)
            hash_match = (proc_hash == rule.sha256_hash
                          if rule.sha256_hash else True)
            if name_match and path_match and hash_match:
                return True

        elif rule.match_mode == 'NAME_ONLY':
            if proc_name_lower == rule.process_name.lower():
                return True

    return False


def _create_signature(alert, alert_type, events=None):
    """Create a Signature record for an alert using the SIGNATURES dict."""
    from .models import Signature
    sig_data = SIGNATURES.get(alert_type)
    if not sig_data:
        return None
    sig = Signature.objects.create(
        alert=alert,
        sig_id=sig_data['sig_id'],
        name=sig_data['name'],
        plain_title=sig_data['plain_title'],
        plain_explanation=sig_data['plain_explanation'],
        plain_action=sig_data['plain_action'],
        mitre_id=sig_data['mitre_id'],
        mitre_tactic=sig_data['mitre_tactic'],
        severity=sig_data['severity'],
    )
    if events:
        sig.events.set(events)
    return sig


def match_iocs(client):
    """Match processes against IoC lists and detect suspicious behavior."""
    # Load TI data with 30-minute cache
    now = timezone.now()
    if (_ti_cache['loaded_at'] is None or
            now - _ti_cache['loaded_at'] > timedelta(minutes=30)):
        _ti_cache['ips'] = set(ThreatIntelIP.objects.filter(
            is_active=True).values_list('ip_address', flat=True))
        _ti_cache['hashes'] = set(ThreatIntelHash.objects.filter(
            is_active=True).values_list('sha256_hash', flat=True))
        _ti_cache['loaded_at'] = now

    ip_set = _ti_cache['ips']
    hash_set = _ti_cache['hashes']

    processes = list(Process.objects.filter(client=client))
    lolbin_count = sum(1 for p in processes if p.is_lolbin)
    print(f"[match_iocs] client={client.hostname}: "
          f"checking {len(processes)} processes, "
          f"{lolbin_count} have is_lolbin=True")

    exclusions = _load_exclusion_rules()
    excluded_count = 0

    alerts_created = 0
    for proc in processes:
        if _is_excluded(proc, exclusions):
            excluded_count += 1
            continue

        # Helper: create a PROCESS_START event for this process
        def _proc_event(p):
            ev, _ = Event.objects.get_or_create(
                client=client, event_type='PROCESS_START', process=p,
                defaults={'raw_data': json.dumps({
                    'pid': p.pid, 'name': p.name, 'path': p.path or '',
                    'parent_pid': p.parent_pid, 'parent_name': p.parent_name or '',
                    'is_lolbin': p.is_lolbin,
                })})
            return ev

        # 1. Hash match against TI database
        if proc.sha256_hash and proc.sha256_hash in hash_set:
            alert = _create_or_update_alert(
                client, 'HASH_MATCH', 'CRITICAL',
                f'Known malware hash detected: {proc.name}. '
                f'Hash matches threat intelligence database.',
                proc.sha256_hash, proc)
            if alert.event_count == 1:
                alerts_created += 1
            event = Event.objects.create(
                client=client, event_type='HASH_MATCH', process=proc,
                raw_data=json.dumps({'pid': proc.pid, 'name': proc.name,
                    'sha256': proc.sha256_hash}))
            alert.events.add(event, _proc_event(proc))
            if alert.event_count == 1:
                _create_signature(alert, 'HASH_MATCH', [event, _proc_event(proc)])

        # 2. Known attack tool by name
        proc_lower = proc.name.lower()
        for tool in KNOWN_ATTACK_TOOLS:
            if tool in proc_lower:
                alert = _create_or_update_alert(
                    client, 'KNOWN_ATTACK_TOOL', 'CRITICAL',
                    f'Known attack tool detected: {proc.name}',
                    f'tool:{proc.name}', proc)
                if alert.event_count == 1:
                    alerts_created += 1
                event = Event.objects.create(
                    client=client, event_type='HASH_MATCH', process=proc,
                    raw_data=json.dumps({'pid': proc.pid, 'name': proc.name,
                        'tool': tool}))
                alert.events.add(event, _proc_event(proc))
                if alert.event_count == 1:
                    _create_signature(alert, 'KNOWN_ATTACK_TOOL', [event, _proc_event(proc)])
                break

        # 3. Suspicious chain (Office/browser spawned LOLBin)
        if proc.is_suspicious_chain:
            alert = _create_or_update_alert(
                client, 'SUSPICIOUS_CHAIN', 'HIGH',
                f'Suspicious process chain: {proc.parent_name} '
                f'spawned {proc.name}',
                f'chain:{proc.parent_name}:{proc.name}', proc)
            if alert.event_count == 1:
                alerts_created += 1
            event = Event.objects.create(
                client=client, event_type='LOLBIN_CHAIN', process=proc,
                raw_data=json.dumps({'child_pid': proc.pid, 'child_name': proc.name,
                    'parent_pid': proc.parent_pid, 'parent_name': proc.parent_name or '',
                    'chain': f"{proc.parent_name} → {proc.name}"}))
            alert.events.add(event, _proc_event(proc))
            if alert.event_count == 1:
                _create_signature(alert, 'SUSPICIOUS_CHAIN', [event, _proc_event(proc)])
        # 5. LOLBin alone (no suspicious parent)
        elif proc.is_lolbin and not proc.is_suspicious_chain:
            alert = _create_or_update_alert(
                client, 'LOLBIN_DETECTED', 'LOW',
                f'LOLBin process detected: {proc.name}',
                f'lolbin:{proc.name}', proc)
            if alert.event_count == 1:
                alerts_created += 1
            alert.events.add(_proc_event(proc))
            if alert.event_count == 1:
                _create_signature(alert, 'LOLBIN_DETECTED', [_proc_event(proc)])

        # 4. Ransomware pre-encryption behavior
        for precursor in RANSOMWARE_PRECURSORS:
            if precursor in proc_lower:
                if proc.is_suspicious_chain or proc.is_lolbin:
                    alert = _create_or_update_alert(
                        client, 'RANSOMWARE_PRECURSOR', 'CRITICAL',
                        f'Ransomware pre-encryption activity: '
                        f'{proc.name} spawned by {proc.parent_name}. '
                        f'Possible shadow copy deletion or '
                        f'backup destruction detected.',
                        f'ransomware:{proc.name}', proc)
                else:
                    alert = _create_or_update_alert(
                        client, 'RANSOMWARE_PRECURSOR', 'HIGH',
                        f'Suspicious ransomware indicator: '
                        f'{proc.name} detected.',
                        f'ransomware:{proc.name}', proc)
                if alert.event_count == 1:
                    alerts_created += 1
                event = Event.objects.create(
                    client=client, event_type='RANSOMWARE_PRECURSOR', process=proc,
                    raw_data=json.dumps({'pid': proc.pid, 'name': proc.name,
                        'path': proc.path or ''}))
                alert.events.add(event, _proc_event(proc))
                if alert.event_count == 1:
                    _create_signature(alert, 'RANSOMWARE_PRECURSOR', [event, _proc_event(proc)])
                break

    # 6. Network connection IP matching against TI database
    all_connections = Port.objects.filter(client=client)
    print(f"[match_iocs] checking {all_connections.count()} "
          f"network connections for blacklisted IPs")
    print(f"[match_iocs] ip_set size: {len(ip_set)}")

    for p in all_connections[:3]:
        print(f"[match_iocs] Port: {p.remote_ip}:{p.remote_port} "
              f"process={p.process_name}")

    if ip_set:
        connections = all_connections.filter(
            remote_ip__isnull=False,
        ).exclude(remote_ip__in=['0.0.0.0', '*', '127.0.0.1', ''])
        for conn in connections:
            if conn.remote_ip in ip_set:
                alert = _create_or_update_alert(
                    client, 'MALICIOUS_IP', 'CRITICAL',
                    f'Connection to known malicious IP: {conn.remote_ip} '
                    f'by {conn.process_name} (PID {conn.process_id})',
                    f'ip:{conn.remote_ip}', None)
                if alert.event_count == 1:
                    alerts_created += 1
                net_event = Event.objects.create(
                    client=client, event_type='NETWORK_CONNECT', port=conn,
                    raw_data=json.dumps({'remote_ip': conn.remote_ip,
                        'remote_port': conn.remote_port,
                        'process_name': conn.process_name or '',
                        'process_id': conn.process_id}))
                ip_event = Event.objects.create(
                    client=client, event_type='IP_MATCH', port=conn,
                    raw_data=json.dumps({'remote_ip': conn.remote_ip}))
                alert.events.add(net_event, ip_event)
                if alert.event_count == 1:
                    _create_signature(alert, 'BLACKLISTED_IP', [net_event, ip_event])

    print(f"[match_iocs] client={client.hostname}: "
          f"{excluded_count} processes skipped by exclusion rules, "
          f"{alerts_created} alerts created")


def analyze_vulnerabilities(client):
    """
    Analyze processes and ports for potential vulnerabilities.
    Returns a list of VulnerabilityMatch objects.
    """
    # Clear previous matches for this client
    VulnerabilityMatch.objects.filter(client=client).delete()
    matches = []

    # Get all active processes and ports for the client
    processes = Process.objects.filter(client=client)
    ports = Port.objects.filter(client=client)
    vulnerabilities = Vulnerability.objects.all()

    # Analyze processes
    for process in processes:
        for vuln in vulnerabilities:
            # Check if process name matches affected software
            if _match_software(process.name, vuln.affected_software):
                # Check version if available
                confidence = _calculate_confidence(process, vuln)
                if confidence > 0:
                    try:
                        match, created = VulnerabilityMatch.objects.get_or_create(
                            vulnerability=vuln,
                            client=client,
                            process=process,
                            defaults={
                                'match_type': 'PROCESS',
                                'confidence_score': confidence
                            }
                        )
                        if not created:
                            match.confidence_score = confidence
                            match.save()
                        matches.append(match)
                    except IntegrityError:
                        # Skip if there's a duplicate
                        continue

    # Analyze ports and services
    for port in ports:
        for vuln in vulnerabilities:
            # Check if service name matches affected software
            if port.service_name and _match_software(port.service_name, vuln.affected_software):
                confidence = _calculate_service_confidence(port, vuln)
                if confidence > 0:
                    try:
                        match, created = VulnerabilityMatch.objects.get_or_create(
                            vulnerability=vuln,
                            client=client,
                            port=port,
                            defaults={
                                'match_type': 'SERVICE',
                                'confidence_score': confidence
                            }
                        )
                        if not created:
                            match.confidence_score = confidence
                            match.save()
                        matches.append(match)
                    except IntegrityError:
                        # Skip if there's a duplicate
                        continue

            # Check common vulnerable ports
            if _is_vulnerable_port(port.port_number, vuln):
                try:
                    match, created = VulnerabilityMatch.objects.get_or_create(
                        vulnerability=vuln,
                        client=client,
                        port=port,
                        defaults={
                            'match_type': 'PORT',
                            'confidence_score': 0.5  # Base confidence for port matches
                        }
                    )
                    if not created:
                        match.confidence_score = 0.5
                        match.save()
                    matches.append(match)
                except IntegrityError:
                    # Skip if there's a duplicate
                    continue

    return matches

def _match_software(name, affected_software):
    """Check if software name matches affected software pattern."""
    if not name or not affected_software:
        return False
    
    # Convert both to lowercase for case-insensitive matching
    name = name.lower()
    affected_software = affected_software.lower()
    
    # Split affected_software by common separators
    patterns = affected_software.replace(',', ' ').split()
    
    for pattern in patterns:
        if pattern in name:
            return True
    
    return False

def _calculate_confidence(process, vulnerability):
    """Calculate confidence score for process vulnerability match."""
    confidence = 0.0
    
    # Base confidence if software name matches
    if _match_software(process.name, vulnerability.affected_software):
        confidence = 0.5
        
        # Additional confidence if version matches
        if process.version and vulnerability.affected_versions:
            if _version_matches(process.version, vulnerability.affected_versions):
                confidence += 0.5
    
    return confidence

def _calculate_service_confidence(port, vulnerability):
    """Calculate confidence score for service vulnerability match."""
    confidence = 0.0
    
    # Base confidence if service name matches
    if port.service_name and _match_software(port.service_name, vulnerability.affected_software):
        confidence = 0.5
        
        # Additional confidence if version matches
        if port.service_version and vulnerability.affected_versions:
            if _version_matches(port.service_version, vulnerability.affected_versions):
                confidence += 0.5
    
    return confidence

def _version_matches(version, affected_versions):
    """Check if version matches affected versions pattern."""
    if not version or not affected_versions:
        return False
    
    # Convert version strings to comparable format
    version = version.lower()
    affected_versions = affected_versions.lower()
    
    # Handle various version patterns (e.g., "<=2.0.0", "2.x", "1.0-2.0")
    version_patterns = affected_versions.split(',')
    
    for pattern in version_patterns:
        pattern = pattern.strip()
        
        # Handle range pattern (e.g., "1.0-2.0")
        if '-' in pattern:
            start, end = pattern.split('-')
            if _version_in_range(version, start, end):
                return True
        
        # Handle comparison patterns (e.g., "<=2.0.0")
        elif any(op in pattern for op in ['<=', '>=', '<', '>', '=']):
            op = re.findall(r'(<=|>=|<|>|=)', pattern)[0]
            ver = pattern.replace(op, '').strip()
            if _compare_versions(version, ver, op):
                return True
        
        # Handle exact match or wildcard
        elif pattern == version or (pattern.endswith('.x') and version.startswith(pattern[:-2])):
            return True
    
    return False

def _version_in_range(version, start, end):
    """Check if version is within range."""
    try:
        version_parts = [int(p) for p in version.split('.')]
        start_parts = [int(p) for p in start.split('.')]
        end_parts = [int(p) for p in end.split('.')]
        
        return start_parts <= version_parts <= end_parts
    except (ValueError, AttributeError):
        return False

def _compare_versions(version1, version2, operator):
    """Compare two version strings using the specified operator."""
    try:
        v1_parts = [int(p) for p in version1.split('.')]
        v2_parts = [int(p) for p in version2.split('.')]
        
        # Pad shorter version with zeros
        max_length = max(len(v1_parts), len(v2_parts))
        v1_parts.extend([0] * (max_length - len(v1_parts)))
        v2_parts.extend([0] * (max_length - len(v2_parts)))
        
        if operator == '<=':
            return v1_parts <= v2_parts
        elif operator == '>=':
            return v1_parts >= v2_parts
        elif operator == '<':
            return v1_parts < v2_parts
        elif operator == '>':
            return v1_parts > v2_parts
        elif operator == '=':
            return v1_parts == v2_parts
        
    except (ValueError, AttributeError):
        return False
    
    return False

def _is_vulnerable_port(port_number, vulnerability):
    """Check if port number is commonly associated with vulnerabilities."""
    # Common vulnerable ports and their typical services
    VULNERABLE_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        135: 'RPC',
        139: 'NetBIOS',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        8080: 'HTTP-ALT'
    }
    
    if port_number in VULNERABLE_PORTS:
        service = VULNERABLE_PORTS[port_number]
        # Check if vulnerability affects this service
        return _match_software(service, vulnerability.affected_software)
    
    return False
