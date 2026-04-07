"""
Tests for Phase 4D and 4E features:
- Report model & _save_report_record utility
- Reports page, download, delete views
- PP-167 compliance report
- Data retention (cleanup_old_data) with incident protection
- Dashboard incident stat card & stats API
- Alert action (status changes)
- Alert counts API
- Alert bulk action
- Incident CRUD (create, add alert, status, comment, list, detail)
- Exclusion create API
- Alerts list with incident reference
- Endpoint events distribution
"""
import json
import os
import tempfile
from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase

from .models import (
    Client as EDRClient, Event, ExclusionRule, Incident,
    IncidentActivity, IncidentComment, Port, Process, Report,
    SuspiciousActivity, ThreatIntelHash, ThreatIntelIP,
)


# ═══════════════════════════════════════════════════════════
# MODEL TESTS
# ═══════════════════════════════════════════════════════════

class ReportModelTests(TestCase):
    def test_report_creation(self):
        r = Report.objects.create(
            report_type='events',
            filename='test.csv',
            file_path='/tmp/test.csv',
            record_count=10,
            filters_applied='{"severity":"HIGH"}',
            file_size_bytes=1024,
        )
        self.assertEqual(r.report_type, 'events')
        self.assertEqual(r.filename, 'test.csv')
        self.assertEqual(r.record_count, 10)
        self.assertIsNotNone(r.generated_at)

    def test_file_size_display_bytes(self):
        r = Report(file_size_bytes=500)
        self.assertEqual(r.file_size_display, '500 B')

    def test_file_size_display_kb(self):
        r = Report(file_size_bytes=2048)
        self.assertEqual(r.file_size_display, '2.0 KB')

    def test_file_size_display_mb(self):
        r = Report(file_size_bytes=2 * 1024 * 1024)
        self.assertEqual(r.file_size_display, '2.0 MB')

    def test_filters_dict_valid(self):
        r = Report(filters_applied='{"key":"val"}')
        self.assertEqual(r.filters_dict, {'key': 'val'})

    def test_filters_dict_empty(self):
        r = Report(filters_applied='')
        self.assertEqual(r.filters_dict, {})

    def test_filters_dict_invalid_json(self):
        r = Report(filters_applied='not-json')
        self.assertEqual(r.filters_dict, {})

    def test_report_ordering(self):
        r1 = Report.objects.create(report_type='events', filename='a.csv')
        r2 = Report.objects.create(report_type='alerts', filename='b.csv')
        reports = list(Report.objects.all())
        # Most recent first (by generated_at descending)
        self.assertEqual(len(reports), 2)
        self.assertTrue(reports[0].generated_at >= reports[1].generated_at)

    def test_report_type_choices(self):
        types = [c[0] for c in Report.REPORT_TYPES]
        self.assertIn('events', types)
        self.assertIn('alerts', types)
        self.assertIn('incidents', types)
        self.assertIn('compliance', types)


class IncidentModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('testuser', password='pass123')
        self.client_obj = EDRClient.objects.create(
            hostname='test-pc', ip_address='10.0.0.1')

    def test_incident_auto_number(self):
        inc = Incident(title='Test Incident', created_by=self.user)
        inc.save()
        self.assertEqual(inc.number, 1)

    def test_incident_reference(self):
        inc = Incident(title='Test', created_by=self.user)
        inc.save()
        self.assertEqual(inc.reference, 'INC-0001')

    def test_incident_time_open(self):
        inc = Incident(title='Test', created_by=self.user)
        inc.save()
        self.assertIn('h open', inc.time_open)

    def test_incident_sequential_numbers(self):
        inc1 = Incident(title='First', created_by=self.user)
        inc1.save()
        inc2 = Incident(title='Second', created_by=self.user)
        inc2.save()
        self.assertEqual(inc2.number, inc1.number + 1)


class SuspiciousActivityModelTests(TestCase):
    def setUp(self):
        self.client_obj = EDRClient.objects.create(
            hostname='test-pc', ip_address='10.0.0.1')

    def test_is_acknowledged(self):
        alert = SuspiciousActivity.objects.create(
            client=self.client_obj, type='TEST', description='test',
            timestamp=timezone.now(), status='in_response')
        self.assertTrue(alert.is_acknowledged)

    def test_is_not_acknowledged(self):
        alert = SuspiciousActivity.objects.create(
            client=self.client_obj, type='TEST', description='test',
            timestamp=timezone.now(), status='open')
        self.assertFalse(alert.is_acknowledged)

    def test_can_mark_false_positive_no_incident(self):
        alert = SuspiciousActivity.objects.create(
            client=self.client_obj, type='TEST', description='test',
            timestamp=timezone.now())
        ok, msg = alert.can_mark_false_positive()
        self.assertTrue(ok)

    def test_can_mark_false_positive_with_incident(self):
        user = User.objects.create_user('u', password='p')
        alert = SuspiciousActivity.objects.create(
            client=self.client_obj, type='TEST', description='test',
            timestamp=timezone.now())
        inc = Incident(title='Inc', created_by=user)
        inc.save()
        inc.alerts.add(alert)
        ok, msg = alert.can_mark_false_positive()
        self.assertFalse(ok)


# ═══════════════════════════════════════════════════════════
# _save_report_record UTILITY
# ═══════════════════════════════════════════════════════════

class SaveReportRecordTests(TestCase):
    def test_save_with_content(self):
        from .views import _save_report_record, REPORTS_DIR
        _save_report_record(
            'events', 'test_save.csv',
            {'severity': 'HIGH'}, 42,
            content=b'col1,col2\nval1,val2\n')
        r = Report.objects.get(filename='test_save.csv')
        self.assertEqual(r.report_type, 'events')
        self.assertEqual(r.record_count, 42)
        self.assertTrue(r.file_size_bytes > 0)
        # File actually written
        self.assertTrue(os.path.exists(r.file_path))
        # Cleanup
        os.remove(r.file_path)

    def test_save_without_content(self):
        from .views import _save_report_record
        _save_report_record('alerts', 'empty.csv', {}, 0)
        r = Report.objects.get(filename='empty.csv')
        self.assertEqual(r.file_size_bytes, 0)

    def test_save_with_user(self):
        from .views import _save_report_record
        user = User.objects.create_user('reporter', password='pass')

        class FakeRequest:
            pass
        req = FakeRequest()
        req.user = user
        _save_report_record('events', 'user_report.csv', {}, 5, request=req,
                            content=b'data')
        r = Report.objects.get(filename='user_report.csv')
        self.assertEqual(r.generated_by, user)
        if os.path.exists(r.file_path):
            os.remove(r.file_path)


# ═══════════════════════════════════════════════════════════
# CLEANUP_OLD_DATA MANAGEMENT COMMAND
# ═══════════════════════════════════════════════════════════

class CleanupOldDataTests(TestCase):
    def setUp(self):
        self.client_obj = EDRClient.objects.create(
            hostname='test-pc', ip_address='10.0.0.1')
        self.user = User.objects.create_user('u', password='p')

    def test_fp_alert_deleted_after_90_days_no_incident(self):
        alert = SuspiciousActivity.objects.create(
            client=self.client_obj, type='TEST', description='fp test',
            timestamp=timezone.now() - timedelta(days=100),
            status='false_positive',
            closed_at=timezone.now() - timedelta(days=91))
        out = StringIO()
        call_command('cleanup_old_data', stdout=out)
        self.assertFalse(
            SuspiciousActivity.objects.filter(id=alert.id).exists())

    def test_fp_alert_preserved_if_incident_linked(self):
        alert = SuspiciousActivity.objects.create(
            client=self.client_obj, type='TEST', description='fp linked',
            timestamp=timezone.now() - timedelta(days=100),
            status='false_positive',
            closed_at=timezone.now() - timedelta(days=91))
        inc = Incident(title='Linked', created_by=self.user)
        inc.save()
        inc.alerts.add(alert)
        out = StringIO()
        call_command('cleanup_old_data', stdout=out)
        self.assertTrue(
            SuspiciousActivity.objects.filter(id=alert.id).exists())

    def test_closed_alert_deleted_after_180_days_no_incident(self):
        alert = SuspiciousActivity.objects.create(
            client=self.client_obj, type='TEST', description='closed test',
            timestamp=timezone.now() - timedelta(days=200),
            status='closed',
            closed_at=timezone.now() - timedelta(days=181))
        out = StringIO()
        call_command('cleanup_old_data', stdout=out)
        self.assertFalse(
            SuspiciousActivity.objects.filter(id=alert.id).exists())

    def test_closed_alert_preserved_if_incident_linked(self):
        alert = SuspiciousActivity.objects.create(
            client=self.client_obj, type='TEST', description='closed linked',
            timestamp=timezone.now() - timedelta(days=200),
            status='closed',
            closed_at=timezone.now() - timedelta(days=181))
        inc = Incident(title='Linked', created_by=self.user)
        inc.save()
        inc.alerts.add(alert)
        out = StringIO()
        call_command('cleanup_old_data', stdout=out)
        self.assertTrue(
            SuspiciousActivity.objects.filter(id=alert.id).exists())

    def test_open_alert_never_deleted(self):
        alert = SuspiciousActivity.objects.create(
            client=self.client_obj, type='TEST', description='open old',
            timestamp=timezone.now() - timedelta(days=365),
            status='open')
        out = StringIO()
        call_command('cleanup_old_data', stdout=out)
        self.assertTrue(
            SuspiciousActivity.objects.filter(id=alert.id).exists())

    def test_in_incident_alert_never_deleted(self):
        alert = SuspiciousActivity.objects.create(
            client=self.client_obj, type='TEST', description='incident',
            timestamp=timezone.now() - timedelta(days=365),
            status='in_incident')
        out = StringIO()
        call_command('cleanup_old_data', stdout=out)
        self.assertTrue(
            SuspiciousActivity.objects.filter(id=alert.id).exists())

    def test_dry_run_preserves_data(self):
        alert = SuspiciousActivity.objects.create(
            client=self.client_obj, type='TEST', description='dry run',
            timestamp=timezone.now() - timedelta(days=100),
            status='false_positive',
            closed_at=timezone.now() - timedelta(days=91))
        out = StringIO()
        call_command('cleanup_old_data', '--dry-run', stdout=out)
        self.assertTrue(
            SuspiciousActivity.objects.filter(id=alert.id).exists())
        self.assertIn('DRY', out.getvalue())

    def test_fp_reason_preserved_in_exclusion_rule(self):
        ExclusionRule.objects.create(
            process_name='test.exe', match_mode='NAME_ONLY',
            reason='', is_active=True)
        alert = SuspiciousActivity.objects.create(
            client=self.client_obj, type='TEST', description='fp reason',
            process_name='test.exe',
            timestamp=timezone.now() - timedelta(days=100),
            status='false_positive',
            false_positive_reason='Known admin tool',
            closed_at=timezone.now() - timedelta(days=91))
        out = StringIO()
        call_command('cleanup_old_data', stdout=out)
        rule = ExclusionRule.objects.get(process_name='test.exe')
        self.assertIn('Known admin tool', rule.reason)


# ═══════════════════════════════════════════════════════════
# VIEW TESTS — REPORTS
# ═══════════════════════════════════════════════════════════

class ReportsPageTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.login(username='admin', password='admin123')

    def test_reports_page_loads(self):
        response = self.client.get(reverse('reports'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'edr_app/reports.html')

    def test_reports_page_empty_state(self):
        response = self.client.get(reverse('reports'))
        self.assertContains(response, 'No reports yet')

    def test_reports_page_with_report(self):
        Report.objects.create(
            report_type='events', filename='test.csv',
            record_count=10, file_size_bytes=500)
        response = self.client.get(reverse('reports'))
        self.assertContains(response, 'Events Report')
        self.assertContains(response, 'Download')

    def test_reports_page_type_filter(self):
        Report.objects.create(report_type='events', filename='e.csv')
        Report.objects.create(report_type='alerts', filename='a.csv')
        response = self.client.get(reverse('reports') + '?type=events')
        # Only 1 report row should render (events), not 2
        content = response.content.decode()
        # Count table rows by id="row-" pattern — only 1 should exist
        import re
        rows = re.findall(r'id="row-\d+"', content)
        self.assertEqual(len(rows), 1)

    def test_reports_page_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse('reports'))
        self.assertEqual(response.status_code, 302)


class ReportDownloadTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.login(username='admin', password='admin123')

    def test_download_existing_file(self):
        from .views import REPORTS_DIR
        filepath = os.path.join(REPORTS_DIR, 'dl_test.csv')
        with open(filepath, 'w') as f:
            f.write('col1,col2\nval1,val2\n')
        report = Report.objects.create(
            report_type='events', filename='dl_test.csv',
            file_path=filepath, file_size_bytes=20)
        response = self.client.get(reverse('report_download', args=[report.id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')
        self.assertIn('dl_test.csv', response['Content-Disposition'])
        os.remove(filepath)

    def test_download_missing_file(self):
        report = Report.objects.create(
            report_type='events', filename='missing.csv',
            file_path='/nonexistent/path/missing.csv')
        response = self.client.get(reverse('report_download', args=[report.id]))
        self.assertEqual(response.status_code, 404)

    def test_download_nonexistent_report(self):
        response = self.client.get(reverse('report_download', args=[99999]))
        self.assertEqual(response.status_code, 404)


class ReportDeleteTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.login(username='admin', password='admin123')

    def test_delete_report_with_file(self):
        from .views import REPORTS_DIR
        filepath = os.path.join(REPORTS_DIR, 'to_delete.csv')
        with open(filepath, 'w') as f:
            f.write('data')
        report = Report.objects.create(
            report_type='events', filename='to_delete.csv',
            file_path=filepath)
        response = self.client.post(reverse('report_delete', args=[report.id]))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'ok')
        self.assertFalse(Report.objects.filter(id=report.id).exists())
        self.assertFalse(os.path.exists(filepath))

    def test_delete_report_without_file(self):
        report = Report.objects.create(
            report_type='events', filename='no_file.csv',
            file_path='/nonexistent/file.csv')
        response = self.client.post(reverse('report_delete', args=[report.id]))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Report.objects.filter(id=report.id).exists())

    def test_delete_requires_post(self):
        report = Report.objects.create(
            report_type='events', filename='get_attempt.csv')
        response = self.client.get(reverse('report_delete', args=[report.id]))
        self.assertEqual(response.status_code, 405)


class ComplianceReportTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.login(username='admin', password='admin123')
        self.edr_client = EDRClient.objects.create(
            hostname='compliance-pc', ip_address='10.0.0.5')

    def test_compliance_report_generates_csv(self):
        response = self.client.get(reverse('compliance_report') +
                                   '?date_from=2026-03-01&date_to=2026-04-07')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')
        self.assertIn('compliance_pp167', response['Content-Disposition'])

    def test_compliance_report_saves_record(self):
        self.client.get(reverse('compliance_report') +
                        '?date_from=2026-03-01&date_to=2026-04-07')
        self.assertTrue(Report.objects.filter(report_type='compliance').exists())

    def test_compliance_report_contains_pp167_footer(self):
        response = self.client.get(reverse('compliance_report') +
                                   '?date_from=2026-03-01&date_to=2026-04-07')
        content = response.content.decode('utf-8')
        self.assertIn('PP-167', content)
        self.assertIn('PQ-153', content)

    def test_compliance_report_contains_metrics(self):
        # Create some data in the period
        SuspiciousActivity.objects.create(
            client=self.edr_client, type='TEST', description='crit alert',
            timestamp=timezone.now(), severity='CRITICAL')
        response = self.client.get(reverse('compliance_report') +
                                   '?date_from=2026-04-01&date_to=2026-04-10')
        content = response.content.decode('utf-8')
        self.assertIn('Total Endpoints Monitored', content)
        self.assertIn('CRITICAL Alerts Detected', content)
        self.assertIn('Mean Time to Acknowledge', content)

    def test_compliance_report_default_dates(self):
        # No date params — defaults to last 30 days
        response = self.client.get(reverse('compliance_report'))
        self.assertEqual(response.status_code, 200)

    def test_compliance_report_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse('compliance_report'))
        self.assertEqual(response.status_code, 302)


# ═══════════════════════════════════════════════════════════
# VIEW TESTS — DASHBOARD
# ═══════════════════════════════════════════════════════════

class DashboardTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.login(username='admin', password='admin123')

    def test_dashboard_contains_incident_card(self):
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Open Incidents')
        self.assertContains(response, 'stat-incidents')

    def test_dashboard_incident_count_zero(self):
        response = self.client.get(reverse('dashboard'))
        self.assertContains(response, 'all clear')

    def test_dashboard_incident_count_nonzero(self):
        inc = Incident(title='Open', created_by=self.user, status='open')
        inc.save()
        response = self.client.get(reverse('dashboard'))
        self.assertContains(response, 'has-incidents')
        self.assertContains(response, 'require attention')


class DashboardStatsAPITests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.login(username='admin', password='admin123')

    def test_stats_api_returns_open_incidents(self):
        inc = Incident(title='API Test', created_by=self.user, status='open')
        inc.save()
        response = self.client.get(reverse('dashboard_stats_api'))
        data = json.loads(response.content)
        self.assertEqual(data['open_incidents'], 1)

    def test_stats_api_excludes_closed_incidents(self):
        inc = Incident(title='Closed', created_by=self.user, status='closed')
        inc.save()
        response = self.client.get(reverse('dashboard_stats_api'))
        data = json.loads(response.content)
        self.assertEqual(data['open_incidents'], 0)

    def test_stats_api_all_fields(self):
        response = self.client.get(reverse('dashboard_stats_api'))
        data = json.loads(response.content)
        for key in ['active_endpoints', 'total_endpoints', 'critical_alerts',
                     'alerts_24h', 'ti_total', 'open_incidents',
                     'severity_counts', 'endpoints', 'recent_alerts']:
            self.assertIn(key, data, f'Missing key: {key}')


# ═══════════════════════════════════════════════════════════
# API TESTS — ALERT ACTIONS
# ═══════════════════════════════════════════════════════════

class AlertActionTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.force_authenticate(user=self.user)
        self.edr_client = EDRClient.objects.create(
            hostname='test-pc', ip_address='10.0.0.1')
        self.alert = SuspiciousActivity.objects.create(
            client=self.edr_client, type='TEST', description='test alert',
            timestamp=timezone.now(), status='open')

    def test_mark_in_response(self):
        url = reverse('alert_action', args=[self.alert.id])
        response = self.client.post(url, {'action': 'in_response'}, format='json')
        self.assertEqual(response.status_code, 200)
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.status, 'in_response')

    def test_mark_false_positive_requires_reason(self):
        url = reverse('alert_action', args=[self.alert.id])
        response = self.client.post(url, {'action': 'false_positive'}, format='json')
        self.assertEqual(response.status_code, 400)

    def test_mark_false_positive_with_reason(self):
        url = reverse('alert_action', args=[self.alert.id])
        response = self.client.post(url, {
            'action': 'false_positive',
            'reason': 'Known admin tool'
        }, format='json')
        self.assertEqual(response.status_code, 200)
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.status, 'false_positive')
        self.assertIsNotNone(self.alert.closed_at)

    def test_close_alert(self):
        url = reverse('alert_action', args=[self.alert.id])
        response = self.client.post(url, {'action': 'close'}, format='json')
        self.assertEqual(response.status_code, 200)
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.status, 'closed')
        self.assertIsNotNone(self.alert.closed_at)

    def test_reopen_closed_alert(self):
        self.alert.status = 'closed'
        self.alert.closed_at = timezone.now()
        self.alert.save()
        url = reverse('alert_action', args=[self.alert.id])
        response = self.client.post(url, {'action': 'reopen'}, format='json')
        self.assertEqual(response.status_code, 200)
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.status, 'open')
        self.assertIsNone(self.alert.closed_at)

    def test_reopen_open_alert_fails(self):
        url = reverse('alert_action', args=[self.alert.id])
        response = self.client.post(url, {'action': 'reopen'}, format='json')
        self.assertEqual(response.status_code, 400)

    def test_unknown_action(self):
        url = reverse('alert_action', args=[self.alert.id])
        response = self.client.post(url, {'action': 'invalid'}, format='json')
        self.assertEqual(response.status_code, 400)

    def test_suggest_exclusion_on_fp(self):
        self.alert.process_name = 'admin_tool.exe'
        self.alert.save()
        url = reverse('alert_action', args=[self.alert.id])
        response = self.client.post(url, {
            'action': 'false_positive', 'reason': 'Expected'
        }, format='json')
        data = response.json()
        self.assertTrue(data['suggest_exclusion'])
        self.assertEqual(data['process_name'], 'admin_tool.exe')

    def test_action_nonexistent_alert(self):
        url = reverse('alert_action', args=[99999])
        response = self.client.post(url, {'action': 'close'}, format='json')
        self.assertEqual(response.status_code, 404)


class AlertCountsTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.force_authenticate(user=self.user)
        self.edr_client = EDRClient.objects.create(
            hostname='test-pc', ip_address='10.0.0.1')

    def test_counts_all_statuses(self):
        for s in ['open', 'in_response', 'false_positive', 'closed']:
            SuspiciousActivity.objects.create(
                client=self.edr_client, type='T', description='d',
                timestamp=timezone.now(), status=s)
        response = self.client.get(reverse('alert_counts'))
        data = response.json()
        self.assertEqual(data['open'], 1)
        self.assertEqual(data['in_response'], 1)
        self.assertEqual(data['false_positive'], 1)
        self.assertEqual(data['closed'], 1)
        self.assertEqual(data['all'], 4)

    def test_counts_empty(self):
        response = self.client.get(reverse('alert_counts'))
        data = response.json()
        self.assertEqual(data['all'], 0)


class AlertBulkActionTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.force_authenticate(user=self.user)
        self.edr_client = EDRClient.objects.create(
            hostname='test-pc', ip_address='10.0.0.1')

    def test_bulk_close(self):
        a1 = SuspiciousActivity.objects.create(
            client=self.edr_client, type='T', description='d',
            timestamp=timezone.now(), status='open')
        a2 = SuspiciousActivity.objects.create(
            client=self.edr_client, type='T', description='d',
            timestamp=timezone.now(), status='open')
        url = reverse('alert_bulk_action')
        response = self.client.post(url, {
            'alert_ids': [a1.id, a2.id], 'action': 'close'
        }, format='json')
        data = response.json()
        self.assertEqual(data['updated'], 2)
        a1.refresh_from_db()
        a2.refresh_from_db()
        self.assertEqual(a1.status, 'closed')
        self.assertEqual(a2.status, 'closed')

    def test_bulk_no_ids(self):
        url = reverse('alert_bulk_action')
        response = self.client.post(url, {
            'alert_ids': [], 'action': 'close'
        }, format='json')
        self.assertEqual(response.status_code, 400)

    def test_bulk_in_response_only_open(self):
        a1 = SuspiciousActivity.objects.create(
            client=self.edr_client, type='T', description='d',
            timestamp=timezone.now(), status='open')
        a2 = SuspiciousActivity.objects.create(
            client=self.edr_client, type='T', description='d',
            timestamp=timezone.now(), status='closed')
        url = reverse('alert_bulk_action')
        response = self.client.post(url, {
            'alert_ids': [a1.id, a2.id], 'action': 'in_response'
        }, format='json')
        data = response.json()
        self.assertEqual(data['updated'], 1)


# ═══════════════════════════════════════════════════════════
# API TESTS — INCIDENTS
# ═══════════════════════════════════════════════════════════

class IncidentCreateTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.force_authenticate(user=self.user)
        self.edr_client = EDRClient.objects.create(
            hostname='test-pc', ip_address='10.0.0.1')

    def test_create_incident(self):
        url = reverse('incident_create')
        response = self.client.post(url, {
            'title': 'New Incident', 'description': 'Test description'
        }, format='json')
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data['title'], 'New Incident')
        self.assertIn('INC-', data['reference'])

    def test_create_incident_with_alerts(self):
        alert = SuspiciousActivity.objects.create(
            client=self.edr_client, type='T', description='d',
            timestamp=timezone.now(), status='open')
        url = reverse('incident_create')
        response = self.client.post(url, {
            'title': 'With Alert', 'alert_ids': [alert.id]
        }, format='json')
        self.assertEqual(response.status_code, 201)
        alert.refresh_from_db()
        self.assertEqual(alert.status, 'in_incident')

    def test_create_incident_no_title(self):
        url = reverse('incident_create')
        response = self.client.post(url, {'title': ''}, format='json')
        self.assertEqual(response.status_code, 400)

    def test_create_incident_logs_activity(self):
        url = reverse('incident_create')
        response = self.client.post(url, {
            'title': 'Activity Test'
        }, format='json')
        inc_id = response.json()['id']
        self.assertTrue(IncidentActivity.objects.filter(
            incident_id=inc_id, action='Created').exists())


class IncidentAddAlertTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.force_authenticate(user=self.user)
        self.edr_client = EDRClient.objects.create(
            hostname='test-pc', ip_address='10.0.0.1')
        self.inc = Incident(title='Test', created_by=self.user)
        self.inc.save()

    def test_add_alert(self):
        alert = SuspiciousActivity.objects.create(
            client=self.edr_client, type='T', description='d',
            timestamp=timezone.now())
        url = reverse('incident_add_alert', args=[self.inc.id])
        response = self.client.post(url, {'alert_id': alert.id}, format='json')
        self.assertEqual(response.status_code, 200)
        alert.refresh_from_db()
        self.assertEqual(alert.status, 'in_incident')
        self.assertTrue(self.inc.alerts.filter(id=alert.id).exists())

    def test_add_alert_no_id(self):
        url = reverse('incident_add_alert', args=[self.inc.id])
        response = self.client.post(url, {}, format='json')
        self.assertEqual(response.status_code, 400)


class IncidentStatusTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.force_authenticate(user=self.user)
        self.inc = Incident(title='Status Test', created_by=self.user)
        self.inc.save()

    def test_change_to_in_progress(self):
        url = reverse('incident_status', args=[self.inc.id])
        response = self.client.post(url, {'status': 'in_progress'}, format='json')
        self.assertEqual(response.status_code, 200)
        self.inc.refresh_from_db()
        self.assertEqual(self.inc.status, 'in_progress')

    def test_resolve_sets_resolved_at(self):
        url = reverse('incident_status', args=[self.inc.id])
        response = self.client.post(url, {'status': 'resolved'}, format='json')
        self.inc.refresh_from_db()
        self.assertIsNotNone(self.inc.resolved_at)

    def test_reopen_clears_resolved_at(self):
        self.inc.status = 'resolved'
        self.inc.resolved_at = timezone.now()
        self.inc.save()
        url = reverse('incident_status', args=[self.inc.id])
        response = self.client.post(url, {'status': 'open'}, format='json')
        self.inc.refresh_from_db()
        self.assertIsNone(self.inc.resolved_at)

    def test_invalid_status(self):
        url = reverse('incident_status', args=[self.inc.id])
        response = self.client.post(url, {'status': 'invalid'}, format='json')
        self.assertEqual(response.status_code, 400)

    def test_status_change_logs_activity(self):
        url = reverse('incident_status', args=[self.inc.id])
        self.client.post(url, {'status': 'in_progress'}, format='json')
        self.assertTrue(IncidentActivity.objects.filter(
            incident=self.inc, action='Status changed').exists())


class IncidentCommentTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.force_authenticate(user=self.user)
        self.inc = Incident(title='Comment Test', created_by=self.user)
        self.inc.save()

    def test_add_comment(self):
        url = reverse('incident_comment', args=[self.inc.id])
        response = self.client.post(url, {'body': 'Test comment'}, format='json')
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data['body'], 'Test comment')
        self.assertEqual(data['author'], 'admin')

    def test_empty_comment(self):
        url = reverse('incident_comment', args=[self.inc.id])
        response = self.client.post(url, {'body': ''}, format='json')
        self.assertEqual(response.status_code, 400)

    def test_comment_logs_activity(self):
        url = reverse('incident_comment', args=[self.inc.id])
        self.client.post(url, {'body': 'Activity check'}, format='json')
        self.assertTrue(IncidentActivity.objects.filter(
            incident=self.inc, action='Comment added').exists())


class IncidentListAPITests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.force_authenticate(user=self.user)

    def test_list_incidents(self):
        inc = Incident(title='Listed', created_by=self.user)
        inc.save()
        url = reverse('incident_list_api')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['title'], 'Listed')

    def test_list_filter_by_status(self):
        inc1 = Incident(title='Open', created_by=self.user, status='open')
        inc1.save()
        inc2 = Incident(title='Closed', created_by=self.user, status='closed')
        inc2.save()
        url = reverse('incident_list_api') + '?status=open'
        response = self.client.get(url)
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['title'], 'Open')


class IncidentDetailAPITests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.force_authenticate(user=self.user)
        self.edr_client = EDRClient.objects.create(
            hostname='detail-pc', ip_address='10.0.0.1')
        self.inc = Incident(title='Detail Test', created_by=self.user)
        self.inc.save()

    def test_detail_returns_all_fields(self):
        url = reverse('incident_detail_api', args=[self.inc.id])
        response = self.client.get(url)
        data = response.json()
        for key in ['id', 'reference', 'title', 'status', 'severity',
                     'alerts', 'activities', 'comments']:
            self.assertIn(key, data, f'Missing key: {key}')

    def test_detail_includes_linked_alert(self):
        alert = SuspiciousActivity.objects.create(
            client=self.edr_client, type='T', description='d',
            timestamp=timezone.now())
        self.inc.alerts.add(alert)
        url = reverse('incident_detail_api', args=[self.inc.id])
        response = self.client.get(url)
        data = response.json()
        self.assertEqual(len(data['alerts']), 1)

    def test_detail_nonexistent(self):
        url = reverse('incident_detail_api', args=[99999])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)


# ═══════════════════════════════════════════════════════════
# API TESTS — EXCLUSION CREATE
# ═══════════════════════════════════════════════════════════

class ExclusionCreateTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.force_authenticate(user=self.user)

    def test_create_name_only(self):
        url = reverse('exclusion_create')
        response = self.client.post(url, {
            'process_name': 'safe.exe',
            'match_mode': 'NAME_ONLY',
            'reason': 'Known safe tool',
        }, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertTrue(ExclusionRule.objects.filter(
            process_name='safe.exe').exists())

    def test_create_missing_name(self):
        url = reverse('exclusion_create')
        response = self.client.post(url, {
            'process_name': '',
            'match_mode': 'NAME_ONLY',
            'reason': 'test',
        }, format='json')
        self.assertEqual(response.status_code, 400)

    def test_create_missing_reason(self):
        url = reverse('exclusion_create')
        response = self.client.post(url, {
            'process_name': 'safe.exe',
            'match_mode': 'NAME_ONLY',
            'reason': '',
        }, format='json')
        self.assertEqual(response.status_code, 400)

    def test_create_name_and_path_requires_path(self):
        url = reverse('exclusion_create')
        response = self.client.post(url, {
            'process_name': 'tool.exe',
            'match_mode': 'NAME_AND_PATH',
            'reason': 'test',
        }, format='json')
        self.assertEqual(response.status_code, 400)

    def test_create_hash_mode_requires_hash(self):
        url = reverse('exclusion_create')
        response = self.client.post(url, {
            'process_name': 'tool.exe',
            'match_mode': 'HASH_ONLY',
            'reason': 'test',
        }, format='json')
        self.assertEqual(response.status_code, 400)


# ═══════════════════════════════════════════════════════════
# VIEW TESTS — ALERTS LIST WITH INCIDENT REFERENCE
# ═══════════════════════════════════════════════════════════

class AlertsListIncidentRefTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.login(username='admin', password='admin123')
        self.edr_client = EDRClient.objects.create(
            hostname='test-pc', ip_address='10.0.0.1')

    def test_alert_json_includes_incident_ref(self):
        alert = SuspiciousActivity.objects.create(
            client=self.edr_client, type='T', description='d',
            timestamp=timezone.now(), status='in_incident')
        inc = Incident(title='Test', created_by=self.user)
        inc.save()
        inc.alerts.add(alert)
        response = self.client.get(
            reverse('alerts') + '?status=in_incident',
            HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        data = json.loads(response.content)
        self.assertEqual(len(data['alerts']), 1)
        self.assertEqual(data['alerts'][0]['incident_ref'], inc.reference)
        self.assertEqual(data['alerts'][0]['incident_id'], inc.id)

    def test_alert_json_no_incident(self):
        SuspiciousActivity.objects.create(
            client=self.edr_client, type='T', description='d',
            timestamp=timezone.now(), status='open')
        response = self.client.get(
            reverse('alerts') + '?status=open',
            HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        data = json.loads(response.content)
        self.assertIsNone(data['alerts'][0]['incident_ref'])
        self.assertIsNone(data['alerts'][0]['incident_id'])


# ═══════════════════════════════════════════════════════════
# VIEW TESTS — ENDPOINT EVENTS DISTRIBUTION
# ═══════════════════════════════════════════════════════════

class EndpointEventsDistributionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.login(username='admin', password='admin123')
        self.edr_client = EDRClient.objects.create(
            hostname='test-pc', ip_address='10.0.0.1')

    def test_events_api_includes_distribution(self):
        Event.objects.create(
            client=self.edr_client, event_type='PROCESS_START')
        Event.objects.create(
            client=self.edr_client, event_type='PROCESS_START')
        Event.objects.create(
            client=self.edr_client, event_type='HASH_MATCH')
        response = self.client.get(
            reverse('endpoint_events_api') + '?hours=24')
        data = json.loads(response.content)
        self.assertIn('distribution', data)
        dist = data['distribution']
        self.assertTrue(len(dist) >= 1)
        types = [d['type'] for d in dist]
        self.assertIn('PROCESS_START', types)
        # PROCESS_START has highest count, should be first
        self.assertEqual(dist[0]['type'], 'PROCESS_START')
        self.assertEqual(dist[0]['count'], 2)


# ═══════════════════════════════════════════════════════════
# VIEW TESTS — PAGES THAT SHOULD LOAD
# ═══════════════════════════════════════════════════════════

class IncidentPageTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.login(username='admin', password='admin123')

    def test_incidents_page_loads(self):
        response = self.client.get(reverse('incidents'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'edr_app/incidents.html')

    def test_incident_detail_page_loads(self):
        inc = Incident(title='Page Test', created_by=self.user)
        inc.save()
        response = self.client.get(
            reverse('incident_detail_page', args=[inc.id]))
        self.assertEqual(response.status_code, 200)


class AlertDetailPageTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.login(username='admin', password='admin123')
        self.edr_client = EDRClient.objects.create(
            hostname='test-pc', ip_address='10.0.0.1')

    def test_alert_detail_shows_status_badge(self):
        alert = SuspiciousActivity.objects.create(
            client=self.edr_client, type='TEST', description='test',
            timestamp=timezone.now(), status='open')
        response = self.client.get(reverse('alert_detail', args=[alert.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'statusBadge')
        self.assertContains(response, 'Change Status')

    def test_alert_detail_shows_incident_link(self):
        alert = SuspiciousActivity.objects.create(
            client=self.edr_client, type='TEST', description='test',
            timestamp=timezone.now(), status='in_incident')
        inc = Incident(title='Linked Inc', created_by=self.user)
        inc.save()
        inc.alerts.add(alert)
        response = self.client.get(reverse('alert_detail', args=[alert.id]))
        self.assertContains(response, inc.reference)


class EndpointEventsPageTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.login(username='admin', password='admin123')

    def test_events_page_has_query_help(self):
        response = self.client.get(reverse('endpoint_events'))
        self.assertContains(response, 'query-help-btn')
        self.assertContains(response, 'Query Language Reference')

    def test_events_page_has_dist_bar(self):
        response = self.client.get(reverse('endpoint_events'))
        self.assertContains(response, 'distBar')


class ContextProcessorTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.login(username='admin', password='admin123')

    def test_stats_include_open_incidents(self):
        inc = Incident(title='CP Test', created_by=self.user, status='open')
        inc.save()
        response = self.client.get(reverse('dashboard'))
        # Context processor adds stats_open_incidents
        self.assertContains(response, 'incBadge')


class SidebarTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('admin', password='admin123')
        self.client.login(username='admin', password='admin123')

    def test_sidebar_has_reports_link(self):
        response = self.client.get(reverse('dashboard'))
        self.assertContains(response, 'Reports')
        self.assertContains(response, '/reports/')

    def test_sidebar_has_incidents_badge(self):
        response = self.client.get(reverse('dashboard'))
        self.assertContains(response, 'incBadge')
