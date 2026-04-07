from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'api/endpoints', views.ClientViewSet)

urlpatterns = [
    # Web interface endpoints
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('device/<int:device_id>/', views.device_detail, name='device_detail'),
    path('processes/', views.processes, name='processes'),
    path('processes/tree/<int:device_id>/', views.process_tree, name='process_tree'),
    path('ports/', views.ports, name='ports'),
    path('alerts/', views.alerts, name='alerts'),
    path('vulnerabilities/', views.vulnerabilities, name='vulnerabilities'),
    path('logs/', views.logs, name='logs'),
    path('logs/view/', views.view_logs, name='view_logs'),
    path('logs/download/', views.download_logs, name='download_logs'),
    
    # API endpoints
    path('api/upload/', views.upload_data, name='upload_data'),
    path('api/logs/upload/', views.upload_logs, name='upload_logs'),
    path('api/logs/windows/', views.upload_windows_logs, name='upload_windows_logs'),
    path('alerts/<int:alert_id>/', views.alert_detail, name='alert_detail'),
    path('api/alerts/<int:alert_id>/context/', views.alert_process_context, name='alert_process_context'),
    path('api/alerts/<int:alert_id>/events/', views.alert_events_api, name='alert_events_api'),
    path('api/alerts/<int:alert_id>/network/', views.alert_network_context, name='alert_network_context'),
    path('api/alerts/<int:alert_id>/acknowledge/', views.alert_acknowledge, name='alert_acknowledge'),
    path('api/health/', views.health_check, name='health_check'),
    path('api/dashboard/stats/', views.dashboard_stats_api, name='dashboard_stats_api'),

    # IoC Manager
    path('ioc-manager/', views.ioc_manager, name='ioc_manager'),
    path('help/', views.help_center, name='help_center'),
    path('api/sync-ti/', views.sync_ti_feeds_view, name='sync_ti_feeds_view'),
    path('api/ioc/add/', views.ioc_add, name='ioc_add'),
    path('api/exclusions/<int:rule_id>/delete/', views.exclusion_delete, name='exclusion_delete'),
    path('api/exclusions/create/', views.exclusion_create, name='exclusion_create'),
    path('api/alerts/<int:alert_id>/action/', views.alert_action, name='alert_action'),
    path('api/alerts/counts/', views.alert_counts, name='alert_counts'),
    path('api/alerts/bulk-action/', views.alert_bulk_action, name='alert_bulk_action'),

    # Incidents
    path('incidents/', views.incidents_page, name='incidents'),
    path('incidents/<int:incident_id>/', views.incident_detail_page, name='incident_detail_page'),
    path('api/incidents/', views.incident_list_api, name='incident_list_api'),
    path('api/incidents/create/', views.incident_create, name='incident_create'),
    path('api/incidents/<int:incident_id>/', views.incident_detail_api, name='incident_detail_api'),
    path('api/incidents/<int:incident_id>/add-alert/', views.incident_add_alert, name='incident_add_alert'),
    path('api/incidents/<int:incident_id>/status/', views.incident_status, name='incident_status'),
    path('api/incidents/<int:incident_id>/comment/', views.incident_comment, name='incident_comment'),

    # Reports
    path('reports/', views.reports_page, name='reports'),
    path('reports/download/<int:report_id>/', views.report_download, name='report_download'),
    path('reports/delete/<int:report_id>/', views.report_delete, name='report_delete'),
    path('reports/compliance/', views.compliance_report, name='compliance_report'),

    # Owner Portal
    path('owner/company/', views.owner_company, name='owner_company'),
    path('owner/users/', views.owner_users, name='owner_users'),

    # Signatures & Events
    path('api/alerts/<int:alert_id>/signatures/', views.alert_signatures, name='alert_signatures'),
    path('api/signatures/<int:sig_id>/events/', views.signature_events, name='signature_events'),
    path('events/', views.endpoint_events, name='endpoint_events'),
    path('api/endpoint-events/', views.endpoint_events_api, name='endpoint_events_api'),
]

urlpatterns += router.urls
