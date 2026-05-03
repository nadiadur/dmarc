from django.urls import path

from reports import notification_views
from . import views, domain_views 
from .views import scan_domain, scan_domain_view

urlpatterns = [
    # ── IMAP Config ──────────────────────────────────────────────────────────
    path('imap/config/', views.IMAPConfigView.as_view(), name='imap-config'),

    # ── Domain Management ─────────────────────────────────────────────────────
    path('domains/', domain_views.DomainListView.as_view(), name='domain-list'),
    path('domains/<int:domain_id>/', domain_views.DomainDetailView.as_view(), name='domain-detail'),
    path('domains/<int:domain_id>/scan/', domain_views.DomainScanView.as_view(), name='domain-scan'),
    path('domains/<int:domain_id>/generate-records/', domain_views.DomainGenerateRecordsView.as_view(), name='domain-generate'),
    path('domains/<int:domain_id>/verify/', domain_views.DomainVerifyView.as_view(), name='domain-verify'),
    path('domains/<int:domain_id>/policy/', domain_views.DomainPolicyView.as_view(), name='domain-policy'),

    # ── Reports ───────────────────────────────────────────────────────────────
    path('reports/', views.ReportListView.as_view(), name='report-list'),
    path('reports/stats/', views.ReportStatsView.as_view(), name='report-stats'),
    path('reports/upload/', views.ReportUploadView.as_view(), name='report-upload'),
    path('reports/fetch-email/', views.FetchEmailView.as_view(), name='fetch-email'),
    path('reports/<uuid:report_id>/', views.ReportDetailView.as_view(), name='report-detail'),

    # ── Records ───────────────────────────────────────────────────────────────
    path('records/', views.RecordListView.as_view(), name='record-list'),

    # ── Celery Task Status ────────────────────────────────────────────────────
    path('tasks/<str:task_id>/status/', views.TaskStatusView.as_view(), name='task-status'),

    # ── Alerts ───────────────────────────────────────────────────────────────
    path('alerts/', views.AlertListView.as_view(), name='alert-list'),
    path('alerts/<int:alert_id>/read/', views.AlertMarkReadView.as_view(), name='alert-read'),

    # ── Dashboard ─────────────────────────────────────────────────────────────
    path('dashboard/overview/', views.DashboardOverviewView.as_view(), name='dashboard-overview'),

    path("scan-domain/", scan_domain),

    
    path("scan-domain/", scan_domain_view),

     # Notifications
    path('notifications/config/', notification_views.NotificationConfigView.as_view(), name='notif-config'),
    path('notifications/test/', notification_views.NotificationTestView.as_view(), name='notif-test'),
    path('notifications/history/', notification_views.NotificationHistoryView.as_view(), name='notif-history'),

    path('alerts/<int:alert_id>/delete/', views.AlertDeleteView.as_view(), name='alert-delete'),
    path('imap/test/', views.GmailTestView.as_view(), name='gmail-test'),

]