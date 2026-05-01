"""
API Views untuk modul DMARC Reports.

Endpoints:
  IMAPConfig   : GET/POST/PUT /api/imap/config/
  Domain       : CRUD         /api/domains/
  Reports      : GET          /api/reports/
  Reports      : GET          /api/reports/{id}/
  Upload       : POST         /api/reports/upload/
  Fetch        : POST         /api/reports/fetch-email/
  Task Status  : GET          /api/tasks/{task_id}/status/
  Records      : GET          /api/records/
  Stats        : GET          /api/reports/stats/
  Alerts       : GET/PATCH    /api/alerts/
  Dashboard    : GET          /api/dashboard/overview/
"""

import logging
import json
from datetime import timedelta

from django.utils import timezone
from django.db.models import Sum, Count, Q
from reports.services.checker import check_domain
from django.http import JsonResponse
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from reports.services.checker import check_domain
from celery.result import AsyncResult
from django.views.decorators.csrf import csrf_exempt
from .services.scanner import scan_domain

from .models import IMAPConfig, Domain, DMARCReport, DMARCRecord, AlertLog
from .serializers import (
    IMAPConfigSerializer, DomainSerializer,
    DMARCReportListSerializer, DMARCReportDetailSerializer,
    ReportUploadSerializer, AlertLogSerializer,
)
from .parser import decompress_attachment, parse_dmarc_xml
from .tasks import fetch_dmarc_emails_task, parse_dmarc_report_task

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# IMAP CONFIG
# ─────────────────────────────────────────────────────────────────────────────

class IMAPConfigView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """GET /api/imap/config/ — Lihat konfigurasi IMAP aktif"""
        try:
            config = IMAPConfig.objects.get(user=request.user)
            serializer = IMAPConfigSerializer(config)
            return Response(serializer.data)
        except IMAPConfig.DoesNotExist:
            return Response(
                {"detail": "Belum ada konfigurasi IMAP"},
                status=status.HTTP_404_NOT_FOUND
            )

    def post(self, request):
        """POST /api/imap/config/ — Buat konfigurasi IMAP baru"""
        # Jika sudah ada, arahkan ke update
        if IMAPConfig.objects.filter(user=request.user).exists():
            return Response(
                {"detail": "Konfigurasi sudah ada. Gunakan PUT untuk update."},
                status=status.HTTP_400_BAD_REQUEST
            )
        serializer = IMAPConfigSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        """PUT /api/imap/config/ — Update konfigurasi IMAP"""
        try:
            config = IMAPConfig.objects.get(user=request.user)
        except IMAPConfig.DoesNotExist:
            return Response(
                {"detail": "Belum ada konfigurasi IMAP"},
                status=status.HTTP_404_NOT_FOUND
            )
        serializer = IMAPConfigSerializer(config, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN
# ─────────────────────────────────────────────────────────────────────────────

class DomainListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """GET /api/domains/ — List semua domain milik user"""
        domains = Domain.objects.filter(user=request.user)
        serializer = DomainSerializer(domains, many=True)
        return Response(serializer.data)

    def post(self, request):
        """POST /api/domains/ — Tambah domain baru"""
        serializer = DomainSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DomainDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def _get_domain(self, domain_id, user):
        try:
            return Domain.objects.get(id=domain_id, user=user)
        except Domain.DoesNotExist:
            return None

    def get(self, request, domain_id):
        """GET /api/domains/{id}/ — Detail domain"""
        domain = self._get_domain(domain_id, request.user)
        if not domain:
            return Response({"detail": "Domain tidak ditemukan"}, status=404)
        return Response(DomainSerializer(domain).data)

    def delete(self, request, domain_id):
        """DELETE /api/domains/{id}/ — Hapus domain"""
        domain = self._get_domain(domain_id, request.user)
        if not domain:
            return Response({"detail": "Domain tidak ditemukan"}, status=404)
        domain.delete()
        return Response({"message": "Domain berhasil dihapus"}, status=204)


# ─────────────────────────────────────────────────────────────────────────────
# FETCH EMAIL (trigger Celery)
# ─────────────────────────────────────────────────────────────────────────────

class FetchEmailView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """POST /api/reports/fetch-email/ — Trigger fetch email DMARC via Celery"""
        if not IMAPConfig.objects.filter(user=request.user, is_active=True).exists():
            return Response(
                {"detail": "Konfigurasi IMAP belum ada atau tidak aktif"},
                status=status.HTTP_400_BAD_REQUEST
            )
        task = fetch_dmarc_emails_task.delay(request.user.id)
        return Response({
            "message": "Proses fetch email dimulai",
            "task_id": task.id,
        }, status=status.HTTP_202_ACCEPTED)


class TaskStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, task_id):
        """GET /api/tasks/{task_id}/status/ — Cek status Celery task"""
        result = AsyncResult(task_id)
        response_data = {
            "task_id": task_id,
            "status": result.status,   # PENDING / STARTED / SUCCESS / FAILURE / RETRY
        }
        if result.status == 'SUCCESS':
            response_data['result'] = result.result
        elif result.status == 'FAILURE':
            response_data['error'] = str(result.result)
        return Response(response_data)


# ─────────────────────────────────────────────────────────────────────────────
# UPLOAD MANUAL
# ─────────────────────────────────────────────────────────────────────────────

class ReportUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        """POST /api/reports/upload/ — Upload file XML/gz/zip secara manual"""
        serializer = ReportUploadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        file_obj = serializer.validated_data['file']
        domain_id = serializer.validated_data.get('domain_id')

        try:
            raw_bytes = file_obj.read()
            xml_bytes = decompress_attachment(raw_bytes, file_obj.name)
        except ValueError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Opsional: link ke domain
        domain = None
        if domain_id:
            domain = Domain.objects.filter(id=domain_id, user=request.user).first()

        report = DMARCReport.objects.create(
            user=request.user,
            domain=domain,
            raw_xml=xml_bytes.decode('utf-8', errors='replace'),
            source_email_subject=f"Manual upload: {file_obj.name}",
            status='pending',
        )

        # Trigger parsing async
        task = parse_dmarc_report_task.delay(str(report.id))

        return Response({
            "message": "File berhasil diupload, sedang diproses",
            "report_id": str(report.id),
            "task_id": task.id,
        }, status=status.HTTP_202_ACCEPTED)


# ─────────────────────────────────────────────────────────────────────────────
# REPORTS
# ─────────────────────────────────────────────────────────────────────────────

class ReportListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        GET /api/reports/
        Query params: domain_id, status, date_from, date_to, page, page_size
        """
        qs = DMARCReport.objects.filter(user=request.user)

        # Filter
        domain_id = request.query_params.get('domain_id')
        report_status = request.query_params.get('status')
        date_from = request.query_params.get('date_from')
        date_to = request.query_params.get('date_to')

        if domain_id:
            qs = qs.filter(domain_id=domain_id)
        if report_status:
            qs = qs.filter(status=report_status)
        if date_from:
            qs = qs.filter(date_begin__gte=date_from)
        if date_to:
            qs = qs.filter(date_end__lte=date_to)

        # Simple pagination
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 20))
        start = (page - 1) * page_size
        end = start + page_size

        total = qs.count()
        reports = qs[start:end]

        return Response({
            "count": total,
            "page": page,
            "page_size": page_size,
            "results": DMARCReportListSerializer(reports, many=True).data,
        })


class ReportDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        """GET /api/reports/{id}/ — Detail laporan beserta semua records"""
        try:
            report = DMARCReport.objects.prefetch_related('records').get(
                id=report_id, user=request.user
            )
        except DMARCReport.DoesNotExist:
            return Response({"detail": "Laporan tidak ditemukan"}, status=404)

        serializer = DMARCReportDetailSerializer(report)
        return Response(serializer.data)

    def delete(self, request, report_id):
        """DELETE /api/reports/{id}/ — Hapus laporan"""
        try:
            report = DMARCReport.objects.get(id=report_id, user=request.user)
        except DMARCReport.DoesNotExist:
            return Response({"detail": "Laporan tidak ditemukan"}, status=404)
        report.delete()
        return Response({"message": "Laporan berhasil dihapus"}, status=204)


# ─────────────────────────────────────────────────────────────────────────────
# RECORDS
# ─────────────────────────────────────────────────────────────────────────────

class RecordListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        GET /api/records/
        Query params: report_id, source_ip, is_suspicious, spf_result, dkim_result
        """
        from .serializers import DMARCRecordSerializer

        qs = DMARCRecord.objects.filter(report__user=request.user).select_related('report')

        report_id = request.query_params.get('report_id')
        source_ip = request.query_params.get('source_ip')
        is_suspicious = request.query_params.get('is_suspicious')
        spf_result = request.query_params.get('spf_result')
        dkim_result = request.query_params.get('dkim_result')

        if report_id:
            qs = qs.filter(report_id=report_id)
        if source_ip:
            qs = qs.filter(source_ip=source_ip)
        if is_suspicious is not None:
            qs = qs.filter(is_suspicious=is_suspicious.lower() == 'true')
        if spf_result:
            qs = qs.filter(spf_result=spf_result)
        if dkim_result:
            qs = qs.filter(dkim_result=dkim_result)

        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 50))
        start = (page - 1) * page_size
        end = start + page_size

        total = qs.count()
        records = qs[start:end]

        return Response({
            "count": total,
            "page": page,
            "page_size": page_size,
            "results": DMARCRecordSerializer(records, many=True).data,
        })


# ─────────────────────────────────────────────────────────────────────────────
# STATISTIK
# ─────────────────────────────────────────────────────────────────────────────

class ReportStatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """GET /api/reports/stats/ — Statistik agregat untuk dashboard"""
        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)

        reports = DMARCReport.objects.filter(
            user=request.user, status='parsed', created_at__gte=since
        )
        records = DMARCRecord.objects.filter(
            report__user=request.user, created_at__gte=since
        )

        agg = reports.aggregate(
            total_messages=Sum('total_messages'),
            passed_messages=Sum('passed_messages'),
            failed_messages=Sum('failed_messages'),
        )

        total_msg   = agg['total_messages'] or 0
        passed_msg  = agg['passed_messages'] or 0
        failed_msg  = agg['failed_messages'] or 0
        pass_rate   = round((passed_msg / total_msg * 100), 2) if total_msg > 0 else 0

        # Top failing IPs
        top_failing = (
            records.filter(is_suspicious=True)
            .values('source_ip', 'geo_country', 'geo_city')
            .annotate(count=Sum('message_count'))
            .order_by('-count')[:10]
        )

        # Laporan per hari (7 hari terakhir)
        from django.db.models.functions import TruncDate
        reports_by_day = (
            reports.annotate(day=TruncDate('created_at'))
            .values('day')
            .annotate(
                total=Count('id'),
                messages=Sum('total_messages'),
                failed=Sum('failed_messages'),
            )
            .order_by('day')
        )

        return Response({
            "period_days": days,
            "total_reports": reports.count(),
            "total_messages": total_msg,
            "passed_messages": passed_msg,
            "failed_messages": failed_msg,
            "pass_rate": pass_rate,
            "suspicious_ips": records.filter(is_suspicious=True).values('source_ip').distinct().count(),
            "top_failing_ips": list(top_failing),
            "reports_by_day": list(reports_by_day),
        })


# ─────────────────────────────────────────────────────────────────────────────
# ALERTS
# ─────────────────────────────────────────────────────────────────────────────

class AlertListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """GET /api/alerts/ — List alert, filter is_read"""
        qs = AlertLog.objects.filter(user=request.user)
        is_read = request.query_params.get('is_read')
        if is_read is not None:
            qs = qs.filter(is_read=is_read.lower() == 'true')

        serializer = AlertLogSerializer(qs[:50], many=True)
        return Response({
            "count": qs.count(),
            "unread": qs.filter(is_read=False).count(),
            "results": serializer.data,
        })


class AlertMarkReadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, alert_id):
        """POST /api/alerts/{id}/read/ — Tandai alert sudah dibaca"""
        try:
            alert = AlertLog.objects.get(id=alert_id, user=request.user)
            alert.is_read = True
            alert.save(update_fields=['is_read'])
            return Response({"message": "Alert ditandai sudah dibaca"})
        except AlertLog.DoesNotExist:
            return Response({"detail": "Alert tidak ditemukan"}, status=404)


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD OVERVIEW (untuk Next.js)
# ─────────────────────────────────────────────────────────────────────────────

class DashboardOverviewView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """GET /api/dashboard/overview/ — Ringkasan untuk halaman utama dashboard"""
        since = timezone.now() - timedelta(days=30)

        reports = DMARCReport.objects.filter(user=request.user, status='parsed')
        recent_reports = reports.filter(created_at__gte=since)
        records = DMARCRecord.objects.filter(report__user=request.user)
        recent_records = records.filter(created_at__gte=since)

        agg = recent_reports.aggregate(
            total_msg=Sum('total_messages'),
            passed_msg=Sum('passed_messages'),
            failed_msg=Sum('failed_messages'),
        )

        total_msg  = agg['total_msg'] or 0
        passed_msg = agg['passed_msg'] or 0
        failed_msg = agg['failed_msg'] or 0
        pass_rate  = round((passed_msg / total_msg * 100), 2) if total_msg > 0 else 0

        # IP Map data (lat, lon untuk peta)
        geo_data = (
            recent_records
            .filter(geo_latitude__isnull=False)
            .values(
                'source_ip', 'geo_country', 'geo_city',
                'geo_latitude', 'geo_longitude',
                'is_suspicious', 'spf_result', 'dkim_result'
            )
            .annotate(total=Sum('message_count'))
            .order_by('-total')[:200]
        )

        # Recent alerts (belum dibaca)
        unread_alerts = AlertLog.objects.filter(
            user=request.user, is_read=False
        ).count()

        # Domain list
        domains = Domain.objects.filter(user=request.user).values(
            'id', 'domain_name', 'is_verified'
        )

        return Response({
            "summary": {
                "total_reports": reports.count(),
                "total_messages_30d": total_msg,
                "pass_rate_30d": pass_rate,
                "failed_messages_30d": failed_msg,
                "suspicious_ips_30d": recent_records.filter(is_suspicious=True)
                                                     .values('source_ip')
                                                     .distinct()
                                                     .count(),
                "unread_alerts": unread_alerts,
            },
            "domains": list(domains),
            "geo_data": list(geo_data),
            "recent_reports": DMARCReportListSerializer(
                recent_reports.order_by('-created_at')[:5], many=True
            ).data,
        })
    

@csrf_exempt
def scan_domain(request):
    print("🔥 HIT VIEW")

    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    try:
        # SAFE PARSING
        try:
            data = json.loads(request.body.decode("utf-8"))
        except Exception:
            data = {}

        domain = data.get("domain")

        if not domain:
            return JsonResponse({"error": "domain required"}, status=400)

        print("DOMAIN:", domain)

        result = check_domain(domain, None)

        return JsonResponse(result)

    except Exception as e:
        print("❌ ERROR:", str(e))
        return JsonResponse({"error": str(e)}, status=500)



@csrf_exempt
def scan_domain_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8"))
        domain = data.get("domain")

        if not domain:
            return JsonResponse({"error": "domain required"}, status=400)

        # 🔥 FIX DI SINI
        user = request.user if request.user.is_authenticated else None

        result = scan_domain(domain, user)

        return JsonResponse(result)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    

def scan_domain_api(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    data = json.loads(request.body)
    domain = data.get("domain")

    user = request.user  # user login

    result = scan_domain(domain, user)

    return JsonResponse(result)

class AlertDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, alert_id):
        try:
            alert = AlertLog.objects.get(id=alert_id, user=request.user)
            alert.delete()
            return Response({'message': 'Alert berhasil dihapus'}, status=204)
        except AlertLog.DoesNotExist:
            return Response({'detail': 'Alert tidak ditemukan'}, status=404)