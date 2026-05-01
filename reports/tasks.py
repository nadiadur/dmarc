"""
Celery Tasks untuk sistem DMARC Report.

Tasks:
  1. fetch_dmarc_emails_task     — fetch email via Gmail API
  2. fetch_all_users_emails_task — fetch semua user (Celery Beat)
  3. parse_dmarc_report_task     — parse XML, simpan records ke DB
  4. enrich_geo_task             — isi geolocation per record
  5. send_alert_task             — kirim email notifikasi
  6. send_telegram_alert_task    — kirim pesan Telegram
"""

import logging
from celery import shared_task
from django.utils import timezone as dj_timezone
from django.core.mail import send_mail
from django.conf import settings

from .models import IMAPConfig, DMARCReport, DMARCRecord, AlertLog, Domain
from .parser import decompress_attachment, parse_dmarc_xml, calculate_summary
from django.utils import timezone
from django.db import transaction
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# TASK 1 — Fetch email via Gmail API
# ─────────────────────────────────────────────────────────────────────────────

@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def fetch_dmarc_emails_task(self, user_id: int):
    """Fetch email laporan DMARC via Gmail API."""
    from .gmail_fetcher import fetch_dmarc_emails
    from accounts.models import User

    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return {'status': 'error', 'reason': 'user_not_found'}

    created_report_ids = []

    try:
        emails = fetch_dmarc_emails(max_results=50)
        logger.info(f"Fetch {len(emails)} email untuk user {user_id}")

        for email_data in emails:
            subject = email_data['subject']
            date_str = email_data['date']
            email_date = None

            try:
                from email.utils import parsedate_to_datetime
                email_date = parsedate_to_datetime(date_str)
            except Exception:
                pass

            for attachment in email_data['attachments']:
                filename = attachment['filename']
                raw_data = attachment['data']

                try:
                    xml_bytes = decompress_attachment(raw_data, filename)
                except ValueError as e:
                    logger.error(f"Gagal decompress {filename}: {e}")
                    continue

                report = DMARCReport.objects.create(
                    user=user,
                    raw_xml=xml_bytes.decode('utf-8', errors='replace'),
                    source_email_subject=subject[:500],
                    source_email_date=email_date,
                    status='pending',
                )
                created_report_ids.append(str(report.id))
                parse_dmarc_report_task.delay(str(report.id))

        # Update last_fetched_at
        try:
            config = IMAPConfig.objects.get(user=user)
            config.last_fetched_at = dj_timezone.now()
            config.save(update_fields=['last_fetched_at'])
        except IMAPConfig.DoesNotExist:
            pass

        return {
            'status': 'ok',
            'emails_processed': len(emails),
            'reports_created': created_report_ids,
        }

    except Exception as e:
        logger.exception(f"Error fetch Gmail API: {e}")
        raise self.retry(exc=e)


# ─────────────────────────────────────────────────────────────────────────────
# TASK 2 — Fetch semua user (untuk Celery Beat)
# ─────────────────────────────────────────────────────────────────────────────

@shared_task
def fetch_all_users_emails_task():
    """Fetch email untuk semua user. Dijalankan Celery Beat setiap 15 menit."""
    from accounts.models import User
    from pathlib import Path

    token_path = Path(__file__).resolve().parent.parent / 'token.json'
    if not token_path.exists():
        logger.warning("token.json tidak ditemukan. Skip fetch.")
        return {'status': 'skipped', 'reason': 'no_token'}

    users = User.objects.filter(is_active=True).exclude(role='admin')
    triggered = 0
    for user in users:
        fetch_dmarc_emails_task.delay(user.id)
        triggered += 1

    return {'status': 'ok', 'users_triggered': triggered}



@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def analyze_report_with_ai_task(self, report_id: str):
    from .models import DMARCReport, DMARCRecord
    from .ai_analysis import analyze_dmarc_report

    try:
        report = DMARCReport.objects.get(id=report_id, status='parsed')
    except DMARCReport.DoesNotExist:
        return {'status': 'skipped'}

    records = list(DMARCRecord.objects.filter(report=report))

    try:
        result = analyze_dmarc_report(report, records)

        if not isinstance(result, dict):
            raise ValueError("AI result invalid")

        with transaction.atomic():

            # Simpan hasil analisa ke report
            report.ai_summary         = result.get('summary', '')
            report.ai_risk_level      = result.get('risk_level', 'unknown')
            report.ai_risk_reason     = result.get('risk_reason', '')
            report.ai_findings        = result.get('findings', [])
            report.ai_recommendations = result.get('recommendations', [])
            report.ai_explanation     = result.get('explanation', '')
            report.ai_policy_advice   = result.get('policy_advice', '')
            report.ai_analyzed_at     = timezone.now()

            # 🔥 FIX UTAMA
            report.save()

        # 🔥 PASTIKAN KE SAVE
        report.refresh_from_db()

        logger.info(
            f"AI OK {report_id} | {report.ai_risk_level} | {report.ai_analyzed_at}"
        )

        return {
            'status': 'ok',
            'report_id': report_id,
        }

    except Exception as e:
        logger.error(f"AI ERROR {report_id}: {e}")
        raise self.retry(exc=e)
# ─────────────────────────────────────────────────────────────────────────────
# TASK 3 — Parse XML dan simpan records
# ─────────────────────────────────────────────────────────────────────────────

@shared_task(bind=True, max_retries=2)
def parse_dmarc_report_task(self, report_id: str):
    """Parse raw_xml dari DMARCReport, simpan DMARCRecord, trigger alert."""
    try:
        report = DMARCReport.objects.get(id=report_id)
    except DMARCReport.DoesNotExist:
        logger.error(f"DMARCReport tidak ditemukan: {report_id}")
        return {'status': 'error', 'reason': 'report_not_found'}

    try:
        parsed = parse_dmarc_xml(report.raw_xml)
    except ValueError as e:
        report.status = 'error'
        report.error_message = str(e)
        report.save(update_fields=['status', 'error_message'])
        return {'status': 'error', 'reason': str(e)}

    meta    = parsed['metadata']
    policy  = parsed['policy']
    records = parsed['records']

    report.org_name      = meta.get('org_name', '')
    report.org_email     = meta.get('org_email', '')
    report.report_id     = meta.get('report_id', '')
    report.date_begin    = meta.get('date_begin')
    report.date_end      = meta.get('date_end')
    report.domain_policy = policy.get('domain', '')
    report.policy_adkim  = policy.get('adkim', 'r')
    report.policy_aspf   = policy.get('aspf', 'r')
    report.policy_p      = policy.get('p', 'none')
    report.policy_sp     = policy.get('sp', 'none')
    report.policy_pct    = policy.get('pct', 100)

    domain_name = policy.get('domain', '')
    if domain_name:
        domain_obj = Domain.objects.filter(
            user=report.user, domain_name=domain_name
        ).first()
        if domain_obj:
            report.domain = domain_obj

    summary = calculate_summary(records)
    report.total_messages   = summary['total_messages']
    report.passed_messages  = summary['passed_messages']
    report.failed_messages  = summary['failed_messages']
    report.status           = 'parsed'
    report.parsed_at        = dj_timezone.now()
    report.save()

    record_objs = []
    suspicious_record_ids = []

    for r in records:
        obj = DMARCRecord(
            report=report,
            source_ip=r.get('source_ip', '0.0.0.0'),
            message_count=r.get('message_count', 1),
            disposition=r.get('disposition', 'none'),
            dkim_result=r.get('dkim_result', 'none'),
            spf_result=r.get('spf_result', 'none'),
            envelope_to=r.get('envelope_to', ''),
            envelope_from=r.get('envelope_from', ''),
            header_from=r.get('header_from', ''),
            dkim_domain=r.get('dkim_domain', ''),
            dkim_selector=r.get('dkim_selector', ''),
            dkim_human_result=r.get('dkim_human_result', ''),
            spf_domain=r.get('spf_domain', ''),
            spf_scope=r.get('spf_scope', ''),
            is_suspicious=r.get('is_suspicious', False),
        )
        record_objs.append(obj)

    created = DMARCRecord.objects.bulk_create(record_objs)

    for obj in created:
        if obj.is_suspicious:
            suspicious_record_ids.append(obj.id)
        enrich_geo_task.delay(obj.id)

    if suspicious_record_ids:
        for rid in suspicious_record_ids:
            send_alert_task.delay(rid, str(report.id))

    logger.info(
        f"Parsed report {report_id}: "
        f"{len(created)} records, {len(suspicious_record_ids)} suspicious"
    )

    analyze_report_with_ai_task.delay(str(report.id))

    return {
        'status': 'ok',
        'report_id': str(report.id),
        'records_created': len(created),
        'suspicious_count': len(suspicious_record_ids),
    }


# ─────────────────────────────────────────────────────────────────────────────
# TASK 4 — Geolocation enrichment
# ─────────────────────────────────────────────────────────────────────────────

@shared_task
def enrich_geo_task(record_id: int):
    """Lookup geolocation untuk source_ip menggunakan ip-api.com."""
    import requests

    try:
        record = DMARCRecord.objects.get(id=record_id)
    except DMARCRecord.DoesNotExist:
        return

    ip = record.source_ip
    if ip.startswith(('10.', '192.168.', '127.', '172.')):
        return

    try:
        resp = requests.get(
            f'http://ip-api.com/json/{ip}',
            params={'fields': 'country,city,lat,lon,isp,status'},
            timeout=5
        )
        data = resp.json()
        if data.get('status') == 'success':
            record.geo_country   = data.get('country', '')
            record.geo_city      = data.get('city', '')
            record.geo_latitude  = data.get('lat')
            record.geo_longitude = data.get('lon')
            record.geo_isp       = data.get('isp', '')
            record.save(update_fields=[
                'geo_country', 'geo_city',
                'geo_latitude', 'geo_longitude', 'geo_isp'
            ])
    except Exception as e:
        logger.warning(f"Geo lookup gagal untuk IP {ip}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# TASK 5 — Kirim alert (Email + Telegram)
# ─────────────────────────────────────────────────────────────────────────────

@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def send_alert_task(self, record_id: int, report_id: str):
    """Kirim notifikasi Email + Telegram saat ada aktivitas mencurigakan."""
    from .models import NotificationConfig
    from .telegram_service import send_telegram_message, build_suspicious_ip_message, build_fail_message

    try:
        record = DMARCRecord.objects.select_related('report__user').get(id=record_id)
        report = DMARCReport.objects.get(id=report_id)
        user   = report.user
    except (DMARCRecord.DoesNotExist, DMARCReport.DoesNotExist):
        return

    # Tentukan tipe alert
    if record.dkim_result != 'pass' and record.spf_result != 'pass':
        alert_type = 'both_fail'
        is_suspicious = True
    elif record.spf_result != 'pass':
        alert_type = 'spf_fail'
        is_suspicious = False
    else:
        alert_type = 'dkim_fail'
        is_suspicious = False

    # ── Kirim Email ───────────────────────────────────────────────────────────
    subject = f"[DMARC Alert] Email mencurigakan terdeteksi di domain {report.domain_policy}"
    body = f"""
Halo {user.name},

Sistem DMARC telah mendeteksi aktivitas mencurigakan pada domain Anda.

Domain       : {report.domain_policy}
Source IP    : {record.source_ip}
Lokasi       : {record.geo_city or '-'}, {record.geo_country or '-'}
ISP          : {record.geo_isp or '-'}
Waktu Laporan: {report.date_begin.strftime('%d %b %Y %H:%M UTC') if report.date_begin else '-'}
Jumlah Pesan : {record.message_count}

SPF          : {record.spf_result.upper()}
DKIM         : {record.dkim_result.upper()}
Disposition  : {record.disposition.upper()}

Segera periksa konfigurasi SPF dan DKIM Anda.

Salam,
Tim DMARC Report
"""
    try:
        send_mail(
            subject=subject,
            message=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        AlertLog.objects.create(
            record=record, report=report, user=user,
            alert_type=alert_type, channel='email',
            recipient=user.email, subject=subject,
            message_body=body, status='sent',
            sent_at=dj_timezone.now(),
        )
        logger.info(f"Alert email terkirim ke {user.email}")
    except Exception as e:
        AlertLog.objects.create(
            record=record, report=report, user=user,
            alert_type=alert_type, channel='email',
            recipient=user.email, subject=subject,
            status='failed', error_detail=str(e),
        )
        logger.error(f"Gagal kirim alert email: {e}")

    # ── Kirim Telegram ────────────────────────────────────────────────────────
    try:
        notif_config = NotificationConfig.objects.get(user=user)

        should_notify = (
            notif_config.telegram_enabled and (
                (is_suspicious and notif_config.notify_on_suspicious) or
                notif_config.notify_on_any_fail
            )
        )

        if should_notify:
            message = build_suspicious_ip_message(report, record) if is_suspicious else build_fail_message(report, record)

            success = send_telegram_message(
                notif_config.telegram_bot_token,
                notif_config.telegram_chat_id,
                message,
            )

            AlertLog.objects.create(
                record=record, report=report, user=user,
                alert_type=alert_type, channel='telegram',
                recipient=notif_config.telegram_chat_id,
                message_body=message,
                status='sent' if success else 'failed',
                sent_at=dj_timezone.now() if success else None,
            )
            logger.info(f"Telegram alert {'terkirim' if success else 'gagal'}")

    except NotificationConfig.DoesNotExist:
        pass  # User belum setup Telegram, skip
    except Exception as e:
        logger.error(f"Error Telegram: {e}")

    record.alert_sent = True
    record.save(update_fields=['alert_sent'])

    return {'status': 'ok', 'alert_type': alert_type}

