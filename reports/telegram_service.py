"""
Telegram Notification Service
Kirim notifikasi ke Telegram saat ada email gagal validasi DMARC
"""

import requests
import logging

logger = logging.getLogger(__name__)


def send_telegram_message(bot_token: str, chat_id: str, message: str) -> bool:
    """
    Kirim pesan ke Telegram.
    Return True jika berhasil, False jika gagal.
    """
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        'chat_id': chat_id,
        'text': message,
        'parse_mode': 'Markdown',
    }

    try:
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        return True
    except requests.exceptions.HTTPError as e:
        logger.error(f"Telegram HTTP error: {e.response.text}")
        return False
    except Exception as e:
        logger.error(f"Telegram error: {e}")
        return False


def verify_telegram_config(bot_token: str, chat_id: str) -> dict:
    """
    Verifikasi bot token dan chat_id valid.
    Kirim pesan test ke user.
    """
    test_message = (
        "✅ *DMARC Alert Bot aktif!*\n\n"
        "Kamu akan menerima notifikasi di sini setiap kali "
        "ada aktivitas mencurigakan pada domain email kamu.\n\n"
        "_Pesan ini adalah konfirmasi bahwa konfigurasi berhasil._"
    )

    success = send_telegram_message(bot_token, chat_id, test_message)
    return {
        'success': success,
        'message': 'Pesan test berhasil dikirim!' if success else 'Gagal kirim pesan. Cek bot token dan chat ID.',
    }


def build_suspicious_ip_message(report, record) -> str:
    """Build pesan notifikasi untuk IP mencurigakan."""
    return (
        f"🚨 *DMARC Alert — IP Mencurigakan*\n\n"
        f"*Domain:* `{report.domain_policy}`\n"
        f"*Source IP:* `{record.source_ip}`\n"
        f"*Lokasi:* {record.geo_city or '-'}, {record.geo_country or '-'}\n"
        f"*ISP:* {record.geo_isp or '-'}\n\n"
        f"*Hasil Validasi:*\n"
        f"▸ SPF: `{record.spf_result.upper()}`\n"
        f"▸ DKIM: `{record.dkim_result.upper()}`\n"
        f"▸ Disposition: `{record.disposition.upper()}`\n\n"
        f"*Jumlah Pesan:* {record.message_count}\n"
        f"*Waktu:* {report.date_begin.strftime('%d %b %Y %H:%M UTC') if report.date_begin else '-'}\n\n"
        f"⚠️ Kemungkinan ada pihak lain yang menggunakan domain email kamu!\n"
        f"Segera cek dashboard DMARC kamu."
    )


def build_fail_message(report, record) -> str:
    """Build pesan notifikasi untuk semua kegagalan validasi."""
    spf = record.spf_result.upper()
    dkim = record.dkim_result.upper()

    spf_icon = '✅' if spf == 'PASS' else '❌'
    dkim_icon = '✅' if dkim == 'PASS' else '❌'

    return (
        f"⚠️ *DMARC Alert — Kegagalan Validasi*\n\n"
        f"*Domain:* `{report.domain_policy}`\n"
        f"*Source IP:* `{record.source_ip}`\n"
        f"*Lokasi:* {record.geo_city or '-'}, {record.geo_country or '-'}\n\n"
        f"*Hasil Validasi:*\n"
        f"{spf_icon} SPF: `{spf}`\n"
        f"{dkim_icon} DKIM: `{dkim}`\n"
        f"▸ Disposition: `{record.disposition.upper()}`\n\n"
        f"*Jumlah Pesan:* {record.message_count}\n"
        f"*Waktu:* {report.date_begin.strftime('%d %b %Y %H:%M UTC') if report.date_begin else '-'}"
    )