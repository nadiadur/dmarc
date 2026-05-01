from django.db import models
from django.conf import settings
import uuid


class IMAPConfig(models.Model):
    """Konfigurasi IMAP untuk fetch email laporan DMARC"""
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='imap_config'
    )
    host = models.CharField(max_length=255)           # e.g. imap.gmail.com
    port = models.IntegerField(default=993)
    username = models.EmailField()
    password = models.CharField(max_length=255)       # simpan encrypted di production
    use_ssl = models.BooleanField(default=True)
    mailbox = models.CharField(max_length=100, default='INBOX')
    is_active = models.BooleanField(default=True)
    last_fetched_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'imap_configs'
        verbose_name = 'IMAP Config'

    def __str__(self):
        return f"{self.user.email} → {self.host}"


class Domain(models.Model):
    """Domain yang dipantau laporannya"""
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='domains'
    )
    domain_name = models.CharField(max_length=255)      # e.g. yourdomain.com
    rua_email = models.EmailField()                      # alamat penerima laporan DMARC
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'domains'
        unique_together = ('user', 'domain_name')
        ordering = ['-created_at']

    def __str__(self):
        return self.domain_name


class DMARCReport(models.Model):
    """
    Satu file XML laporan DMARC = satu DMARCReport.
    Berisi metadata laporan dari mail server pengirim.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('parsed', 'Parsed'),
        ('error', 'Error'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    domain = models.ForeignKey(
        Domain,
        on_delete=models.CASCADE,
        related_name='reports',
        null=True, blank=True
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='dmarc_reports'
    )

    # Metadata dari tag <report_metadata> di XML
    org_name = models.CharField(max_length=255, blank=True)         # pengirim laporan (e.g. Google)
    org_email = models.EmailField(blank=True)
    report_id = models.CharField(max_length=255, blank=True)        # ID unik dari pengirim
    date_begin = models.DateTimeField(null=True, blank=True)        # periode laporan mulai
    date_end = models.DateTimeField(null=True, blank=True)          # periode laporan selesai

    # Metadata dari tag <policy_published>
    domain_policy = models.CharField(max_length=255, blank=True)    # domain yang dilaporkan
    policy_adkim = models.CharField(max_length=10, blank=True)      # r=relaxed, s=strict
    policy_aspf = models.CharField(max_length=10, blank=True)
    policy_p = models.CharField(max_length=20, blank=True)          # none/quarantine/reject
    policy_sp = models.CharField(max_length=20, blank=True)         # subdomain policy
    policy_pct = models.IntegerField(default=100)                   # persentase pesan yang di-filter

    # Raw file
    raw_xml = models.TextField(blank=True)                          # isi XML asli
    source_email_subject = models.CharField(max_length=500, blank=True)
    source_email_date = models.DateTimeField(null=True, blank=True)

    # Status parsing
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    error_message = models.TextField(blank=True)

    # Agregat cepat (dihitung saat parsing)
    total_messages = models.IntegerField(default=0)
    passed_messages = models.IntegerField(default=0)
    failed_messages = models.IntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    parsed_at = models.DateTimeField(null=True, blank=True)

    # ── AI Analysis ──────────────────────────────────────────────────────────
    ai_summary = models.TextField(blank=True)
    ai_risk_level = models.CharField(
        max_length=20,
        choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('unknown', 'Unknown')],
        blank=True
    )
    ai_risk_reason = models.TextField(blank=True)
    ai_findings = models.JSONField(default=list, blank=True)
    ai_recommendations = models.JSONField(default=list, blank=True)
    ai_explanation = models.TextField(blank=True)
    ai_policy_advice = models.TextField(blank=True)
    ai_analyzed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'dmarc_reports'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.org_name} | {self.domain_policy} | {self.date_begin}"

    @property
    def pass_rate(self):
        if self.total_messages == 0:
            return 0
        return round((self.passed_messages / self.total_messages) * 100, 2)


class DMARCRecord(models.Model):
    """
    Satu baris <record> di dalam XML = satu DMARCRecord.
    Berisi detail per source IP: hasil SPF, DKIM, dan policy DMARC.
    """
    RESULT_CHOICES = [
        ('pass', 'Pass'),
        ('fail', 'Fail'),
        ('softfail', 'Softfail'),
        ('neutral', 'Neutral'),
        ('none', 'None'),
        ('temperror', 'Temperror'),
        ('permerror', 'Permerror'),
    ]

    DISPOSITION_CHOICES = [
        ('none', 'None'),
        ('quarantine', 'Quarantine'),
        ('reject', 'Reject'),
    ]

    report = models.ForeignKey(
        DMARCReport,
        on_delete=models.CASCADE,
        related_name='records'
    )

    # Dari <row>
    source_ip = models.GenericIPAddressField()
    message_count = models.IntegerField(default=1)
    disposition = models.CharField(
        max_length=20, choices=DISPOSITION_CHOICES, default='none'
    )

    # Dari <policy_evaluated>
    dkim_result = models.CharField(max_length=20, choices=RESULT_CHOICES, default='none')
    spf_result = models.CharField(max_length=20, choices=RESULT_CHOICES, default='none')

    # Dari <identifiers>
    envelope_to = models.CharField(max_length=255, blank=True)
    envelope_from = models.CharField(max_length=255, blank=True)
    header_from = models.CharField(max_length=255, blank=True)

    # Dari <auth_results><dkim>
    dkim_domain = models.CharField(max_length=255, blank=True)
    dkim_selector = models.CharField(max_length=255, blank=True)
    dkim_human_result = models.TextField(blank=True)

    # Dari <auth_results><spf>
    spf_domain = models.CharField(max_length=255, blank=True)
    spf_scope = models.CharField(max_length=50, blank=True)     # mfrom / helo

    # Geolocation (diisi async oleh Celery)
    geo_country = models.CharField(max_length=100, blank=True)
    geo_city = models.CharField(max_length=100, blank=True)
    geo_latitude = models.FloatField(null=True, blank=True)
    geo_longitude = models.FloatField(null=True, blank=True)
    geo_isp = models.CharField(max_length=255, blank=True)

    # Flag otomatis
    is_suspicious = models.BooleanField(default=False)          # True jika spf+dkim fail
    alert_sent = models.BooleanField(default=False)             # True jika notif sudah dikirim

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'dmarc_records'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.source_ip} | SPF:{self.spf_result} DKIM:{self.dkim_result}"

    @property
    def is_fully_passing(self):
        return self.spf_result == 'pass' and self.dkim_result == 'pass'


class AlertLog(models.Model):
    """
    Log setiap notifikasi yang dikirim ke admin/pemilik email.
    """
    ALERT_TYPE_CHOICES = [
        ('spf_fail', 'SPF Fail'),
        ('dkim_fail', 'DKIM Fail'),
        ('both_fail', 'SPF & DKIM Fail'),
        ('suspicious_ip', 'Suspicious IP'),
        ('policy_reject', 'Policy Reject'),
    ]

    CHANNEL_CHOICES = [
        ('email', 'Email'),
        ('telegram', 'Telegram'),
    ]

    STATUS_CHOICES = [
        ('sent', 'Sent'),
        ('failed', 'Failed'),
        ('pending', 'Pending'),
    ]

    record = models.ForeignKey(
        DMARCRecord,
        on_delete=models.CASCADE,
        related_name='alert_logs',
        null=True, blank=True
    )
    report = models.ForeignKey(
        DMARCReport,
        on_delete=models.CASCADE,
        related_name='alert_logs',
        null=True, blank=True
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='alert_logs'
    )

    alert_type = models.CharField(max_length=30, choices=ALERT_TYPE_CHOICES)
    channel = models.CharField(max_length=20, choices=CHANNEL_CHOICES)
    recipient = models.CharField(max_length=255)       # email atau chat_id Telegram
    subject = models.CharField(max_length=500, blank=True)
    message_body = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    error_detail = models.TextField(blank=True)
    is_read = models.BooleanField(default=False)

    sent_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'alert_logs'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.alert_type} → {self.recipient} [{self.status}]"
    


class NotificationConfig(models.Model):
    """Konfigurasi notifikasi Telegram per user"""
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='notification_config'
    )
 
    # Telegram
    telegram_enabled = models.BooleanField(default=False)
    telegram_bot_token = models.CharField(max_length=255, blank=True)
    telegram_chat_id = models.CharField(max_length=100, blank=True)
 
    # Trigger settings
    notify_on_suspicious = models.BooleanField(default=True)   # SPF+DKIM fail
    notify_on_any_fail = models.BooleanField(default=False)    # semua kegagalan
 
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
 
    class Meta:
        db_table = 'notification_configs'
 
    def __str__(self):
        return f"{self.user.email} — Telegram: {self.telegram_enabled}"