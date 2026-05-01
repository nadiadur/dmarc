from rest_framework import serializers
from .models import IMAPConfig, Domain, DMARCReport, DMARCRecord, AlertLog


class IMAPConfigSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = IMAPConfig
        fields = [
            'id', 'host', 'port', 'username', 'password',
            'use_ssl', 'mailbox', 'is_active', 'last_fetched_at',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'last_fetched_at', 'created_at', 'updated_at']


class DomainSerializer(serializers.ModelSerializer):
    total_reports = serializers.SerializerMethodField()

    class Meta:
        model = Domain
        fields = [
            'id', 'domain_name', 'rua_email',
            'is_verified', 'total_reports', 'created_at'
        ]
        read_only_fields = ['id', 'is_verified', 'created_at']

    def get_total_reports(self, obj):
        return obj.reports.count()


class DMARCRecordSerializer(serializers.ModelSerializer):
    is_fully_passing = serializers.ReadOnlyField()

    class Meta:
        model = DMARCRecord
        fields = [
            'id', 'source_ip', 'message_count', 'disposition',
            'dkim_result', 'spf_result',
            'envelope_to', 'envelope_from', 'header_from',
            'dkim_domain', 'dkim_selector',
            'spf_domain', 'spf_scope',
            'geo_country', 'geo_city', 'geo_latitude', 'geo_longitude', 'geo_isp',
            'is_suspicious', 'is_fully_passing', 'alert_sent',
            'created_at',
        ]
        read_only_fields = fields


class DMARCReportListSerializer(serializers.ModelSerializer):
    """Serializer ringkas untuk list view (tanpa records)"""
    pass_rate = serializers.ReadOnlyField()
    domain_name = serializers.CharField(source='domain.domain_name', read_only=True)

    class Meta:
        model = DMARCReport
        fields = [
            'id', 'org_name', 'org_email', 'report_id',
            'domain_policy', 'domain_name',
            'date_begin', 'date_end',
            'policy_p', 'policy_sp',
            'total_messages', 'passed_messages', 'failed_messages', 'pass_rate',
            'status', 'created_at', 'parsed_at',
        ]
        read_only_fields = fields


class DMARCReportDetailSerializer(serializers.ModelSerializer):
    """Serializer lengkap untuk detail view (dengan records)"""
    records = DMARCRecordSerializer(many=True, read_only=True)
    pass_rate = serializers.ReadOnlyField()
    domain_name = serializers.CharField(source='domain.domain_name', read_only=True)

    class Meta:
        model = DMARCReport
        fields = [
            'id', 'org_name', 'org_email', 'report_id',
            'domain_policy', 'domain_name',
            'date_begin', 'date_end',
            'policy_adkim', 'policy_aspf', 'policy_p', 'policy_sp', 'policy_pct',
            'total_messages', 'passed_messages', 'failed_messages', 'pass_rate',
            'status', 'error_message',
            'source_email_subject', 'source_email_date',
            'created_at', 'parsed_at',
            'records',
        ]
        read_only_fields = fields


class ReportUploadSerializer(serializers.Serializer):
    """Untuk upload manual file XML / gz / zip"""
    file = serializers.FileField()
    domain_id = serializers.IntegerField(required=False)

    def validate_file(self, value):
        filename = value.name.lower()
        allowed = ('.xml', '.gz', '.zip')
        if not any(filename.endswith(ext) for ext in allowed):
            raise serializers.ValidationError(
                "Format file tidak didukung. Gunakan .xml, .gz, atau .zip"
            )
        # Batas ukuran 10MB
        if value.size > 10 * 1024 * 1024:
            raise serializers.ValidationError("Ukuran file maksimal 10MB")
        return value


class AlertLogSerializer(serializers.ModelSerializer):
    source_ip = serializers.CharField(source='record.source_ip', read_only=True)
    domain = serializers.CharField(source='report.domain_policy', read_only=True)

    class Meta:
        model = AlertLog
        fields = [
            'id', 'alert_type', 'channel', 'recipient',
            'subject', 'status', 'is_read',
            'source_ip', 'domain',
            'sent_at', 'created_at',
        ]
        read_only_fields = fields


class ReportStatsSerializer(serializers.Serializer):
    """
    Serializer untuk endpoint statistik agregat.
    Data diisi manual di view, bukan dari model langsung.
    """
    total_reports = serializers.IntegerField()
    total_messages = serializers.IntegerField()
    passed_messages = serializers.IntegerField()
    failed_messages = serializers.IntegerField()
    pass_rate = serializers.FloatField()
    suspicious_ips = serializers.IntegerField()
    top_failing_ips = serializers.ListField(child=serializers.DictField())
    reports_by_day = serializers.ListField(child=serializers.DictField())

class DMARCReportDetailSerializer(serializers.ModelSerializer):
    """Serializer lengkap untuk detail view (dengan records + AI)"""

    records = DMARCRecordSerializer(many=True, read_only=True)
    pass_rate = serializers.ReadOnlyField()
    domain_name = serializers.CharField(source='domain.domain_name', read_only=True)

    # 🔥 ADD AI FIELDS
    ai_summary = serializers.CharField(read_only=True)
    ai_risk_level = serializers.CharField(read_only=True)
    ai_risk_reason = serializers.CharField(read_only=True)
    ai_findings = serializers.JSONField(read_only=True)
    ai_recommendations = serializers.JSONField(read_only=True)
    ai_explanation = serializers.CharField(read_only=True)
    ai_policy_advice = serializers.CharField(read_only=True)
    ai_analyzed_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = DMARCReport
        fields = [
            'id', 'org_name', 'org_email', 'report_id',
            'domain_policy', 'domain_name',
            'date_begin', 'date_end',
            'policy_adkim', 'policy_aspf', 'policy_p', 'policy_sp', 'policy_pct',
            'total_messages', 'passed_messages', 'failed_messages', 'pass_rate',
            'status', 'error_message',
            'source_email_subject', 'source_email_date',
            'created_at', 'parsed_at',

            # 🔥 AI OUTPUT
            'ai_summary',
            'ai_risk_level',
            'ai_risk_reason',
            'ai_findings',
            'ai_recommendations',
            'ai_explanation',
            'ai_policy_advice',
            'ai_analyzed_at',

            'records',
        ]
        read_only_fields = fields