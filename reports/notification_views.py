import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import serializers
 
from .models import AlertLog
from .telegram_service import verify_telegram_config
 
logger = logging.getLogger(__name__)
 
 
class NotificationConfigSerializer(serializers.Serializer):
    telegram_enabled = serializers.BooleanField(default=False)
    telegram_bot_token = serializers.CharField(max_length=255, allow_blank=True, default='')
    telegram_chat_id = serializers.CharField(max_length=100, allow_blank=True, default='')
    notify_on_suspicious = serializers.BooleanField(default=True)
    notify_on_any_fail = serializers.BooleanField(default=False)
 
 
class NotificationConfigView(APIView):
    permission_classes = [IsAuthenticated]
 
    def get(self, request):
        """GET /api/notifications/config/ — Lihat konfigurasi notifikasi"""
        try:
            from .models import NotificationConfig
            config = NotificationConfig.objects.get(user=request.user)
            return Response({
                'telegram_enabled': config.telegram_enabled,
                'telegram_bot_token': config.telegram_bot_token,
                'telegram_chat_id': config.telegram_chat_id,
                'notify_on_suspicious': config.notify_on_suspicious,
                'notify_on_any_fail': config.notify_on_any_fail,
                'created_at': config.created_at,
                'updated_at': config.updated_at,
            })
        except Exception:
            # Belum ada config — return default
            return Response({
                'telegram_enabled': False,
                'telegram_bot_token': '',
                'telegram_chat_id': '',
                'notify_on_suspicious': True,
                'notify_on_any_fail': False,
            })
 
    def post(self, request):
        """POST /api/notifications/config/ — Simpan konfigurasi notifikasi"""
        from .models import NotificationConfig
 
        serializer = NotificationConfigSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)
 
        data = serializer.validated_data
 
        config, created = NotificationConfig.objects.update_or_create(
            user=request.user,
            defaults={
                'telegram_enabled': data['telegram_enabled'],
                'telegram_bot_token': data['telegram_bot_token'],
                'telegram_chat_id': data['telegram_chat_id'],
                'notify_on_suspicious': data['notify_on_suspicious'],
                'notify_on_any_fail': data['notify_on_any_fail'],
            }
        )
 
        return Response({
            'message': 'Konfigurasi notifikasi berhasil disimpan',
            'telegram_enabled': config.telegram_enabled,
        }, status=201 if created else 200)
 
 
class NotificationTestView(APIView):
    permission_classes = [IsAuthenticated]
 
    def post(self, request):
        """POST /api/notifications/test/ — Kirim pesan test ke Telegram"""
        from .models import NotificationConfig
 
        try:
            config = NotificationConfig.objects.get(user=request.user)
        except NotificationConfig.DoesNotExist:
            return Response({'detail': 'Konfigurasi belum ada'}, status=404)
 
        if not config.telegram_enabled:
            return Response({'detail': 'Telegram belum diaktifkan'}, status=400)
 
        if not config.telegram_bot_token or not config.telegram_chat_id:
            return Response({'detail': 'Bot token dan Chat ID wajib diisi'}, status=400)
 
        result = verify_telegram_config(
            config.telegram_bot_token,
            config.telegram_chat_id,
        )
 
        if result['success']:
            return Response({'message': result['message']})
        else:
            return Response({'detail': result['message']}, status=400)
 
 
class NotificationHistoryView(APIView):
    permission_classes = [IsAuthenticated]
 
    def get(self, request):
        """GET /api/notifications/history/ — Riwayat notifikasi Telegram"""
        qs = AlertLog.objects.filter(
            user=request.user,
            channel='telegram'
        ).order_by('-created_at')[:50]
 
        results = []
        for log in qs:
            results.append({
                'id': log.id,
                'alert_type': log.alert_type,
                'status': log.status,
                'recipient': log.recipient,
                'domain': log.report.domain_policy if log.report else '-',
                'source_ip': log.record.source_ip if log.record else '-',
                'is_read': log.is_read,
                'sent_at': log.sent_at,
                'created_at': log.created_at,
            })
 
        return Response({
            'count': qs.count(),
            'results': results,
        })