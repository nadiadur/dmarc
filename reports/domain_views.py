"""
Domain Management API Views — Updated dengan DNS Scan & DKIM Generate
"""

import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from .models import Domain
from .serializers import DomainSerializer
from .domain_utils import (
    scan_dns,
    generate_dkim_keypair,
    generate_missing_records,
    generate_dmarc_record,
    extract_policy_from_dmarc,
)

logger = logging.getLogger(__name__)


class DomainListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        domains = Domain.objects.filter(user=request.user).order_by('-created_at')
        return Response(DomainSerializer(domains, many=True).data)

    def post(self, request):
        domain_name = request.data.get('domain_name', '').strip().lower()
        rua_email = 'nadiabelajar672@gmail.com'

        if not domain_name:
            return Response({'detail': 'Domain name wajib diisi'}, status=400)
        if not rua_email:
            return Response({'detail': 'RUA email wajib diisi'}, status=400)

        if Domain.objects.filter(user=request.user, domain_name=domain_name).exists():
            return Response({'detail': f'Domain {domain_name} sudah terdaftar'}, status=400)

        domain = Domain.objects.create(
            user=request.user,
            domain_name=domain_name,
            rua_email=rua_email,
            is_verified=False,
        )
        return Response(DomainSerializer(domain).data, status=201)


class DomainDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, domain_id):
        try:
            domain = Domain.objects.get(id=domain_id, user=request.user)
        except Domain.DoesNotExist:
            return Response({'detail': 'Domain tidak ditemukan'}, status=404)
        return Response(DomainSerializer(domain).data)

    def delete(self, request, domain_id):
        try:
            domain = Domain.objects.get(id=domain_id, user=request.user)
        except Domain.DoesNotExist:
            return Response({'detail': 'Domain tidak ditemukan'}, status=404)
        domain.delete()
        return Response({'message': 'Domain berhasil dihapus'}, status=204)


class DomainScanView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, domain_id):
        """
        POST /api/domains/{id}/scan/
        Scan DNS untuk cek kondisi SPF, DKIM, DMARC yang sudah ada.
        """
        try:
            domain = Domain.objects.get(id=domain_id, user=request.user)
        except Domain.DoesNotExist:
            return Response({'detail': 'Domain tidak ditemukan'}, status=404)

        selector = request.data.get('dkim_selector', 'default')
        scan_result = scan_dns(domain.domain_name, dkim_selector=selector)

        # Update status verifikasi jika semua sudah ada
        if scan_result['dmarc']['found']:
            domain.is_verified = True
            domain.save(update_fields=['is_verified'])

        return Response({
            'domain': domain.domain_name,
            'scan': scan_result,
            'needs_setup': {
                'spf': not scan_result['spf']['found'],
                'dkim': not scan_result['dkim']['found'],
                'dmarc': not scan_result['dmarc']['found'],
            },
            'all_good': (
                scan_result['spf']['found'] and
                scan_result['dkim']['found'] and
                scan_result['dmarc']['found']
            ),
            'summary': scan_result['summary'],
        })


class DomainGenerateRecordsView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, domain_id):
        """
        POST /api/domains/{id}/generate-records/
        Generate DNS record yang belum ada.
        Otomatis generate DKIM keypair jika DKIM belum ada.

        Body (optional):
          dkim_selector : string (default: 'default')
          policy        : none / quarantine / reject (default: 'none')
        """
        try:
            domain = Domain.objects.get(id=domain_id, user=request.user)
        except Domain.DoesNotExist:
            return Response({'detail': 'Domain tidak ditemukan'}, status=404)

        selector = request.data.get('dkim_selector', 'default')
        policy = request.data.get('policy', 'none')
        if policy not in ['none', 'quarantine', 'reject']:
            policy = 'none'

        # Scan dulu kondisi DNS yang ada
        scan_result = scan_dns(domain.domain_name, dkim_selector=selector)

        # Generate DKIM keypair jika belum ada
        dkim_keypair = None
        if not scan_result['dkim']['found']:
            dkim_keypair = generate_dkim_keypair(
                selector=selector,
                domain=domain.domain_name,
            )

        # Generate hanya yang belum ada
        records = generate_missing_records(
            domain=domain.domain_name,
            rua_email=domain.rua_email,
            scan_result=scan_result,
            policy=policy,
            dkim_keypair=dkim_keypair,
        )

        return Response({
            'domain': domain.domain_name,
            'rua_email': domain.rua_email,
            'scan_result': {
                'spf_exists': scan_result['spf']['found'],
                'dkim_exists': scan_result['dkim']['found'],
                'dmarc_exists': scan_result['dmarc']['found'],
                'summary': scan_result['summary'],
            },
            'records_to_add': records,
            'dkim_keypair': {
                'generated': dkim_keypair is not None,
                'private_key': dkim_keypair['private_key_pem'] if dkim_keypair else None,
                'selector': selector,
                'note': 'Simpan private key ini di mail server kamu. Jangan dibagikan ke siapapun!',
            } if dkim_keypair else {'generated': False},
            'instructions': {
                'postfix': f'Tambahkan di /etc/opendkim/keys/{domain.domain_name}/{selector}.private',
                'cpanel': 'Email → Email Deliverability → Manage → paste private key',
                'google_workspace': 'Admin Console → Apps → Google Workspace → Gmail → Authenticate email',
            } if dkim_keypair else {},
        })


class DomainVerifyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, domain_id):
        """
        POST /api/domains/{id}/verify/
        Verifikasi semua record DNS sudah terpasang.
        """
        try:
            domain = Domain.objects.get(id=domain_id, user=request.user)
        except Domain.DoesNotExist:
            return Response({'detail': 'Domain tidak ditemukan'}, status=404)

        selector = request.data.get('dkim_selector', 'default')
        scan_result = scan_dns(domain.domain_name, dkim_selector=selector)

        all_good = (
            scan_result['spf']['found'] and
            scan_result['dkim']['found'] and
            scan_result['dmarc']['found']
        )

        if scan_result['dmarc']['found']:
            domain.is_verified = True
            domain.save(update_fields=['is_verified'])

        return Response({
            'domain': domain.domain_name,
            'is_verified': all_good,
            'checks': {
                'spf': {
                    'status': '✅ Ditemukan' if scan_result['spf']['found'] else '❌ Belum ada',
                    'found': scan_result['spf']['found'],
                    'value': scan_result['spf']['value'],
                },
                'dkim': {
                    'status': '✅ Ditemukan' if scan_result['dkim']['found'] else '❌ Belum ada',
                    'found': scan_result['dkim']['found'],
                    'value': scan_result['dkim']['value'],
                    'selector': selector,
                },
                'dmarc': {
                    'status': '✅ Ditemukan' if scan_result['dmarc']['found'] else '❌ Belum ada',
                    'found': scan_result['dmarc']['found'],
                    'value': scan_result['dmarc']['value'],
                    'policy': scan_result['dmarc']['policy'],
                },
            },
            'message': (
                '🎉 Semua record terpasang! Domain siap menerima laporan DMARC.'
                if all_good else
                f'⚠️ {scan_result["summary"]}. Tunggu propagasi DNS (1-24 jam) lalu coba lagi.'
            ),
        })


class DomainPolicyView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, domain_id):
        """
        PATCH /api/domains/{id}/policy/
        Update policy DMARC.
        """
        try:
            domain = Domain.objects.get(id=domain_id, user=request.user)
        except Domain.DoesNotExist:
            return Response({'detail': 'Domain tidak ditemukan'}, status=404)

        if not domain.is_verified:
            return Response(
                {'detail': 'Domain belum diverifikasi. Pasang DNS record terlebih dahulu.'},
                status=400
            )

        policy = request.data.get('policy', '').lower()
        if policy not in ['none', 'quarantine', 'reject']:
            return Response(
                {'detail': 'Policy tidak valid. Pilih: none, quarantine, atau reject'},
                status=400
            )

        new_dns_value = (
            f'v=DMARC1; p={policy}; rua=mailto:{domain.rua_email}; '
            f'pct=100; adkim=r; aspf=r'
        )

        return Response({
            'domain': domain.domain_name,
            'policy': policy,
            'message': f'Update DNS record DMARC kamu dengan value berikut:',
            'new_dns_record': {
                'name': f'_dmarc.{domain.domain_name}',
                'type': 'TXT',
                'value': new_dns_value,
            },
            'note': (
                'Setelah update DNS record di panel domain kamu, '
                'klik Verifikasi untuk mengkonfirmasi perubahan.'
            ),
        })
