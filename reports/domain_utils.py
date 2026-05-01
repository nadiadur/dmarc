"""
Domain Utility — DNS Scanner & Record Generator

Fitur:
- Scan DNS existing (SPF, DKIM, DMARC)
- Generate DKIM keypair (RSA 2048)
- Generate DNS record sesuai kondisi yang belum ada
- Verifikasi DNS setelah dipasang
"""

import dns.resolver
import logging
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# DNS SCANNER
# ─────────────────────────────────────────────────────────────────────────────

def scan_dns(domain: str, dkim_selector: str = 'default') -> dict:
    """
    Scan DNS domain untuk cek kondisi SPF, DKIM, DMARC.
    Return dict status lengkap per record.
    """
    result = {
        'domain': domain,
        'spf': {
            'found': False,
            'value': '',
            'valid': False,
        },
        'dkim': {
            'found': False,
            'value': '',
            'selector': dkim_selector,
            'valid': False,
        },
        'dmarc': {
            'found': False,
            'value': '',
            'policy': 'none',
            'valid': False,
        },
        'error': '',
        'summary': '',
    }

    # ── Cek SPF ──────────────────────────────────────────────────────────────
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            value = ''.join(s.decode() for s in rdata.strings)
            if 'v=spf1' in value:
                result['spf']['found'] = True
                result['spf']['value'] = value
                result['spf']['valid'] = True
                break
    except dns.resolver.NXDOMAIN:
        result['error'] = f'Domain {domain} tidak ditemukan di DNS'
        return result
    except dns.resolver.NoAnswer:
        pass
    except Exception as e:
        logger.warning(f"SPF check error: {e}")

    # ── Cek DKIM ─────────────────────────────────────────────────────────────
    try:
        dkim_host = f'{dkim_selector}._domainkey.{domain}'
        answers = dns.resolver.resolve(dkim_host, 'TXT')
        for rdata in answers:
            value = ''.join(s.decode() for s in rdata.strings)
            if 'v=DKIM1' in value or 'p=' in value:
                result['dkim']['found'] = True
                result['dkim']['value'] = value
                result['dkim']['valid'] = True
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as e:
        logger.warning(f"DKIM check error: {e}")

    # ── Cek DMARC ────────────────────────────────────────────────────────────
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for rdata in answers:
            value = ''.join(s.decode() for s in rdata.strings)
            if 'v=DMARC1' in value:
                result['dmarc']['found'] = True
                result['dmarc']['value'] = value
                result['dmarc']['valid'] = True
                result['dmarc']['policy'] = extract_policy_from_dmarc(value)
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as e:
        logger.warning(f"DMARC check error: {e}")

    # ── Summary ──────────────────────────────────────────────────────────────
    missing = []
    if not result['spf']['found']:
        missing.append('SPF')
    if not result['dkim']['found']:
        missing.append('DKIM')
    if not result['dmarc']['found']:
        missing.append('DMARC')

    if not missing:
        result['summary'] = 'Semua record sudah terpasang dengan benar!'
    else:
        result['summary'] = f"Record yang belum ada: {', '.join(missing)}"

    return result


# ─────────────────────────────────────────────────────────────────────────────
# DKIM KEY GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_dkim_keypair(selector: str = 'default', domain: str = '') -> dict:
    """
    Generate DKIM keypair RSA 2048-bit.
    Return:
      - private_key_pem : string PEM (disimpan di mail server)
      - public_key_dns  : string value untuk DNS TXT record
      - dns_name        : nama record yang harus dipasang
      - dns_value       : nilai lengkap TXT record
    """
    # Generate RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Private key PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # Public key — ambil dalam format DER lalu base64
    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_b64 = base64.b64encode(public_der).decode('utf-8')

    dns_name = f'{selector}._domainkey.{domain}' if domain else f'{selector}._domainkey'
    dns_value = f'v=DKIM1; k=rsa; p={public_b64}'

    return {
        'selector': selector,
        'private_key_pem': private_pem,
        'public_key_b64': public_b64,
        'dns_name': dns_name,
        'dns_value': dns_value,
        'instructions': {
            'dns': f'Tambahkan TXT record: {dns_name} → {dns_value}',
            'mail_server': 'Simpan private key di mail server kamu (lihat panduan di bawah)',
        }
    }


# ─────────────────────────────────────────────────────────────────────────────
# DNS RECORD GENERATOR — hanya generate yang belum ada
# ─────────────────────────────────────────────────────────────────────────────

def generate_missing_records(
    domain: str,
    rua_email: str,
    scan_result: dict,
    policy: str = 'none',
    dkim_keypair: dict = None,
) -> dict:
    """
    Generate hanya DNS record yang belum ada berdasarkan hasil scan.
    Return dict berisi record yang perlu dipasang.
    """
    records = {}

    # SPF — generate jika belum ada
    if not scan_result['spf']['found']:
        records['spf'] = {
            'status': 'missing',
            'name': domain,
            'type': 'TXT',
            'value': f'v=spf1 mx a ~all',
            'description': 'SPF record belum ada — tambahkan ini',
            'note': 'Sesuaikan dengan mail server kamu. '
                    'Contoh untuk Google: v=spf1 include:_spf.google.com ~all',
        }
    else:
        records['spf'] = {
            'status': 'exists',
            'value': scan_result['spf']['value'],
            'description': 'SPF record sudah ada ✅',
        }

    # DKIM — generate jika belum ada
    if not scan_result['dkim']['found']:
        if dkim_keypair:
            records['dkim'] = {
                'status': 'missing',
                'name': dkim_keypair['dns_name'],
                'type': 'TXT',
                'value': dkim_keypair['dns_value'],
                'private_key': dkim_keypair['private_key_pem'],
                'selector': dkim_keypair['selector'],
                'description': 'DKIM record belum ada — tambahkan ini',
            }
        else:
            records['dkim'] = {
                'status': 'missing',
                'description': 'DKIM belum ada — generate keypair terlebih dahulu',
            }
    else:
        records['dkim'] = {
            'status': 'exists',
            'value': scan_result['dkim']['value'],
            'description': 'DKIM record sudah ada ✅',
        }

    # DMARC — generate jika belum ada
    if not scan_result['dmarc']['found']:
        records['dmarc'] = {
            'status': 'missing',
            'name': f'_dmarc.{domain}',
            'type': 'TXT',
            'value': f'v=DMARC1; p={policy}; rua=mailto:{rua_email}; pct=100; adkim=r; aspf=r',
            'description': 'DMARC record belum ada — tambahkan ini',
        }
    else:
        records['dmarc'] = {
            'status': 'exists',
            'value': scan_result['dmarc']['value'],
            'policy': scan_result['dmarc']['policy'],
            'description': f'DMARC record sudah ada ✅ (policy: {scan_result["dmarc"]["policy"]})',
        }

    return records


# ─────────────────────────────────────────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────────────────────────────────────────

def extract_policy_from_dmarc(dmarc_value: str) -> str:
    """Ambil nilai policy (p=) dari string DMARC record."""
    for part in dmarc_value.split(';'):
        part = part.strip()
        if part.startswith('p='):
            return part[2:].strip()
    return 'none'


def generate_dmarc_record(domain: str, rua_email: str, policy: str = 'none', pct: int = 100) -> dict:
    """Generate full DNS record set (dipakai untuk preview policy)."""
    return {
        'dmarc': {
            'name': f'_dmarc.{domain}',
            'type': 'TXT',
            'value': f'v=DMARC1; p={policy}; rua=mailto:{rua_email}; pct={pct}; adkim=r; aspf=r',
            'description': 'Record DMARC utama',
        },
        'spf': {
            'name': domain,
            'type': 'TXT',
            'value': f'v=spf1 mx a ~all',
            'description': 'Record SPF',
        },
        'instructions': [
            f'1. Login ke panel DNS domain kamu (Cloudflare, GoDaddy, Namecheap, dll)',
            f'2. Tambahkan TXT record untuk _dmarc.{domain}',
            f'3. Tunggu propagasi DNS (bisa 1-24 jam)',
            f'4. Klik Verifikasi DNS untuk mengecek',
        ]
    }