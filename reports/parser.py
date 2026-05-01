"""
DMARC XML Parser
Mengurai file XML laporan DMARC menjadi objek Python
yang siap disimpan ke database.
"""

import gzip
import zipfile
import io
import logging
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)


def decompress_attachment(data: bytes, filename: str) -> bytes:
    """
    Laporan DMARC biasanya dikirim dalam format .gz atau .zip.
    Fungsi ini mendekompresi dan mengembalikan raw XML bytes.
    """
    filename_lower = filename.lower()

    if filename_lower.endswith('.gz') or filename_lower.endswith('.xml.gz'):
        try:
            return gzip.decompress(data)
        except Exception as e:
            logger.error(f"Gagal decompress gzip: {e}")
            raise ValueError(f"File .gz tidak valid: {e}")

    if filename_lower.endswith('.zip'):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                # Ambil file XML pertama di dalam zip
                xml_files = [f for f in zf.namelist() if f.endswith('.xml')]
                if not xml_files:
                    raise ValueError("Tidak ada file .xml di dalam .zip")
                return zf.read(xml_files[0])
        except zipfile.BadZipFile as e:
            raise ValueError(f"File .zip tidak valid: {e}")

    # Jika sudah raw XML
    return data


def _get_text(element, tag: str, default: str = '') -> str:
    """Helper: ambil teks dari child element, return default jika tidak ada."""
    child = element.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return default


def _get_int(element, tag: str, default: int = 0) -> int:
    """Helper: ambil integer dari child element."""
    text = _get_text(element, tag, str(default))
    try:
        return int(text)
    except (ValueError, TypeError):
        return default


def _parse_timestamp(unix_str: str):
    """Convert Unix timestamp string ke datetime object (UTC)."""
    try:
        return datetime.fromtimestamp(int(unix_str), tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return None


def parse_dmarc_xml(xml_content: str | bytes) -> dict:
    """
    Parse XML laporan DMARC menjadi dictionary terstruktur.

    Struktur return:
    {
        'metadata': { org_name, org_email, report_id, date_begin, date_end },
        'policy':   { domain, adkim, aspf, p, sp, pct },
        'records':  [ { source_ip, count, disposition, dkim, spf, ... }, ... ]
    }
    """
    if isinstance(xml_content, str):
        xml_content = xml_content.encode('utf-8')

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        raise ValueError(f"XML tidak valid: {e}")

    result = {
        'metadata': {},
        'policy': {},
        'records': [],
    }

    # ── 1. <report_metadata> ──────────────────────────────────────────────────
    metadata_el = root.find('report_metadata')
    if metadata_el is not None:
        date_range = metadata_el.find('date_range')
        result['metadata'] = {
            'org_name':   _get_text(metadata_el, 'org_name'),
            'org_email':  _get_text(metadata_el, 'email'),
            'report_id':  _get_text(metadata_el, 'report_id'),
            'date_begin': _parse_timestamp(_get_text(date_range, 'begin')) if date_range is not None else None,
            'date_end':   _parse_timestamp(_get_text(date_range, 'end'))   if date_range is not None else None,
        }

    # ── 2. <policy_published> ─────────────────────────────────────────────────
    policy_el = root.find('policy_published')
    if policy_el is not None:
        result['policy'] = {
            'domain': _get_text(policy_el, 'domain'),
            'adkim':  _get_text(policy_el, 'adkim', 'r'),
            'aspf':   _get_text(policy_el, 'aspf', 'r'),
            'p':      _get_text(policy_el, 'p', 'none'),
            'sp':     _get_text(policy_el, 'sp', 'none'),
            'pct':    _get_int(policy_el, 'pct', 100),
        }

    # ── 3. <record> (bisa banyak) ─────────────────────────────────────────────
    for record_el in root.findall('record'):
        record = {}

        # <row>
        row_el = record_el.find('row')
        if row_el is not None:
            policy_eval = row_el.find('policy_evaluated')
            record['source_ip']    = _get_text(row_el, 'source_ip')
            record['message_count'] = _get_int(row_el, 'count', 1)
            record['disposition']  = _get_text(policy_eval, 'disposition', 'none') if policy_eval is not None else 'none'
            record['dkim_result']  = _get_text(policy_eval, 'dkim', 'none')        if policy_eval is not None else 'none'
            record['spf_result']   = _get_text(policy_eval, 'spf', 'none')         if policy_eval is not None else 'none'

        # <identifiers>
        id_el = record_el.find('identifiers')
        if id_el is not None:
            record['envelope_to']   = _get_text(id_el, 'envelope_to')
            record['envelope_from'] = _get_text(id_el, 'envelope_from')
            record['header_from']   = _get_text(id_el, 'header_from')

        # <auth_results>
        auth_el = record_el.find('auth_results')
        if auth_el is not None:
            dkim_el = auth_el.find('dkim')
            if dkim_el is not None:
                record['dkim_domain']       = _get_text(dkim_el, 'domain')
                record['dkim_selector']     = _get_text(dkim_el, 'selector')
                record['dkim_human_result'] = _get_text(dkim_el, 'human_result')

            spf_el = auth_el.find('spf')
            if spf_el is not None:
                record['spf_domain'] = _get_text(spf_el, 'domain')
                record['spf_scope']  = _get_text(spf_el, 'scope')

        # Flag suspicious: spf DAN dkim sama-sama fail
        dkim_r = record.get('dkim_result', 'none')
        spf_r  = record.get('spf_result', 'none')
        record['is_suspicious'] = (dkim_r != 'pass' and spf_r != 'pass')

        result['records'].append(record)

    logger.info(
        f"Parsed DMARC report: org={result['metadata'].get('org_name')} "
        f"domain={result['policy'].get('domain')} "
        f"records={len(result['records'])}"
    )

    return result


def calculate_summary(records: list[dict]) -> dict:
    """
    Hitung total, passed, dan failed dari list records hasil parsing.
    Dipakai untuk update field agregat di DMARCReport.
    """
    total = sum(r.get('message_count', 1) for r in records)
    passed = sum(
        r.get('message_count', 1) for r in records
        if r.get('dkim_result') == 'pass' and r.get('spf_result') == 'pass'
    )
    return {
        'total_messages':  total,
        'passed_messages': passed,
        'failed_messages': total - passed,
    }