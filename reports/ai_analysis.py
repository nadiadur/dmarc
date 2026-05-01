import logging
import json
import os
from openai import OpenAI
from django.conf import settings

logger = logging.getLogger(__name__)

# setup OpenRouter

client = OpenAI(
    api_key=settings.OPENROUTER_API_KEY,
    base_url="https://openrouter.ai/api/v1",
    default_headers={
        "HTTP-Referer": "http://localhost",
        "X-Title": "DMARC Analyzer"
    }
)

def fallback_analysis(report):
    pass_rate = report.pass_rate or 0
    failed = report.failed_messages or 0

    if pass_rate < 50 or failed > 100:
        risk = "high"
    elif pass_rate < 80:
        risk = "medium"
    else:
        risk = "low"

    findings = []

    if pass_rate < 80:
        findings.append("Banyak email gagal SPF/DKIM")

    if report.policy_p == "none":
        findings.append("Policy DMARC masih 'none' (tidak aman)")

    return {
        "summary": f"Pass rate {pass_rate}%, menunjukkan kondisi keamanan email domain.",
        "risk_level": risk,
        "risk_reason": "Berdasarkan jumlah email gagal dan policy DMARC.",
        "findings": findings,
        "recommendations": [
            "Perbaiki konfigurasi SPF",
            "Perbaiki konfigurasi DKIM",
            "Gunakan policy quarantine atau reject"
        ],
        "explanation": "Analisa menggunakan rule-based karena AI tidak tersedia.",
        "policy_advice": "Gunakan quarantine jika sudah cukup stabil."
    }


def clean_json(text: str):
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()
    return text.strip()


def analyze_dmarc_report(report, records):
    try:
        records_data = []
        for rec in records[:20]:
            records_data.append({
                "ip": rec.source_ip,
                "count": rec.message_count,
                "spf": rec.spf_result,
                "dkim": rec.dkim_result,
                "disposition": rec.disposition,
                "suspicious": rec.is_suspicious,
                "country": rec.geo_country or "Unknown",
                "isp": rec.geo_isp or "Unknown"
            })

        prompt = f"""
Kamu adalah ahli keamanan email (DMARC).

Analisa data berikut dan WAJIB balas JSON VALID TANPA PENJELASAN LAIN.

Domain: {report.domain_policy}
Policy: {report.policy_p}
Total: {report.total_messages}
Pass: {report.passed_messages}
Fail: {report.failed_messages}
Pass rate: {report.pass_rate}%

Records:
{records_data}

Output:
{{
    "summary": "ringkasan 2-3 kalimat",
    "risk_level": "low|medium|high",
    "risk_reason": "alasan singkat",
    "findings": ["temuan"],
    "recommendations": ["rekomendasi"],
    "explanation": "penjelasan",
    "policy_advice": "saran policy"
}}
"""

        # 🔥 MODEL STABIL (TANPA :free)
        response = client.chat.completions.create(
        model="openai/gpt-3.5-turbo",
        messages=[
            {
                "role": "system",
                "content": "Kamu adalah ahli keamanan email DMARC. Jawab hanya dalam JSON valid."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.3,
    )

        text = response.choices[0].message.content
        cleaned = clean_json(text)

        return json.loads(cleaned)

    except Exception as e:
        logger.error(f"AI ERROR: {e}")
        return fallback_analysis(report)