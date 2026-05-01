from .dns import check_spf, check_dkim, check_dmarc
from .telegram import send_telegram


def scan_domain(domain, user=None):
    spf = check_spf(domain)
    dkim = check_dkim(domain)
    dmarc = check_dmarc(domain)

    status = "pass" if spf == "pass" and dkim == "pass" and dmarc == "pass" else "fail"

    result = {
        "domain": domain,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "status": status
    }

    # 🚨 ALERT TELEGRAM
    if status == "fail" and user and user.chat_id:
        send_telegram(
            user.chat_id,
            f"""🚨 ALERT DMARC
Domain: {domain}
SPF: {spf}
DKIM: {dkim}
DMARC: {dmarc}
Status: {status}"""
        )

    return result