import dns.resolver
from .dns import check_spf, check_dmarc
from .telegram import send_telegram

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            if "v=spf1" in str(r):
                return "pass"
        return "fail"
    except:
        return "fail"


def check_dmarc(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            if "v=DMARC1" in str(r):
                return "pass"
        return "fail"
    except:
        return "fail"


def check_domain(domain, user):
    spf = check_spf(domain)
    dmarc = check_dmarc(domain)

    result = {
        "domain": domain,
        "spf": spf,
        "dmarc": dmarc,
        "status": "pass" if all(x == "pass" for x in [spf, dmarc]) else "fail"
    }

    return result



def scan_domain(domain, user):
    spf = check_spf(domain)
    dmarc = check_dmarc(domain)

    status = "pass" if spf == "pass" and dmarc == "pass" else "fail"

    # 🚨 KIRIM NOTIF TELEGRAM
    if status == "fail" and user and user.chat_id:
        message = f"""🚨 DMARC ALERT

Domain: {domain}
SPF: {spf}
DMARC: {dmarc}
Status: FAIL"""

        send_telegram(user.chat_id, message)

    return {
        "domain": domain,
        "spf": spf,
        "dmarc": dmarc,
        "status": status
    }