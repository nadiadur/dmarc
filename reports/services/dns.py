import dns.resolver

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


# 🔥 TAMBAHKAN INI
def check_dkim(domain):
    try:
        # pakai selector default (google/mail umum)
        selectors = ["default", "google", "mail"]

        for selector in selectors:
            try:
                answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                for r in answers:
                    if "v=DKIM1" in str(r):
                        return "pass"
            except:
                continue

        return "fail"

    except:
        return "fail"