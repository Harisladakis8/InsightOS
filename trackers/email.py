import re
import dns.resolver

def track_email(email: str):
    regex = r"[^@]+@[^@]+\.[^@]+"
    valid = re.match(regex, email) is not None

    domain = email.split("@")[-1]
    mx_records = []

    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_records = [str(r.exchange) for r in answers]
    except:
        pass

    return {
        "valid_format": valid,
        "domain": domain,
        "mx_records": mx_records,
        "disposable": False  # εδώ μπαίνει API αν θες
    }
