import whois
import socket
from datetime import datetime
from typing import Optional, Dict, Any, Union

def track_domain(domain: str) -> Dict[str, Any]:
    """
    Advanced domain tracker using python-whois.
    Returns a structured dictionary with safe types and error handling.
    """
    try:
        w = whois.whois(domain)
    except Exception as e:
        return {"domain": domain, "error": str(e)}

    # Helper to normalize dates
    def normalize_date(d: Union[datetime, list, None]) -> Optional[str]:
        if isinstance(d, list) and d:
            return str(d[0])
        if isinstance(d, datetime):
            return d.isoformat()
        return None

    # Helper to normalize lists
    def normalize_list(lst: Union[list, str, None]) -> Optional[list]:
        if isinstance(lst, str):
            return [lst]
        if isinstance(lst, list):
            return lst
        return None

    # Optional: resolve IP
    try:
        ip_address = socket.gethostbyname(domain)
    except Exception:
        ip_address = None

    return {
        "domain": domain,
        "ip_address": ip_address,
        "registrar": w.registrar or None,
        "creation_date": normalize_date(w.creation_date),
        "expiration_date": normalize_date(w.expiration_date),
        "updated_date": normalize_date(w.updated_date),
        "country": w.country or None,
        "name_servers": normalize_list(w.name_servers),
        "status": normalize_list(w.status),
        "emails": normalize_list(getattr(w, "emails", None)),
    }

# Example usage
if __name__ == "__main__":
    domain_info = track_domain("example.com")
    print(domain_info)
