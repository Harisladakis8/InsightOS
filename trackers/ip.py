import requests

def track_ip(ip: str):
    res = requests.get(f"https://ipapi.co/{ip}/json/").json()

    return {
        "ip": ip,
        "city": res.get("city"),
        "region": res.get("region"),
        "country": res.get("country_name"),
        "org": res.get("org"),
        "asn": res.get("asn"),
        "latitude": res.get("latitude"),
        "longitude": res.get("longitude")
    }
