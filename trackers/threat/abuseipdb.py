import requests

def check_abuseipdb(ip: str, api_key: str = None) -> dict:
    """Check IP reputation on AbuseIPDB."""
    if not api_key:
        return {
            "error": "AbuseIPDB API key not configured",
            "ip": ip
        }
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "success": True,
                "ip": ip,
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "risk_level": "HIGH" if data.get("abuseConfidenceScore", 0) > 75 else "LOW"
            }
        else:
            return {"error": f"AbuseIPDB API error: {response.status_code}"}
            
    except Exception as e:
        return {"error": str(e)}