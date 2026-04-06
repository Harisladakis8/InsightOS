import requests

def check_greynoise(ip: str, api_key: str) -> dict:
    """Check IP in GreyNoise (internet background noise)."""
    BASE_URL = "https://api.greynoise.io/v3"
    
    headers = {
        "key": api_key,
        "Accept": "application/json"
    }
    
    try:
        # Community API (free)
        response = requests.get(f"{BASE_URL}/community/{ip}", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            
            results = {
                "ip": ip,
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "classification": data.get("classification", "unknown"),
                "name": data.get("name", ""),
                "link": data.get("link", ""),
                "last_seen": data.get("last_seen"),
                "message": data.get("message", ""),
            }
            
            # Enhanced threat info if RIOT (benign) or malicious
            if results["riot"]:
                results["threat_level"] = "BENIGN"
                results["description"] = "Known benign service"
            elif results["noise"]:
                results["threat_level"] = "SUSPICIOUS"
                results["description"] = "Internet scanner/malicious activity"
            else:
                results["threat_level"] = "UNKNOWN"
                results["description"] = "No notable activity detected"
            
            return results
            
        elif response.status_code == 404:
            return {"error": "IP not found in GreyNoise"}
        else:
            return {"error": f"API error: {response.status_code}"}
            
    except Exception as e:
        return {"error": str(e)}