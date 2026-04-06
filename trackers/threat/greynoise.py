# greynoise.py
import requests

class GreyNoiseAnalyzer:
    """GreyNoise threat intelligence integration."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.greynoise.io/v3"
        self.headers = {
            "key": api_key,
            "User-Agent": "InsightOS-Threat-Intel/1.0",
            "Accept": "application/json"
        }
    
    def check_ip(self, ip_address: str) -> dict:
        """Check IP against GreyNoise."""
        try:
            response = requests.get(
                f"{self.base_url}/community/{ip_address}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_response(data)
            else:
                return {
                    "error": f"API Error: {response.status_code}",
                    "ip": ip_address,
                    "risk_level": "UNKNOWN"
                }
                
        except requests.RequestException as e:
            return {
                "error": f"Connection error: {str(e)}",
                "ip": ip_address,
                "risk_level": "UNKNOWN"
            }
    
    def _parse_response(self, data: dict) -> dict:
        """Parse GreyNoise API response."""
        result = {
            "ip": data.get("ip"),
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "classification": data.get("classification", "unknown"),
            "name": data.get("name", "Unknown"),
            "link": data.get("link", ""),
            "last_seen": data.get("last_seen", ""),
            "message": data.get("message", "")
        }
        
        # Υπολογισμός risk_level
        if data.get("classification") == "malicious":
            result["risk_level"] = "HIGH"
        elif data.get("noise") and not data.get("riot"):
            result["risk_level"] = "LOW"  # Αβλαβής θόρυβος
        elif data.get("riot"):
            result["risk_level"] = "BENIGN"  
        else:
            result["risk_level"] = "UNKNOWN"
        
        return result

# Συνάρτηση για compatibility με τον aggregator
def check_greynoise(ip: str, api_key: str) -> dict:
    """Wrapper function for the aggregator."""
    analyzer = GreyNoiseAnalyzer(api_key)
    return analyzer.check_ip(ip)