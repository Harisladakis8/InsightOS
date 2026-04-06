import requests

def scan_shodan(target: str, target_type: str, api_key: str) -> dict:
    """
    Scan with Shodan.io
    target_type: 'ip', 'domain', 'port'
    """
    BASE_URL = "https://api.shodan.io"
    
    try:
        if target_type == "ip":
            response = requests.get(f"{BASE_URL}/shodan/host/{target}?key={api_key}")
            
            if response.status_code == 200:
                data = response.json()
                
                results = {
                    "ip": target,
                    "org": data.get("org", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "country": data.get("country_name", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "last_update": data.get("last_update"),
                    "ports": data.get("ports", []),
                    "vulnerabilities": data.get("vulns", []),
                    "tags": data.get("tags", []),
                }
                
                # Services found
                services = []
                for item in data.get("data", []):
                    service = {
                        "port": item.get("port"),
                        "product": item.get("product", "Unknown"),
                        "version": item.get("version", "Unknown"),
                        "transport": item.get("transport"),
                        "banner": item.get("data", "")[:200]
                    }
                    services.append(service)
                
                results["services"] = services
                results["service_count"] = len(services)
                
                # Threat assessment
                vuln_count = len(results["vulnerabilities"])
                open_ports = len(results["ports"])
                
                if vuln_count > 5:
                    results["risk_level"] = "CRITICAL"
                elif vuln_count > 2:
                    results["risk_level"] = "HIGH"
                elif open_ports > 20:
                    results["risk_level"] = "MEDIUM"
                else:
                    results["risk_level"] = "LOW"
                
                return results
                
        elif target_type == "domain":
            response = requests.get(f"{BASE_URL}/dns/domain/{target}?key={api_key}")
            
            if response.status_code == 200:
                data = response.json()
                
                results = {
                    "domain": target,
                    "subdomains": data.get("subdomains", []),
                    "tags": data.get("tags", []),
                    "data": data.get("data", [])[:10]  # First 10 records
                }
                
                return results
        
        return {"error": f"Shodan returned {response.status_code}"}
        
    except Exception as e:
        return {"error": str(e)}