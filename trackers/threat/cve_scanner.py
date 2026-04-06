import requests

def scan_cves(target: str, target_type: str = "software") -> dict:
    """
    Search for CVEs related to target.
    target_type: 'software', 'vendor', 'product', 'keyword'
    """
    BASE_URL = "https://cve.circl.lu/api"
    
    try:
        if target_type == "software":
            # Search by software name/version
            response = requests.get(f"{BASE_URL}/search/{target}")
        elif target_type == "vendor":
            response = requests.get(f"{BASE_URL}/browse/{target}")
        else:
            response = requests.get(f"{BASE_URL}/search", params={"keyword": target})
        
        if response.status_code == 200:
            data = response.json()
            
            results = {
                "target": target,
                "type": target_type,
                "cve_count": len(data) if isinstance(data, list) else 0,
                "cvss_threshold": 7.0,  # High severity threshold
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "cves": []
            }
            
            if isinstance(data, list):
                for cve in data[:10]:  # Top 10 CVEs
                    cve_id = cve.get("id", "")
                    cvss = cve.get("cvss", 0)
                    
                    # Categorize by severity
                    if cvss >= 9.0:
                        severity = "CRITICAL"
                        results["critical_count"] += 1
                    elif cvss >= 7.0:
                        severity = "HIGH"
                        results["high_count"] += 1
                    elif cvss >= 4.0:
                        severity = "MEDIUM"
                        results["medium_count"] += 1
                    else:
                        severity = "LOW"
                        results["low_count"] += 1
                    
                    cve_info = {
                        "id": cve_id,
                        "cvss": cvss,
                        "severity": severity,
                        "summary": cve.get("summary", "")[:200],
                        "published": cve.get("Published", ""),
                        "modified": cve.get("Modified", ""),
                        "references": cve.get("references", [])[:3]
                    }
                    results["cves"].append(cve_info)
            
            # Overall risk
            if results["critical_count"] > 0:
                results["risk_level"] = "CRITICAL"
            elif results["high_count"] > 0:
                results["risk_level"] = "HIGH"
            elif results["medium_count"] > 0:
                results["risk_level"] = "MEDIUM"
            else:
                results["risk_level"] = "LOW"
            
            return results
            
        else:
            return {"error": f"API error: {response.status_code}"}
            
    except Exception as e:
        return {"error": str(e)}