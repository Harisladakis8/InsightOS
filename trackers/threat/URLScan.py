import requests
import time

def scan_urlscan(target_url: str, api_key: str = None, public: bool = True) -> dict:
    """Scan URL with URLScan.io."""
    BASE_URL = "https://urlscan.io/api/v1"
    
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["API-Key"] = api_key
    
    # Submit scan
    scan_data = {
        "url": target_url,
        "public": "on" if public else "off"
    }
    
    try:
        # Submit scan
        submit_response = requests.post(f"{BASE_URL}/scan/", 
                                        headers=headers, 
                                        json=scan_data)
        
        if submit_response.status_code == 200:
            submit_result = submit_response.json()
            scan_id = submit_result.get("uuid")
            results_url = submit_result.get("api")
            
            # Wait for results (polling)
            for _ in range(10):  # 10 attempts
                time.sleep(3)
                results_response = requests.get(results_url)
                
                if results_response.status_code == 200:
                    data = results_response.json()
                    
                    results = {
                        "url": target_url,
                        "scan_id": scan_id,
                        "verdicts": data.get("verdicts", {}),
                        "page": {
                            "url": data.get("page", {}).get("url"),
                            "domain": data.get("page", {}).get("domain"),
                            "ip": data.get("page", {}).get("ip"),
                            "country": data.get("page", {}).get("country"),
                        },
                        "lists": {
                            "ips": data.get("lists", {}).get("ips", []),
                            "countries": data.get("lists", {}).get("countries", []),
                            "asns": data.get("lists", {}).get("asns", []),
                            "domains": data.get("lists", {}).get("domains", []),
                        },
                        "screenshot_url": data.get("task", {}).get("screenshotURL"),
                        "report_url": data.get("task", {}).get("reportURL"),
                    }
                    
                    # Threat analysis
                    verdicts = results["verdicts"]
                    overall_score = 0
                    
                    if "overall" in verdicts:
                        overall = verdicts["overall"]
                        overall_score = overall.get("score", 0)
                        results["overall_score"] = overall_score
                        
                        if overall_score >= 8:
                            results["threat_level"] = "MALICIOUS"
                        elif overall_score >= 5:
                            results["threat_level"] = "SUSPICIOUS"
                        elif overall_score >= 2:
                            results["threat_level"] = "UNSAFE"
                        else:
                            results["threat_level"] = "SAFE"
                    
                    return results
            
            return {"error": "Scan timeout"}
            
        else:
            return {"error": f"Submission failed: {submit_response.status_code}"}
            
    except Exception as e:
        return {"error": str(e)}