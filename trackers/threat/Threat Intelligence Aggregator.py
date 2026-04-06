"""
Threat Intelligence Aggregator - Central module for all security scans
"""
import concurrent.futures
import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import requests

# Import all threat modules - ΒΑΛΕ ΤΑ ΣΩΣΤΑ IMPORTS
try:
    from .virustotal import scan_virustotal
    from .abuseipdb import check_abuseipdb
    from .shodan import scan_shodan
    from .greynoise import check_greynoise
    from .URLScan  import scan_urlscan
    from .cve_scanner import scan_cves
    from .ssl_analyzer import analyze_ssl
except ImportError:
    # Fallback imports αν τα αρχεία δεν υπάρχουν ακόμα
    def scan_virustotal(target: str, target_type: str, api_key: str) -> Dict:
        return {"error": "VirusTotal module not available", "target": target}
    
    def check_abuseipdb(ip: str, api_key: str) -> Dict:
        return {"error": "AbuseIPDB module not available", "ip": ip}
    
    def scan_shodan(target: str, target_type: str, api_key: str) -> Dict:
        return {"error": "Shodan module not available", "target": target}
    
    def check_greynoise(ip: str, api_key: str) -> Dict:
        return {"error": "GreyNoise module not available", "ip": ip}
    
    def scan_urlscan(target_url: str, api_key: str) -> Dict:
        return {"error": "URLScan module not available", "url": target_url}
    
    def scan_cves(target: str, target_type: str) -> Dict:
        return {"error": "CVE Scanner module not available", "target": target}
    
    def analyze_ssl(domain: str) -> Dict:
        return {"error": "SSL Analyzer module not available", "domain": domain}

class ThreatIntelligence:
    """Main threat intelligence aggregator class."""
    
    def __init__(self, api_keys: Dict[str, str] = None):
        """
        Initialize with API keys for various services.
        """
        self.api_keys = api_keys or {}
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "InsightOS-Threat-Intel/1.0"
        })
        
    def full_threat_analysis(self, target: str, target_type: str) -> Dict:
        """Run comprehensive threat analysis on target."""
        results = {
            "target": target,
            "type": target_type,
            "timestamp": datetime.now().isoformat(),
            "scans": {},
            "overall_risk": "UNKNOWN",
            "recommendations": []
        }
        
        # Define scan functions based on target type
        scan_functions = []
        
        if target_type == "ip":
            scan_functions = [
                ("VirusTotal", lambda: scan_virustotal(target, "ip", self.api_keys.get("virustotal"))),
                ("AbuseIPDB", lambda: check_abuseipdb(target, self.api_keys.get("abuseipdb"))),
                ("GreyNoise", lambda: check_greynoise(target, self.api_keys.get("greynoise"))),
                ("Shodan", lambda: scan_shodan(target, "ip", self.api_keys.get("shodan"))),
            ]
        
        elif target_type == "domain":
            scan_functions = [
                ("VirusTotal", lambda: scan_virustotal(target, "domain", self.api_keys.get("virustotal"))),
                ("SSL Analysis", lambda: analyze_ssl(target)),
                ("URLScan", lambda: scan_urlscan(f"https://{target}", self.api_keys.get("urlscan"))),
            ]
        
        elif target_type == "url":
            scan_functions = [
                ("VirusTotal", lambda: scan_virustotal(target, "url", self.api_keys.get("virustotal"))),
                ("URLScan", lambda: scan_urlscan(target, self.api_keys.get("urlscan"))),
            ]
        
        # Run scans in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_scan = {
                executor.submit(func): name 
                for name, func in scan_functions
            }
            
            for future in concurrent.futures.as_completed(future_to_scan):
                scan_name = future_to_scan[future]
                try:
                    scan_result = future.result(timeout=30)
                    results["scans"][scan_name] = scan_result
                except concurrent.futures.TimeoutError:
                    results["scans"][scan_name] = {"error": "Scan timeout (30s)"}
                except Exception as e:
                    results["scans"][scan_name] = {"error": str(e)}
        
        # Calculate overall risk
        risk_scores = []
        for scan_name, scan_data in results["scans"].items():
            if isinstance(scan_data, dict) and "risk_level" in scan_data:
                risk_map = {
                    "CRITICAL": 4,
                    "HIGH": 3,
                    "MEDIUM": 2,
                    "LOW": 1,
                    "CLEAN": 0,
                    "BENIGN": 0,
                    "SAFE": 0
                }
                risk_scores.append(risk_map.get(scan_data["risk_level"], 0))
        
        if risk_scores:
            avg_risk = sum(risk_scores) / len(risk_scores)
            if avg_risk >= 3.5:
                results["overall_risk"] = "CRITICAL"
            elif avg_risk >= 2.5:
                results["overall_risk"] = "HIGH"
            elif avg_risk >= 1.5:
                results["overall_risk"] = "MEDIUM"
            else:
                results["overall_risk"] = "LOW"
        else:
            results["overall_risk"] = "UNKNOWN"
        
        # Generate recommendations
        if results["overall_risk"] == "CRITICAL":
            results["recommendations"].extend([
                "🚨 IMMEDIATE ACTION REQUIRED",
                "• Block/quarantine immediately",
                "• Notify security team",
                "• Conduct forensic analysis",
                "• Update firewall rules"
            ])
        elif results["overall_risk"] == "HIGH":
            results["recommendations"].extend([
                "⚠️ HIGH PRIORITY INVESTIGATION",
                "• Monitor closely",
                "• Isolate if possible",
                "• Review logs for related activity",
                "• Consider blocking"
            ])
        elif results["overall_risk"] == "MEDIUM":
            results["recommendations"].extend([
                "🔍 INVESTIGATE FURTHER",
                "• Add to watchlist",
                "• Monitor for changes",
                "• Schedule regular re-scans"
            ])
        elif results["overall_risk"] == "LOW":
            results["recommendations"].extend([
                "✓ LOW RISK - MONITOR",
                "• No immediate action needed",
                "• Regular monitoring recommended"
            ])
        else:
            results["recommendations"].append("✅ No threats detected or scan incomplete")
        
        return results

    # ... rest of the class methods remain the same ...

# Σημαντικό: Βεβαιώσου ότι έχεις τα imports σωστά