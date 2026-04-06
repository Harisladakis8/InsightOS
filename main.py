# main.py
from flask import Flask, render_template, request, jsonify 
import os
from werkzeug.utils import secure_filename
from datetime import datetime
import re
import sys
from trackers.cryptograph import app_crypto
from trackers.metadata import app_file
# Προσθήκη του φακέλου trackers στο path
sys.path.append(os.path.join(os.path.dirname(__file__), 'trackers'))

# Import all trackers
try:
    from trackers.phone import track_phone
    from trackers.email import track_email
    from trackers.ip import track_ip
    from trackers.domain import track_domain
    from trackers.crypto import track_crypto
    from trackers.metadata import track_metadata
    from trackers.username import username_tracker
    print("✓ Loaded all OSINT trackers")
except ImportError as e:
    print(f"✗ Error loading OSINT trackers: {e}")
    # Δημιουργία dummy functions αν λείπουν τα modules
    def track_phone(phone):
        return {"error": "Phone tracker module not available", "phone": phone}
    
    def track_email(email):
        return {"error": "Email tracker module not available", "email": email}
    
    def track_ip(ip):
        return {"error": "IP tracker module not available", "ip": ip}
    
    def track_domain(domain):
        return {"error": "Domain tracker module not available", "domain": domain}
    
    def track_crypto(address):
        return {"error": "Crypto tracker module not available", "address": address}
    
    def track_metadata(filepath):
        return {"error": "Metadata tracker module not available", "filepath": filepath}
    
    def username_tracker(username):
        return {"error": "Username tracker module not available", "username": username}

print("⚠️ Threat Intelligence Module: Using basic mode (no external imports)")

# Δημιούργησε ένα απλό ThreatIntelligence class
class ThreatIntelligence:
    def __init__(self, api_keys=None):
        self.api_keys = api_keys or {}
        print(f"✓ Created ThreatIntelligence with {len(self.api_keys)} API keys")
    
    def detect_target_type(self, target: str) -> str:
        """Simple target type detection."""
        target = target.lower().strip()
        
        if target.startswith(('http://', 'https://')):
            return "url"
        
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, target):
            parts = target.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                return "ip"
        
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        if '.' in target and re.match(domain_pattern, target):
            return "domain"
        
        return "unknown"
    
    def full_threat_analysis(self, target, target_type="auto"):
        """Return dummy threat analysis."""
        if target_type == "auto":
            target_type = self.detect_target_type(target)
        
        # Dummy results based on target
        dummy_scans = {
            "Basic Analysis": {
                "target": target,
                "type": target_type,
                "risk_level": "LOW",
                "message": "Threat intelligence module is in development",
                "recommendation": "Configure API keys for full analysis"
            }
        }
        
        return {
            "target": target,
            "type": target_type,
            "timestamp": datetime.now().isoformat(),
            "scans": dummy_scans,
            "overall_risk": "UNKNOWN",
            "risk_score": 0,
            "recommendations": [
                "Threat intelligence module is in development",
                "Configure API keys for full functionality"
            ],
            "tags": ["basic", "dummy"]
        }
    
    def quick_scan(self, target):
        """Quick dummy scan."""
        result = self.full_threat_analysis(target)
        result["scan_mode"] = "quick"
        return result

print("✓ Created basic ThreatIntelligence class")

# Import AI module (αν υπάρχει)
try:
    from ai import app_ai
    app = Flask(__name__)
    app.register_blueprint(app_ai)
    print("✓ Loaded AI module")
except ImportError:
    app = Flask(__name__)
    print("⚠️ AI module not available")

# Configuration για API keys
THREAT_API_KEYS = {
    "virustotal": os.getenv("VT_API_KEY", ""),
    "abuseipdb": os.getenv("ABUSEIPDB_API_KEY", ""),
    "shodan": os.getenv("SHODAN_API_KEY", ""),
    "greynoise": os.getenv("GREYNOISE_API_KEY", ""),
    "urlscan": os.getenv("URLSCAN_API_KEY", "")
}

# Καθαρισμός κενών API keys
THREAT_API_KEYS = {k: v for k, v in THREAT_API_KEYS.items() if v and v.strip()}

# Initialize threat intelligence
threat_intel = ThreatIntelligence(THREAT_API_KEYS)

# Configuration for file uploads
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'tiff', 'bmp', 'pdf', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def detect_target_type(target: str) -> str:
    """Detect target type automatically."""
    target = target.strip()
    
    # IP Address (IPv4)
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, target):
        try:
            octets = target.split('.')
            if all(0 <= int(octet) <= 255 for octet in octets):
                return "ip"
        except:
            pass
    
    # URL
    if target.startswith(('http://', 'https://')):
        return "url"
    
    # Domain
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    if re.match(domain_pattern, target) and '.' in target and '/' not in target:
        return "domain"
    
    # Email
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(email_pattern, target):
        return "email"
    
    # Phone (international format)
    phone_pattern = r'^\+?[1-9]\d{1,14}$'
    if re.match(phone_pattern, target.replace(' ', '')):
        return "phone"
    
    # Hash
    if re.match(r'^[a-fA-F0-9]{32}$', target):
        return "hash_md5"
    if re.match(r'^[a-fA-F0-9]{40}$', target):
        return "hash_sha1"
    if re.match(r'^[a-fA-F0-9]{64}$', target):
        return "hash_sha256"
    
    # Crypto address (basic patterns)
    if re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', target):  # Bitcoin
        return "crypto_btc"
    if re.match(r'^0x[a-fA-F0-9]{40}$', target):  # Ethereum
        return "crypto_eth"
    
    # File path/name
    if '.' in target and len(target.split('.')[-1]) <= 5:
        return "file"
    
    # Username (απλός έλεγχος)
    if len(target) >= 3 and len(target) <= 30 and ' ' not in target:
        return "username"
    
    return "unknown"

# ===================== ROUTES =====================
app.register_blueprint(app_crypto, url_prefix='/crypto')
app.register_blueprint(app_file)
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/threat-dashboard', methods=['GET'])
def threat_dashboard():
    """Render the threat intelligence dashboard."""
    return render_template('threat_dashboard.html')

@app.route('/api/health', methods=['GET'])
def api_health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'InsightOS',
        'version': '4.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/threat/scan', methods=['POST'])
def threat_scan():
    """Endpoint για threat intelligence scans."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        target = data.get('target', '').strip()
        scan_mode = data.get('mode', 'standard')
        scan_type = data.get('type', 'auto')
        
        if not target:
            return jsonify({'success': False, 'error': 'Target is required'}), 400
        
        print(f"Threat scan requested: {target} (mode: {scan_mode}, type: {scan_type})")
        
        # Validate scan mode
        if scan_mode not in ['quick', 'standard', 'full']:
            scan_mode = 'standard'
        
        # Determine target type if auto
        if scan_type == 'auto':
            target_type = detect_target_type(target)
        else:
            target_type = scan_type
        
        print(f"Detected target type: {target_type}")
        
        # Run appropriate scan
        if scan_mode == 'quick':
            results = threat_intel.quick_scan(target)
        else:
            results = threat_intel.full_threat_analysis(target, target_type)
        
        # Add scan metadata
        results['scan_mode'] = scan_mode
        results['api_keys_configured'] = len([k for k, v in THREAT_API_KEYS.items() if v])
        
        return jsonify({
            'success': True,
            'target': target,
            'type': target_type,
            'mode': scan_mode,
            'results': results,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Threat scan error: {str(e)}")
        print(error_details)
        return jsonify({
            'success': False, 
            'error': f'Server error: {str(e)}'
        }), 500

@app.route('/api/threat/status', methods=['GET'])
def threat_api_status():
    """Check status of all threat intelligence APIs."""
    api_status = {}
    
    # Check which APIs are configured
    for api_name, api_key in THREAT_API_KEYS.items():
        api_status[api_name] = {
            'configured': api_key is not None and api_key.strip() != '',
            'key_present': bool(api_key),
            'status': 'available' if api_key else 'not_configured'
        }
    
    return jsonify({
        'success': True,
        'apis': api_status,
        'total_configured': len([k for k, v in THREAT_API_KEYS.items() if v]),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/track', methods=['POST'])
def track():
    """Main tracking endpoint for all tracker types."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        tracker_type = data.get('type')
        target = data.get('target', '').strip()
        
        if not tracker_type:
            return jsonify({'success': False, 'error': 'Missing tracker type'}), 400
        
        if not target:
            return jsonify({'success': False, 'error': 'Target cannot be empty'}), 400
        
        print(f"Tracking request: type={tracker_type}, target={target}")
        
        # Route to appropriate tracker
        if tracker_type == 'phone':
            result = track_phone(target)
            
        elif tracker_type == 'email':
            if '@' not in target:
                return jsonify({'success': False, 'error': 'Invalid email format'}), 400
            result = track_email(target)
            
        elif tracker_type == 'ip':
            import socket
            try:
                socket.inet_aton(target)
            except socket.error:
                return jsonify({'success': False, 'error': 'Invalid IP address format'}), 400
            result = track_ip(target)
            
        elif tracker_type == 'domain':
            if '.' not in target or ' ' in target:
                return jsonify({'success': False, 'error': 'Invalid domain format'}), 400
            result = track_domain(target)
            
        elif tracker_type == 'crypto':
            result = track_crypto(target)
            
        elif tracker_type == 'username':
            if not target.strip():
                return jsonify({'success': False, 'error': 'Username cannot be empty'}), 400
            result = username_tracker(target)
            
        elif tracker_type == 'metadata':
            return jsonify({'success': False, 'error': 'Use /upload endpoint for metadata analysis'}), 400
            
        elif tracker_type == 'threat':
            # Use the threat scan endpoint
            return threat_scan()
            
        else:
            return jsonify({'success': False, 'error': f'Unsupported tracker type: {tracker_type}'}), 400
        
        # Προσθήκη metadata στα results
        if isinstance(result, dict):
            result['tracker_type'] = tracker_type
            result['timestamp'] = datetime.now().isoformat()
        
        return jsonify({
            'success': True,
            'type': tracker_type,
            'target': target,
            'results': result,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in track endpoint: {str(e)}")
        print(error_details)
        return jsonify({
            'success': False, 
            'error': f'Server error: {str(e)}'
        }), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    """Endpoint για ανέβασμα και ανάλυση αρχείων (metadata)."""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No selected file'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({
                'success': False, 
                'error': f'File type not allowed. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}'
            }), 400
        
        # Ασφαλής όνομα αρχείου
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Δημιουργία φακέλου uploads αν δεν υπάρχει
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Αποθήκευση αρχείου
        file.save(filepath)
        
        print(f"File uploaded: {filename} ({os.path.getsize(filepath)} bytes)")
        
        # Εξαγωγή metadata
        result = track_metadata(filepath)
        
        # Καθαρισμός (διαγραφή αρχείου)
        try:
            os.remove(filepath)
        except Exception as e:
            print(f"Warning: Could not delete uploaded file: {e}")
        
        return jsonify({
            'success': True,
            'type': 'metadata',
            'filename': filename,
            'results': result,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in upload endpoint: {str(e)}")
        print(error_details)
        return jsonify({
            'success': False, 
            'error': f'Server error: {str(e)}'
        }), 500

@app.route('/api/ai-chat', methods=['POST'])
def ai_chat():
    """Endpoint για το AI Helper."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        question = data.get('question', '').strip()
        context = data.get('context', {})
        
        if not question:
            return jsonify({'success': False, 'error': 'Question is required'}), 400
        
        print(f"AI Chat question: {question[:100]}...")
        
        # Προσομοίωση AI responses
        tracker_type = context.get('type', 'unknown')
        target = context.get('target', 'unknown')
        results = context.get('results', {})
        
        question_lower = question.lower()
        
        # Threat Intelligence specific responses
        if 'threat' in tracker_type or 'risk' in question_lower or 'malicious' in question_lower:
            risk_level = results.get('overall_risk', 'UNKNOWN')
            
            if risk_level == 'CRITICAL':
                response = f"🚨 **CRITICAL THREAT DETECTED**\n\nTarget: {target}\nRisk Level: {risk_level}\n\n**Immediate Actions Required:**\n1. Isolate the target immediately\n2. Notify security team\n3. Block in firewall rules\n4. Conduct forensic analysis\n\n**Explanation:** This target has been flagged by multiple threat intelligence sources with high confidence of malicious activity."
            
            elif risk_level == 'HIGH':
                response = f"⚠️ **HIGH RISK THREAT**\n\nTarget: {target}\nRisk Level: {risk_level}\n\n**Recommended Actions:**\n1. Monitor closely for suspicious activity\n2. Consider blocking the target\n3. Investigate further with additional tools\n4. Document findings for compliance\n\n**Note:** Multiple indicators suggest this target may be involved in malicious activities."
            
            elif risk_level == 'MEDIUM':
                response = f"🔍 **MEDIUM RISK**\n\nTarget: {target}\nRisk Level: {risk_level}\n\n**Suggestions:**\n1. Add to watchlist for monitoring\n2. Schedule regular re-scans\n3. Investigate historical activity\n4. Check for related indicators\n\n**Context:** Some security tools have flagged this target, but further investigation is needed."
            
            elif risk_level == 'LOW':
                response = f"📊 **LOW RISK**\n\nTarget: {target}\nRisk Level: {risk_level}\n\n**Guidance:**\n1. Normal monitoring recommended\n2. No immediate action required\n3. Update threat intelligence feeds\n4. Maintain security best practices"
            
            else:
                response = f"**Threat Analysis**\n\nTarget: {target}\nStatus: {risk_level}\n\n**General Advice:**\n1. Always verify findings with multiple sources\n2. Consider the context of your investigation\n3. Document all evidence properly\n4. Follow your organization's security protocols"
        
        # General OSINT responses
        elif 'explain' in question_lower:
            response = f"**Analysis Explanation:**\n\nBased on {tracker_type} tracking of **{target}**:\n\nThis OSINT analysis provides information gathered from publicly available sources. The results should be verified through additional means and interpreted within the proper legal and ethical context.\n\n**Key Considerations:**\n• Always respect privacy laws\n• Verify information from multiple sources\n• Document your methodology\n• Consider the recency of the data"
        
        elif 'next step' in question_lower or 'what next' in question_lower:
            response = f"**Next Steps for {tracker_type.upper()} Investigation:**\n\n1. **Corroborate Evidence** - Verify findings with additional OSINT tools\n2. **Contextual Analysis** - Research related entities and patterns\n3. **Timeline Creation** - Document when information was discovered\n4. **Source Validation** - Assess the reliability of each data source\n5. **Report Generation** - Compile findings into a structured report\n\n**Advanced Techniques:**\n• Cross-reference with threat intelligence feeds\n• Check for associated infrastructure\n• Analyze behavioral patterns\n• Monitor for changes over time"
        
        elif 'legal' in question_lower or 'ethical' in question_lower:
            response = f"**Legal & Ethical Considerations for OSINT:**\n\n1. **Compliance** - Ensure you comply with local laws (GDPR, CCPA, etc.)\n2. **Authorization** - Only conduct investigations with proper authorization\n3. **Data Minimization** - Collect only necessary information\n4. **Purpose Limitation** - Use data only for stated legitimate purposes\n5. **Transparency** - Be transparent about data collection methods\n\n**Best Practices:**\n• Always obtain proper authorization\n• Respect terms of service of platforms\n• Avoid accessing non-public information\n• Document your legal basis for investigation"
        
        elif 'tool' in question_lower or 'resource' in question_lower:
            response = f"**Recommended OSINT Tools & Resources:**\n\n**General OSINT:**\n• Maltego - Data visualization and link analysis\n• SpiderFoot - Automated OSINT collection\n• Recon-ng - Web reconnaissance framework\n\n**Threat Intelligence:**\n• MISP - Threat intelligence sharing platform\n• TheHive - Security incident response platform\n• Cortex - Analysis engine for observables\n\n**Training Resources:**\n• OSINT Framework (osintframework.com)\n• SANS SEC487 OSINT course\n• Trace Labs OSINT CTFs"
        
        else:
            response = f"**InsightOS AI Assistant**\n\nI understand you're asking about **'{question}'** regarding {tracker_type} tracking of **{target}**.\n\n**General OSINT Guidance:**\n1. Always verify information from multiple independent sources\n2. Consider the timeliness and relevance of collected data\n3. Document your process and findings systematically\n4. Maintain professional ethics throughout your investigation\n\n**Tip:** For specific threat analysis, try the Threat Intelligence module which aggregates data from VirusTotal, AbuseIPDB, Shodan, and other security sources."
        
        return jsonify({
            'success': True,
            'response': response,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in AI chat: {str(e)}")
        print(error_details)
        return jsonify({
            'success': False, 
            'error': f'Server error: {str(e)}'
        }), 500

@app.route('/api/system/status', methods=['GET'])
def system_status():
    """Check system status and available trackers."""
    trackers_available = {
        'phone': True,
        'email': True,
        'ip': True,
        'domain': True,
        'crypto': True,
        'username': True,
        'metadata': True,
        'threat': True  # Πάντα διαθέσιμο ακόμα και ως dummy
    }
    
    # Check if directories exist
    directories = {
        'uploads': os.path.exists('uploads'),
        'templates': os.path.exists('templates'),
        'trackers': os.path.exists('trackers')
    }
    
    return jsonify({
        'success': True,
        'status': 'operational',
        'version': '4.0',
        'service': 'InsightOS - OSINT & Threat Intelligence Platform',
        'trackers_available': trackers_available,
        'threat_intelligence': {
            'enabled': True,
            'apis_configured': len([k for k, v in THREAT_API_KEYS.items() if v]),
            'total_apis': len(THREAT_API_KEYS)
        },
        'directories': directories,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/target/detect', methods=['POST'])
def detect_target():
    """Endpoint για αυτόματη ανίχνευση τύπου στόχου."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({'success': False, 'error': 'Target is required'}), 400
        
        target_type = detect_target_type(target)
        
        # Προτάσεις για το τι μπορεί να γίνει με αυτόν τον τύπο στόχου
        suggestions = {
            'ip': ['IP Geolocation', 'Threat Intelligence Scan', 'Whois Lookup', 'Port Scan'],
            'domain': ['DNS Records', 'SSL Certificate Analysis', 'Whois Lookup', 'Subdomain Enumeration'],
            'email': ['Email Validation', 'Breach Check', 'Domain Analysis', 'Social Media Search'],
            'phone': ['Carrier Lookup', 'Geolocation', 'Social Media Search', 'Caller ID Check'],
            'url': ['URL Analysis', 'Screenshot Capture', 'Security Scan', 'Content Analysis'],
            'username': ['Social Media Search', 'Forum Search', 'Data Breach Check', 'Profile Analysis'],
            'hash_md5': ['VirusTotal Scan', 'Hash Lookup', 'Malware Analysis'],
            'hash_sha1': ['VirusTotal Scan', 'Hash Lookup', 'Malware Analysis'],
            'hash_sha256': ['VirusTotal Scan', 'Hash Lookup', 'Malware Analysis'],
            'crypto_btc': ['Transaction History', 'Balance Check', 'Address Analysis'],
            'crypto_eth': ['Transaction History', 'Balance Check', 'Address Analysis'],
            'unknown': ['Try different format', 'Manual analysis required']
        }
        
        return jsonify({
            'success': True,
            'target': target,
            'detected_type': target_type,
            'suggestions': suggestions.get(target_type, ['Manual analysis required']),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({
        'success': False,
        'error': 'Endpoint not found',
        'message': 'The requested URL was not found on the server.'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'message': 'An internal server error occurred.'
    }), 500

@app.errorhandler(413)
def too_large(error):
    """Handle 413 errors (file too large)."""
    return jsonify({
        'success': False,
        'error': 'File too large',
        'message': f'File exceeds maximum size of {app.config["MAX_CONTENT_LENGTH"] / (1024*1024)}MB'
    }), 413

# ===================== MAIN =====================

if __name__ == '__main__':
    # Δημιουργία απαραίτητων φακέλων
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    
    print("\n" + "=" * 60)
    print("🚀 InsightOS - OSINT & Threat Intelligence Platform")
    print("=" * 60)
    print(f"📡 Server URL: http://localhost:5000")
    print(f"🤖 AI Chat: http://localhost:5000 (click AI button)")
    print(f"🏥 Health Check: http://localhost:5000/api/health")
    print("\n📊 Available Trackers:")
    print("  • Phone Tracker")
    print("  • Email Tracker") 
    print("  • IP Tracker")
    print("  • Domain Tracker")
    print("  • Username Tracker")
    print("  • Crypto Tracker")
    print("  • Metadata Tracker")
    print("  • Threat Intelligence (Basic)")
    
    print("\n🔑 Threat Intelligence API Status:")
    configured_apis = 0
    for api_name, api_key in THREAT_API_KEYS.items():
        status = "✅ Configured" if api_key else "❌ Not configured"
        configured_apis += 1 if api_key else 0
        print(f"  {api_name:15} {status}")
    
    print(f"\n📈 APIs Configured: {configured_apis}/{len(THREAT_API_KEYS)}")
    
    if configured_apis == 0:
        print("\nℹ️  NOTE: Threat Intelligence is in basic mode")
        print("   Configure API keys for full functionality:")
        print("   export VT_API_KEY='your-key-here'")
        print("   export ABUSEIPDB_API_KEY='your-key-here'")
    
    print("\n💡 Features:")
    print("  • All OSINT trackers operational")
    print("  • AI Chat Helper with context-aware responses")
    print("  • Threat Intelligence with risk assessment")
    print("  • File upload for metadata analysis")
    print("  • Auto target type detection")
    print("  • Dark/Light theme support")
    print("=" * 60 + "\n")
    
    # Εκτέλεση server
    app.run(
        debug=True, 
        port=5000,
        host='0.0.0.0'
    )