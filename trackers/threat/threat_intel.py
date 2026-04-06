# Στο app.py προσθέτουμε:
import os
from trackers.threat.threat_intel import get_threat_intel
import re 
import json
from flask import Flask , jsonify ,  request,blueprints,Blueprint
import datetime

threat = Blueprint("threat", __name__)
# Configuration για threat intelligence
THREAT_API_KEYS = {
    "virustotal": os.getenv("VT_API_KEY"),
    "abuseipdb": os.getenv("ABUSEIPDB_API_KEY"),
    "shodan": os.getenv("SHODAN_API_KEY"),
    "greynoise": os.getenv("GREYNOISE_API_KEY"),
    "urlscan": os.getenv("URLSCAN_API_KEY")
}

# Initialize threat intelligence
threat_intel = get_threat_intel(THREAT_API_KEYS)

@threat.route('/threat-scan', methods=['POST'])
def threat_scan():
    """Endpoint για threat intelligence scans."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        target = data.get('target', '').strip()
        scan_mode = data.get('mode', 'standard')  # quick, standard, full
        scan_type = data.get('type', 'auto')  # auto, ip, domain, url, hash
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Validate scan mode
        if scan_mode not in ['quick', 'standard', 'full']:
            scan_mode = 'standard'
        
        # Determine target type if auto
        if scan_type == 'auto':
            target_type = threat_intel.detect_target_type(target)
        else:
            target_type = scan_type
        
        # Perform scan based on type
        if target_type == 'ip':
            results = threat_intel.scan_ip_address(target, scan_mode)
        elif target_type == 'domain':
            results = threat_intel.scan_domain(target, scan_mode)
        elif target_type == 'url':
            results = threat_intel.scan_url(target, scan_mode)
        elif target_type.startswith('hash'):
            results = threat_intel.scan_hash(target, scan_mode)
        elif scan_mode == 'quick':
            results = threat_intel.quick_scan(target)
        else:
            return jsonify({
                'error': f'Unsupported target type: {target_type}',
                'detected_type': target_type
            }), 400
        
        return jsonify({
            'success': True,
            'target': target,
            'type': target_type,
            'mode': scan_mode,
            'results': results
        })
        
    except Exception as e:
        import traceback
        print(f"Threat scan error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@threat.route('/threat-batch', methods=['POST'])
def threat_batch():
    """Endpoint για batch scanning πολλών targets."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        targets = data.get('targets', [])
        target_type = data.get('type', 'auto')
        
        if not targets or not isinstance(targets, list):
            return jsonify({'error': 'Targets list is required'}), 400
        
        if len(targets) > 20:  # Limit batch size
            return jsonify({'error': 'Maximum 20 targets per batch'}), 400
        
        # Perform batch scan
        results = threat_intel.batch_scan(targets, target_type)
        
        return jsonify({
            'success': True,
            'batch_id': results['batch_id'],
            'statistics': results['statistics'],
            'results': results['results']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threat.route('/threat-stats', methods=['GET'])
def threat_stats():
    """Endpoint για στατιστικά και system status."""
    try:
        # This would normally check API quotas, health, etc.
        stats = {
            'status': 'operational',
            'apis_configured': list(THREAT_API_KEYS.keys()),
            'apis_active': [k for k, v in THREAT_API_KEYS.items() if v],
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0'
        }
        
        return jsonify({
            'success': True,
            'stats': stats
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500