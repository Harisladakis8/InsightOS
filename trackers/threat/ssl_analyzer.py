import ssl
import socket
from datetime import datetime
import OpenSSL
import requests

def analyze_ssl(domain: str) -> dict:
    """Analyze SSL/TLS certificate of a domain."""
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cert_bin = ssock.getpeercert(binary_form=True)
                
                # Parse certificate with OpenSSL
                x509 = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_ASN1, cert_bin
                )
                
                # Extract certificate details
                issuer = dict(x509.get_issuer().get_components())
                subject = dict(x509.get_subject().get_components())
                
                not_before = x509.get_notBefore().decode('utf-8')
                not_after = x509.get_notAfter().decode('utf-8')
                
                # Convert dates
                from datetime import datetime
                fmt = "%Y%m%d%H%M%SZ"
                valid_from = datetime.strptime(not_before, fmt)
                valid_to = datetime.strptime(not_after, fmt)
                days_left = (valid_to - datetime.now()).days
                
                results = {
                    "domain": domain,
                    "valid": True,
                    "days_remaining": days_left,
                    "valid_from": valid_from.isoformat(),
                    "valid_to": valid_to.isoformat(),
                    "issuer": {
                        "organization": issuer.get(b'O', b'').decode(),
                        "common_name": issuer.get(b'CN', b'').decode()
                    },
                    "subject": {
                        "organization": subject.get(b'O', b'').decode(),
                        "common_name": subject.get(b'CN', b'').decode(),
                        "country": subject.get(b'C', b'').decode()
                    },
                    "serial_number": str(x509.get_serial_number()),
                    "signature_algorithm": x509.get_signature_algorithm().decode(),
                    "version": x509.get_version(),
                }
                
                # Check SSL Labs grade (optional)
                try:
                    ssl_labs = requests.get(
                        f"https://api.ssllabs.com/api/v3/analyze?host={domain}",
                        timeout=10
                    )
                    if ssl_labs.status_code == 200:
                        labs_data = ssl_labs.json()
                        results["ssl_labs_grade"] = labs_data.get("grade", "Unknown")
                except:
                    results["ssl_labs_grade"] = "Check failed"
                
                # Security assessment
                if days_left < 0:
                    results["cert_status"] = "EXPIRED"
                    results["risk_level"] = "CRITICAL"
                elif days_left < 7:
                    results["cert_status"] = "EXPIRING_SOON"
                    results["risk_level"] = "HIGH"
                elif days_left < 30:
                    results["cert_status"] = "NEAR_EXPIRATION"
                    results["risk_level"] = "MEDIUM"
                else:
                    results["cert_status"] = "VALID"
                    results["risk_level"] = "LOW"
                
                # Check for vulnerabilities
                cipher = ssock.cipher()
                results["cipher"] = {
                    "name": cipher[0],
                    "version": cipher[1],
                    "bits": cipher[2]
                }
                
                # Weak cipher check
                weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT"]
                if any(weak in cipher[0] for weak in weak_ciphers):
                    results["weak_cipher"] = True
                    results["risk_level"] = "HIGH"
                else:
                    results["weak_cipher"] = False
                
                return results
                
    except ssl.SSLError as e:
        return {
            "domain": domain,
            "valid": False,
            "error": f"SSL Error: {str(e)}",
            "risk_level": "HIGH"
        }
    except Exception as e:
        return {
            "domain": domain,
            "valid": False,
            "error": str(e),
            "risk_level": "UNKNOWN"
        }