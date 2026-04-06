from flask import Flask, request, jsonify, Blueprint
from flask_cors import CORS
import openai
import json
import re
from config import KEY
from datetime import datetime

app_ai = Blueprint('app_ai', __name__)
CORS(app_ai)

# Φόρτωση API Key από περιβάλλον ή config
openai.api_key = KEY

# Βελτιωμένο System Prompt για OSINT & Threat Intelligence
SYSTEM_PROMPT = """Είσαι το InsightOS AI Helper - Ένας ειδικός βοηθός για OSINT (Open Source Intelligence) και Threat Intelligence.

Ρόλος σου:
1. Εξειδικευμένος σύμβουλος σε θέματα ασφαλείας, ανάλυσης δεδομένων και ερευνών
2. Βοηθός χρηστών στην κατανόηση και χρήση της πλατφόρμας InsightOS
3. Πηγή γνώσης για τεχνικές OSINT, εργαλεία και βέλτιστες πρακτικές

Ειδικές γνώσεις:
- Ανάλυση IP, Domain, Email, Usernames
- Εξαγωγή και ανάλυση μεταδεδομένων
- Ανίχνευση απειλών και ανάλυση κινδύνου
- Cryptocurrency tracking
- Legal and ethical considerations in OSINT

Στυλ απαντήσεων:
1. Χρησιμοποίησε Ελληνικά με επαγγελματικό τόνο
2. Δώσε πρακτικές συμβουλές και βήματα
3. Όταν χρειάζεται, πρότεινε συγκεκριμένα εργαλεία ή τεχνικές
4. Εξήγησε τεχνικούς όρους με απλό τρόπο
5. Συνδέσου με τις λειτουργίες της πλατφόρμας (Phone Tracker, IP Tracker, κλπ)
6. Χρησιμοποίησε μορφοποίηση Markdown (## για επικεφαλίδες, **bold**, lists)

Πάντα:
- Να είσαι ακριβής και επαγγελματικός
- Να τονίζεις την σημασία της νομικότητας και ηθικής
- Να προτείνεις συγκεκριμένες ενέργειες
- Να αναφέρεσαι στις δυνατότητες του InsightOS
- Να προσαρμόζεσαι στο επίπεδο γνώσεων του χρήστη"""

# Βάση γνώσεων για συγκεκριμένες λειτουργίες της εφαρμογής
APP_KNOWLEDGE_BASE = {
    "trackers": {
        "phone": "Ανίχνευση τηλεφώνων: Ανάλυση αριθμού, φορέα, γεωγραφικής θέσης. Χρήση APIs όπως NumVerify, Google Libphonenumber.",
        "email": "Email Analysis: Έλεγχος εγκυρότητας, MX records, disposable email detection, breach databases.",
        "ip": "IP Intelligence: Γεωτοποθεσία, ISP, threat reputation, open ports, whois, historical data.",
        "domain": "Domain Analysis: Whois, DNS records, SSL certificates, subdomains, historical changes.",
        "username": "Username Search: Cross-platform reconnaissance, social media presence, data leaks.",
        "crypto": "Cryptocurrency Tracking: Blockchain analysis, transaction history, wallet monitoring.",
        "metadata": "Metadata Extraction: EXIF data from images, document metadata, GPS coordinates, timestamps.",
        "threat": "Threat Intelligence: Comprehensive security assessment, risk scoring, vulnerability scanning."
    },
    "features": [
        "Real-time tracking across multiple data sources",
        "Threat scoring and risk assessment",
        "AI-powered analysis and recommendations",
        "Interactive visualizations",
        "Export capabilities for reports",
        "API integration for automation"
    ],
    "tools": [
        "Shodan - IoT and device scanning",
        "VirusTotal - Malware analysis",
        "HaveIBeenPwned - Breach checking",
        "Hunter.io - Email finding",
        "Maltego - Data visualization",
        "theHarvester - Information gathering"
    ]
}

@app_ai.route("/api/chat-enhanced", methods=["POST"])
def chat_enhanced():
    """
    Enhanced AI chat endpoint with context awareness and app integration
    """
    data = request.get_json()
    user_message = data.get("message", "").strip()
    context = data.get("context", {})  # Μπορεί να περιέχει info για τρέχουσα λειτουργία
    
    if not user_message:
        return jsonify({
            "success": False,
            "response": "Παρακαλώ εισάγετε ένα μήνυμα."
        })
    
    try:
        # Προσθήκη context στο prompt αν υπάρχει
        enhanced_prompt = SYSTEM_PROMPT
        
        # Προσθέτουμε πληροφορίες για την τρέχουσα κατάσταση της εφαρμογής
        if context:
            context_info = f"\n\nΠληροφορίες από την εφαρμογή:\n"
            
            if context.get("current_tracker"):
                tracker = context.get("current_tracker")
                tracker_info = APP_KNOWLEDGE_BASE["trackers"].get(tracker, "")
                context_info += f"- Τρέχων Tracker: {tracker}\n"
                context_info += f"- Περιγραφή: {tracker_info}\n"
            
            if context.get("last_results"):
                context_info += f"- Προηγούμενα αποτελέσματα: Υπάρχουν διαθέσιμα\n"
            
            if context.get("user_role"):
                context_info += f"- Ρόλος χρήστη: {context.get('user_role')}\n"
            
            enhanced_prompt += context_info
        
        # Προσθήκη συγκεκριμένων οδηγιών βάσει του μηνύματος
        enhanced_prompt += f"\n\nUser Question: {user_message}"
        enhanced_prompt += "\n\nΑπάντησε στα Ελληνικά με βάση τις παραπάνω οδηγίες."
        
        # Ανάλυση του μηνύματος για να προσδιορίσουμε τον τύπο
        message_type = analyze_message_type(user_message)
        
        if message_type == "app_function":
            # Προσθήκη ειδικών οδηγιών για λειτουργίες εφαρμογής
            enhanced_prompt += "\n\nΣημείωση: Ο χρήστης ρωτάει για λειτουργία της εφαρμογής. Δώσε πρακτικές οδηγίες και αναφέρθηκε στις δυνατότητες του InsightOS."
        
        # Καλείμε το OpenAI API
        response = openai.chat.completions.create(
            model="gpt-4",  # ή "gpt-3.5-turbo" για καλύτερη ταχύτητα
            messages=[
                {"role": "system", "content": enhanced_prompt},
                {"role": "user", "content": user_message}
            ],
            temperature=0.7,
            max_tokens=800,
            presence_penalty=0.3,
            frequency_penalty=0.2
        )
        
        gpt_response = response.choices[0].message.content
        
        # Επεξεργασία της απάντησης για να την κάνουμε πιο χρήσιμη
        processed_response = enhance_response(gpt_response, user_message, context)
        
        return jsonify({
            "success": True,
            "response": processed_response,
            "metadata": {
                "message_type": message_type,
                "contains_actions": check_for_actions(processed_response),
                "timestamp": datetime.now().isoformat()
            }
        })
        
    except Exception as e:
        print(f"AI Error: {str(e)}")
        return jsonify({
            "success": False,
            "response": f"Σφάλμα στην επεξεργασία της αιτήσεως: {str(e)}"
        })

@app_ai.route("/api/chat-simple", methods=["POST"])
def chat_simple():
    """
    Απλοποιημένο endpoint για γρήγορη ανταπόκριση
    """
    data = request.get_json()
    message = data.get("message", "")
    
    if not message:
        return jsonify({"success": False, "response": "Δεν στάλθηκε μήνυμα!"})
    
    try:
        # Χρησιμοποιούμε το ίδιο system prompt αλλά με πιο σύντομες απαντήσεις
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",  # Ταχύτερο για απλές ερωτήσεις
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT[:500] + "... (Χρησιμοποίησε Ελληνικά)"},
                {"role": "user", "content": message}
            ],
            temperature=0.7,
            max_tokens=400
        )
        
        gpt_response = response.choices[0].message.content
        
        return jsonify({
            "success": True,
            "response": gpt_response
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "response": f"Σφάλμα: {str(e)}"
        })

@app_ai.route("/api/chat-with-context", methods=["POST"])
def chat_with_context():
    """
    AI chat που διατηρεί ιστορικό συζήτησης
    """
    data = request.get_json()
    messages_history = data.get("messages", [])
    new_message = data.get("message", "")
    
    if not new_message:
        return jsonify({"success": False, "response": "Δεν στάλθηκε μήνυμα!"})
    
    try:
        # Προετοιμάζουμε το ιστορικό μηνυμάτων
        all_messages = [
            {"role": "system", "content": SYSTEM_PROMPT}
        ]
        
        # Προσθέτουμε το ιστορικό (περιορίζουμε σε 10 τελευταία μηνύματα)
        for msg in messages_history[-10:]:
            all_messages.append({
                "role": msg.get("role", "user"),
                "content": msg.get("content", "")
            })
        
        # Προσθέτουμε το νέο μήνυμα
        all_messages.append({"role": "user", "content": new_message})
        
        # Καλούμε το API
        response = openai.chat.completions.create(
            model="gpt-4",
            messages=all_messages,
            temperature=0.7,
            max_tokens=600
        )
        
        gpt_response = response.choices[0].message.content
        
        return jsonify({
            "success": True,
            "response": gpt_response,
            "context_length": len(all_messages)
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "response": f"Σφάλμα: {str(e)}"
        })

@app_ai.route("/api/get-quick-tips", methods=["GET"])
def get_quick_tips():
    """
    Επιστρέφει προκαθορισμένες συμβουλές και ερωτήσεις για τον χρήστη
    """
    tips = [
        {
            "id": 1,
            "question": "Πώς να αναλύσω ένα IP address;",
            "category": "ip_analysis",
            "short_answer": "Χρησιμοποίησε το IP Tracker του InsightOS για πληροφορίες γεωτοποθεσίας, ISP και threat reputation."
        },
        {
            "id": 2,
            "question": "Τι είναι το OSINT και είναι νόμιμο;",
            "category": "basics",
            "short_answer": "Το OSINT είναι συλλογή πληροφοριών από ανοιχτές πηγές. Είναι νόμιμο όταν γίνεται για νόμιμους σκοπούς και σεβασμό της ιδιωτικότητας."
        },
        {
            "id": 3,
            "question": "Πώς να ελέγξω αν ένα email έχει παραβιαστεί;",
            "category": "email_security",
            "short_answer": "Χρησιμοποίησε το Email Tracker και ελέγχεσε σε βάσεις δεδομένων όπως το HaveIBeenPwned."
        },
        {
            "id": 4,
            "question": "Ποιες είναι οι καλύτερες πρακτικές για Threat Intelligence;",
            "category": "threat_intel",
            "short_answer": "1. Συλλογή δεδομένων 2. Ανάλυση 3. Αξιολόγηση κινδύνου 4. Λήψη μέτρων. Χρησιμοποίησε το Threat Intelligence module του InsightOS."
        },
        {
            "id": 5,
            "question": "Πώς να εξάγω μεταδεδομένα από εικόνες;",
            "category": "metadata",
            "short_answer": "Χρησιμοποίησε το Metadata Tracker του InsightOS. Ανέβασε εικόνα και θα δεις EXIF data, GPS coordinates, κλπ."
        },
        {
            "id": 6,
            "question": "Ποιες πηγές χρησιμοποιεί το InsightOS;",
            "category": "app_info",
            "short_answer": "Δημόσια APIs, threat intelligence feeds, whois databases, social media platforms, και ειδικές βάσεις δεδομένων."
        }
    ]
    
    return jsonify({
        "success": True,
        "tips": tips,
        "count": len(tips)
    })

@app_ai.route("/api/analyze-results", methods=["POST"])
def analyze_results():
    """
    Ανάλυση αποτελεσμάτων tracking με AI
    """
    data = request.get_json()
    results = data.get("results", {})
    tracker_type = data.get("tracker_type", "unknown")
    
    if not results:
        return jsonify({
            "success": False,
            "analysis": "Δεν υπάρχουν αποτελέσματα για ανάλυση."
        })
    
    try:
        # Δημιουργούμε prompt για ανάλυση αποτελεσμάτων
        analysis_prompt = f"""
        Είσαι ειδικός αναλυτής OSINT. Αναλύεις τα παρακάτω αποτελέσματα από το InsightOS.
        
        Τύπος Ανίχνευσης: {tracker_type}
        Αποτελέσματα: {json.dumps(results, indent=2)}
        
        Παρέχε ανάλυση στα Ελληνικά που περιλαμβάνει:
        1. Σύνοψη των ευρημάτων
        2. Βαθμός κινδύνου (Κρίσιμος, Υψηλός, Μεσαίος, Χαμηλός, Καθαρός)
        3. Πιθανές απειλές ή θέματα ασφαλείας
        4. Πρακτικές συμβουλές για περαιτέρω δράση
        5. Προς τι πρέπει να προσέξει ο χρήστης
        
        Μορφοποίησε την απάντηση με Markdown.
        """
        
        response = openai.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": analysis_prompt}
            ],
            temperature=0.5,  # Χαμηλότερο για πιο συνεπείς αναλύσεις
            max_tokens=1000
        )
        
        analysis = response.choices[0].message.content
        
        # Εξαγωγή βαθμού κινδύνου από την ανάλυση
        risk_level = extract_risk_level(analysis)
        
        return jsonify({
            "success": True,
            "analysis": analysis,
            "risk_level": risk_level,
            "summary": generate_summary(analysis)
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "analysis": f"Σφάλμα στην ανάλυση: {str(e)}"
        })

# Βοηθητικές συναρτήσεις
def analyze_message_type(message):
    """Ανάλυση του τύπου του μηνύματος"""
    message_lower = message.lower()
    
    # Λέξεις-κλειδιά για κάθε τύπο
    app_keywords = ['insightos', 'tracker', 'module', 'πλατφόρμα', 'εφαρμογή']
    technical_keywords = ['api', 'technical', 'τέχνη', 'protocol', 'code']
    guidance_keywords = ['πώς', 'how to', 'βήματα', 'steps', 'οδηγίες']
    legal_keywords = ['νόμιμο', 'legal', 'ηθικό', 'ethical', 'privacy']
    
    if any(keyword in message_lower for keyword in app_keywords):
        return "app_function"
    elif any(keyword in message_lower for keyword in technical_keywords):
        return "technical"
    elif any(keyword in message_lower for keyword in guidance_keywords):
        return "guidance"
    elif any(keyword in message_lower for keyword in legal_keywords):
        return "legal"
    else:
        return "general"

def enhance_response(response, user_message, context):
    """Βελτίωση της απόκρισης του AI"""
    # Προσθήκη συγκεκριμένων παραπομπών στη λειτουργικότητα της εφαρμογής
    enhanced = response
    
    # Αν ο χρήστης ρωτάει για συγκεκριμένο tracker
    if context and context.get("current_tracker"):
        tracker = context.get("current_tracker")
        tracker_name = tracker.capitalize()
        
        # Προσθήκη note για το συγκεκριμένο tracker
        tracker_note = f"\n\n---\n*Για {tracker_name} Tracking, χρησιμοποίησε το αντίστοιχο module στο InsightOS.*"
        
        if tracker_note not in enhanced:
            enhanced += tracker_note
    
    # Προσθήκη general tip για το InsightOS
    insightos_tip = "\n\n💡 **InsightOS Tip:** Μπορείς να χρησιμοποιήσεις πολλαπλά trackers ταυτόχρονα για ολοκληρωμένη ανάλυση."
    
    if insightos_tip not in enhanced:
        enhanced += insightos_tip
    
    return enhanced

def check_for_actions(response):
    """Έλεγχος αν η απόκριση περιέχει προτεινόμενες ενέργειες"""
    action_keywords = [
        'πρέπει να', 'should', 'προτείνω', 'recommend',
        'βήματα', 'steps', 'ενέργειες', 'actions',
        'ελέγξτε', 'check', 'χρησιμοποιήστε', 'use'
    ]
    
    return any(keyword in response.lower() for keyword in action_keywords)

def extract_risk_level(analysis):
    """Εξαγωγή επιπέδου κινδύνου από ανάλυση"""
    analysis_lower = analysis.lower()
    
    if 'κρίσιμο' in analysis_lower or 'critical' in analysis_lower:
        return "CRITICAL"
    elif 'υψηλό' in analysis_lower or 'high' in analysis_lower:
        return "HIGH"
    elif 'μεσαίο' in analysis_lower or 'medium' in analysis_lower:
        return "MEDIUM"
    elif 'χαμηλό' in analysis_lower or 'low' in analysis_lower:
        return "LOW"
    elif 'καθαρό' in analysis_lower or 'clean' in analysis_lower:
        return "CLEAN"
    else:
        return "UNKNOWN"

def generate_summary(analysis, max_length=150):
    """Δημιουργία σύντομης σύνοψης από ανάλυση"""
    # Απλή λογική για δημιουργία σύνοψης
    sentences = analysis.split('.')
    if len(sentences) > 0:
        summary = sentences[0]
        if len(summary) > max_length:
            summary = summary[:max_length] + "..."
        return summary
    return "Δεν είναι δυνατή η δημιουργία σύνοψης."

# Health check endpoint
@app_ai.route("/api/ai-health", methods=["GET"])
def ai_health():
    """Health check για το AI module"""
    return jsonify({
        "status": "healthy",
        "service": "InsightOS AI Helper",
        "version": "2.0",
        "capabilities": [
            "Enhanced chat with context",
            "Quick tips and guidance",
            "Results analysis",
            "Multi-language support",
            "App integration"
        ]
    })


