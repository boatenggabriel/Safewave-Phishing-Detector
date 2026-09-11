import re
import hmac
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

# Enterprise Security Configuration
API_SECRET_KEY = b"ChangeThisToAStrongSecureSecretKeyForSafewave"
COMPANY_DOMAINS = {"safewavesolutions.com", "safewave.com.gh"}

# Known high-risk keywords associated with Business Email Compromise (BEC)
BEC_KEYWORDS = [
    "wire transfer", "bank details", "update payment", "invoice attached",
    "urgent payment", "confidential review", "immediate action required",
    "purchase order", "bitcoin", "crypto payment"
]

def verify_hmac_signature(req):
    """Validates incoming requests from mail servers or plugins using HMAC-SHA256."""
    signature = req.headers.get("X-Signature")
    if not signature:
        return False
    computed = hmac.new(API_SECRET_KEY, req.get_data(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, signature)

def analyze_email_headers(headers):
    """Analyzes authentication protocols (SPF, DKIM, DMARC) and return paths."""
    score = 0
    anomalies = []

    auth_results = headers.get("Authentication-Results", "").lower()
    if "spf=fail" in auth_results or "spf=softfail" in auth_results:
        score += 35
        anomalies.append("SPF validation failed or soft-failed.")
    if "dkim=fail" in auth_results:
        score += 35
        anomalies.append("DKIM signature verification failed.")
    if "dmarc=fail" in auth_results:
        score += 40
        anomalies.append("DMARC policy check failed.")

    return score, anomalies

def analyze_sender_spoofing(from_header, reply_to):
    """Detects display-name spoofing and external lookalike domains."""
    score = 0
    anomalies = []

    # Extract email address inside angle brackets if present (e.g., "CEO <attacker@evil.com>")
    email_match = re.search(r"<([^>]+)>", from_header)
    sender_email = email_match.group(1).lower() if email_match else from_header.lower()
    
    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""

    # Check if sender claims company name but uses an external domain
    if any(keyword in from_header.lower() for keyword in ["safewave", "executive", "ceo", "director"]) \
       and sender_domain not in COMPANY_DOMAINS:
        score += 50
        anomalies.append("Potential Executive Display-Name Spoofing from external domain.")

    # Check for Reply-To Mismatch (Classic BEC tactic)
    if reply_to and reply_to.lower() not in sender_email:
        score += 40
        anomalies.append("Reply-To header mismatch detected (diverting replies to external address).")

    return score, anomalies

def analyze_content(subject, body):
    """Scans subject and body text for urgent financial triggers and suspicious URLs."""
    score = 0
    anomalies = []

    combined_text = f"{subject} {body}".lower()

    # Keyword matching
    matched_keywords = [kw for kw in BEC_KEYWORDS if kw in combined_text]
    if matched_keywords:
        score += len(matched_keywords) * 15
        anomalies.append(f"High-risk BEC trigger keywords found: {', '.join(matched_keywords)}")

    # Suspicious link patterns (IP addresses in URLs or url shorteners)
    ip_url_pattern = r"https?://(?:\d{1,3}\.){3}\d{1,3}"
    if re.search(ip_url_pattern, combined_text):
        score += 50
        anomalies.append("Email contains a direct IP address URL link.")

    return score, anomalies

@app.route("/api/v1/analyze-email", methods=["POST"])
def analyze_email():
    # 1. Security Check
    if not verify_hmac_signature(request):
        return jsonify({"error": "Unauthorized: Invalid or missing cryptographic signature."}), 401

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid payload format."}), 400

    # 2. Extract Data Fields
    sender = data.get("from", "")
    reply_to = data.get("reply_to", "")
    subject = data.get("subject", "")
    body = data.get("body", "")
    headers = data.get("headers", {})

    # 3. Risk Calculation Engine
    total_score = 0
    all_anomalies = []

    h_score, h_anomalies = analyze_email_headers(headers)
    total_score += h_score
    all_anomalies.extend(h_anomalies)

    s_score, s_anomalies = analyze_sender_spoofing(sender, reply_to)
    total_score += s_score
    all_anomalies.extend(s_anomalies)

    c_score, c_anomalies = analyze_content(subject, body)
    total_score += c_score
    all_anomalies.extend(c_anomalies)

    # 4. Decision Thresholds
    if total_score >= 70:
        action = "QUARANTINE"
        risk_level = "HIGH"
    elif total_score >= 40:
        action = "TAG_WARNING"
        risk_level = "MEDIUM"
    else:
        action = "ALLOW"
        risk_level = "LOW"

    # 5. Enterprise Response Log
    response_payload = {
        "company": "Safewave Solutions Enterprise",
        "risk_score": total_score,
        "risk_level": risk_level,
        "recommended_action": action,
        "indicators": all_anomalies
    }

    return jsonify(response_payload), 200

if __name__ == "__main__":
    # Run locally or behind an enterprise production WSGI server like Gunicorn
    app.run(host="0.0.0.0", port=5000, debug=False)