<div align="center">

# 🛡️ Safewave Phishing & BEC Detection Engine
### *Enterprise-Grade Security Operations Microservice*

[![Vercel Deployment](https://img.shields.io/badge/Status-Live%20Production-success?style=for-the-badge&logo=vercel)](https://vercel.com)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)](https://www.python.org)
[![Flask](https://img.shields.io/badge/Flask-Microservice-black?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com)
[![Security](https://img.shields.io/badge/HMAC-SHA256%20Secured-informational?style=for-the-badge&logo=securityscorecard)](https://github.com)

</div>

---

## 🏢 Overview
**Safewave Solutions Enterprise** Phishing & Business Email Compromise (BEC) Detection Engine is a high-performance, serverless backend microservice designed to inspect inbound emails, validate cryptographic mail protocols, catch display-name spoofing, and mitigate targeted financial fraud vectors in real time.

---

## ⚙️ Core Detection Capabilities

| Security Layer | Threat Target | Detection Mechanism |
| :--- | :--- | :--- |
| **1. Authentication Check** | Spoofed Domain Infrastructure | Parses `Authentication-Results` headers for SPF, DKIM, and DMARC failures. |
| **2. Sender Spoofing Analysis** | Executive Impersonation / BEC | Flags lookalike domains attempting to mimic internal company handles. |
| **3. Content Risk Engine** | Wire Fraud & Ransomware | Scans subject lines and bodies for high-risk trigger keywords (*wire transfer*, *bitcoin*, *urgent payment*). |
| **4. Cryptographic Security** | Unauthorized API Access | Enforces strict **HMAC-SHA256** digital signature authentication on all POST requests. |

---

## 🚀 API Endpoint Reference

### Base URL
https://safewave-phishing-detector.vercel.app/

### 1. Health Check (GET)
* **Endpoint:** `/`
* **Description:** Verifies service availability.

### 2. Email Threat Analysis (POST)
* **Endpoint:** `/api/v1/analyze-email`
* **Headers Required:**
  * `Content-Type: application/json`
  * `X-Signature: <HMAC-SHA256-HEX>`
* **Sample Payload:**
* json
{
"from": "CEO support@evil-lookalike.com",
"reply_to": "attacker@gmail.com",
"subject": "Urgent Wire Transfer Required",
"body": "Please wire funds immediately to account 12345.",
"headers": {
"Authentication-Results": "spf=fail dkim=fail"
}
}

* ---

## 🔒 Security & Deployment
Built for high availability and low latency on Vercel's serverless edge infrastructure. Protected via cryptographic header validation to prevent unauthorized telemetry injection.

<div align="center">
<b>Safewave Solutions Enterprise # Next-Gen Security for Next-Gen Threats</b>
</div>
