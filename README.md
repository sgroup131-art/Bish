# Bish - Phishing & Vulnerability Scanner

Bish is a lightweight Python tool designed to detect suspicious URLs, analyze website security headers, validate SSL certificates, collect WHOIS data, and lookup CVEs from the NVD database.  
It helps security learners and professionals quickly identify potential phishing attempts and common misconfigurations.

---

## ✨ Features
- **URL Analysis**: Detects suspicious keywords, long URLs, encoded characters, and risky TLDs.
- **Header Security Check**: Identifies missing security headers (CSP, HSTS, X-Frame-Options, etc.).
- **WHOIS Lookup**: Retrieves registrar, creation/expiration dates, and name servers.
- **SSL Certificate Validation**: Checks issuer, validity period, and expiry status.
- **CVE Search**: Queries NVD API for known vulnerabilities related to the domain.

---

## 🚀 Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/sgroup131-art/Bish.git
cd Bish
pip install -r requirements.txt