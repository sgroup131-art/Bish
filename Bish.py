#!/usr/bin/env python3
# Bish - Phishing & Vulnerability Scanner
# Created by Muhammad Baloch
# Lightweight, modular script with risk scoring, URL normalization, and better error handling

import re
import json
import ssl
import socket
import requests
import whois
from urllib.parse import urlparse
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

SUSPICIOUS_PATTERNS = [
    "login", "signin", "update", "verify", "paypal", "password", "confirm",
    "secure", "account", "banking"
]

SUSPICIOUS_TLDS = {
    "tk", "xyz", "top", "work", "gq", "cf", "ga", "club", "loan", "men",
    "click", "fit", "win", "review"
}

HEADERS_SECURITY = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

def show_logo():
    logo = r"""
██████╗░██╗░░██╗██╗░██████╗██╗░░██╗
██╔══██╗██║░░██║██║██╔════╝██║░░██║
██████╦╝███████║██║╚█████╗░███████║
██╔══██╗██╔══██║██║░╚═══██╗██╔══██║
██████╦╝██║░░██║██║██████╔╝██║░░██║
╚═════╝░╚═╝░░╚═╝╚═╝╚═════╝░╚═╝░░╚═╝
"""
    print(Fore.CYAN + logo + Style.RESET_ALL)
    print(Fore.CYAN + "Bish - Phishing & Vulnerability Scanner" + Style.RESET_ALL)
    print(Fore.CYAN + "Created by Muhammad Baloch\n" + Style.RESET_ALL)

def normalize_url(url: str) -> str:
    url = url.strip()
    # Prepend scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

def parse_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return ""

def is_ip(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False

def check_url(url: str) -> dict:
    result = {
        "url": url,
        "domain": parse_domain(url),
        "risk": 0,
        "findings": []
    }

    lower_url = url.lower()

    # Suspicious keywords
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in lower_url:
            result["risk"] += 2
            result["findings"].append(f"Contains suspicious keyword: {pattern}")

    # IP address instead of domain
    host = result["domain"].split(":")[0] if result["domain"] else ""
    if is_ip(host):
        result["risk"] += 3
        result["findings"].append("Uses IP address instead of domain")

    # Excessive subdomains
    if not is_ip(host) and host:
        parts = host.split(".")
        if len(parts) >= 5:  # e.g., a.b.c.d.example.com
            result["risk"] += 2
            result["findings"].append("Excessive subdomains")

    # Suspicious TLDs
    if not is_ip(host) and host:
        tld = host.split(".")[-1]
        if tld in SUSPICIOUS_TLDS:
            result["risk"] += 2
            result["findings"].append(f"Suspicious TLD: .{tld}")

    # URL length
    if len(url) > 100:
        result["risk"] += 1
        result["findings"].append("Unusually long URL")

    # Presence of @ or encoded characters common in phishing
    if "@" in url:
        result["risk"] += 2
        result["findings"].append("Contains '@' which can hide real destination")
    if re.search(r"%[0-9A-Fa-f]{2}", url):
        result["risk"] += 1
        result["findings"].append("Contains encoded characters")

    # Display
    if result["risk"] > 0:
        print(Fore.RED + "⚠ Suspicious URL" + Style.RESET_ALL)
        for r in result["findings"]:
            print(Fore.YELLOW + "- " + r + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "✅ URL looks safe" + Style.RESET_ALL)

    return result

def site_vulnerability(url: str) -> dict:
    findings = {
        "server": "Unknown",
        "x_powered_by": "Unknown",
        "content_type": "Unknown",
        "missing_headers": [],
        "risk": 0
    }
    try:
        response = requests.get(url, timeout=8, allow_redirects=True)
        headers = response.headers

        print(Fore.CYAN + "\n[+] Site Headers:" + Style.RESET_ALL)
        findings["server"] = headers.get("Server", "Unknown")
        findings["x_powered_by"] = headers.get("X-Powered-By", "Unknown")
        findings["content_type"] = headers.get("Content-Type", "Unknown")
        print("Server:", findings["server"])
        print("X-Powered-By:", findings["x_powered_by"])
        print("Content-Type:", findings["content_type"])

        for h in HEADERS_SECURITY:
            if h not in headers:
                findings["missing_headers"].append(h)

        if findings["missing_headers"]:
            findings["risk"] += len(findings["missing_headers"])
            for h in findings["missing_headers"]:
                msg = ""
                if h == "X-Frame-Options":
                    msg = "Clickjacking risk"
                elif h == "Content-Security-Policy":
                    msg = "Cross-site scripting risk"
                elif h == "X-Content-Type-Options":
                    msg = "MIME sniffing risk"
                elif h == "Strict-Transport-Security":
                    msg = "HTTPS enforcement risk"
                elif h == "Referrer-Policy":
                    msg = "Privacy leakage risk"
                print(Fore.RED + f"⚠ Missing {h} ({msg})" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "✅ Common security headers present" + Style.RESET_ALL)

    except requests.exceptions.SSLError as e:
        findings["risk"] += 2
        print(Fore.RED + f"SSL error fetching site: {e}" + Style.RESET_ALL)
    except requests.exceptions.Timeout:
        findings["risk"] += 1
        print(Fore.RED + "Timeout fetching site headers." + Style.RESET_ALL)
    except Exception as e:
        findings["risk"] += 1
        print(Fore.RED + f"Error checking site headers: {e}" + Style.RESET_ALL)

    return findings

def _parse_cert_date(date_str: str):
    # Try multiple common formats
    fmts = [
        "%b %d %H:%M:%S %Y %Z",      # e.g., "Jun  1 12:00:00 2025 GMT"
        "%Y-%m-%d %H:%M:%S %Z",      # ISO-like with zone
        "%b %d %H:%M:%S %Y",         # without zone
    ]
    for f in fmts:
        try:
            return datetime.strptime(date_str, f)
        except Exception:
            continue
    return None

def ssl_check(domain: str) -> dict:
    info = {
        "issuer": None,
        "valid_from": None,
        "valid_until": None,
        "expired": None,
        "risk": 0
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(8)
            s.connect((domain, 443))
            cert = s.getpeercert()

            print(Fore.CYAN + "\n[+] SSL Certificate Info:" + Style.RESET_ALL)
            info["issuer"] = cert.get("issuer")
            info["valid_from"] = cert.get("notBefore")
            info["valid_until"] = cert.get("notAfter")
            print("Issuer:", info["issuer"])
            print("Valid From:", info["valid_from"])
            print("Valid Until:", info["valid_until"])

            parsed_expiry = _parse_cert_date(cert.get("notAfter", ""))
            if parsed_expiry:
                if parsed_expiry < datetime.utcnow():
                    info["expired"] = True
                    info["risk"] += 3
                    print(Fore.RED + "❌ Certificate has expired!" + Style.RESET_ALL)
                else:
                    info["expired"] = False
                    print(Fore.GREEN + "✅ Certificate is valid" + Style.RESET_ALL)
            else:
                info["risk"] += 1
                print(Fore.YELLOW + "⚠ Could not parse certificate expiry date reliably" + Style.RESET_ALL)

    except Exception as e:
        info["risk"] += 2
        print(Fore.RED + f"Error checking SSL: {e}" + Style.RESET_ALL)

    return info

def cve_lookup(keyword: str, api_key: str = None) -> dict:
    result = {
        "keyword": keyword,
        "items": [],
        "risk": 0
    }
    try:
        print(Fore.CYAN + f"\n[+] Searching CVEs for: {keyword}" + Style.RESET_ALL)
        base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": keyword, "resultsPerPage": 5}
        headers = {}
        if api_key:
            headers["apiKey"] = api_key

        resp = requests.get(base, params=params, headers=headers, timeout=10)
        data = resp.json()
        vulns = data.get("vulnerabilities", [])

        if vulns:
            for v in vulns[:5]:
                cve_id = v.get("cve", {}).get("id", "N/A")
                descs = v.get("cve", {}).get("descriptions", [])
                desc = descs[0]["value"] if descs else "No description"
                result["items"].append({"id": cve_id, "description": desc})
                print(Fore.RED + f"{cve_id}: {desc}" + Style.RESET_ALL)
            result["risk"] += min(len(vulns), 5)  # heuristic bump
        else:
            print(Fore.GREEN + "No CVEs found for this keyword." + Style.RESET_ALL)

    except requests.exceptions.HTTPError as e:
        print(Fore.RED + f"HTTP error fetching CVEs: {e}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error fetching CVEs: {e}" + Style.RESET_ALL)

    return result

def summarize_risk(*components) -> int:
    return sum(c.get("risk", 0) for c in components if isinstance(c, dict))

def save_report(report: dict, filename: str = "Bish_report.json"):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(Fore.CYAN + f"\n[+] Report saved to {filename}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error saving report: {e}" + Style.RESET_ALL)

def main():
    show_logo()
    api_key = None  # Optional: set NVD API key here if you have one

    while True:
        user_input = input(Fore.YELLOW + "\nEnter a URL (or type 'exit' to quit): " + Style.RESET_ALL).strip()
        if user_input.lower() == "exit":
            print(Fore.CYAN + "Thanks for using Bish. Stay safe!" + Style.RESET_ALL)
            break

        url = normalize_url(user_input)
        domain = parse_domain(url)

        # Run checks
        url_result = check_url(url)
        headers_result = site_vulnerability(url)
        whois_result = {}
        ssl_result = {}
        cve_result = {}

        # WHOIS
        try:
            if domain:
                w = whois.whois(domain)
                creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                expiration = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                whois_result = {
                    "domain": domain,
                    "registrar": w.registrar,
                    "creation_date": str(creation),
                    "expiration_date": str(expiration),
                    "name_servers": list(w.name_servers) if w.name_servers else [],
                    "risk": 0
                }
                print(Fore.CYAN + "\n[+] WHOIS Data:" + Style.RESET_ALL)
                print("Domain:", whois_result["domain"])
                print("Registrar:", whois_result["registrar"])
                print("Creation Date:", whois_result["creation_date"])
                print("Expiration Date:", whois_result["expiration_date"])
                print("Name Servers:", ", ".join(whois_result["name_servers"]) if whois_result["name_servers"] else "None")
            else:
                print(Fore.RED + "⚠ Unable to parse domain for WHOIS." + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"⚠ Unable to fetch WHOIS data: {e}" + Style.RESET_ALL)
            whois_result = {"risk": 1}

        # SSL
        if domain:
            ssl_result = ssl_check(domain)
        else:
            ssl_result = {"risk": 1}
            print(Fore.RED + "⚠ Domain missing; skipping SSL check." + Style.RESET_ALL)

        # CVE
        if domain:
            cve_result = cve_lookup(domain, api_key=api_key)
        else:
            cve_result = {"risk": 0}

        # Aggregate
        total_risk = summarize_risk(url_result, headers_result, whois_result, ssl_result, cve_result)

        print(Fore.CYAN + "\n[+] Risk Summary" + Style.RESET_ALL)
        if total_risk >= 8:
            print(Fore.RED + f"Overall Risk: HIGH ({total_risk})" + Style.RESET_ALL)
        elif total_risk >= 4:
            print(Fore.YELLOW + f"Overall Risk: MEDIUM ({total_risk})" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + f"Overall Risk: LOW ({total_risk})" + Style.RESET_ALL)

        # Save a report for auditing
        report = {
            "input_url": user_input,
            "normalized_url": url,
            "domain": domain,
            "url_analysis": url_result,
            "headers_analysis": headers_result,
            "whois": whois_result,
            "ssl": ssl_result,
            "cve": cve_result,
            "total_risk": total_risk,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        save_report("Bish_report.json")

if __name__ == "__main__":
    main()
