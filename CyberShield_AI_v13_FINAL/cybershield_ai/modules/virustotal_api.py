"""
CyberShield AI – VirusTotal API Integration
Real-time URL and IP scanning using VirusTotal's 90+ security engines.
"""
import urllib.request
import urllib.parse
import json
import base64
import os

# ── PUT YOUR API KEY HERE ─────────────────────────────────────────────────────
VIRUSTOTAL_API_KEY = "YOUR_API_KEY_HERE"
# ─────────────────────────────────────────────────────────────────────────────

BASE_URL = "https://www.virustotal.com/api/v3"

def _headers():
    return {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
    }

def _get(url):
    try:
        req = urllib.request.Request(url, headers={"x-apikey": VIRUSTOTAL_API_KEY})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}

def _post(url, data):
    try:
        encoded = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(url, data=encoded, headers=_headers())
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}

def scan_url(url: str) -> dict:
    """
    Submit a URL to VirusTotal for scanning.
    Returns real results from 90+ security engines.
    """
    if VIRUSTOTAL_API_KEY == "YOUR_API_KEY_HERE":
        return {"error": "API key not configured. Please add your VirusTotal API key."}

    # Clean the URL
    clean_url = url.replace("hxxp", "http").replace("hxxps", "https")

    # Encode URL to base64 for VirusTotal v3 API
    url_id = base64.urlsafe_b64encode(clean_url.encode()).decode().rstrip("=")

    # First try to get existing report
    result = _get(f"{BASE_URL}/urls/{url_id}")

    if "error" in result and "NotFoundError" in str(result):
        # Submit for scanning
        _post(f"{BASE_URL}/urls", {"url": clean_url})
        return {"status": "submitted", "message": "URL submitted for scanning. Try again in 30 seconds."}

    if "data" not in result:
        return {"error": "Could not retrieve scan results.", "raw": result}

    stats = result["data"]["attributes"].get("last_analysis_stats", {})
    vendors = result["data"]["attributes"].get("last_analysis_results", {})

    malicious_vendors = [
        name for name, data in vendors.items()
        if data.get("category") == "malicious"
    ]
    suspicious_vendors = [
        name for name, data in vendors.items()
        if data.get("category") == "suspicious"
    ]

    total    = sum(stats.values())
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless  = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    threat_score = min(100, int((malicious / max(total, 1)) * 100 * 1.5 + (suspicious / max(total, 1)) * 50))

    if malicious >= 10:   verdict = "MALICIOUS"
    elif malicious >= 3:  verdict = "SUSPICIOUS"
    elif suspicious >= 5: verdict = "SUSPICIOUS"
    else:                 verdict = "CLEAN"

    return {
        "url":                clean_url,
        "verdict":            verdict,
        "threat_score":       threat_score,
        "total_engines":      total,
        "malicious_count":    malicious,
        "suspicious_count":   suspicious,
        "harmless_count":     harmless,
        "undetected_count":   undetected,
        "malicious_vendors":  malicious_vendors[:10],
        "suspicious_vendors": suspicious_vendors[:5],
        "scan_date":          result["data"]["attributes"].get("last_analysis_date", "N/A"),
        "categories":         result["data"]["attributes"].get("categories", {}),
    }

def scan_ip(ip: str) -> dict:
    """
    Lookup an IP address on VirusTotal.
    Returns reputation, country, ISP, and threat data.
    """
    if VIRUSTOTAL_API_KEY == "YOUR_API_KEY_HERE":
        return {"error": "API key not configured. Please add your VirusTotal API key."}

    result = _get(f"{BASE_URL}/ip_addresses/{ip}")

    if "data" not in result:
        return {"error": "Could not retrieve IP data.", "raw": result}

    attrs  = result["data"]["attributes"]
    stats  = attrs.get("last_analysis_stats", {})
    total  = sum(stats.values())
    malicious = stats.get("malicious", 0)

    return {
        "ip":              ip,
        "country":         attrs.get("country", "Unknown"),
        "isp":             attrs.get("as_owner", "Unknown"),
        "asn":             attrs.get("asn", "Unknown"),
        "malicious_count": malicious,
        "total_engines":   total,
        "reputation":      attrs.get("reputation", 0),
        "verdict":         "MALICIOUS" if malicious >= 5 else "SUSPICIOUS" if malicious >= 2 else "CLEAN",
        "tags":            attrs.get("tags", []),
    }

def is_configured() -> bool:
    return VIRUSTOTAL_API_KEY != "YOUR_API_KEY_HERE" and len(VIRUSTOTAL_API_KEY) > 10
