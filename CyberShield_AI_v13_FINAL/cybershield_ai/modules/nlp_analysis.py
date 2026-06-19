"""
CyberShield AI — NLP Threat Analysis Utilities
Keyword extraction, urgency detection, suspicious pattern highlighting.
"""

import re
from typing import Any

# ─── Keyword Dictionaries ────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = {
    "financial":    ["bitcoin", "btc", "ethereum", "crypto", "wire transfer",
                     "western union", "moneygram", "gift card", "bank account",
                     "credit card", "routing number", "iban", "swift"],
    "urgency":      ["urgent", "immediately", "asap", "now", "today", "expires",
                     "limited time", "act fast", "deadline", "hours", "minutes",
                     "warning", "alert", "last chance", "final notice"],
    "credential":   ["password", "username", "login", "verify", "confirm",
                     "account suspended", "unusual activity", "sign-in",
                     "click here", "update your information", "validate"],
    "threat":       ["i know where you live", "i will expose", "i have footage",
                     "pay or", "will be sent", "will be leaked", "consequences",
                     "i am watching", "regret this", "destroy your reputation"],
    "social_eng":   ["you have been selected", "congratulations", "winner",
                     "free", "guaranteed", "no risk", "100% safe", "secret",
                     "exclusive", "limited offer", "act now"],
    "url_patterns": [r"https?://\S+", r"\bbit\.ly\b", r"\btinyurl\b",
                     r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"],
}

THREAT_CATEGORY_KEYWORDS = {
    "phishing":        ["verify", "account", "suspended", "login", "confirm",
                        "click here", "update", "unusual", "security alert"],
    "fraud":           ["prince", "million", "inheritance", "investment",
                        "guaranteed returns", "fee", "lottery", "won"],
    "blackmail":       ["footage", "recorded", "webcam", "bitcoin", "pay or",
                        "expose", "leak", "silence", "compromising", "spyware"],
    "harassment":      ["i know", "watching", "regret", "destroy", "expose",
                        "show up", "fake accounts", "doxxed", "flood"],
    "scam":            ["free", "limited", "offer", "earn", "work from home",
                        "miracle", "lose weight", "guaranteed", "warranty"],
    "suspicious_link": ["http", "bit.ly", "tinyurl", "click", "download",
                        "free robux", "you won", "tracking"],
}


# ─── Keyword Highlighter ─────────────────────────────────────────────────────

def highlight_keywords(text: str) -> dict:
    """
    Identify and categorize suspicious keywords in a message.

    Returns
    -------
    found        : {category: [matched_keywords]}
    risk_counts  : {category: count}
    total_hits   : int
    risk_density : float (hits / word_count)
    """
    text_lower = text.lower()
    found: dict[str, list] = {}
    total_hits = 0

    for category, keywords in SUSPICIOUS_KEYWORDS.items():
        matches = []
        for kw in keywords:
            if category == "url_patterns":
                if re.search(kw, text_lower):
                    matches.append(kw)
            elif kw in text_lower:
                matches.append(kw)
        if matches:
            found[category] = matches
            total_hits += len(matches)

    word_count = max(len(text.split()), 1)

    return {
        "found": found,
        "risk_counts": {cat: len(kws) for cat, kws in found.items()},
        "total_hits": total_hits,
        "risk_density": round(total_hits / word_count, 4),
        "categories_triggered": list(found.keys()),
    }


def urgency_score(text: str) -> float:
    """Return 0-1 urgency score based on urgency keyword density."""
    text_lower = text.lower()
    hits = sum(1 for kw in SUSPICIOUS_KEYWORDS["urgency"] if kw in text_lower)
    return round(min(hits / 6.0, 1.0), 3)


def threat_score_from_text(text: str) -> float:
    """Heuristic threat score from raw text — no model needed."""
    text_lower = text.lower()
    hits = 0
    for cat, kws in SUSPICIOUS_KEYWORDS.items():
        if cat == "url_patterns":
            hits += sum(1 for p in kws if re.search(p, text_lower))
        else:
            hits += sum(1 for kw in kws if kw in text_lower)
    return round(min(hits / 15.0, 1.0), 3)


def extract_urls(text: str) -> list[str]:
    pattern = re.compile(r'https?://\S+|www\.\S+')
    return pattern.findall(text)


def extract_entities(text: str) -> dict:
    """Lightweight entity extraction (no external NER required)."""
    emails  = re.findall(r'[\w.+-]+@[\w-]+\.[a-z]{2,}', text, re.I)
    phones  = re.findall(r'\+?\d[\d\s\-().]{7,}\d', text)
    urls    = extract_urls(text)
    amounts = re.findall(r'\$[\d,]+|\d+\s*(BTC|ETH|USD|GBP|EUR)', text, re.I)
    wallets = re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', text)  # BTC pattern

    return {
        "emails":       emails,
        "phone_numbers": phones,
        "urls":         urls,
        "monetary":     amounts,
        "crypto_wallets": wallets,
    }


# ─── Risk Analysis Report ────────────────────────────────────────────────────

def full_risk_analysis(text: str, predicted_label: str = "") -> dict:
    """
    Comprehensive risk analysis combining:
    keyword analysis, entity extraction, urgency, threat score, and recommendations.
    """
    kw_result  = highlight_keywords(text)
    entities   = extract_entities(text)
    urgency    = urgency_score(text)
    threat     = threat_score_from_text(text)
    urls       = extract_urls(text)

    # Determine top risk indicators
    indicators = []
    if urls:
        indicators.append(f"Contains {len(urls)} suspicious URL(s)")
    if entities["crypto_wallets"]:
        indicators.append("Crypto wallet address detected — likely extortion or fraud")
    if entities["monetary"]:
        indicators.append(f"Financial demand detected: {entities['monetary']}")
    if urgency > 0.5:
        indicators.append(f"High urgency pressure tactics (score: {urgency})")
    if kw_result["total_hits"] > 5:
        indicators.append(f"{kw_result['total_hits']} suspicious keywords across {len(kw_result['categories_triggered'])} categories")
    if "threat" in kw_result["found"]:
        indicators.append("Direct threat language detected")

    # Overall risk level
    composite = round((threat * 0.5 + urgency * 0.3 + min(kw_result["risk_density"] * 2, 0.2)), 3)
    if composite >= 0.75:
        risk_level = "CRITICAL"
    elif composite >= 0.55:
        risk_level = "HIGH"
    elif composite >= 0.35:
        risk_level = "MEDIUM"
    elif composite >= 0.15:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    recommendations = _recommendations(predicted_label, risk_level, entities)

    return {
        "keyword_analysis":  kw_result,
        "entities":          entities,
        "urgency_score":     urgency,
        "threat_score":      threat,
        "composite_risk":    composite,
        "risk_level":        risk_level,
        "risk_indicators":   indicators,
        "recommendations":   recommendations,
    }


def _recommendations(label: str, risk_level: str, entities: dict) -> list[str]:
    rec = []
    if risk_level in ("CRITICAL", "HIGH"):
        rec.append("Immediately escalate to cybercrime investigation unit")
        rec.append("Preserve all digital evidence (screenshots, headers, metadata)")
    if label == "phishing":
        rec.append("Do NOT click any links; report to anti-phishing authorities")
        rec.append("Forward to phishing@reportfraud.ftc.gov or local equivalent")
    if label == "blackmail":
        rec.append("Report to law enforcement; do NOT comply with demands")
        rec.append("Document everything — payments only escalate demands")
    if label == "fraud":
        rec.append("Alert your bank if financial details were shared")
        rec.append("File report with national fraud reporting center")
    if label == "harassment":
        rec.append("Document all communications for legal proceedings")
        rec.append("Consider restraining order / platform abuse report")
    if entities["crypto_wallets"]:
        rec.append("Trace wallet via blockchain explorer for further investigation")
    if not rec:
        rec.append("Monitor for follow-up messages; log and observe")
    return rec
