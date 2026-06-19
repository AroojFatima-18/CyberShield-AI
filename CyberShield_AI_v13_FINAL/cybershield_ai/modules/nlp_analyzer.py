"""
CyberShield AI – NLP Analyzer v3
Comprehensive threat lexicon with broad single-word and phrase coverage.
"""
import re

THREAT_LEXICON = {
    "extortion_coercion": [
        "pay me", "pay or", "pay now", "pay $", "send me money", "send money",
        "send $", "transfer $", "transfer money", "transfer funds", "wire transfer",
        "bitcoin wallet", "crypto wallet", "send btc", "send bitcoin",
        "wallet address", "pay or i will", "pay or else", "give me money",
        "ransom", "pay the fee", "deposit funds", "send cash", "venmo me",
        "pay via", "payment required", "demand payment", "or i will expose",
        "or i release", "or i publish", "or i send",
    ],
    "image_privacy_threat": [
        "leaked your pics", "leak your pictures", "leaked your pictures",
        "leaked your photos", "leak your photos", "your pics", "your pictures",
        "your photos", "your images", "intimate photos", "private photos",
        "explicit photos", "your nude", "private videos", "your videos",
        "compromising footage", "compromising photos", "compromising material",
        "compromising content", "your footage", "recorded you", "recorded your",
        "webcam footage", "camera footage", "screen activity", "screen recording",
        "spyware", "keylogger", "your private", "private material",
    ],
    "threat_language": [
        "i will expose", "i will destroy", "i will leak", "i will send",
        "i will publish", "i will share", "i will release", "i will post",
        "expose you", "destroy you", "ruin your life", "ruin your reputation",
        "you will regret", "i am watching", "i know where you live",
        "i know your address", "coming for you", "consequences",
        "face consequences", "or else", "or i will", "if you don't",
        "if you do not", "i have hacked", "hacked your", "i have access",
        "i infiltrated", "i have evidence", "i have proof",
        "i have footage", "i have recordings", "i have compromising",
        "do not ignore", "last warning", "final warning", "you were warned",
        "harm you", "hurt you", "contact your employer", "tell your employer",
        "send everything", "send it to your", "send to your family",
        "send to your contacts", "your employer and family", "your family and friends",
        "show your friends", "tell your family", "everyone you know",
        "your entire contact", "all your contacts",
    ],
    "surveillance_stalking": [
        "i am watching you", "i have been watching", "i installed",
        "i have installed", "installed spyware", "installed malware",
        "installed software", "monitoring your", "tracking your",
        "i know your location", "i know where you", "i know your schedule",
        "i know your daily", "following your", "i can see you",
        "i watch your", "i saw you", "recording your activity",
        "recorded your activity", "screen activity", "device activity",
        "past 3 weeks", "past few weeks", "past several weeks",
        "weeks of activity", "months of activity",
    ],
    "urgency_pressure": [
        "urgent", "immediately", "right now", "24 hours", "48 hours",
        "72 hours", "final notice", "last chance", "act now",
        "time is running out", "deadline", "do not delay", "respond now",
        "reply immediately", "hours left", "limited time", "do not wait",
        "before it is too late", "you have until", "expires soon",
    ],
    "credential_theft": [
        "verify your account", "confirm your identity", "login here",
        "reset your password", "update your info", "click here to verify",
        "your account will be closed", "suspended account", "account locked",
        "validate your details", "enter your credentials",
        "provide your password", "confirm your email",
        "account suspended", "account has been suspended",
        "account disabled", "account will expire",
        "verify now", "confirm now", "login to verify",
        "click to verify", "update your account", "verify your identity",
        "unusual login", "unusual activity", "suspicious activity",
        "temporary suspension", "permanently closed",
    ],
    "financial_fraud": [
        "you have won", "congratulations you", "lottery winner",
        "claim your prize", "processing fee", "guaranteed return",
        "guaranteed profit", "investment opportunity", "work from home earn",
        "make money fast", "no experience needed", "government grant",
        "unclaimed property", "you are selected", "special offer",
        "100% profit", "300% return", "double your money",
    ],
    "lure_scam": [
        "gift is expiring", "gift expiring", "nitro gift", "free gift",
        "claim it before", "claim before", "expires tonight", "expires at midnight",
        "before midnight", "last chance to claim", "claim your free",
        "free reward", "free prize", "free token", "free subscription",
        "activate your gift", "activate code", "redeem now", "redeem your",
        "limited time offer", "offer expires", "deal expires",
        "free upgrade", "claim upgrade", "your reward is waiting",
        "you have been gifted", "someone sent you", "gift card",
        "free coins", "free credits", "free membership", "free trial claim",
        "click to activate", "activate now", "activate at",
        "winner selected", "you are selected", "randomly selected",
        "congratulations you have been", "you have been chosen",
        "exclusive access", "vip access free", "unlock free",
    ],
    "impersonation": [
        "microsoft support", "apple support", "google support",
        "irs notice", "fbi warning", "interpol", "your bank",
        "paypal alert", "amazon notice", "netflix alert",
        "official notice", "government official", "tax authority",
        "social security", "customs department",
    ],
}

SEVERITY_WEIGHTS = {
    "extortion_coercion":    35,
    "image_privacy_threat":  40,
    "threat_language":       32,
    "surveillance_stalking": 38,
    "urgency_pressure":      15,
    "credential_theft":      20,
    "financial_fraud":       18,
    "impersonation":         12,
    "lure_scam":             22,
}

CATEGORY_MINIMUMS = {
    "extortion_coercion":    70,
    "image_privacy_threat":  78,
    "threat_language":       65,
    "surveillance_stalking": 75,
    "urgency_pressure":      30,
    "credential_theft":      55,
    "financial_fraud":       45,
    "impersonation":         35,
    "lure_scam":             52,
}

URL_PATTERN    = re.compile(r"(?:https?://|hxxps?://)[^\s<>\"\']+"  , re.I)
IP_PATTERN     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MONEY_PATTERN  = re.compile(r"\$[\d,]+(?:\.\d{2})?")
CRYPTO_PATTERN = re.compile(r"\b(?:BTC|ETH|bitcoin|ethereum|crypto|wallet)\b", re.I)
EMAIL_PATTERN  = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")

def analyze_text(text: str) -> dict:
    tl = text.lower()
    category_hits = {}
    highlighted   = []

    for category, keywords in THREAT_LEXICON.items():
        hits = [kw for kw in keywords if kw in tl]
        if hits:
            category_hits[category] = hits
            highlighted.extend(hits)

    urls   = URL_PATTERN.findall(text)
    ips    = IP_PATTERN.findall(text)
    money  = MONEY_PATTERN.findall(text)
    crypto = CRYPTO_PATTERN.findall(text)
    emails = EMAIL_PATTERN.findall(text)

    if category_hits:
        base_minimum = max(CATEGORY_MINIMUMS[cat] for cat in category_hits)
        additive = sum(
            SEVERITY_WEIGHTS[cat] * len(hits)
            for cat, hits in category_hits.items()
        )
        raw_score = base_minimum + additive
    else:
        raw_score = 0

    raw_score += len(urls)*10 + len(ips)*8 + len(money)*10 + len(crypto)*15
    threat_score = min(100, raw_score)

    dominant = (max(category_hits, key=lambda c: SEVERITY_WEIGHTS[c] * len(category_hits[c]))
                if category_hits else "none")

    return {
        "category_hits":        category_hits,
        "highlighted_keywords": list(set(highlighted)),
        "threat_score":         threat_score,
        "dominant_category":    dominant,
        "entities": {
            "urls":              urls,
            "ip_addresses":      ips,
            "money_references":  money,
            "crypto_references": crypto,
            "email_addresses":   emails,
        },
        "total_threat_signals": sum(len(v) for v in category_hits.values()),
        "text_length":          len(text),
        "word_count":           len(text.split()),
    }

def highlight_text_html(text: str, keywords: list) -> str:
    if not keywords:
        return text
    # Split text into parts, only highlight outside existing HTML tags
    import html as html_module
    safe_text = html_module.escape(text)
    for kw in sorted(keywords, key=len, reverse=True):
        pattern = re.compile(re.escape(html_module.escape(kw)), re.I)
        safe_text = pattern.sub(
            lambda m: f'<span style="background:#8b0000;color:#ffaaaa;padding:2px 5px;'
                      f'border-radius:3px;font-weight:bold;">{m.group(0)}</span>',
            safe_text
        )
    return safe_text

def get_risk_profile(analysis: dict) -> str:
    score = analysis["threat_score"]
    if score == 0:  return "CLEAN"
    if score < 25:  return "LOW RISK"
    if score < 50:  return "MODERATE"
    if score < 75:  return "HIGH RISK"
    return "CRITICAL"
