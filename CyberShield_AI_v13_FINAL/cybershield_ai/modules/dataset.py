"""
CyberShield AI — Dataset Generator
Generates a realistic labeled cybercrime dataset for training and evaluation.
"""

import pandas as pd
import numpy as np
import random

# ─── Seed for reproducibility ───────────────────────────────────────────────
SEED = 42
random.seed(SEED)
np.random.seed(SEED)

# ─── Per-category message templates ─────────────────────────────────────────
TEMPLATES = {
    "phishing": [
        "Your account has been compromised. Click here immediately to verify: http://secure-login-verify.xyz/auth",
        "Urgent: Unusual sign-in detected. Confirm your identity now at http://banklogin-alert.net",
        "Your PayPal account is limited. Please update your information at http://paypa1-verify.com",
        "IT Department: Your mailbox quota exceeded. Login to restore access: http://mail-restore-now.tk",
        "Congratulations! You've been selected. Verify your email at http://prize-claim.ru/verify",
        "Security Alert: Sign-in attempt blocked. Click to review: http://accounts-alerts.xyz",
        "Apple ID suspended due to suspicious activity. Restore at http://apple-id-support.top",
        "Your Netflix subscription is expiring. Update payment at http://netflix-billing-update.cc",
        "DHL Package held at customs. Confirm details at http://dhl-parcel-release.net",
        "IRS Tax Notice: Pending refund $2,840. Claim at http://irs-refund-portal.ml",
    ],
    "fraud": [
        "I am a Nigerian prince with $45 million. I need your help to transfer funds. You get 30%.",
        "Investment opportunity: 400% returns guaranteed in 30 days. Send $500 to start.",
        "You won the UK National Lottery £1,000,000. Send processing fee of $200 to claim.",
        "Work from home. Earn $5000/week. Just pay $99 registration fee to get started today.",
        "Crypto trading bot guarantees profit. Minimum deposit $1000. No risk involved.",
        "Fake check enclosed. Deposit and wire back the difference before it clears.",
        "Grandmother, I'm in trouble. Send $2000 Western Union immediately. Don't tell mom.",
        "Inheritance release requires attorney fee of $500. Contact us to unlock $3.2M.",
        "Your computer has virus detected by Microsoft. Call 1-800-FIX-NOW. Pay $299 for removal.",
        "Gold investment scheme: Buy at $800/oz now, sell at $2000 guaranteed by us.",
    ],
    "blackmail": [
        "I have recorded you through your webcam. Pay $2000 in Bitcoin or I send the video to your contacts.",
        "We have compromising photos. Transfer 0.5 BTC to wallet 1Hx72... within 48 hours.",
        "Your browsing history will be exposed to your employer unless you pay immediately.",
        "I've hacked your device. Send $500 or I leak your private messages to your family.",
        "We have installed spyware on your device. Proof: your password is [PASSWORD]. Pay now.",
        "Silence costs $1500. Otherwise, your affair is sent to your wife and workplace.",
        "I know what you did. Pay 0.3 ETH within 24 hours or face consequences.",
        "Your secrets are worth $3000 to me. Bitcoin only. No police or I release everything.",
        "Ransomware activated. All your files encrypted. Send 1 BTC to decrypt key: 3FZb...",
        "We have footage from your home camera. $1000 ensures your privacy remains intact.",
    ],
    "harassment": [
        "You will regret this. I know where you live and I am watching your every move.",
        "I will destroy your reputation. Every platform, every person you know will know the truth.",
        "Stop ignoring me or I will show up at your workplace tomorrow.",
        "You think you can block me? I have 50 fake accounts. You can't escape.",
        "I have sent your photos to 200 people. Next batch goes to your parents.",
        "Keep your mouth shut about what happened or things will get much worse for you.",
        "You better drop the case. We know your kids' school schedule.",
        "Doxxed: [Your address here]. Let's see how brave you are now.",
        "I will flood your inbox until you respond. Day 14 of 100.",
        "Your coworkers have been informed. Your boss is next. Then your family.",
    ],
    "scam": [
        "Limited offer: iPhone 15 Pro for $99 only today. Stocks running out fast!",
        "Miracle weight loss pill. Lose 30 lbs in 14 days guaranteed or full refund.",
        "Your car warranty expired. Press 1 now to renew at special rate before midnight.",
        "Free vacation to Cancun. You've been selected. Just pay $199 in taxes.",
        "Psychic reading reveals your future. Call now: only $9.99/min. Life-changing!",
        "Buy followers: 10,000 Instagram followers for $5. Real accounts guaranteed.",
        "Antivirus expired. Your PC is infected. Buy protection now $49.99. Act fast!",
        "Timeshare investment: Buy now at 90% off. Exclusive member pricing ends tonight.",
        "Secret government money you're owed. Get your $17,500 check. Free report inside.",
        "Make money from home typing ads: $25/ad. No experience needed. Start today.",
    ],
    "suspicious_link": [
        "Check this out: http://bit.ly/3xR7mKp2 — you won't believe what I found about you",
        "See your leaked data here: http://tinyurl.com/databreach2024-yourname",
        "Someone posted your photo: http://track-me-now.ru/img?uid=48291",
        "Your package awaits: http://192.168.1.1/tracking?id=XR291 — click to confirm address",
        "Free Robux generator: http://robux-gen.xyz?ref=8829 — working 2024",
        "Hot deal expires in 10 mins: http://shop-mega-deal.cn/flash?prod=829",
        "Login to view: http://g00gle-secure.com/accounts/recovery?token=9f3a",
        "Download your document: http://docs-share.top/file.exe?id=user_9281",
        "See who viewed your profile: http://profilespy.ml/results?u=target",
        "Emergency broadcast: http://emergency-alert.xyz/message?priority=URGENT",
    ],
    "legitimate": [
        "Hi! Just checking if you're free for coffee on Thursday afternoon?",
        "The quarterly report has been attached. Please review before Friday's meeting.",
        "Your order #ORD-88291 has shipped. Tracking number: UPS-2948271.",
        "Thank you for your purchase. Your receipt is attached for your records.",
        "Reminder: Team standup at 9AM tomorrow. Zoom link in calendar invite.",
        "Your password was successfully changed. If this wasn't you, contact support.",
        "Monthly bank statement for account ending 4821 is now available.",
        "Meeting rescheduled to 3PM on Wednesday. Conference room B.",
        "Happy birthday! Wishing you a wonderful day and a great year ahead!",
        "Maintenance scheduled Sunday 2-4AM. Services may be temporarily unavailable.",
        "Please find the project proposal document attached for your review.",
        "Interview confirmed for Monday at 10AM. Please bring a copy of your CV.",
    ],
}

URGENCY_KEYWORDS = [
    "urgent", "immediately", "now", "today", "expires", "limited", "act fast",
    "hours", "minutes", "deadline", "warning", "alert", "suspended", "blocked",
    "compromised", "detected", "verify", "confirm", "required", "attention"
]

SUSPICIOUS_KEYWORDS = [
    "bitcoin", "btc", "eth", "crypto", "wallet", "wire transfer", "western union",
    "moneygram", "gift card", "click here", "verify", "account suspended",
    "unusual activity", "login attempt", "password", "ssn", "social security",
    "bank account", "credit card", "refund", "prize", "winner", "selected",
    "inheritance", "prince", "attorney", "processing fee", "guaranteed returns",
]


def generate_dataset(n_samples: int = 1200) -> pd.DataFrame:
    """
    Generate a balanced, labeled cybercrime dataset.
    Returns a DataFrame with columns: message, label, urgency_score, threat_score.
    """
    categories = list(TEMPLATES.keys())
    per_class = n_samples // len(categories)

    records = []
    for label in categories:
        base = TEMPLATES[label]
        for i in range(per_class):
            msg = base[i % len(base)]
            # Add light variation
            if random.random() < 0.3:
                msg = msg + " " + random.choice([
                    "Do not ignore this.",
                    "This is time-sensitive.",
                    "Reply ASAP.",
                    "No further notice will be sent.",
                    "Action required immediately.",
                ])

            urgency = _urgency_score(msg)
            threat = _threat_score(msg, label)

            records.append({
                "message": msg,
                "label": label,
                "urgency_score": urgency,
                "threat_score": threat,
            })

    df = pd.DataFrame(records).sample(frac=1, random_state=SEED).reset_index(drop=True)
    return df


def _urgency_score(text: str) -> float:
    text_lower = text.lower()
    hits = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
    return round(min(hits / 5.0, 1.0), 3)


def _threat_score(text: str, label: str) -> float:
    base = {
        "phishing": 0.75, "fraud": 0.70, "blackmail": 0.95,
        "harassment": 0.85, "scam": 0.60, "suspicious_link": 0.65, "legitimate": 0.05,
    }
    text_lower = text.lower()
    hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in text_lower)
    bonus = min(hits * 0.04, 0.20)
    score = base.get(label, 0.5) + bonus + random.uniform(-0.05, 0.05)
    return round(max(0.0, min(score, 1.0)), 3)


def save_dataset(path: str = "data/cybercrime_dataset.csv"):
    df = generate_dataset()
    df.to_csv(path, index=False)
    return df


if __name__ == "__main__":
    df = save_dataset()
    print(f"Dataset saved: {len(df)} records")
    print(df["label"].value_counts())
