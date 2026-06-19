"""
CyberShield AI – Dataset Builder v2
Richer, more varied training data for better ML confidence.
200+ pattern templates per category with diverse vocabulary.
"""
import pandas as pd, random, os

random.seed(42)

# ── PHISHING PATTERNS ─────────────────────────────────────────────────────────
PHISHING = [
    "URGENT: Your {bank} account has been suspended due to suspicious activity. Verify at {url} immediately.",
    "Security Alert: Unusual login detected on your {service} account. Confirm your identity now: {url}",
    "Your {service} account will be permanently closed in 24 hours. Update details: {url}",
    "Dear Customer, we have locked your {bank} online access. Restore it here: {url}",
    "Action Required: Your {service} password expires today. Reset immediately at {url}",
    "WARNING: Your {bank} debit card has been blocked. Unblock now: {url}",
    "Final Notice: Verify your {service} account or lose access permanently. Click: {url}",
    "Your {bank} account shows unauthorized transactions. Secure it now at {url}",
    "Important: Your {service} subscription could not be renewed. Update payment: {url}",
    "ALERT: Someone tried to access your {bank} account from another country. Verify: {url}",
    "Your {service} account has been flagged for unusual activity. Confirm details: {url}",
    "Immediate action needed: {bank} account verification required at {url}",
    "We noticed a sign-in to your {service} account from a new device. Verify: {url}",
    "Your {bank} online banking has been temporarily disabled. Re-enable at {url}",
    "Security update: {service} requires you to confirm your account details at {url}",
    "Account suspension notice: Your {bank} access is limited. Restore access: {url}",
    "Your {service} account information is outdated. Update now to avoid suspension: {url}",
    "Unauthorized access attempt detected on your {bank} account. Secure now: {url}",
    "Your {service} account verification is incomplete. Complete it here: {url}",
    "Critical: {bank} detected unusual spending on your account. Review at {url}",
    "Your {service} login credentials need to be updated immediately at {url}",
    "Notice: Your {bank} account will be deactivated unless you verify at {url}",
    "We have placed a temporary hold on your {service} account. Verify identity: {url}",
    "Your {bank} account has been compromised. Change your password now at {url}",
    "Attention: {service} account requires mandatory security update at {url}",
    "Your {bank} mobile banking access has expired. Renew here: {url}",
    "Important security message from {service}: verify your account at {url} now.",
    "Your {bank} account statement is ready. Login to view: {url}",
    "Due to inactivity your {service} account will close. Reactivate at {url}",
    "Risk alert: your {bank} account shows suspicious patterns. Investigate: {url}",
]

BANKS    = ["bank","online banking portal","credit union","financial institution","savings account"]
SERVICES = ["PayPal","Netflix","Apple ID","Google","Microsoft","Amazon","Instagram","Dropbox","Spotify","Adobe"]
URLS     = ["hxxp://secure-verify-{r}.tk/auth","hxxp://{s}-login-{r}.ml/verify",
            "hxxp://account-{r}.xyz/confirm","hxxp://{s}-secure-{r}.cc/update"]

# ── BLACKMAIL PATTERNS ────────────────────────────────────────────────────────
BLACKMAIL = [
    "I have installed spyware on your device and recorded your screen activity. Pay {amt} Bitcoin or I expose everything.",
    "I hacked your webcam and have footage of you. Transfer {amt} to my wallet or I send it to all your contacts.",
    "I have compromising photos from your cloud storage. Pay {amt} within 48 hours or I publish them publicly.",
    "I infiltrated your device and recorded you visiting adult websites. Pay {amt} or your family sees this.",
    "Your private messages and photos are in my possession. Pay {amt} or I leak everything to your employer.",
    "I have been monitoring your online activity for weeks. I have very compromising footage. Pay {amt} now.",
    "I installed malware on your computer and captured everything. Transfer {amt} or face public exposure.",
    "I have screenshots of your private conversations. Send {amt} to my Bitcoin wallet or I share them.",
    "Your intimate photos were found in your hacked cloud account. Pay {amt} or I distribute them widely.",
    "I recorded you through your own camera. The footage is very compromising. Pay {amt} to keep it private.",
    "I have access to all your files and messages. Pay {amt} in crypto or everything gets leaked.",
    "Your browsing history is very revealing. Pay {amt} or I send a detailed report to your contacts.",
    "I have evidence of your online activities that would destroy your reputation. Pay {amt} to stop me.",
    "I hacked your email account and read every message. Pay {amt} or I forward them to everyone you know.",
    "I have your private videos. Transfer {amt} to this wallet address or I post them on social media.",
    "Spyware I installed captured your screen for 30 days. Pay {amt} or the recordings go public.",
    "Your phone camera footage is very compromising. Send {amt} in Bitcoin within 24 hours.",
    "I have your deleted photos recovered from your device backup. Pay {amt} or they get leaked.",
    "I know your deepest secrets from months of monitoring your device. Pay {amt} for my silence.",
    "Your private data has been copied from your hacked accounts. Pay {amt} or I release everything.",
    "I recorded your video calls without your knowledge. The footage is damaging. Pay {amt} now.",
    "I infiltrated your cloud backup and downloaded everything. Pay {amt} or it all gets exposed.",
    "Your personal files including private photos are now in my hands. Transfer {amt} immediately.",
    "I have access to your camera roll and messages. Pay {amt} or your partner sees everything.",
    "Compromising material from your device will be published unless you transfer {amt} today.",
    "I installed a keylogger on your computer and captured your passwords and private data. Pay {amt}.",
    "Your private emails contain very sensitive information. Pay {amt} or I forward them to your boss.",
    "I have screenshots proving your secret activities. Send {amt} in crypto or I go public.",
    "The footage I captured from your webcam is very embarrassing. Pay {amt} to make this go away.",
    "Your personal accounts have been fully compromised. Pay {amt} or watch your life fall apart.",
]

AMOUNTS = ["$500","$800","$1000","$1500","$2000","$3000","0.05 BTC","0.1 BTC","0.3 BTC"]

# ── HARASSMENT PATTERNS ───────────────────────────────────────────────────────
HARASSMENT = [
    "I know where you live and I am coming for you. You should be very afraid right now.",
    "Stop ignoring me or you will deeply regret it. I am not someone you want to cross.",
    "I will destroy your reputation completely. Everyone you know will find out who you really are.",
    "I know your home address and your daily routine. I am always watching you.",
    "Keep ignoring me and see what happens. I have been patient long enough.",
    "I will contact everyone at your workplace and tell them exactly what kind of person you are.",
    "You cannot hide from me. I have your address, phone number, and schedule.",
    "I will make your life absolutely miserable until you respond to me.",
    "Your family deserves to know what you have been doing. Do not make me contact them.",
    "I have a network of people ready to make your existence very difficult.",
    "Every post you make I screenshot. I am building a case against you right now.",
    "You humiliated me publicly and I will do ten times worse to you.",
    "Blocking me was the worst decision you ever made. I have other ways to reach you.",
    "I filed a complaint with your employer today. Enjoy explaining yourself on Monday.",
    "I know your schedule. I know when you leave and when you come back.",
    "You cannot escape me online or in real life. I am everywhere you go.",
    "I will spam every account you own until you talk to me. There is no escape.",
    "Your children will find out what kind of parent they have. Do not test me.",
    "I have people watching your house right now. Think carefully about your next move.",
    "I will ruin every relationship you have if you continue to ignore me.",
    "I sent messages to all your friends already. Wait until you see their reactions.",
    "You think this is a joke but you will soon realize how serious I am.",
    "I know your car, your route to work, everything. You are not safe ignoring me.",
    "Your online accounts are all going to be mass reported and terminated today.",
    "I will show up where you work if you do not respond by tonight.",
    "Everything you have ever posted online is saved and ready to be used against you.",
    "Your neighbors will know everything about you by tomorrow morning.",
    "I have been documenting all your online activity for months. I have everything I need.",
    "Do not call the police. It will only make things much worse for you.",
    "I am going to make sure everyone in your life abandons you completely.",
]

# ── FRAUD PATTERNS ────────────────────────────────────────────────────────────
FRAUD = [
    "Congratulations! You have won {prize} in our international lottery. Pay {fee} processing fee to claim.",
    "Investment opportunity: guaranteed {pct}% return in {days} days. Send Bitcoin to register.",
    "I am a foreign diplomat with {prize} that needs urgent transfer. Share your bank details for 30% cut.",
    "You have been selected for a government grant of {prize}. Pay {fee} admin fee to receive funds.",
    "Work from home opportunity: earn {prize} weekly stuffing envelopes. Pay {fee} starter kit fee.",
    "Exclusive crypto signal group: turn {fee} into {prize} in 30 days guaranteed.",
    "Your email was selected in our annual sweepstakes. You won {prize}. Pay {fee} to claim.",
    "Secret investment system: guaranteed {pct}% daily returns. Minimum deposit {fee}.",
    "Romance investment: my company needs investors. I guarantee you will earn {prize} monthly.",
    "Car wrap advertising: earn {prize} monthly. Cash this check and send back {fee} first.",
    "Unclaimed inheritance of {prize} in your name. Pay {fee} legal fee to transfer funds.",
    "Advance fee loan: get {prize} loan with bad credit. Just pay {fee} insurance upfront.",
    "Binary options trading guaranteed income. Fund {fee} account today and earn {prize} weekly.",
    "Mystery shopper job: cash this {prize} check, keep {fee}, send the rest via wire transfer.",
    "Government stimulus payment of {prize} available for you. Pay {fee} processing to receive.",
    "Your pension plan has unclaimed funds of {prize}. Pay {fee} retrieval fee to access them.",
    "Charity lottery: your ticket won {prize}. Donate {fee} to claim your winnings today.",
    "Online business opportunity: invest {fee} and earn {prize} every month passively.",
    "Crypto mining pool: invest {fee} and receive {prize} in Bitcoin within 7 days.",
    "Inheritance claim: a distant relative left you {prize}. Pay {fee} to process the release.",
    "International prize committee: you won {prize}. Pay {fee} taxes upfront to receive.",
    "Guaranteed stock tips: invest {fee} and triple your money in {days} days guaranteed.",
    "Real estate investment: guaranteed {pct}% returns. Minimum investment {fee} to join.",
    "Your social media account was selected. You won {prize}. Pay {fee} to claim your reward.",
    "Pyramid scheme opportunity: recruit 3 people, earn {prize} per week. Join fee {fee}.",
    "Day trading system: never lose money. Guaranteed {pct}% profit. Sign up fee {fee}.",
    "International business deal: help transfer {prize}, keep 40%. Send {fee} to start.",
    "You have unclaimed tax refund of {prize}. Pay {fee} processing fee to receive.",
    "Influencer sponsorship: we pay {prize} monthly. Pay {fee} registration to start.",
    "Jewelry investment scheme: buy at {fee}, guaranteed resale value of {prize} in 60 days.",
]

PRIZES = ["$5,000","$10,000","$50,000","$100,000","$500,000","$1,000,000"]
FEES   = ["$50","$99","$150","$200","$299","$500"]
PCTS   = ["200","300","500","1000"]
DAYS   = ["7","14","30"]

# ── SCAM PATTERNS ─────────────────────────────────────────────────────────────
SCAM = [
    "Congratulations! You are our 1,000,000th visitor! Claim your free iPhone now: {url}",
    "URGENT: Your computer has a virus. Call Microsoft Support immediately: 1-800-XXX-XXXX",
    "Your antivirus has expired. Your files are at risk. Download protection: {url}",
    "Free gift card: complete this 30-second survey and receive a {prize} Amazon card.",
    "You qualify for student loan forgiveness of {prize}. Pay {fee} processing fee now.",
    "Singles in your area want to meet you tonight. Join free: {url}",
    "Make {prize} daily from your phone with this secret app. No skills needed.",
    "Your social security number was used in suspicious activity. Call federal agents now.",
    "Exclusive member deal: {fee} trial then {prize} monthly. Cancel anytime.",
    "Earn free cryptocurrency: complete 3 tasks and receive 0.1 BTC instantly.",
    "Psychic reading: I sense great danger in your near future. Pay {fee} for protection ritual.",
    "Miracle weight loss: lose 30 pounds in 30 days guaranteed. Order now for {fee}.",
    "You have been pre-approved for a {prize} personal loan. Bad credit OK. Apply fee {fee}.",
    "TECH SUPPORT: We detected malware on your Windows PC. Call 1-800-XXX-XXXX now.",
    "Free vacation package to Cancun. Just pay {fee} taxes and booking fee.",
    "Earn {prize} per week liking posts on social media. No experience required. Sign up {fee}.",
    "Your car warranty is about to expire. Press 1 to speak with a specialist immediately.",
    "Confirm your account to receive {prize} weekly survey payment from our research panel.",
    "Secret shopper needed in your area. Earn {prize} per assignment. Register at {url}",
    "Your package could not be delivered. Pay {fee} redelivery fee at {url}",
    "You have been selected for a {prize} reward. Complete verification at {url}",
    "IRS tax refund of {prize} is waiting. Verify your identity at {url} to receive.",
    "Congratulations! Your phone number won our monthly draw. Claim {prize} at {url}",
    "Free trial of premium software worth {prize}. Download here: {url}",
    "Nigerian prince lottery: you won {prize}. Contact us to arrange transfer.",
    "Work from home data entry: earn {prize} hourly. No experience. Register for {fee}.",
    "Exclusive investment club: minimum {fee} to join, guaranteed {prize} monthly returns.",
    "Your streaming service account has been compromised. Secure it at {url}",
    "Government approved debt relief program. Eliminate {prize} in debt. Call now.",
    "Flash sale: designer goods at 95% off. Limited stock. Order at {url}",
]

# ── SUSPICIOUS LINK PATTERNS ──────────────────────────────────────────────────
SUSPICIOUS_LINK = [
    "Check this important document: hxxp://docs-{r}-secure.{tld}/view?id={tok}",
    "Verify your account: hxxp://{s}-login-{r}.{tld}/auth?redirect=account",
    "Download the attachment: hxxp://file-{r}.{tld}/download?name=invoice_{tok}",
    "Access shared file: hxxp://drive-{r}-share.{tld}/file?id={tok}",
    "Claim your reward: hxxp://{s}-prize-{r}.{tld}/claim?user={tok}",
    "Reset your password: hxxp://{s}-secure-{r}.{tld}/password/reset",
    "View invoice: hxxp://invoice-{r}.{tld}/pay?amount=500&ref={tok}",
    "Track your order: hxxp://delivery-{r}-track.{tld}/status?id={tok}",
    "Security update required: hxxp://{s}-update-{r}.{tld}/patch",
    "Your account: hxxp://{s}.com.{r}.{tld}/login?session={tok}",
    "Activate account: hxxp://activate-{r}.{tld}/code?val={tok}",
    "Confirm email: hxxp://confirm-{r}-mail.{tld}/verify?token={tok}",
    "Join meeting: hxxp://zoom-{r}.{tld}/j/{tok}?pwd=abc123",
    "View statement: hxxp://bank-{r}-statement.{tld}/pdf?ref={tok}",
    "Download update: hxxp://update-{r}-patch.{tld}/exe?ver={tok}",
    "Sign document: hxxp://esign-{r}.{tld}/doc?id={tok}&action=sign",
    "Collect gift: hxxp://gift-{r}-free.{tld}/collect?code={tok}",
    "Verify payment: hxxp://pay-verify-{r}.{tld}/confirm?txn={tok}",
    "Access report: hxxp://report-{r}-secure.{tld}/view?key={tok}",
    "New message: hxxp://msg-{r}.{tld}/read?inbox={tok}&user=you",
    "Complete survey: hxxp://survey-{r}-earn.{tld}/start?ref={tok}",
    "Unlock account: hxxp://unlock-{r}.{tld}/account?verify={tok}",
    "Claim refund: hxxp://refund-{r}-tax.{tld}/apply?ssn={tok}",
    "View attachment: hxxp://attach-{r}.{tld}/open?file={tok}.pdf",
    "Login portal: hxxp://{s}-portal-{r}.{tld}/signin?next={tok}",
    "Renew subscription: hxxp://renew-{r}.{tld}/plan?user={tok}",
    "Security scan: hxxp://scan-{r}-protect.{tld}/result?id={tok}",
    "Accept invitation: hxxp://invite-{r}.{tld}/join?group={tok}",
    "Download receipt: hxxp://receipt-{r}.{tld}/download?order={tok}",
    "Verify identity: hxxp://id-verify-{r}.{tld}/submit?case={tok}",
]

TLDS  = ["tk","ml","ga","cf","xyz","cc","pw","top","info","biz"]
RANDS = ["a7f2","b3d9","c8e1","d4k7","e2m5","f9p3","g6n8","h1q4"]
TOKS  = ["aB3xK9","zR7mP2","qW5nL8","yT4vH6","xC2jF5","wD8kG1"]
SVCS  = ["paypal","amazon","netflix","apple","google","microsoft","bank","dropbox"]

# ── NORMAL PATTERNS ───────────────────────────────────────────────────────────
NORMAL = [
    "Hi, are you free for a call on {day}? Let me know what time works best.",
    "The quarterly report is ready for review. Please check the shared drive.",
    "Reminder: team meeting tomorrow at {time} in conference room B.",
    "Happy birthday! Hope you have a wonderful day filled with joy.",
    "Your Amazon order has shipped. Estimated delivery: {day}.",
    "The project deadline has been moved to next {day}. Please update schedules.",
    "Great presentation today! The client was very impressed with our proposal.",
    "Can you review my pull request? I fixed the authentication bug and added tests.",
    "Dinner tonight at {time}? I found a great new restaurant downtown.",
    "The server maintenance is scheduled for this weekend. Expected downtime 2 hours.",
    "Your prescription is ready for pickup at the pharmacy. Open until 9 PM.",
    "Sales figures for Q3 exceeded targets by 18%. Excellent work from the team.",
    "Please update your emergency contact information in the HR portal by month end.",
    "The library book you requested is now available for pickup within 7 days.",
    "Flight confirmation: your flight on {day} at {time} is confirmed.",
    "Welcome to the team! Your onboarding session starts {day} at {time}.",
    "Monthly newsletter: new features, community updates, and upcoming webinars inside.",
    "Your appointment is confirmed for {day} at {time}. Please arrive 10 minutes early.",
    "The park cleanup event was a success! Thank you all for volunteering.",
    "Code review feedback: looks good overall. A few minor style suggestions in comments.",
    "The budget proposal has been approved. You can proceed with the project.",
    "Please find attached the meeting notes from this morning session.",
    "Your annual performance review is scheduled for next {day} at {time}.",
    "The office will be closed on Friday for the public holiday.",
    "Can you send me the latest version of the presentation before {time}?",
    "The new hire starts on {day}. Please make them feel welcome.",
    "Lunch order cutoff is at {time}. Please submit your preferences before then.",
    "The training session recording has been uploaded to the shared folder.",
    "Your ticket has been resolved. Please let us know if you need further assistance.",
    "The weekly standup has been moved from {time} to 30 minutes later this week.",
]

DAYS_LIST  = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]
TIMES_LIST = ["9:00 AM","10:00 AM","11:30 AM","2:00 PM","3:30 PM","4:00 PM","5:00 PM"]

def _fill(template, category):
    import random
    s = template
    s = s.replace("{bank}",   random.choice(BANKS))
    s = s.replace("{service}",random.choice(SERVICES))
    s = s.replace("{url}",    random.choice(URLS).replace("{r}",random.choice(RANDS)).replace("{s}",random.choice(SVCS)))
    s = s.replace("{amt}",    random.choice(AMOUNTS))
    s = s.replace("{prize}",  random.choice(PRIZES))
    s = s.replace("{fee}",    random.choice(FEES))
    s = s.replace("{pct}",    random.choice(PCTS))
    s = s.replace("{days}",   random.choice(DAYS))
    s = s.replace("{day}",    random.choice(DAYS_LIST))
    s = s.replace("{time}",   random.choice(TIMES_LIST))
    s = s.replace("{tld}",    random.choice(TLDS))
    s = s.replace("{r}",      random.choice(RANDS))
    s = s.replace("{tok}",    random.choice(TOKS))
    s = s.replace("{s}",      random.choice(SVCS))
    return s

def _urgency(label, score):
    if label == "normal": return "LOW"
    if score >= 85: return "CRITICAL"
    if score >= 65: return "HIGH"
    return "MEDIUM"

CATEGORY_MAP = {
    "phishing":        (PHISHING,        (68, 95)),
    "blackmail":       (BLACKMAIL,       (82, 99)),
    "harassment":      (HARASSMENT,      (65, 92)),
    "fraud":           (FRAUD,           (60, 88)),
    "scam":            (SCAM,            (52, 80)),
    "suspicious_link": (SUSPICIOUS_LINK, (50, 78)),
    "normal":          (NORMAL,          (0,  8)),
}

def build_dataset(samples_per_class=80):
    rows = []
    for label, (templates, (lo, hi)) in CATEGORY_MAP.items():
        for i in range(samples_per_class):
            tmpl  = templates[i % len(templates)]
            text  = _fill(tmpl, label)
            score = random.randint(lo, hi)
            rows.append({
                "text":          text,
                "label":         label,
                "threat_score":  score,
                "urgency_level": _urgency(label, score),
                "source":        random.choice(["email","sms","social_media","web_form","chat"]),
            })
    df = pd.DataFrame(rows).sample(frac=1, random_state=42).reset_index(drop=True)
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybercrime_dataset.csv")
    df.to_csv(path, index=False)
    return df

if __name__ == "__main__":
    df = build_dataset(200)
    print(f"Built: {len(df)} rows | {df['label'].value_counts().to_dict()}")
