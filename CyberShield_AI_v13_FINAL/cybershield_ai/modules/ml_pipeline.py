"""
CyberShield AI – ML Pipeline
Full scikit-learn pipeline: preprocessing, TF-IDF vectorization,
Random Forest + SVM ensemble, evaluation metrics, confusion matrix.
"""
import os, re, joblib
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import LinearSVC
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (classification_report, confusion_matrix,
                             accuracy_score, f1_score)
from sklearn.preprocessing import LabelEncoder

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "..", "models", "cybershield_model.joblib")
ENCODER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "..", "models", "label_encoder.joblib")

# ── Text preprocessing ────────────────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "verify","urgent","suspended","confirm","account","password","click",
    "login","secure","update","alert","access","expire","limited","unusual",
    "winner","prize","lottery","fee","wire","bitcoin","crypto","wallet",
    "threat","expose","delete","blackmail","ransom","harm","watching","evidence",
    "grant","investment","guaranteed","return","profit","free money",
]

def preprocess_text(text: str) -> str:
    """Lowercase, remove noise, preserve structural signals."""
    text = text.lower()
    text = re.sub(r"https?://\S+", " SUSPICIOUSURL ", text)
    text = re.sub(r"hxxp://\S+", " SUSPICIOUSURL ", text)
    text = re.sub(r"\$[\d,]+", " MONEYAMOUNT ", text)
    text = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", " IPADDRESS ", text)
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

def extract_threat_features(text: str) -> dict:
    """Rule-based feature extraction for threat scoring."""
    tl = text.lower()
    kw_hits = sum(1 for k in SUSPICIOUS_KEYWORDS if k in tl)
    has_url = bool(re.search(r"hxxp|https?://|SUSPICIOUSURL", text))
    has_money = bool(re.search(r"MONEYAMOUNT|\$[\d,]+", text))
    has_urgency = any(w in tl for w in ["urgent","immediate","final notice","warning","alert"])
    has_threat = any(w in tl for w in ["expose","leak","destroy","harm","arrest","report"])
    score = (kw_hits * 5) + (has_url * 15) + (has_money * 10) + (has_urgency * 12) + (has_threat * 18)
    return {
        "keyword_hits": kw_hits,
        "has_url": has_url,
        "has_money": has_money,
        "has_urgency": has_urgency,
        "has_threat": has_threat,
        "raw_threat_score": min(score, 100),
    }

def compute_urgency(label: str, threat_score: int) -> str:
    if label == "normal":
        return "LOW"
    if threat_score >= 85:
        return "CRITICAL"
    if threat_score >= 65:
        return "HIGH"
    return "MEDIUM"

# ── Build ensemble pipeline ───────────────────────────────────────────────────
def build_pipeline() -> Pipeline:
    tfidf = TfidfVectorizer(
        max_features=15000,
        ngram_range=(1, 3),
        sublinear_tf=True,
        analyzer="word",
        preprocessor=preprocess_text,
        min_df=1,
        max_df=0.95,
    )
    rf  = RandomForestClassifier(n_estimators=300, max_depth=30,
                                 min_samples_split=2, min_samples_leaf=1,
                                 random_state=42, n_jobs=-1)
    lr  = LogisticRegression(C=10.0, max_iter=3000, solver="lbfgs",
                             random_state=42)
    from sklearn.naive_bayes import ComplementNB
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.svm import LinearSVC
    svm_cal = CalibratedClassifierCV(LinearSVC(C=2.0, max_iter=3000, random_state=42))

    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("lr", lr), ("svm", svm_cal)],
        voting="soft",
        weights=[2, 4, 2],
    )
    return Pipeline([("tfidf", tfidf), ("clf", ensemble)])

# ── Training ──────────────────────────────────────────────────────────────────
def train_model(df: pd.DataFrame):
    """Train the ML pipeline and persist to disk. Returns evaluation dict."""
    df = df.copy()
    df["processed"] = df["text"].apply(preprocess_text)

    le = LabelEncoder()
    y = le.fit_transform(df["label"])
    X = df["processed"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y)

    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1  = f1_score(y_test, y_pred, average="weighted")
    cm  = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred,
                                   target_names=le.classes_, output_dict=True)
    cv_scores = cross_val_score(pipeline, X, y, cv=5, scoring="accuracy")

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    joblib.dump(le, ENCODER_PATH)

    return {
        "accuracy": round(acc, 4),
        "f1_weighted": round(f1, 4),
        "confusion_matrix": cm,
        "classification_report": report,
        "classes": list(le.classes_),
        "cv_mean": round(cv_scores.mean(), 4),
        "cv_std": round(cv_scores.std(), 4),
        "cv_scores": cv_scores.tolist(),
        "X_test": X_test,
        "y_test": y_test,
        "y_pred": y_pred,
    }

# ── Inference ─────────────────────────────────────────────────────────────────
def load_model():
    if not os.path.exists(MODEL_PATH):
        return None, None
    return joblib.load(MODEL_PATH), joblib.load(ENCODER_PATH)

def predict(text: str, pipeline=None, le=None):
    """Return label, confidence, threat_score, urgency, keyword features."""
    if pipeline is None:
        pipeline, le = load_model()
        if pipeline is None:
            return {"error": "Model not trained yet."}

    processed = preprocess_text(text)
    proba = pipeline.predict_proba([processed])[0]
    pred_idx = np.argmax(proba)
    label = le.inverse_transform([pred_idx])[0]
    confidence = float(proba[pred_idx])

    feats = extract_threat_features(text)
    rule_score = feats["raw_threat_score"]

    # For non-normal: take MAX of (NLP rule score, ML confidence-based score)
    # This ensures high-severity messages always get high scores
    if label == "normal":
        threat_score = min(20, rule_score)
    else:
        ml_score   = int(confidence * 95)   # ML confidence → 0-95
        # Boost for high-severity categories
        CATEGORY_BOOSTS = {
            "blackmail":      20,
            "harassment":     15,
            "phishing":       10,
            "fraud":          10,
            "scam":            8,
            "suspicious_link": 8,
        }
        boost = CATEGORY_BOOSTS.get(label, 0)
        threat_score = min(100, max(ml_score, rule_score) + boost)

    urgency = compute_urgency(label, threat_score)

    flagged_kw = [k for k in SUSPICIOUS_KEYWORDS if k in text.lower()]

    return {
        "label": label,
        "confidence": confidence,
        "threat_score": threat_score,
        "urgency": urgency,
        "flagged_keywords": flagged_kw,
        "features": feats,
        "all_proba": {le.classes_[i]: round(float(p), 4) for i, p in enumerate(proba)},
    }
