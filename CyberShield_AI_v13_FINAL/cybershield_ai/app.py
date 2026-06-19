
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from database.db_manager import (initialize_database, insert_complaint,
    log_investigation, log_threat, fetch_all_complaints,
    fetch_threat_logs, fetch_investigation_logs, get_stats)
from modules.ml_pipeline import train_model, predict, load_model
from modules.search_algorithms import build_investigation_graph, run_all_algorithms
from modules.nlp_analyzer import analyze_text, highlight_text_html, get_risk_profile
from modules.virustotal_api import scan_url, scan_ip, is_configured as vt_configured
from modules.visualizer import (plot_confusion_matrix, plot_class_accuracy,
    plot_probability_radar, plot_threat_gauge, plot_cv_scores,
    render_investigation_graph)
from data.dataset_builder import build_dataset

st.set_page_config(
    page_title="CyberShield AI",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap');
html,body,[class*="css"]{font-family:'Exo 2',sans-serif;background-color:#060b18;color:#c8d8f0;}
.stApp{background:linear-gradient(135deg,#060b18 0%,#0a1228 50%,#060b18 100%);}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#080f22 0%,#0d1530 100%);border-right:1px solid #1a2d50;}
.metric-card{background:linear-gradient(135deg,#0f1a35,#162040);border:1px solid #1e3058;border-radius:10px;padding:18px 22px;position:relative;overflow:hidden;}
.metric-card::before{content:'';position:absolute;top:0;left:0;width:3px;height:100%;background:linear-gradient(180deg,#00d4ff,#0060aa);}
.metric-card.danger::before{background:linear-gradient(180deg,#ff4444,#aa0000);}
.metric-card.warning::before{background:linear-gradient(180deg,#ffaa00,#aa6600);}
.metric-card.success::before{background:linear-gradient(180deg,#00ff88,#006633);}
.metric-label{font-size:11px;color:#6688aa;text-transform:uppercase;letter-spacing:2px;}
.metric-value{font-family:'Share Tech Mono',monospace;font-size:32px;color:#00d4ff;margin:4px 0;}
.metric-card.danger .metric-value{color:#ff4444;}
.metric-card.warning .metric-value{color:#ffaa00;}
.metric-card.success .metric-value{color:#00ff88;}
.section-header{font-family:'Share Tech Mono',monospace;font-size:13px;color:#00d4ff;letter-spacing:3px;text-transform:uppercase;border-bottom:1px solid #1e3058;padding-bottom:8px;margin-bottom:18px;}
.badge{display:inline-block;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:1px;}
.badge-critical{background:#3a0000;color:#ff4444;border:1px solid #ff4444;}
.badge-high{background:#2a1a00;color:#ffaa00;border:1px solid #ffaa00;}
.badge-medium{background:#1a2a1a;color:#88ff88;border:1px solid #44aa44;}
.badge-low{background:#0a1a2a;color:#88aaff;border:1px solid #4466aa;}
.badge-clean{background:#0a2a1a;color:#00ff88;border:1px solid #00aa44;}
.algo-card{background:#0d1830;border:1px solid #1e3058;border-radius:8px;padding:14px 18px;margin:6px 0;}
.stTextArea textarea{background:#0d1830 !important;color:#c8d8f0 !important;border:1px solid #1e3058 !important;}
.stButton>button{background:linear-gradient(135deg,#003366,#005599);color:#00d4ff;border:1px solid #0077cc;border-radius:6px;font-family:'Share Tech Mono',monospace;letter-spacing:1px;}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


# ── USERS DATABASE ────────────────────────────────────────────────────────────
USERS = {
    "admin":   {"password": "cyber@admin123",   "role": "admin",   "name": "SOC Administrator"},
    "analyst": {"password": "analyst@2026",      "role": "analyst", "name": "Cyber Analyst"},
    "viewer":  {"password": "viewer@2026",        "role": "viewer",  "name": "Read-Only Auditor"},
}

ROLE_ACCESS = {
    "admin":   ["Dashboard", "ML Pipeline", "Threat Analyzer", "Investigation Graph", "Case Records", "Analytics", "System Info"],
    "analyst": ["Dashboard", "Threat Analyzer", "Investigation Graph", "Case Records", "Analytics", "System Info"],
    "viewer":  ["Dashboard", "Case Records", "Analytics"],
}

ROLE_COLOR = {"admin": "#ff4444", "analyst": "#00d4ff", "viewer": "#00ff88"}

def show_login():
    st.markdown("""
    <div style='display:flex;justify-content:center;align-items:center;min-height:80vh;'>
    <div style='background:#0d1830;border:1px solid #1e3058;border-radius:16px;
                padding:48px 52px;width:420px;text-align:center;'>
        <div style='font-family:Share Tech Mono,monospace;font-size:28px;
                    color:#00d4ff;letter-spacing:4px;margin-bottom:6px;'>
            🛡 CYBERSHIELD
        </div>
        <div style='font-size:11px;color:#446688;letter-spacing:3px;
                    margin-bottom:32px;'>AI INVESTIGATION SYSTEM</div>
        <div style='font-size:12px;color:#ff4444;font-family:Share Tech Mono,monospace;
                    letter-spacing:2px;margin-bottom:24px;border:1px solid #3a0000;
                    background:#1a0000;padding:8px;border-radius:4px;'>
            ⚠ AUTHORIZED PERSONNEL ONLY
        </div>
    </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        username = st.text_input("Username", placeholder="Enter username", key="login_user")
        password = st.text_input("Password", placeholder="Enter password", type="password", key="login_pass")
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🔐  ACCESS SYSTEM", use_container_width=True):
            if username in USERS and USERS[username]["password"] == password:
                st.session_state.logged_in = True
                st.session_state.username  = username
                st.session_state.role      = USERS[username]["role"]
                st.session_state.name      = USERS[username]["name"]
                st.rerun()
            else:
                st.error("Invalid credentials. Access denied.")


# ── AUTH GATE ─────────────────────────────────────────────────────────────────
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    show_login()
    st.stop()

initialize_database()

if "model"         not in st.session_state: st.session_state.model         = None
if "encoder"       not in st.session_state: st.session_state.encoder       = None
if "df"            not in st.session_state: st.session_state.df            = None
if "train_results" not in st.session_state: st.session_state.train_results = None
if "last_analysis" not in st.session_state: st.session_state.last_analysis = None
if "graph"         not in st.session_state:
    st.session_state.graph = build_investigation_graph(num_nodes=18, seed=42)

model, encoder = load_model()
if model:
    st.session_state.model   = model
    st.session_state.encoder = encoder

# ── SIDEBAR ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style='text-align:center;padding:20px 0 10px;'>
        <div style='font-size:42px;'>🛡️</div>
        <div style='font-family:Share Tech Mono,monospace;font-size:18px;color:#00d4ff;letter-spacing:3px;'>CYBERSHIELD</div>
        <div style='font-size:10px;color:#446688;letter-spacing:5px;'>AI INVESTIGATION SYSTEM</div>
    </div>
    <hr style='border-color:#1e3058;margin:10px 0 20px;'>
    """, unsafe_allow_html=True)

    ROLE_ACCESS = {
        "admin":   ["Dashboard", "ML Pipeline", "Threat Analyzer", "Investigation Graph", "Case Records", "Analytics", "System Info"],
        "analyst": ["Dashboard", "Threat Analyzer", "Investigation Graph", "Case Records", "Analytics", "System Info"],
        "viewer":  ["Dashboard", "Case Records", "Analytics"],
    }
    _role = st.session_state.get("role", "viewer")
    _allowed = ROLE_ACCESS.get(_role, ["Dashboard"])
    page = st.radio("NAVIGATION", _allowed)

    st.markdown("<hr style='border-color:#1e3058;margin:20px 0;'>", unsafe_allow_html=True)
    stats = get_stats()
    model_color  = "00ff88" if st.session_state.model else "ff4444"
    model_status = "LOADED"  if st.session_state.model else "UNTRAINED"

    # ── User Info + Logout ────────────────────────────────────────────────────
    role       = st.session_state.get("role", "viewer")
    name       = st.session_state.get("name", "User")
    role_color = {"admin": "#ff4444", "analyst": "#00d4ff", "viewer": "#00ff88"}.get(role, "#00d4ff")
    st.markdown(f"""
    <div style='background:#060b18;border:1px solid #1e3058;border-radius:8px;
                padding:10px 14px;margin:10px 0 6px;font-size:12px;'>
        <div style='color:#446688;font-size:10px;letter-spacing:2px;margin-bottom:4px;'>LOGGED IN AS</div>
        <div style='color:#c8d8f0;margin-bottom:6px;'>{name}</div>
        <div style='display:inline-block;background:#0a0e1a;border:1px solid {role_color};
                    color:{role_color};font-size:10px;padding:2px 8px;border-radius:3px;
                    font-family:Share Tech Mono,monospace;letter-spacing:1px;'>
            {role.upper()}
        </div>
    </div>""", unsafe_allow_html=True)
    if st.button("🔓 Logout", use_container_width=True):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()
    st.markdown("---")

    st.markdown(f"""
    <div style='font-size:10px;color:#446688;letter-spacing:2px;margin-bottom:8px;'>LIVE STATS</div>
    <div style='font-family:Share Tech Mono,monospace;font-size:12px;color:#88aacc;line-height:2;'>
        CASES    : <span style='color:#00d4ff'>{stats["total"]}</span><br>
        CRITICAL : <span style='color:#ff4444'>{stats["critical_count"]}</span><br>
        AVG SCORE: <span style='color:#ffaa00'>{stats["avg_threat_score"]}</span><br>
        MODEL    : <span style='color:#{model_color}'>{model_status}</span>
    </div>
    """, unsafe_allow_html=True)

# ── PAGE: DASHBOARD ───────────────────────────────────────────────────────────
if page == "Dashboard":
    st.markdown('<div class="section-header">⬡ REAL-TIME SYSTEM OVERVIEW</div>', unsafe_allow_html=True)

    c1,c2,c3,c4 = st.columns(4)
    c1.markdown(f'<div class="metric-card"><div class="metric-label">Total Cases</div><div class="metric-value">{stats["total"]}</div><div style="font-size:11px;color:#446688;">Logged</div></div>', unsafe_allow_html=True)
    c2.markdown(f'<div class="metric-card danger"><div class="metric-label">Critical Threats</div><div class="metric-value">{stats["critical_count"]}</div><div style="font-size:11px;color:#446688;">Immediate action</div></div>', unsafe_allow_html=True)
    c3.markdown(f'<div class="metric-card warning"><div class="metric-label">Avg Threat Score</div><div class="metric-value">{stats["avg_threat_score"]}</div><div style="font-size:11px;color:#446688;">Across all cases</div></div>', unsafe_allow_html=True)
    card_type = "success" if st.session_state.model else "danger"
    c4.markdown(f'<div class="metric-card {card_type}"><div class="metric-label">AI Engine</div><div class="metric-value" style="font-size:22px;">{model_status}</div><div style="font-size:11px;color:#446688;">ML classifier</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    col_l, col_r = st.columns([1.4,1])

    with col_l:
        st.markdown('<div class="section-header">THREAT CATEGORY DISTRIBUTION</div>', unsafe_allow_html=True)
        if stats["by_label"]:
            labels = list(stats["by_label"].keys())
            values = list(stats["by_label"].values())
            colors = ["#ff4444","#ffaa00","#ff6688","#aa44ff","#00aaff","#00ff88","#446688"]
            fig = go.Figure(go.Pie(labels=labels, values=values, hole=0.55,
                marker_colors=colors[:len(labels)], textinfo="label+percent",
                textfont=dict(size=11,color="#c8d8f0")))
            fig.update_layout(paper_bgcolor="#060b18",plot_bgcolor="#060b18",
                font=dict(color="#c8d8f0"),showlegend=False,
                margin=dict(l=20,r=20,t=20,b=20),height=260)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No cases yet — analyze messages to populate charts.")

    with col_r:
        st.markdown('<div class="section-header">RECENT THREAT ALERTS</div>', unsafe_allow_html=True)
        logs = fetch_threat_logs(limit=6)
        if logs:
            for log in logs:
                sev = log["severity"]
                bc  = {"CRITICAL":"badge-critical","HIGH":"badge-high",
                       "MEDIUM":"badge-medium","LOW":"badge-low"}.get(sev,"badge-low")
                bc2 = "#ff4444" if sev=="CRITICAL" else "#ffaa00" if sev=="HIGH" else "#4488aa"
                st.markdown(f"""<div style='background:#0d1830;border-left:3px solid {bc2};
                    padding:8px 12px;margin:5px 0;border-radius:4px;font-size:12px;'>
                    <span class='badge {bc}'>{sev}</span>
                    <span style='color:#88aacc;margin-left:8px;'>{log["threat_type"]}</span><br>
                    <span style='color:#446688;font-size:10px;'>{log["timestamp"][:19]}</span>
                    </div>""", unsafe_allow_html=True)
        else:
            st.markdown('<div style="color:#446688;font-size:13px;">No alerts yet.</div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="section-header">RECENT CASE LOG</div>', unsafe_allow_html=True)
    complaints = fetch_all_complaints(limit=8)
    if complaints:
        df_c = pd.DataFrame(complaints)[["id","submitted_at","predicted_label","threat_score","urgency_level","status"]]
        df_c.columns = ["ID","Timestamp","Classification","Threat Score","Urgency","Status"]
        st.dataframe(df_c, use_container_width=True, hide_index=True)
    else:
        st.info("No cases yet. Use Threat Analyzer to submit messages.")

# ── PAGE: ML PIPELINE ─────────────────────────────────────────────────────────
elif page == "ML Pipeline":
    st.markdown('<div class="section-header">🤖 ML PIPELINE — TRAINING & EVALUATION</div>', unsafe_allow_html=True)
    st.markdown("""<div style='background:#0d1830;border:1px solid #1e3058;border-radius:8px;padding:16px;margin-bottom:20px;'>
    <b style='color:#00d4ff;'>Architecture:</b>
    <span style='color:#88aacc;font-size:13px;'>
    Text → NLP Preprocessing → TF-IDF Vectorization (bigrams, 8k features)
    → Ensemble (RandomForest + LogisticRegression soft-vote) → Probability → Threat Score
    </span></div>""", unsafe_allow_html=True)

    col1, col2 = st.columns([1,2])
    with col1:
        st.markdown('<div class="section-header">TRAINING CONTROLS</div>', unsafe_allow_html=True)
        samples = st.slider("Samples per class", 20, 200, 200)
        if st.button("BUILD DATASET & TRAIN MODEL", use_container_width=True):
            with st.spinner("Building dataset..."):
                df = build_dataset(samples_per_class=samples)
                st.session_state.df = df
            st.success(f"Dataset: {len(df)} samples, {df['label'].nunique()} classes")
            with st.spinner("Training ensemble classifier..."):
                results = train_model(df)
                st.session_state.train_results = results
            m, e = load_model()
            st.session_state.model   = m
            st.session_state.encoder = e
            log_threat("MODEL_RETRAIN","LOW",f"Acc={results['accuracy']:.3f}")
            st.success(f"Training complete! Accuracy: {results['accuracy']*100:.1f}%")

        if st.session_state.df is not None:
            st.markdown('<div class="section-header" style="margin-top:20px;">DATASET</div>', unsafe_allow_html=True)
            for lbl, cnt in st.session_state.df["label"].value_counts().items():
                st.markdown(f"""<div style='display:flex;justify-content:space-between;
                    font-size:12px;color:#88aacc;padding:3px 0;'>
                    <span>{lbl}</span><span style='color:#00d4ff;'>{cnt}</span></div>""",
                    unsafe_allow_html=True)

    with col2:
        if st.session_state.train_results:
            r = st.session_state.train_results
            st.markdown('<div class="section-header">EVALUATION METRICS</div>', unsafe_allow_html=True)
            m1,m2,m3,m4 = st.columns(4)
            m1.metric("Accuracy",    f"{r['accuracy']:.1%}")
            m2.metric("F1 Weighted", f"{r['f1_weighted']:.1%}")
            m3.metric("CV Mean",     f"{r['cv_mean']:.1%}")
            m4.metric("CV Std",      f"{r['cv_std']:.4f}")
            tab1,tab2,tab3 = st.tabs(["Confusion Matrix","Per-Class F1","Cross-Validation"])
            with tab1:
                st.plotly_chart(plot_confusion_matrix(r["confusion_matrix"], r["classes"]), use_container_width=True)
            with tab2:
                st.plotly_chart(plot_class_accuracy(r["classification_report"], r["classes"]), use_container_width=True)
            with tab3:
                st.plotly_chart(plot_cv_scores(r["cv_scores"]), use_container_width=True)
        else:
            st.markdown("""<div style='text-align:center;padding:80px 20px;color:#446688;'>
                <div style='font-size:48px;'>🤖</div>
                <div style='font-family:Share Tech Mono,monospace;font-size:14px;margin-top:12px;'>
                MODEL NOT TRAINED<br><span style='font-size:11px;'>Click Build Dataset & Train Model</span></div>
                </div>""", unsafe_allow_html=True)

# ── PAGE: THREAT ANALYZER ─────────────────────────────────────────────────────
elif page == "Threat Analyzer":
    st.markdown('<div class="section-header">🔍 INTELLIGENT THREAT ANALYZER</div>', unsafe_allow_html=True)
    col_form, col_result = st.columns([1, 1.3])

    with col_form:
        user_text = st.text_area("Enter message / URL / report:", height=200,
            placeholder="Paste suspicious content here for AI analysis...")
        source_type = st.selectbox("Source Channel",
            ["email","sms","social_media","web_form","chat","unknown"])
        analyze_btn = st.button("ANALYZE THREAT", use_container_width=True)

        if analyze_btn and user_text.strip():
            nlp_result   = analyze_text(user_text)
            risk_profile = get_risk_profile(nlp_result)

            if st.session_state.model:
                ml_result  = predict(user_text, st.session_state.model, st.session_state.encoder)
                label      = ml_result["label"]
                confidence = ml_result["confidence"]
                # Always take the HIGHER of ML score vs NLP score
                nlp_score  = nlp_result["threat_score"]
                ml_score   = ml_result["threat_score"]
                threat_sc  = max(nlp_score, ml_score)
                # Recompute urgency from final score
                if label == "normal" and nlp_score < 20:
                    urgency = "LOW"
                elif threat_sc >= 80:
                    urgency = "CRITICAL"
                elif threat_sc >= 55:
                    urgency = "HIGH"
                elif threat_sc >= 30:
                    urgency = "MEDIUM"
                else:
                    urgency = "LOW"
            else:
                label      = "UNCLASSIFIED (train model first)"
                confidence = 0.0
                threat_sc  = nlp_result["threat_score"]
                # Proper urgency based on NLP score
                if threat_sc >= 80:
                    urgency = "CRITICAL"
                elif threat_sc >= 55:
                    urgency = "HIGH"
                elif threat_sc >= 30:
                    urgency = "MEDIUM"
                else:
                    urgency = "LOW"
                ml_result  = {"all_proba": {}, "flagged_keywords": []}

            st.session_state.last_analysis = {
                "text": user_text, "nlp": nlp_result, "ml": ml_result,
                "label": label, "confidence": confidence,
                "threat_score": threat_sc, "urgency": urgency,
            }
            cid = insert_complaint(user_text, label, confidence, threat_sc, urgency, source_type)
            log_threat(label, urgency, f"Case #{cid}", keywords=", ".join(ml_result.get("flagged_keywords",[])))
            st.success(f"Case #{cid} logged.")

            # ── Auto-populate Investigation Graph from extracted entities ──
            entities = nlp_result.get("entities", {})
            G = st.session_state.graph
            added = []

            for url in entities.get("urls", []):
                node_id = f"URL-{url[:30]}"
                if node_id not in G:
                    risk = min(95, int(threat_sc * 0.95))
                    level = "critical" if risk >= 80 else "high" if risk >= 60 else "medium"
                    G.add_node(node_id, node_type="server", label=f"Extracted URL: {url[:25]}...",
                               risk_score=risk, risk_level=level)
                    G.add_edge("SUSP-IP-001",     node_id,             weight=9.1, comm_type="url_deploy")
                    G.add_edge(node_id,            "PHISH-SERVER-001",  weight=8.7, comm_type="server_link")
                    G.add_edge("PHISH-SERVER-001", "VICTIM-EMAIL-001",  weight=8.5, comm_type="phishing_email")
                    added.append(node_id)

            for ip in entities.get("ip_addresses", []):
                node_id = f"IP-{ip}"
                if node_id not in G:
                    risk = min(92, int(threat_sc * 0.90))
                    level = "critical" if risk >= 80 else "high" if risk >= 60 else "medium"
                    G.add_node(node_id, node_type="ip_address", label=f"Extracted IP: {ip}",
                               risk_score=risk, risk_level=level)
                    G.add_edge("SUSP-IP-001", node_id,            weight=9.0, comm_type="ip_relay")
                    G.add_edge(node_id,        "PROXY-SERVER-001", weight=8.3, comm_type="proxy_connect")
                    added.append(node_id)

            for email in entities.get("emails", []):
                node_id = f"EMAIL-{email[:30]}"
                if node_id not in G:
                    risk = min(90, int(threat_sc * 0.88))
                    level = "critical" if risk >= 80 else "high" if risk >= 60 else "medium"
                    G.add_node(node_id, node_type="email", label=f"Extracted Email: {email[:25]}",
                               risk_score=risk, risk_level=level)
                    G.add_edge("SUSP-EMAIL-001", node_id,            weight=8.8, comm_type="email_spoof")
                    G.add_edge(node_id,           "VICTIM-EMAIL-001", weight=8.2, comm_type="email_sent")
                    added.append(node_id)

            if added:
                st.info(f"🔗 {len(added)} new entity/entities linked into Investigation Graph.")

    with col_result:
        analysis = st.session_state.last_analysis
        if analysis:
            st.plotly_chart(plot_threat_gauge(analysis["threat_score"]), use_container_width=True)

            badge_map = {"normal":"badge-clean","phishing":"badge-critical","blackmail":"badge-critical",
                         "fraud":"badge-high","harassment":"badge-high","scam":"badge-medium",
                         "suspicious_link":"badge-medium"}
            badge = badge_map.get(analysis["label"].lower(), "badge-medium")
            urg_badge = {"CRITICAL":"badge-critical","HIGH":"badge-high",
                         "MEDIUM":"badge-medium","LOW":"badge-low"}.get(analysis["urgency"],"badge-low")

            st.markdown(f"""<div style='background:#0d1830;border:1px solid #1e3058;border-radius:8px;padding:16px;margin:8px 0;'>
                <div style='font-family:Share Tech Mono,monospace;font-size:11px;color:#446688;margin-bottom:8px;'>CLASSIFICATION RESULT</div>
                <span class='badge {badge}' style='font-size:14px;padding:5px 14px;'>{analysis["label"].upper()}</span>
                <span class='badge {urg_badge}' style='margin-left:8px;'>{analysis["urgency"]}</span>
                <div style='margin-top:10px;font-size:13px;color:#88aacc;'>
                    Confidence: <b style='color:#00d4ff;'>{analysis["confidence"]*100:.1f}%</b>
                    &nbsp;|&nbsp; Threat Score: <b style='color:#ffaa00;'>{analysis["threat_score"]}/100</b>
                </div></div>""", unsafe_allow_html=True)

            kws = analysis["nlp"]["highlighted_keywords"]
            if kws:
                st.markdown('<div class="section-header" style="margin-top:14px;">FLAGGED KEYWORDS</div>', unsafe_allow_html=True)
                import html as _html
                safe_text = _html.escape(analysis["text"])
                for _kw in sorted(kws, key=len, reverse=True):
                    import re as _re
                    safe_text = _re.compile(_re.escape(_html.escape(_kw)), _re.I).sub(
                        lambda m: f'<span style="background:#8b0000;color:#ffaaaa;padding:2px 5px;border-radius:3px;font-weight:bold;">{m.group(0)}</span>',
                        safe_text
                    )
                st.markdown(f"""<div style='background:#080f20;border:1px solid #1e3058;border-radius:6px;
                    padding:12px;font-size:13px;line-height:1.8;'>{safe_text}</div>""",
                    unsafe_allow_html=True)

            if analysis["ml"].get("all_proba"):
                st.plotly_chart(plot_probability_radar(analysis["ml"]["all_proba"]), use_container_width=True)

            entities = analysis["nlp"]["entities"]
            if any(v for v in entities.values()):
                st.markdown('<div class="section-header">EXTRACTED ENTITIES</div>', unsafe_allow_html=True)
                for etype, items in entities.items():
                    if items:
                        st.markdown(f"""<div style='font-size:12px;color:#88aacc;margin:4px 0;'>
                            <b style='color:#00d4ff;'>{etype.replace("_"," ").upper()}:</b>
                            {" | ".join(str(i) for i in items)}</div>""", unsafe_allow_html=True)

            # ── VirusTotal Real-Time Scan ─────────────────────────────────
            urls_found = analysis["nlp"]["entities"].get("urls", [])
            ips_found  = analysis["nlp"]["entities"].get("ip_addresses", [])

            if urls_found or ips_found:
                st.markdown('<div class="section-header" style="margin-top:18px;">🛡️ VIRUSTOTAL REAL-TIME SCAN</div>',
                            unsafe_allow_html=True)
                if not vt_configured():
                    st.markdown("""
                    <div style='background:#1a1000;border:1px solid #ffaa00;border-radius:8px;
                                padding:20px;font-size:13px;margin:8px 0;'>
                        <div style='font-family:Share Tech Mono,monospace;color:#ffaa00;
                                    font-size:13px;letter-spacing:2px;margin-bottom:14px;'>
                            ⚠ VIRUSTOTAL INTEGRATION — API KEY REQUIRED
                        </div>
                        <div style='color:#88aacc;line-height:2.2;'>
                            Real-time scanning via 90+ security engines is available but requires
                            a VirusTotal API key. To activate this feature:<br>
                            <div style='margin:10px 0 6px;'>
                            <span style='color:#446688;font-family:Share Tech Mono,monospace;'>STEP 1</span>
                            &nbsp; Register a free account at
                            <b style='color:#00d4ff;'>virustotal.com</b>
                            </div>
                            <div style='margin:0 0 6px;'>
                            <span style='color:#446688;font-family:Share Tech Mono,monospace;'>STEP 2</span>
                            &nbsp; Navigate to <b style='color:#00d4ff;'>Profile → API Key</b>
                            and copy your key
                            </div>
                            <div style='margin:0 0 10px;'>
                            <span style='color:#446688;font-family:Share Tech Mono,monospace;'>STEP 3</span>
                            &nbsp; Open <b style='color:#00d4ff;'>modules/virustotal_api.py</b>
                            and set:
                            </div>
                            <code style='display:block;background:#0a0e1a;border:1px solid #1e3058;
                                padding:8px 14px;border-radius:4px;color:#00ff88;font-size:12px;'>
                                VIRUSTOTAL_API_KEY = "your_api_key_here"
                            </code>
                        </div>
                    </div>""", unsafe_allow_html=True)
                else:
                    for url in urls_found[:2]:
                        clean = url.replace("hxxp","http").replace("hxxps","https")
                        with st.spinner(f"Scanning on VirusTotal: {clean[:45]}..."):
                            vt = scan_url(url)
                        if "error" in vt:
                            st.error(f"VirusTotal Error: {vt['error']}")
                        elif "status" in vt:
                            st.info(vt["message"])
                        else:
                            vc  = "#ff4444" if vt["verdict"]=="MALICIOUS" else "#ffaa00" if vt["verdict"]=="SUSPICIOUS" else "#00ff88"
                            mal = vt["malicious_count"]
                            sus = vt["suspicious_count"]
                            hrm = vt["harmless_count"]
                            tot = vt["total_engines"]
                            vendors_html = f"<div style='font-size:11px;color:#ff4444;margin-top:8px;'>Flagged by: {', '.join(vt['malicious_vendors'][:6])}</div>" if vt["malicious_vendors"] else ""
                            st.markdown(f"""
                            <div style='background:#0d1830;border:2px solid {vc};
                                        border-radius:8px;padding:16px;margin:8px 0;'>
                                <div style='font-family:Share Tech Mono,monospace;
                                            font-size:14px;color:{vc};margin-bottom:12px;'>
                                    VIRUSTOTAL — {vt["verdict"]}
                                </div>
                                <div style='display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:8px;'>
                                    <div style='text-align:center;background:#0a0e1a;border-radius:6px;padding:10px;'>
                                        <div style='font-size:26px;color:#ff4444;font-weight:bold;'>{mal}</div>
                                        <div style='font-size:10px;color:#446688;letter-spacing:1px;'>MALICIOUS</div>
                                    </div>
                                    <div style='text-align:center;background:#0a0e1a;border-radius:6px;padding:10px;'>
                                        <div style='font-size:26px;color:#ffaa00;font-weight:bold;'>{sus}</div>
                                        <div style='font-size:10px;color:#446688;letter-spacing:1px;'>SUSPICIOUS</div>
                                    </div>
                                    <div style='text-align:center;background:#0a0e1a;border-radius:6px;padding:10px;'>
                                        <div style='font-size:26px;color:#00ff88;font-weight:bold;'>{hrm}</div>
                                        <div style='font-size:10px;color:#446688;letter-spacing:1px;'>HARMLESS</div>
                                    </div>
                                    <div style='text-align:center;background:#0a0e1a;border-radius:6px;padding:10px;'>
                                        <div style='font-size:26px;color:#446688;font-weight:bold;'>{tot}</div>
                                        <div style='font-size:10px;color:#446688;letter-spacing:1px;'>TOTAL ENGINES</div>
                                    </div>
                                </div>
                                <div style='font-size:11px;color:#446688;margin-top:10px;'>
                                    URL: <span style='color:#88aacc;'>{clean[:65]}</span>
                                </div>
                                {vendors_html}
                            </div>""", unsafe_allow_html=True)

                    for ip in ips_found[:1]:
                        with st.spinner(f"Checking IP reputation: {ip}..."):
                            ip_r = scan_ip(ip)
                        if "error" not in ip_r:
                            ivc = "#ff4444" if ip_r["verdict"]=="MALICIOUS" else "#ffaa00" if ip_r["verdict"]=="SUSPICIOUS" else "#00ff88"
                            st.markdown(f"""
                            <div style='background:#0d1830;border:1px solid {ivc};
                                        border-radius:8px;padding:14px;margin:8px 0;'>
                                <div style='font-family:Share Tech Mono,monospace;font-size:12px;color:{ivc};'>
                                    IP REPUTATION: {ip_r["verdict"]}</div>
                                <div style='font-size:12px;color:#88aacc;margin-top:8px;line-height:2;'>
                                    IP: <b style='color:#00d4ff;'>{ip}</b> |
                                    Country: <b style='color:#00d4ff;'>{ip_r["country"]}</b> |
                                    ISP: <b style='color:#00d4ff;'>{ip_r["isp"]}</b><br>
                                    Malicious Reports:
                                    <b style='color:#ff4444;'>{ip_r["malicious_count"]}/{ip_r["total_engines"]}</b>
                                </div>
                            </div>""", unsafe_allow_html=True)
        else:
            st.markdown("""<div style='text-align:center;padding:80px 20px;color:#446688;'>
                <div style='font-size:48px;'>🔍</div>
                <div style='font-family:Share Tech Mono,monospace;font-size:14px;margin-top:12px;'>
                AWAITING INPUT<br><span style='font-size:11px;'>Submit text for threat analysis</span></div>
                </div>""", unsafe_allow_html=True)

# ── PAGE: INVESTIGATION GRAPH ─────────────────────────────────────────────────
elif page == "Investigation Graph":
    st.markdown('<div class="section-header">🌐 CYBER INVESTIGATION GRAPH — SEARCH ALGORITHMS</div>', unsafe_allow_html=True)
    G = st.session_state.graph
    nodes = list(G.nodes())

    st.markdown("""<div style='background:#0d1830;border:1px solid #1e3058;border-radius:8px;
        padding:14px 18px;margin-bottom:16px;font-size:13px;'>
        <b style='color:#00d4ff;'>Graph Model:</b>
        <span style='color:#88aacc;'> Nodes = digital entities (IPs, accounts, devices, servers, wallets).
        Edges = suspicious communications weighted by threat intensity.
        Each algorithm reveals a different investigative perspective on the attack network.</span></div>""",
        unsafe_allow_html=True)

    col_ctrl, col_legend = st.columns([2,1])
    with col_ctrl:
        src = st.selectbox("Source Node (Suspect)", nodes, index=0)
        tgt = st.selectbox("Target Node (Victim)", nodes, index=min(7, len(nodes)-1))
    with col_legend:
        st.markdown("""<div style='font-size:11px;color:#446688;line-height:2.4;padding-top:10px;'>
            <span style='color:#00d4ff;'>━━</span> BFS — shortest hop path<br>
            <span style='color:#ff8800;'>━━</span> DFS — deep chain traversal<br>
            <span style='color:#00ff88;'>━━</span> A* — optimal cost path<br>
            <span style='color:#8a0000;'>●</span> Critical risk node<br>
            <span style='color:#4a3a0a;'>●</span> High risk node
            </div>""", unsafe_allow_html=True)

    if st.button("RUN ALL SEARCH ALGORITHMS", use_container_width=True) and src != tgt:
        with st.spinner("Running BFS, DFS, A*..."):
            results = run_all_algorithms(G, src, tgt)

        st.markdown("<br>", unsafe_allow_html=True)
        ac1,ac2,ac3 = st.columns(3)
        algo_colors = {"BFS":"#00d4ff","DFS":"#ff8800","A*":"#00ff88"}
        use_cases   = {
            "BFS": "Minimum hop chain — fewest relay nodes between suspect and victim",
            "DFS": "Full attack chain exploration — uncovers deeply nested networks",
            "A*":  "Cost-optimal route — prioritises highest-threat investigation path",
        }
        for col,(algo,res) in zip([ac1,ac2,ac3], results.items()):
            c = algo_colors[algo]
            found = res["found"]
            path_str = " → ".join(res["path"]) if found else "No path found"
            cost_str = f" | Cost: {res.get('total_cost','N/A')}" if "total_cost" in res else ""
            col.markdown(f"""<div class='algo-card' style='border-color:{c}33;'>
                <div style='font-family:Share Tech Mono,monospace;color:{c};font-size:13px;'>{algo} Search</div>
                <div style='font-size:11px;color:#446688;margin:6px 0 10px;'>{use_cases[algo]}</div>
                <div style='font-size:11px;color:#88aacc;'>
                    Status: <b style='color:{"#00ff88" if found else "#ff4444"};'>{"FOUND" if found else "NOT FOUND"}</b><br>
                    Explored: <b style='color:{c};'>{res["nodes_explored"]} nodes</b>{cost_str}<br>
                    Hops: <b style='color:{c};'>{len(res["path"])-1 if found else 0}</b>
                </div>
                <div style='margin-top:10px;font-size:10px;color:#446688;
                    word-break:break-all;font-family:Share Tech Mono,monospace;'>{path_str}</div>
                </div>""", unsafe_allow_html=True)

        log_investigation(None, "BFS+DFS+A*", results["BFS"]["path"],
                          results["BFS"]["nodes_explored"], f"{src} -> {tgt}")

        st.markdown('<div class="section-header" style="margin-top:22px;">GRAPH VISUALIZATION</div>', unsafe_allow_html=True)
        with st.spinner("Rendering..."):
            fig = render_investigation_graph(G, results["BFS"], results["DFS"], results["A*"], src, tgt)
        st.pyplot(fig, use_container_width=True)
        plt.close(fig)

    else:
        st.markdown(f'''<div style="background:#0d1830;border:1px solid #1e3058;border-radius:8px;
            padding:14px 18px;font-size:13px;color:#88aacc;">
            Graph loaded: <b style="color:#00d4ff;">{G.number_of_nodes()} nodes</b> |
            <b style="color:#00d4ff;">{G.number_of_edges()} edges</b> |
            Select a source and target node then click Run.
            </div>''', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="section-header">INVESTIGATION NETWORK — ALL ENTITIES</div>',
                    unsafe_allow_html=True)

        risk_colors = {"critical":"#ff4444","high":"#ffaa00","medium":"#4488aa","low":"#00ff88"}
        nd = []
        for n in G.nodes():
            node = G.nodes[n]
            nd.append({
                "Entity ID":    n,
                "Description":  node.get("label", n),
                "Type":         node.get("node_type","unknown").replace("_"," ").title(),
                "Risk Score":   node.get("risk_score", 0),
                "Risk Level":   node.get("risk_level","low").upper(),
                "Connections":  G.degree(n),
            })
        df_nodes = pd.DataFrame(nd).sort_values("Risk Score", ascending=False)
        st.dataframe(df_nodes, use_container_width=True, hide_index=True)



# ── PAGE: CASE RECORDS ────────────────────────────────────────────────────────
elif page == "Case Records":
    st.markdown('<div class="section-header">📋 CASE MANAGEMENT DATABASE</div>', unsafe_allow_html=True)
    tab1,tab2,tab3 = st.tabs(["Complaints","Threat Logs","Investigation Logs"])
    with tab1:
        df_c = pd.DataFrame(fetch_all_complaints(200))
        if not df_c.empty:
            st.dataframe(df_c, use_container_width=True, hide_index=True)
            st.download_button("Export CSV", df_c.to_csv(index=False).encode(), "complaints.csv","text/csv")
        else: st.info("No complaints yet.")
    with tab2:
        df_t = pd.DataFrame(fetch_threat_logs(100))
        if not df_t.empty: st.dataframe(df_t, use_container_width=True, hide_index=True)
        else: st.info("No threat logs yet.")
    with tab3:
        df_i = pd.DataFrame(fetch_investigation_logs(100))
        if not df_i.empty: st.dataframe(df_i, use_container_width=True, hide_index=True)
        else: st.info("No investigation logs yet.")

# ── PAGE: ANALYTICS ───────────────────────────────────────────────────────────
elif page == "Analytics":
    st.markdown('<div class="section-header">📊 SYSTEM-WIDE ANALYTICS</div>', unsafe_allow_html=True)
    df_a = pd.DataFrame(fetch_all_complaints(500))
    if df_a.empty:
        st.info("No data yet.")
    else:
        col1,col2 = st.columns(2)
        with col1:
            fig = go.Figure(go.Histogram(x=df_a["threat_score"],nbinsx=20,
                marker_color="#00d4ff",opacity=0.8))
            fig.update_layout(title="Threat Score Distribution",
                paper_bgcolor="#060b18",plot_bgcolor="#0f1629",
                font=dict(color="#c8d8f0"),margin=dict(l=30,r=10,t=40,b=30))
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            uc = df_a["urgency_level"].value_counts()
            cm = {"CRITICAL":"#ff4444","HIGH":"#ffaa00","MEDIUM":"#4488aa","LOW":"#224455"}
            fig2 = go.Figure(go.Bar(x=uc.index,y=uc.values,
                marker_color=[cm.get(u,"#446688") for u in uc.index]))
            fig2.update_layout(title="Cases by Urgency",
                paper_bgcolor="#060b18",plot_bgcolor="#0f1629",
                font=dict(color="#c8d8f0"),margin=dict(l=30,r=10,t=40,b=30))
            st.plotly_chart(fig2, use_container_width=True)

        sc = df_a["source_type"].value_counts()
        fig3 = go.Figure(go.Bar(x=sc.index,y=sc.values,marker_color="#8844ff",opacity=0.85))
        fig3.update_layout(title="Cases by Source Channel",
            paper_bgcolor="#060b18",plot_bgcolor="#0f1629",
            font=dict(color="#c8d8f0"),margin=dict(l=30,r=10,t=40,b=30))
        st.plotly_chart(fig3, use_container_width=True)

# ── PAGE: SYSTEM INFO ─────────────────────────────────────────────────────────
elif page == "System Info":
    st.markdown('<div class="section-header">ℹ️ SYSTEM DOCUMENTATION</div>', unsafe_allow_html=True)

    # Architecture Overview
    st.markdown("""
    <div style='background:#0d1830;border:1px solid #1e3058;border-radius:10px;padding:22px 26px;margin-bottom:18px;'>
        <div style='font-family:Share Tech Mono,monospace;color:#00d4ff;font-size:13px;
                    letter-spacing:2px;margin-bottom:16px;border-bottom:1px solid #1e3058;padding-bottom:10px;'>
            ARCHITECTURE OVERVIEW
        </div>
        <div style='font-size:13px;color:#88aacc;line-height:2.0;'>
            CyberShield AI is a multi-layered cyber threat intelligence platform that combines
            classical machine learning, graph-based investigation algorithms, and real-time
            threat intelligence APIs into a unified analysis pipeline.
        </div>
    </div>""", unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("""
        <div style='background:#0d1830;border:1px solid #1e3058;border-radius:10px;
                    padding:20px 24px;margin-bottom:16px;'>
            <div style='font-family:Share Tech Mono,monospace;color:#00ff88;font-size:11px;
                        letter-spacing:2px;margin-bottom:14px;'>ML PIPELINE</div>
            <div style='font-size:12px;color:#88aacc;line-height:2.2;'>
                <span style='color:#446688;'>VECTORIZER</span><br>
                TF-IDF · bigrams · 8 000 features · sublinear TF scaling<br><br>
                <span style='color:#446688;'>CLASSIFIER</span><br>
                RandomForest + LogisticRegression soft-vote ensemble<br>
                7-class output · threat score fusion<br><br>
                <span style='color:#446688;'>EVALUATION</span><br>
                5-fold cross-validation · confusion matrix · per-class F1
            </div>
        </div>

        <div style='background:#0d1830;border:1px solid #1e3058;border-radius:10px;
                    padding:20px 24px;margin-bottom:16px;'>
            <div style='font-family:Share Tech Mono,monospace;color:#00ff88;font-size:11px;
                        letter-spacing:2px;margin-bottom:14px;'>NLP THREAT LEXICON</div>
            <div style='font-size:12px;color:#88aacc;line-height:2.2;'>
                6 semantic threat categories with weighted scoring:<br><br>
                · Financial Coercion<br>
                · Urgency Pressure Tactics<br>
                · Credential Theft Patterns<br>
                · Explicit Threat Language<br>
                · Identity Impersonation<br>
                · Privacy Violation Indicators<br><br>
                <span style='color:#446688;'>+</span> Named entity extraction (URLs, IPs, emails, amounts)
            </div>
        </div>""", unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div style='background:#0d1830;border:1px solid #1e3058;border-radius:10px;
                    padding:20px 24px;margin-bottom:16px;'>
            <div style='font-family:Share Tech Mono,monospace;color:#00ff88;font-size:11px;
                        letter-spacing:2px;margin-bottom:14px;'>INVESTIGATION GRAPH ALGORITHMS</div>
            <div style='font-size:12px;color:#88aacc;line-height:2.4;'>
                <span style='color:#00d4ff;font-family:Share Tech Mono,monospace;'>BFS</span>
                &nbsp;— Breadth-First Search · O(V+E)<br>
                <span style='color:#446688;font-size:11px;'>Minimum relay chain · shortest hop path</span><br><br>
                <span style='color:#ff8800;font-family:Share Tech Mono,monospace;'>DFS</span>
                &nbsp;— Depth-First Search · O(V+E)<br>
                <span style='color:#446688;font-size:11px;'>Deep chain traversal · nested network discovery</span><br><br>
                <span style='color:#00ff88;font-family:Share Tech Mono,monospace;'>A* </span>
                &nbsp;— Heuristic Search · O(E log V)<br>
                <span style='color:#446688;font-size:11px;'>Risk-weighted optimal path · GPS-style routing</span>
            </div>
        </div>

        <div style='background:#0d1830;border:1px solid #1e3058;border-radius:10px;
                    padding:20px 24px;margin-bottom:16px;'>
            <div style='font-family:Share Tech Mono,monospace;color:#00ff88;font-size:11px;
                        letter-spacing:2px;margin-bottom:14px;'>DATABASE SCHEMA</div>
            <div style='font-size:12px;color:#88aacc;line-height:2.4;'>
                <span style='color:#00d4ff;font-family:Share Tech Mono,monospace;'>complaints</span>
                &nbsp;— Case records with ML predictions<br>
                <span style='color:#00d4ff;font-family:Share Tech Mono,monospace;'>threat_logs</span>
                &nbsp;— Real-time threat event log<br>
                <span style='color:#00d4ff;font-family:Share Tech Mono,monospace;'>investigation_logs</span>
                &nbsp;— Graph traversal history<br>
                <span style='color:#00d4ff;font-family:Share Tech Mono,monospace;'>network_nodes</span>
                &nbsp;— Entity relationship store<br><br>
                <span style='color:#446688;'>Engine: SQLite 3 · embedded · zero-config</span>
            </div>
        </div>""", unsafe_allow_html=True)

    # Tech Stack
    st.markdown("""
    <div style='background:#0d1830;border:1px solid #1e3058;border-radius:10px;padding:20px 26px;'>
        <div style='font-family:Share Tech Mono,monospace;color:#00ff88;font-size:11px;
                    letter-spacing:2px;margin-bottom:14px;'>TECHNOLOGY STACK</div>
        <div style='display:grid;grid-template-columns:repeat(4,1fr);gap:12px;'>
            <div style='background:#060b18;border:1px solid #1e3058;border-radius:6px;
                        padding:12px;text-align:center;font-size:11px;'>
                <div style='color:#00d4ff;font-family:Share Tech Mono,monospace;font-size:13px;'>Python</div>
                <div style='color:#446688;margin-top:4px;'>3.10+</div>
            </div>
            <div style='background:#060b18;border:1px solid #1e3058;border-radius:6px;
                        padding:12px;text-align:center;font-size:11px;'>
                <div style='color:#00d4ff;font-family:Share Tech Mono,monospace;font-size:13px;'>Streamlit</div>
                <div style='color:#446688;margin-top:4px;'>UI Framework</div>
            </div>
            <div style='background:#060b18;border:1px solid #1e3058;border-radius:6px;
                        padding:12px;text-align:center;font-size:11px;'>
                <div style='color:#00d4ff;font-family:Share Tech Mono,monospace;font-size:13px;'>Scikit-learn</div>
                <div style='color:#446688;margin-top:4px;'>ML Engine</div>
            </div>
            <div style='background:#060b18;border:1px solid #1e3058;border-radius:6px;
                        padding:12px;text-align:center;font-size:11px;'>
                <div style='color:#00d4ff;font-family:Share Tech Mono,monospace;font-size:13px;'>NetworkX</div>
                <div style='color:#446688;margin-top:4px;'>Graph Engine</div>
            </div>
            <div style='background:#060b18;border:1px solid #1e3058;border-radius:6px;
                        padding:12px;text-align:center;font-size:11px;'>
                <div style='color:#00d4ff;font-family:Share Tech Mono,monospace;font-size:13px;'>Plotly</div>
                <div style='color:#446688;margin-top:4px;'>Interactive Charts</div>
            </div>
            <div style='background:#060b18;border:1px solid #1e3058;border-radius:6px;
                        padding:12px;text-align:center;font-size:11px;'>
                <div style='color:#00d4ff;font-family:Share Tech Mono,monospace;font-size:13px;'>Matplotlib</div>
                <div style='color:#446688;margin-top:4px;'>Graph Render</div>
            </div>
            <div style='background:#060b18;border:1px solid #1e3058;border-radius:6px;
                        padding:12px;text-align:center;font-size:11px;'>
                <div style='color:#00d4ff;font-family:Share Tech Mono,monospace;font-size:13px;'>SQLite</div>
                <div style='color:#446688;margin-top:4px;'>Database</div>
            </div>
            <div style='background:#060b18;border:1px solid #1e3058;border-radius:6px;
                        padding:12px;text-align:center;font-size:11px;'>
                <div style='color:#00d4ff;font-family:Share Tech Mono,monospace;font-size:13px;'>VirusTotal</div>
                <div style='color:#446688;margin-top:4px;'>Threat Intel API</div>
            </div>
        </div>
    </div>""", unsafe_allow_html=True)
