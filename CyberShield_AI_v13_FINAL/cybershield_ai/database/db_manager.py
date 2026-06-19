"""
CyberShield AI – Database Manager
SQLite layer: complaints, investigation logs, threat logs, network nodes.
"""
import sqlite3, os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybershield.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS complaints (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            submitted_at  TEXT    NOT NULL,
            text_content  TEXT    NOT NULL,
            predicted_label TEXT  NOT NULL,
            confidence    REAL    NOT NULL,
            threat_score  INTEGER NOT NULL,
            urgency_level TEXT    NOT NULL,
            source_type   TEXT,
            status        TEXT    DEFAULT 'OPEN'
        );
        CREATE TABLE IF NOT EXISTS investigation_logs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            complaint_id    INTEGER,
            algorithm_used  TEXT NOT NULL,
            path_found      TEXT,
            nodes_explored  INTEGER,
            timestamp       TEXT NOT NULL,
            result_summary  TEXT,
            FOREIGN KEY (complaint_id) REFERENCES complaints(id)
        );
        CREATE TABLE IF NOT EXISTS threat_logs (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp        TEXT NOT NULL,
            threat_type      TEXT NOT NULL,
            severity         TEXT NOT NULL,
            description      TEXT,
            source_ip        TEXT,
            flagged_keywords TEXT
        );
        CREATE TABLE IF NOT EXISTS network_nodes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id    TEXT UNIQUE NOT NULL,
            node_type  TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            metadata   TEXT
        );
    """)
    conn.commit(); conn.close()

def insert_complaint(text, label, confidence, threat_score, urgency, source):
    conn = get_connection(); cur = conn.cursor()
    # Auto-assign status based on threat level
    if label == "normal":
        status = "CLOSED"
    elif urgency == "CRITICAL":
        status = "UNDER INVESTIGATION"
    elif urgency == "HIGH":
        status = "REVIEWING"
    else:
        status = "OPEN"
    cur.execute("""INSERT INTO complaints
        (submitted_at,text_content,predicted_label,confidence,threat_score,urgency_level,source_type,status)
        VALUES(?,?,?,?,?,?,?,?)""",
        (datetime.now().isoformat(), text, label, confidence, threat_score, urgency, source, status))
    cid = cur.lastrowid; conn.commit(); conn.close(); return cid

def log_investigation(complaint_id, algorithm, path, nodes_explored, summary):
    conn = get_connection(); cur = conn.cursor()
    cur.execute("""INSERT INTO investigation_logs
        (complaint_id,algorithm_used,path_found,nodes_explored,timestamp,result_summary)
        VALUES(?,?,?,?,?,?)""",
        (complaint_id, algorithm, str(path), nodes_explored,
         datetime.now().isoformat(), summary))
    conn.commit(); conn.close()

def log_threat(threat_type, severity, description, source_ip="N/A", keywords=""):
    conn = get_connection(); cur = conn.cursor()
    cur.execute("""INSERT INTO threat_logs
        (timestamp,threat_type,severity,description,source_ip,flagged_keywords)
        VALUES(?,?,?,?,?,?)""",
        (datetime.now().isoformat(), threat_type, severity, description, source_ip, keywords))
    conn.commit(); conn.close()

def fetch_all_complaints(limit=100):
    conn = get_connection(); cur = conn.cursor()
    cur.execute("SELECT * FROM complaints ORDER BY submitted_at DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]; conn.close(); return rows

def fetch_threat_logs(limit=50):
    conn = get_connection(); cur = conn.cursor()
    cur.execute("SELECT * FROM threat_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]; conn.close(); return rows

def fetch_investigation_logs(limit=50):
    conn = get_connection(); cur = conn.cursor()
    cur.execute("SELECT * FROM investigation_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]; conn.close(); return rows

def get_stats():
    conn = get_connection(); cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as total FROM complaints")
    total = cur.fetchone()["total"]
    cur.execute("SELECT predicted_label, COUNT(*) as cnt FROM complaints GROUP BY predicted_label")
    by_label = {r["predicted_label"]: r["cnt"] for r in cur.fetchall()}
    cur.execute("SELECT AVG(threat_score) as avg FROM complaints")
    avg_score = round((cur.fetchone()["avg"] or 0), 1)
    cur.execute("SELECT COUNT(*) as cnt FROM complaints WHERE urgency_level='CRITICAL'")
    critical = cur.fetchone()["cnt"]
    conn.close()
    return {"total": total, "by_label": by_label,
            "avg_threat_score": avg_score, "critical_count": critical}
