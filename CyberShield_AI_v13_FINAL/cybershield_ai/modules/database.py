"""
CyberShield AI — Database Layer
SQLite-backed storage for complaints, investigation records, and threat logs.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager
from typing import Optional

DB_PATH = "data/cybershield.db"


@contextmanager
def _conn():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db():
    """Create all tables on first run."""
    with _conn() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS complaints (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            submitted_at TEXT NOT NULL,
            reporter    TEXT,
            message     TEXT NOT NULL,
            label       TEXT,
            confidence  REAL,
            threat_tier TEXT,
            urgency_score REAL,
            threat_score  REAL,
            status      TEXT DEFAULT 'open',
            notes       TEXT
        );

        CREATE TABLE IF NOT EXISTS investigation_records (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at   TEXT NOT NULL,
            case_ref     TEXT UNIQUE NOT NULL,
            algorithm    TEXT,
            source_node  TEXT,
            target_node  TEXT,
            result_json  TEXT,
            analyst      TEXT DEFAULT 'System'
        );

        CREATE TABLE IF NOT EXISTS threat_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            logged_at   TEXT NOT NULL,
            event_type  TEXT,
            severity    TEXT,
            description TEXT,
            metadata    TEXT
        );

        CREATE TABLE IF NOT EXISTS model_runs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ran_at      TEXT NOT NULL,
            model_name  TEXT,
            accuracy    REAL,
            f1_macro    REAL,
            cv_mean     REAL,
            cv_std      REAL,
            train_size  INTEGER,
            test_size   INTEGER
        );
        """)


# ─── Complaints ──────────────────────────────────────────────────────────────

def insert_complaint(
    message: str,
    label: str,
    confidence: float,
    threat_tier: str,
    urgency_score: float = 0.0,
    threat_score: float = 0.0,
    reporter: str = "Anonymous",
    notes: str = "",
) -> int:
    with _conn() as con:
        cur = con.execute(
            """INSERT INTO complaints
               (submitted_at, reporter, message, label, confidence,
                threat_tier, urgency_score, threat_score, notes)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (datetime.now().isoformat(), reporter, message, label,
             confidence, threat_tier, urgency_score, threat_score, notes),
        )
        return cur.lastrowid


def get_complaints(limit: int = 200, status: Optional[str] = None) -> list[dict]:
    with _conn() as con:
        if status:
            rows = con.execute(
                "SELECT * FROM complaints WHERE status=? ORDER BY id DESC LIMIT ?",
                (status, limit)
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM complaints ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]


def complaint_stats() -> dict:
    with _conn() as con:
        total = con.execute("SELECT COUNT(*) FROM complaints").fetchone()[0]
        by_label = con.execute(
            "SELECT label, COUNT(*) as cnt FROM complaints GROUP BY label"
        ).fetchall()
        by_tier = con.execute(
            "SELECT threat_tier, COUNT(*) as cnt FROM complaints GROUP BY threat_tier"
        ).fetchall()
        avg_conf = con.execute(
            "SELECT AVG(confidence) FROM complaints"
        ).fetchone()[0] or 0
    return {
        "total": total,
        "by_label": {r["label"]: r["cnt"] for r in by_label},
        "by_tier": {r["threat_tier"]: r["cnt"] for r in by_tier},
        "avg_confidence": round(avg_conf, 4),
    }


# ─── Investigation Records ───────────────────────────────────────────────────

def save_investigation(
    algorithm: str,
    source_node: str,
    result: dict,
    target_node: str = "",
    analyst: str = "System",
) -> str:
    case_ref = f"CASE-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    with _conn() as con:
        con.execute(
            """INSERT INTO investigation_records
               (created_at, case_ref, algorithm, source_node, target_node,
                result_json, analyst)
               VALUES (?,?,?,?,?,?,?)""",
            (datetime.now().isoformat(), case_ref, algorithm, source_node,
             target_node, json.dumps(result, default=str), analyst),
        )
    return case_ref


def get_investigations(limit: int = 50) -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM investigation_records ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# ─── Threat Logs ─────────────────────────────────────────────────────────────

def log_threat(event_type: str, severity: str, description: str, metadata: dict = None):
    with _conn() as con:
        con.execute(
            """INSERT INTO threat_logs (logged_at, event_type, severity, description, metadata)
               VALUES (?,?,?,?,?)""",
            (datetime.now().isoformat(), event_type, severity, description,
             json.dumps(metadata or {})),
        )


def get_threat_logs(limit: int = 100) -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM threat_logs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# ─── Model Runs ──────────────────────────────────────────────────────────────

def save_model_run(model_name: str, metrics: dict):
    with _conn() as con:
        con.execute(
            """INSERT INTO model_runs
               (ran_at, model_name, accuracy, f1_macro, cv_mean, cv_std,
                train_size, test_size)
               VALUES (?,?,?,?,?,?,?,?)""",
            (datetime.now().isoformat(), model_name,
             metrics.get("accuracy"), metrics.get("f1_macro"),
             metrics.get("cv_mean"), metrics.get("cv_std"),
             metrics.get("train_size"), metrics.get("test_size")),
        )


def get_model_history(limit: int = 20) -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM model_runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
