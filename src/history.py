"""Local SQLite history for PhishTrace investigations."""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parents[1] / "reports" / "phishtrace_history.db"

def save_investigation(report: dict[str, Any]) -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    assessment = report.get("overall_assessment", {})
    source = report.get("email_analysis", {}).get("file", "")
    if not source:
        source = report.get("file", report.get("source_file", "Uploaded email"))
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigated_at TEXT NOT NULL,
                source_file TEXT,
                verdict TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                report_json TEXT NOT NULL
            )
        """)
        conn.execute("""
            INSERT INTO investigations
            (investigated_at, source_file, verdict, risk_score, risk_level, report_json)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            str(source),
            str(assessment.get("verdict", "Unknown")),
            int(assessment.get("risk_score", 0) or 0),
            str(assessment.get("risk_level", "Unknown")),
            json.dumps(report, ensure_ascii=False, default=str),
        ))

def get_recent_investigations(limit: int = 50) -> list[dict[str, Any]]:
    if not DB_PATH.exists():
        return []
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT id, investigated_at, source_file, verdict, risk_score, risk_level
            FROM investigations ORDER BY id DESC LIMIT ?
        """, (max(1, min(int(limit), 500)),)).fetchall()
    return [dict(row) for row in rows]


def get_investigation_by_id(investigation_id: int) -> dict[str, Any] | None:
    """Return a saved investigation report by its SQLite history ID."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, investigated_at, source_file, verdict, "
            "risk_score, risk_level, report_json "
            "FROM investigations WHERE id = ?",
            (int(investigation_id),),
        ).fetchone()

    if row is None:
        return None

    result = dict(row)
    try:
        report = json.loads(result["report_json"])
    except (TypeError, json.JSONDecodeError):
        return None

    if not isinstance(report, dict):
        return None

    # Retain the database's original filename in the displayed report.
    report["source_file"] = result.get("source_file") or report.get("source_file")
    result["report"] = report
    return result
