"""Collecte : stocke les findings de chaque scan dans une base SQLite.

C'est le volet « collecter » de l'énoncé : garder un historique multi-apps,
suivre un même défaut dans le temps (via son empreinte), et permettre des
statistiques (failles les plus fréquentes, par plateforme).
"""
from __future__ import annotations
import json
import sqlite3
import time
from pathlib import Path

DEFAULT_DB = Path.home() / ".vibehunt" / "findings.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT, platform TEXT, uses_supabase INTEGER,
    scanned_at REAL, n_findings INTEGER
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER, fingerprint TEXT, detector TEXT, title TEXT,
    severity TEXT, category TEXT, file TEXT, line INTEGER,
    score INTEGER, confidence TEXT, exposure TEXT, data TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_fp ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_sev ON findings(severity);
"""


def _conn(db_path):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.executescript(SCHEMA)
    return conn


def store(result: dict, db_path=DEFAULT_DB) -> int:
    conn = _conn(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO scans(target, platform, uses_supabase, scanned_at, n_findings) "
            "VALUES(?,?,?,?,?)",
            (result["target"], result["platform"], int(result["uses_supabase"]),
             time.time(), len(result["findings"])),
        )
        scan_id = cur.lastrowid
        for f in result["findings"]:
            conn.execute(
                "INSERT INTO findings(scan_id, fingerprint, detector, title, severity, "
                "category, file, line, score, confidence, exposure, data) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (scan_id, f["fingerprint"], f["detector"], f["title"], f["severity"],
                 f["category"], f["file"], f["line"], f.get("score", 0),
                 f["confidence"], f["exposure"], json.dumps(f, ensure_ascii=False)),
            )
        conn.commit()
        return scan_id
    finally:
        conn.close()


def stats(db_path=DEFAULT_DB) -> dict:
    conn = _conn(db_path)
    try:
        n_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        by_sev = dict(conn.execute(
            "SELECT severity, COUNT(*) FROM findings GROUP BY severity").fetchall())
        top = conn.execute(
            "SELECT title, COUNT(*) c FROM findings GROUP BY title ORDER BY c DESC LIMIT 10"
        ).fetchall()
        by_platform = dict(conn.execute(
            "SELECT platform, COUNT(*) FROM scans GROUP BY platform").fetchall())
        return {"scans": n_scans, "par_severite": by_sev,
                "top_failles": top, "par_plateforme": by_platform}
    finally:
        conn.close()


def comparison(db_path=DEFAULT_DB) -> dict:
    """Vue comparative de la dernière collecte de chaque cible : sert à comparer
    plusieurs apps vibe codées entre elles (cœur du volet analyse du mémoire)."""
    conn = _conn(db_path)
    try:
        # dernier scan par cible
        rows = conn.execute("""
            SELECT s.target, s.platform, s.scanned_at, s.id
            FROM scans s
            JOIN (SELECT target, MAX(scanned_at) mx FROM scans GROUP BY target) last
              ON s.target = last.target AND s.scanned_at = last.mx
            ORDER BY s.scanned_at DESC
        """).fetchall()
        apps = []
        for target, platform, ts, scan_id in rows:
            sev = dict(conn.execute(
                "SELECT severity, COUNT(*) FROM findings WHERE scan_id=? GROUP BY severity",
                (scan_id,)).fetchall())
            apps.append({"target": target, "platform": platform,
                         "critique": sev.get("critique", 0), "elevee": sev.get("elevee", 0),
                         "moyenne": sev.get("moyenne", 0), "faible": sev.get("faible", 0),
                         "total": sum(sev.values())})
        # failles les plus répandues à travers les apps (dédupliquées par cible)
        spread = conn.execute("""
            SELECT title, COUNT(DISTINCT scan_id) n FROM findings
            GROUP BY title ORDER BY n DESC LIMIT 12
        """).fetchall()
        return {"apps": apps, "failles_repandues": spread}
    finally:
        conn.close()
