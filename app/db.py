"""SQLite storage. One row per artifact, deduped by fingerprint.

SECURITY RULE: secret material (seeds, private keys, API secrets) is
never stored in full - only a masked preview + sha256 fingerprint.
Addresses are public data and are stored in full.
"""
from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone

from .parser import fingerprint

DB_PATH = os.environ.get("CRYPTO_FINDINGS_DB",
                         os.path.join(os.path.dirname(__file__), "..", "findings.db"))

SECRET_TYPES = {"seed_phrase", "private_key", "api_key"}


def mask_value(artifact_type: str, value: str) -> str:
    if artifact_type == "seed_phrase":
        words = value.split()
        return f"{words[0]} {words[1]} ... ({len(words)} words)"
    if artifact_type in SECRET_TYPES:
        if len(value) <= 10:
            return value[:2] + "..."
        return f"{value[:6]}...{value[-4:]}"
    return value


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with conn() as c:
        c.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            chain TEXT NOT NULL DEFAULT '',
            value TEXT NOT NULL,
            masked_value TEXT NOT NULL,
            fingerprint TEXT NOT NULL UNIQUE,
            source TEXT NOT NULL,
            target TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT 'medium',
            label TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'new',
            balance_json TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )""")


def upsert(artifact, source: str, target: str = "", note: str = "") -> bool:
    """Insert if new fingerprint; bump last_seen otherwise. True if new."""
    fp = fingerprint(artifact.type, artifact.value)
    masked = mask_value(artifact.type, artifact.value)
    stored = masked if artifact.type in SECRET_TYPES else artifact.value
    ts = now_iso()
    with conn() as c:
        cur = c.execute(
            "INSERT OR IGNORE INTO findings (type, chain, value, masked_value,"
            " fingerprint, source, target, severity, label, note, first_seen,"
            " last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (artifact.type, artifact.chain, stored, masked, fp, source,
             target, artifact.severity, artifact.label, note, ts, ts))
        if cur.rowcount == 0:
            c.execute("UPDATE findings SET last_seen=? WHERE fingerprint=?",
                      (ts, fp))
            return False
        return True


def balance_of(row: dict) -> dict:
    import json as _json
    if row.get("balance_json"):
        try:
            return _json.loads(row["balance_json"])
        except Exception:
            return {}
    return {}


def total_exposed_usd(rows=None) -> float:
    if rows is None:
        with conn() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT balance_json FROM findings WHERE type='address'")]
    total = 0.0
    for r in rows:
        b = balance_of(r)
        if b.get("ok") and b.get("usd"):
            total += float(b["usd"])
    return round(total, 2)


def list_findings(search: str = "", chain: str = "", type_: str = "",
                  source: str = "", status: str = "", limit: int = 500,
                  sort: str = ""):
    q = "SELECT * FROM findings WHERE 1=1"
    args: list = []
    if search:
        q += " AND (masked_value LIKE ? OR target LIKE ? OR label LIKE ?)"
        args += [f"%{search}%"] * 3
    for col, val in (("chain", chain), ("type", type_), ("source", source),
                     ("status", status)):
        if val:
            # source stored like 'paste' or 'recon:<runid>'; prefix match
            if col == "source":
                q += " AND source LIKE ?"
                args.append(val + "%")
            else:
                q += f" AND {col}=?"
                args.append(val)
    if sort == "usd":
        q += " LIMIT ?"
        args.append(100000)
        with conn() as c:
            rows = [dict(r) for r in c.execute(q, args)]
        rows.sort(key=lambda r: float(balance_of(r).get("usd") or 0),
                  reverse=True)
        return rows[:limit]
    q += " ORDER BY first_seen DESC LIMIT ?"
    args.append(limit)
    with conn() as c:
        return [dict(r) for r in c.execute(q, args)]


def unenriched_addresses():
    with conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM findings WHERE type='address'"
            " AND (balance_json IS NULL OR balance_json='')")]


def richest(limit: int = 10):
    with conn() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM findings WHERE type='address'"
            " AND balance_json IS NOT NULL")]
    rows = [r for r in rows if balance_of(r).get("ok")]
    rows.sort(key=lambda r: float(balance_of(r).get("usd") or 0),
              reverse=True)
    return rows[:limit]


def get(finding_id: int):
    with conn() as c:
        r = c.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        return dict(r) if r else None


def set_status(finding_id: int, status: str) -> bool:
    if status not in ("new", "reviewed", "reported", "ignored"):
        return False
    with conn() as c:
        cur = c.execute("UPDATE findings SET status=? WHERE id=?",
                        (status, finding_id))
        return cur.rowcount > 0


def set_balance(finding_id: int, balance_json: str) -> None:
    with conn() as c:
        c.execute("UPDATE findings SET balance_json=? WHERE id=?",
                  (balance_json, finding_id))


def stats() -> dict:
    with conn() as c:
        total = c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        by = {}
        for name, col in (("by_chain", "chain"), ("by_type", "type"),
                          ("by_severity", "severity"), ("by_status", "status"),
                          ("by_source", "source")):
            by[name] = {r[0] or "(none)": r[1] for r in c.execute(
                f"SELECT {col}, COUNT(*) FROM findings GROUP BY {col}")}
        return {"total": total, "total_exposed_usd": total_exposed_usd(),
                "enriched_addresses": len(richest(100000)), **by}
