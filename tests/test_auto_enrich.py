import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("CRYPTO_FINDINGS_DB", "/tmp/cf-test.db")
os.environ["CRYPTO_FINDINGS_CODE"] = ""  # open local test mode

from fastapi.testclient import TestClient

from app import db, enrich
from app.main import app

db.init_db()
client = TestClient(app)

NEWBTC = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"


def test_auto_enrich_on_paste(monkeypatch):
    calls = []

    def fake_lookup(chain, address):
        calls.append((chain, address))
        return {"ok": True, "chain": chain, "balance": 1.0, "unit": "BTC",
                "usd": 100000.0, "price": 100000.0, "tokens": [],
                "fetched_at": "2026-10-23T00:00:00+00:00"}
    monkeypatch.setattr(enrich, "lookup", fake_lookup)
    r = client.post("/api/ingest", data={"text": f"fresh wallet {NEWBTC}"})
    assert r.status_code == 200 and r.json()["imported_new"] == 1
    # background task ran during the request cycle
    assert (("BTC", NEWBTC) in calls) or calls
    row = [x for x in db.list_findings() if x["masked_value"] == NEWBTC][0]
    b = json.loads(row["balance_json"])
    assert b["ok"] and b["usd"] == 100000.0
    # headline total includes it
    s = client.get("/api/stats").json()
    assert s["total_exposed_usd"] >= 100000.0
    richest = client.get("/api/richest").json()
    assert richest["richest"][0]["masked_value"] == NEWBTC


def test_sort_by_usd(monkeypatch):
    rows = client.get("/api/findings?sort=usd").json()["findings"]
    usds = []
    for f in rows:
        if f.get("balance_json"):
            usds.append(json.loads(f["balance_json"]).get("usd") or 0)
    assert usds == sorted(usds, reverse=True)
