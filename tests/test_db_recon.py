import importlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ["CRYPTO_FINDINGS_DB"] = "/tmp/cf-test.db"
if os.path.exists("/tmp/cf-test.db"):
    os.remove("/tmp/cf-test.db")

from app import db, recon
from app.parser import extract, Artifact

db.init_db()

SEED = ("abandon " * 11 + "about").strip()
BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


def test_masking_rules():
    assert db.mask_value("seed_phrase", SEED).startswith("abandon abandon")
    assert "(12 words)" in db.mask_value("seed_phrase", SEED)
    k = "0123456789abcdef" * 4
    assert db.mask_value("private_key", k) == "012345...cdef"
    assert db.mask_value("address", BTC) == BTC  # public, stored full


def test_dedupe_by_fingerprint():
    a = extract("pay " + BTC)[0]
    assert db.upsert(a, source="paste") is True
    assert db.upsert(a, source="recon:xyz") is False  # same fingerprint
    rows = db.list_findings()
    assert len([r for r in rows if r["type"] == "address"
                and r["masked_value"] == BTC]) == 1


def test_secret_never_stored_full():
    a = [x for x in extract("mnemonic: " + SEED) if x.type == "seed_phrase"][0]
    db.upsert(a, source="paste")
    row = [r for r in db.list_findings() if r["type"] == "seed_phrase"][0]
    assert row["value"] == row["masked_value"]
    assert "ability" not in row["value"] and SEED not in json.dumps(row)
    assert len(row["fingerprint"]) == 64


def _fake_run():
    return {
        "targets": [{"id": "t1", "normalized": "example-shop.com"}],
        "findings": [
            {"plugin": "cp_btc_legacy", "category": "crypto", "key": "btc",
             "value": f"BTC wallet {BTC} found", "source": "cp pack",
             "target_id": "t1", "evidence": {"severity": "high"}},
            {"plugin": "dns", "category": "dns", "key": "a",
             "value": "1.2.3.4", "source": "DNS A", "target_id": "t1",
             "evidence": {"severity": "low"}},
            {"plugin": "cp_miner_coinhive", "category": "crypto",
             "key": "miner", "value": "coinhive.min.js loaded",
             "source": "cp pack", "target_id": "t1",
             "evidence": {"severity": "high"}},
        ],
    }


def test_recon_import_filters_and_dedupes():
    res = recon.import_run(_fake_run(), "run123")
    assert res["imported_new"] >= 1
    rows = db.list_findings(source="recon")
    assert rows and all(r["source"] == "recon:run123" for r in rows)
    assert any(r["target"] == "example-shop.com" for r in rows)
    res2 = recon.import_run(_fake_run(), "run123")  # pull twice
    assert res2["imported_new"] == 0 and res2["duplicates"] >= 1


def test_recon_pull_mocked(monkeypatch):
    monkeypatch.setattr(recon, "fetch_runs",
                        lambda code, limit=5: [{"id": "run123"}])
    monkeypatch.setattr(recon, "fetch_run",
                        lambda code, rid: _fake_run())
    out = recon.pull(code="testcode", limit=1)
    assert out["ok"] and out["runs"][0]["run_id"] == "run123"
    out2 = recon.pull(code="testcode", limit=1)
    assert out2["imported_new"] == 0
