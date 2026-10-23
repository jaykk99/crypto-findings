import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("CRYPTO_FINDINGS_DB", "/tmp/cf-test.db")

from app import chain_ingest, db, url_ingest
from app import validators as _v

db.init_db()

BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
ETH = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
CP1 = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
CP2 = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
FRESH = _v.b58check_encode(b"\x00" + bytes(range(20)))  # unique to URL test

PAGE = f"""<html><body>
<p>Tips welcome: {FRESH}</p>
<a href="/about">about</a>
<a href="https://etherscan.io/address/{ETH}">our eth</a>
<script src="https://cdn.example.com/coinhive.min.js"></script>
</body></html>"""

ABOUT = f"<html><body>eth treasury {ETH}</body></html>"


def test_url_ingest_mocked(monkeypatch):
    pages = {"https://site.example/": PAGE,
             "https://site.example/about": ABOUT}
    monkeypatch.setattr(url_ingest, "fetch_text",
                        lambda url, timeout=20: pages[url])
    out = url_ingest.ingest_url("https://site.example/")
    assert out["ok"] and out["pages_count"] == 2
    assert out["artifacts_found"] >= 3  # BTC, ETH (page+link), miner
    rows = db.list_findings(source="url")
    assert any(r["masked_value"] == FRESH for r in rows)
    assert any(r["type"] == "miner_indicator" for r in db.list_findings())
    out2 = url_ingest.ingest_url("https://site.example/")
    assert out2["imported_new"] == 0  # dedupe across ingests


def test_explorer_url_parse():
    assert chain_ingest.parse_input(
        f"https://blockstream.info/address/{BTC}") == ("address", "BTC", BTC)
    assert chain_ingest.parse_input(
        f"https://etherscan.io/address/{ETH}") == ("address", "ETH", ETH)
    assert chain_ingest.parse_input(BTC) == ("address", "BTC", BTC)
    tx = "ab" * 32
    assert chain_ingest.parse_input(
        f"https://blockstream.info/tx/{tx}") == ("tx", "BTC", tx)
    assert chain_ingest.parse_input("hello world") is None


def test_chain_pull_counterparties(monkeypatch):
    monkeypatch.setitem(chain_ingest._PULLERS, "BTC",
                        lambda addr: ({CP1, CP2}, 3))
    out = chain_ingest.ingest_chain(BTC)
    assert out["ok"] and out["input_kind"] == "address"
    assert out["counterparties"] == 2 and out["txs_seen"] == 3
    assert out["findings_out"] == 3  # seed + 2 counterparties
    # dedupe keeps the FIRST source a value was seen under, so check the
    # full table for the set, and the blockchain slice for targeting
    vals = {r["masked_value"] for r in db.list_findings()}
    assert {BTC, CP1, CP2} <= vals
    rows = db.list_findings(source="blockchain")
    assert rows and all(r["target"] == BTC for r in rows)
    out2 = chain_ingest.ingest_chain(BTC)
    assert out2["imported_new"] == 0


def test_chain_tx_hash(monkeypatch):
    monkeypatch.setattr(chain_ingest, "_tx_parties",
                        lambda chain, h: ({CP1, CP2}, 1.5, "BTC"))
    tx = "cd" * 32
    out = chain_ingest.ingest_chain(f"https://blockstream.info/tx/{tx}")
    assert out["ok"] and out["input_kind"] == "tx"
    assert out["findings_out"] == 2 and out["tx_value"] == 1.5
