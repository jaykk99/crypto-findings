import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import enrich

PRICES = {"bitcoin": 100000.0, "ethereum": 3000.0, "solana": 150.0,
          "litecoin": 100.0, "dogecoin": 0.25, "tether": 1.0,
          "usd-coin": 1.0, "dai": 1.0, "wrapped-bitcoin": 100000.0,
          "chainlink": 15.0, "uniswap": 10.0, "weth": 3000.0}

BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
ETH = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
SOL = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"


def _mock(monkeypatch, get=None, post=None):
    monkeypatch.setattr(enrich, "prices", lambda: dict(PRICES))
    if get:
        monkeypatch.setattr(enrich, "_get", get)
    if post:
        monkeypatch.setattr(enrich, "_post", post)


def test_btc_usd_math(monkeypatch):
    _mock(monkeypatch, get=lambda url: {"chain_stats": {
        "funded_txo_sum": 250_000_000, "spent_txo_sum": 50_000_000,
        "tx_count": 7}})
    r = enrich.lookup("BTC", BTC)
    assert r["ok"] and r["balance"] == 2.0 and r["usd"] == 200000.0
    assert r["fetched_at"] and r["price"] == 100000.0


def test_ltc_and_doge(monkeypatch):
    _mock(monkeypatch, get=lambda url: {"chain_stats": {
        "funded_txo_sum": 100_000_000, "spent_txo_sum": 0,
        "tx_count": 1}} if "litecoinspace" in url else {"balance": "400.0"})
    r = enrich.lookup("LTC", "L" + "a" * 30)
    assert r["ok"] and r["balance"] == 1.0 and r["usd"] == 100.0
    r = enrich.lookup("DOGE", "D" + "a" * 30)
    assert r["ok"] and r["balance"] == 400.0 and r["usd"] == 100.0


def test_eth_with_tokens(monkeypatch):
    def post(url, payload):
        if payload["method"] == "eth_getBalance":
            return {"result": hex(2 * 10 ** 18)}
        if payload["method"] == "eth_call":
            to = payload["params"][0]["to"]
            if to.lower().startswith("0xdac17f"):  # USDT, 6 dp
                return {"result": hex(500 * 10 ** 6)}
            return {"result": "0x0"}
        raise AssertionError(payload)
    _mock(monkeypatch, post=post)
    r = enrich.lookup("ETH", ETH)
    assert r["ok"] and r["balance"] == 2.0
    assert r["native_usd"] == 6000.0
    usdt = [t for t in r["tokens"] if t["symbol"] == "USDT"]
    assert usdt and usdt[0]["balance"] == 500.0 and usdt[0]["usd"] == 500.0
    assert r["usd"] == 6500.0


def test_sol_with_spl(monkeypatch):
    def post(url, payload):
        if payload["method"] == "getBalance":
            return {"result": {"value": 3 * 10 ** 9}}
        if payload["method"] == "getTokenAccountsByOwner":
            return {"result": {"value": [
                {"account": {"data": {"parsed": {"info": {
                    "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                    "tokenAmount": {"uiAmount": 250.0}}}}}}]}}
        raise AssertionError(payload)
    _mock(monkeypatch, post=post)
    r = enrich.lookup("SOL", SOL)
    assert r["ok"] and r["balance"] == 3.0 and r["native_usd"] == 450.0
    assert r["usd"] == 700.0
    assert r["tokens"][0]["symbol"] == "USDC"


def test_failure_is_not_zero(monkeypatch):
    def boom(url):
        raise RuntimeError("network down")
    _mock(monkeypatch, get=boom)
    r = enrich.lookup("BTC", BTC)
    assert r["ok"] is False and "lookup failed" in r["error"]
    assert "balance" not in r  # never a fake zero


def test_xmr_not_public(monkeypatch):
    _mock(monkeypatch)
    r = enrich.lookup("XMR", "4" + "a" * 94)
    assert r["ok"] is False and r.get("not_public") is True
    assert "not public" in r["display"]
