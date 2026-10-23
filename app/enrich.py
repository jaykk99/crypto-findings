"""Public-data balance lookups for full addresses (keyless APIs only).

BTC: blockstream.info. LTC: litecoinspace.org (mempool-style API).
DOGE: dogechain.info. ETH: public JSON-RPC eth_getBalance + ERC-20
balanceOf for top tokens via the same RPC. SOL: public Solana RPC
getBalance + getTokenAccountsByOwner for SPL tokens.
XMR: balances are NOT publicly viewable without a view key - the
lookup returns not_public and the UI says so. Never a fake number.
Failures return ok=False ("lookup failed"), never a zero balance.
USD via keyless CoinGecko prices. Every result carries fetched_at.
"""
from __future__ import annotations

import json
import time
import urllib.request
from datetime import datetime, timezone

_CACHE: dict = {"ts": 0, "prices": {}}

# symbol, contract, decimals, coingecko id
ERC20_TOP = [
    ("USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7", 6, "tether"),
    ("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6, "usd-coin"),
    ("DAI", "0x6B175474E89094C44Da98b954EedeAC495271d0F", 18, "dai"),
    ("WBTC", "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", 8, "wrapped-bitcoin"),
    ("LINK", "0x514910771AF9Ca656af840dff83E8264EcF986CA", 18, "chainlink"),
    ("UNI", "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", 18, "uniswap"),
    ("WETH", "0xC02aaA39b223FE8D0F0e5C4F27eAD9083C756Cc2", 18, "weth"),
]
SPL_KNOWN = {  # mint -> (symbol, price coingecko id or fixed 1.0 for stables)
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": ("USDC", "usd-coin"),
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB": ("USDT", "tether"),
}


def _get(url: str, timeout: int = 15):
    req = urllib.request.Request(url, headers={"User-Agent": "crypto-findings/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _post(url: str, payload: dict, timeout: int = 15):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"User-Agent": "crypto-findings/1.0",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def prices() -> dict:
    if time.time() - _CACHE["ts"] < 300:
        return _CACHE["prices"]
    ids = ("bitcoin,ethereum,solana,litecoin,dogecoin,tether,usd-coin,dai,"
           "wrapped-bitcoin,chainlink,uniswap,weth")
    try:
        d = _get("https://api.coingecko.com/api/v3/simple/price"
                 f"?ids={ids}&vs_currencies=usd")
        _CACHE["prices"] = {k: v["usd"] for k, v in d.items()}
        _CACHE["ts"] = time.time()
    except Exception:
        pass
    return _CACHE["prices"]


def _usd(amount: float, gecko_id: str, p: dict):
    px = p.get(gecko_id)
    return round(amount * px, 2) if px else None


def _eth_token_balances(address: str, p: dict) -> list:
    out = []
    data = "0x70a08231" + address[2:].lower().rjust(64, "0")
    for sym, contract, decimals, gid in ERC20_TOP:
        try:
            d = _post("https://eth.llamarpc.com",
                      {"jsonrpc": "2.0", "id": 1, "method": "eth_call",
                       "params": [{"to": contract, "data": data}, "latest"]})
            raw = d.get("result")
            if not raw or raw == "0x":
                continue
            amt = int(raw, 16) / (10 ** decimals)
            if amt > 0:
                out.append({"symbol": sym, "balance": amt,
                            "usd": _usd(amt, gid, p),
                            "price": p.get(gid)})
        except Exception:
            continue
    return out


def _sol_token_balances(address: str, p: dict) -> list:
    out = []
    try:
        d = _post("https://api.mainnet-beta.solana.com",
                  {"jsonrpc": "2.0", "id": 1,
                   "method": "getTokenAccountsByOwner",
                   "params": [address,
                              {"programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},
                              {"encoding": "jsonParsed"}]})
        for acc in (d.get("result") or {}).get("value") or []:
            info = (acc.get("account", {}).get("data", {})
                    .get("parsed", {}).get("info", {}))
            mint = info.get("mint", "")
            amt = float(info.get("tokenAmount", {}).get("uiAmount") or 0)
            if amt <= 0:
                continue
            sym, gid = SPL_KNOWN.get(mint, (mint[:6] + "...", None))
            out.append({"symbol": sym, "mint": mint, "balance": amt,
                        "usd": _usd(amt, gid, p) if gid else None,
                        "price": p.get(gid) if gid else None})
    except Exception:
        pass
    return out


def lookup(chain: str, address: str) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    if chain == "XMR":
        return {"ok": False, "not_public": True, "chain": "XMR",
                "display": "not public (Monero balances need a view key)",
                "fetched_at": ts}
    p = prices()
    try:
        if chain == "BTC":
            d = _get(f"https://blockstream.info/api/address/{address}")
            cs = d["chain_stats"]
            btc = (cs["funded_txo_sum"] - cs["spent_txo_sum"]) / 1e8
            return {"ok": True, "chain": "BTC", "balance": btc, "unit": "BTC",
                    "txs": cs["tx_count"], "price": p.get("bitcoin"),
                    "usd": _usd(btc, "bitcoin", p), "tokens": [],
                    "fetched_at": ts}
        if chain == "LTC":
            d = _get(f"https://litecoinspace.org/api/address/{address}")
            cs = d["chain_stats"]
            ltc = (cs["funded_txo_sum"] - cs["spent_txo_sum"]) / 1e8
            return {"ok": True, "chain": "LTC", "balance": ltc, "unit": "LTC",
                    "txs": cs["tx_count"], "price": p.get("litecoin"),
                    "usd": _usd(ltc, "litecoin", p), "tokens": [],
                    "fetched_at": ts}
        if chain == "DOGE":
            d = _get(f"https://dogechain.info/api/v1/address/balance/{address}")
            doge = float(d["balance"])
            return {"ok": True, "chain": "DOGE", "balance": doge,
                    "unit": "DOGE", "price": p.get("dogecoin"),
                    "usd": _usd(doge, "dogecoin", p), "tokens": [],
                    "fetched_at": ts}
        if chain == "ETH":
            d = _post("https://eth.llamarpc.com",
                      {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
                       "params": [address, "latest"]})
            eth = int(d["result"], 16) / 1e18
            tokens = _eth_token_balances(address, p)
            total = (_usd(eth, "ethereum", p) or 0) + sum(
                t["usd"] or 0 for t in tokens)
            return {"ok": True, "chain": "ETH", "balance": eth, "unit": "ETH",
                    "price": p.get("ethereum"),
                    "usd": round(total, 2) if p else None,
                    "native_usd": _usd(eth, "ethereum", p),
                    "tokens": tokens, "fetched_at": ts}
        if chain == "SOL":
            d = _post("https://api.mainnet-beta.solana.com",
                      {"jsonrpc": "2.0", "id": 1, "method": "getBalance",
                       "params": [address]})
            sol = d["result"]["value"] / 1e9
            tokens = _sol_token_balances(address, p)
            total = (_usd(sol, "solana", p) or 0) + sum(
                t["usd"] or 0 for t in tokens)
            return {"ok": True, "chain": "SOL", "balance": sol, "unit": "SOL",
                    "price": p.get("solana"),
                    "usd": round(total, 2) if p else None,
                    "native_usd": _usd(sol, "solana", p),
                    "tokens": tokens, "fetched_at": ts}
        return {"ok": False, "error": f"no public lookup for chain {chain or '?'}",
                "fetched_at": ts}
    except Exception as e:
        return {"ok": False, "error": f"lookup failed: {e}",
                "fetched_at": ts}
