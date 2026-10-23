"""Blockchain ingestion: address / explorer URL / tx hash in,
findings out. Keyless public APIs, read-only, depth 1 counterparties.

BTC: blockstream.info address txs + tx lookup.
ETH: Blockscout public API (eth.blockscout.com) for tx lists + tx,
falling back to balance-only when unavailable.
SOL: public RPC getSignaturesForAddress + getTransaction.
Every counterparty address becomes a finding (source: blockchain),
then the shared auto-enrich pipeline fills balances in.
"""
from __future__ import annotations

import re
import urllib.parse

from . import db
from .enrich import _get, _post
from .parser import Artifact, extract

TX_LIMIT = 25

_EXPLORER_ADDR = [
    (re.compile(r"(?:blockstream\.info|mempool\.space|btc\.com|blockchain\.com"
                 r"(?:/explorer)?(?:/[^/]+)?/address)/([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})"),
     "BTC"),
    (re.compile(r"(?:etherscan\.io|eth\.blockscout\.com|blockscout\.com"
                 r"(?:/[^/]+)?/address)/(0x[a-fA-F0-9]{40})"), "ETH"),
    (re.compile(r"(?:solscan\.io|explorer\.solana\.com)/account/"
                 r"([1-9A-HJ-NP-Za-km-z]{32,44})"), "SOL"),
    (re.compile(r"(?:blockstream\.info/litecoin|litecoinspace\.org)"
                 r"/address/([LM3][a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[ac-hj-np-z02-9]{11,71})"),
     "LTC"),
    (re.compile(r"dogechain\.info/address/([DA9][a-km-zA-HJ-NP-Z1-9]{25,34})"),
     "DOGE"),
]
_EXPLORER_TX = re.compile(
    r"(?:tx|transaction)/([0-9a-fA-F]{64})\b")
_TX_HASH = re.compile(r"\b[0-9a-fA-F]{64}\b")


def parse_input(raw: str):
    """Return ('address', chain, value) or ('tx', chain, hash) or None."""
    raw = raw.strip()
    for rx, chain in _EXPLORER_ADDR:
        m = rx.search(raw)
        if m:
            return ("address", chain, m.group(1))
    m = _EXPLORER_TX.search(raw)
    if m:
        chain = ("ETH" if ("etherscan" in raw or "blockscout" in raw)
                 else "BTC")
        return ("tx", chain, m.group(1).lower())
    arts = [a for a in extract(raw) if a.type == "address"]
    if arts:
        return ("address", arts[0].chain, arts[0].value)
    if _TX_HASH.fullmatch(raw):
        return ("tx", "BTC", raw.lower())
    return None


def _store(chain: str, value: str, target: str, note: str,
           severity: str = "medium") -> bool:
    a = Artifact("address", chain, value, secret=False,
                 severity=severity, label=f"{chain} address (blockchain pull)")
    return db.upsert(a, source="blockchain", target=target, note=note)


def _btc_counterparties(addr: str):
    txs = _get(f"https://blockstream.info/api/address/{addr}/txs")
    parties, seen_tx = set(), 0
    for tx in txs[:TX_LIMIT]:
        seen_tx += 1
        for vin in tx.get("vin", []):
            a = (vin.get("prevout") or {}).get("scriptpubkey_address")
            if a:
                parties.add(a)
        for vout in tx.get("vout", []):
            a = vout.get("scriptpubkey_address")
            if a:
                parties.add(a)
    return parties, seen_tx


def _eth_counterparties(addr: str):
    d = _get(f"https://eth.blockscout.com/api/v2/addresses/{addr}"
             "/transactions?page_size=50")
    parties, n = set(), 0
    for tx in d.get("items", [])[:TX_LIMIT]:
        n += 1
        for side in ("from", "to"):
            v = (tx.get(side) or {}).get("hash")
            if v:
                parties.add(v)
    return parties, n


def _sol_counterparties(addr: str):
    sigs = _post("https://api.mainnet-beta.solana.com",
                 {"jsonrpc": "2.0", "id": 1,
                  "method": "getSignaturesForAddress",
                  "params": [addr, {"limit": TX_LIMIT}]})
    parties, n = set(), 0
    for s in (sigs.get("result") or [])[:TX_LIMIT]:
        n += 1
        try:
            tx = _post("https://api.mainnet-beta.solana.com",
                       {"jsonrpc": "2.0", "id": 1, "method": "getTransaction",
                        "params": [s["signature"],
                                   {"encoding": "json",
                                    "maxSupportedTransactionVersion": 0}]})
            keys = (tx.get("result") or {}).get("transaction", {}) \
                .get("message", {}).get("accountKeys", [])
            parties.update(k for k in keys if isinstance(k, str))
        except Exception:
            continue
    return parties, n


_PULLERS = {"BTC": _btc_counterparties, "ETH": _eth_counterparties,
            "SOL": _sol_counterparties}


def _tx_parties(chain: str, txh: str):
    if chain == "ETH":
        d = _get(f"https://eth.blockscout.com/api/v2/transactions/{txh}")
        parties = set()
        for side in ("from", "to"):
            v = (d.get(side) or {}).get("hash")
            if v:
                parties.add(v)
        return parties, d.get("value"), "ETH"
    d = _get(f"https://blockstream.info/api/tx/{txh}")
    parties = set()
    for vin in d.get("vin", []):
        a = (vin.get("prevout") or {}).get("scriptpubkey_address")
        if a:
            parties.add(a)
    total = 0
    for vout in d.get("vout", []):
        if vout.get("scriptpubkey_address"):
            parties.add(vout["scriptpubkey_address"])
        total += vout.get("value", 0)
    return parties, total / 1e8, "BTC"


def ingest_chain(raw: str) -> dict:
    parsed = parse_input(raw)
    if not parsed:
        return {"ok": False,
                "error": "could not parse an address, explorer URL, or tx hash"}
    kind, chain, value = parsed
    new = dup = 0

    def store(c, v, target, note, sev="medium"):
        nonlocal new, dup
        if _store(c, v, target, note, sev):
            new += 1
        else:
            dup += 1

    if kind == "address":
        store(chain, value, value, "seed address (blockchain ingest)",
              sev="high")
        parties, ntx = set(), 0
        puller = _PULLERS.get(chain)
        note = ""
        if puller:
            try:
                parties, ntx = puller(value)
            except Exception as e:
                note = f"tx pull failed: {e}"
        else:
            note = f"tx history not available keyless for {chain}"
        parties.discard(value)
        for p in sorted(parties):
            store(chain, p, value,
                  f"counterparty of {value} (depth 1, blockchain ingest)")
        return {"ok": True, "mode": "blockchain", "input_kind": "address",
                "seed": value, "chain": chain, "txs_seen": ntx,
                "counterparties": len(parties),
                "findings_out": new + dup, "imported_new": new,
                "duplicates": dup, "note": note}

    parties, tx_value, tx_chain = _tx_parties(chain, value)
    for p in sorted(parties):
        store(tx_chain, p, value,
              f"party in tx {value[:16]}... (value {tx_value} {tx_chain})",
              sev="high")
    return {"ok": True, "mode": "blockchain", "input_kind": "tx",
            "seed": value, "chain": tx_chain, "tx_value": tx_value,
            "counterparties": len(parties), "findings_out": new + dup,
            "imported_new": new, "duplicates": dup}
