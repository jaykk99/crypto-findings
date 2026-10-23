"""Crypto artifact extraction from pasted text / files / recon findings.

Checksum-verified where the chain has one (ported validators from
recon-anything's cp_* pack). Secret material is returned raw here and
MASKED at storage time (see db.mask_value) - full seeds/keys are never
persisted.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import List, Optional

from . import validators as v
from .bip39 import BIP39_WORDSET, BIP39_WORD_INDEX

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


@dataclass
class Artifact:
    type: str            # address | seed_phrase | private_key | api_key | miner_indicator
    chain: str           # BTC, ETH, SOL, XMR, ... or ""
    value: str           # raw matched value (masked before storage if secret)
    secret: bool = False
    severity: str = "medium"
    label: str = ""


def _b58check_ok(s: str, prefixes: tuple) -> bool:
    p = v.b58check_verify(s)
    return p is not None and any(p.startswith(pr) for pr in prefixes)


def _solana_ok(s: str) -> bool:
    raw = v.b58decode(s)
    return raw is not None and len(raw) == 32


def bip39_checksum_ok(words: List[str]) -> bool:
    """Full BIP-39 checksum verification (entropy bits + sha256 nibble)."""
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    if not all(w in BIP39_WORDSET for w in words):
        return False
    bits = "".join(format(BIP39_WORD_INDEX[w], "011b") for w in words)
    ent_len = len(bits) * 32 // 33
    ent_bits, cs_bits = bits[:ent_len], bits[ent_len:]
    ent = int(ent_bits, 2).to_bytes(ent_len // 8, "big")
    digest = hashlib.sha256(ent).digest()
    cs_expect = format(digest[0], "08b")[: len(cs_bits)]
    return cs_bits == cs_expect


# ---------------------------------------------------------------------------
# Pattern table: (regex, type, chain, secret, severity, validator, label)
# ---------------------------------------------------------------------------

def _eth_ok(s: str) -> bool:
    return v.eip55_state(s) != "bad"


PATTERNS = [
    # --- addresses (public data) ---
    (rf"\bbc1p[{B32}]{{58}}\b", "address", "BTC", False, "medium",
     lambda s: v.segwit_verify(s, "bc", 1), "BTC taproot address"),
    (rf"\bbc1q[{B32}]{{38,58}}\b", "address", "BTC", False, "medium",
     lambda s: v.segwit_verify(s, "bc", 0), "BTC bech32 address"),
    (rf"\b[13][{B58}]{{25,34}}\b", "address", "BTC", False, "medium",
     lambda s: _b58check_ok(s, (b"\x00", b"\x05")), "BTC legacy address"),
    (rf"\b(?:tb1q|tb1p)[{B32}]{{38,58}}\b", "address", "BTC-testnet", False, "low",
     lambda s: v.bech32_decode(s) is not None, "BTC testnet address"),
    (r"\b0x[a-fA-F0-9]{40}\b", "address", "ETH", False, "medium",
     _eth_ok, "Ethereum address (EIP-55 checked when mixed-case)"),
    (rf"\b4[{B58}]{{94}}\b", "address", "XMR", False, "medium",
     lambda s: v.xmr_verify(s, (18,)), "Monero standard address"),
    (rf"\b8[{B58}]{{94}}\b", "address", "XMR", False, "medium",
     lambda s: v.xmr_verify(s, (42,)), "Monero subaddress"),
    (rf"\b[LM3][{B58}]{{26,33}}\b", "address", "LTC", False, "low",
     lambda s: _b58check_ok(s, (b"\x30", b"\x05", b"\x32")), "Litecoin address"),
    (rf"\bltc1q[{B32}]{{38,58}}\b", "address", "LTC", False, "low",
     lambda s: v.segwit_verify(s, "ltc", 0), "Litecoin bech32 address"),
    (rf"\bD[{B58}]{{25,34}}\b", "address", "DOGE", False, "low",
     lambda s: _b58check_ok(s, (b"\x1e",)), "Dogecoin address"),
    (r"\b(?:bitcoincash:)?[qp][a-z0-9]{41}\b", "address", "BCH", False, "low",
     v.cashaddr_verify, "Bitcoin Cash cashaddr"),
    (rf"\b[{B58}]{{32,44}}\b", "address", "SOL", False, "low",
     _solana_ok, "Solana address (32-byte base58)"),
    # --- secrets ---
    (r"\b[0-9a-fA-F]{64}\b", "private_key", "", True, "critical",
     None, "64-hex secret (private key shape; context decides)"),
    (r"\bnsec1[a-z0-9]{58}\b", "private_key", "NOSTR", True, "critical",
     None, "Nostr private key (nsec)"),
    (r"\bAKIA[0-9A-Z]{16}\b", "api_key", "", True, "high",
     None, "AWS access key id"),
]

# Context-gated hex keys: only flag 64-hex as a private key when crypto
# context words sit nearby; bare hashes are too noisy.
_HEXKEY_CTX = re.compile(
    r"private[_ ]?key|privkey|secret|signer|wallet|mnemonic|seed", re.I)

API_KEY_PATTERNS = [
    (re.compile(r"(?:infura\.io/v3/|INFURA_(?:API_)?KEY\s*[=:]\s*)([A-Za-z0-9]{32})"),
     "Infura project key"),
    (re.compile(r"(?:alchemy\.com/v2/|ALCHEMY_(?:API_)?KEY\s*[=:]\s*)([A-Za-z0-9_\-]{32,})"),
     "Alchemy API key"),
    (re.compile(r"(?:ETHERSCAN_API_KEY|BSCSCAN_API_KEY|POLYGONSCAN_API_KEY)\s*[=:]\s*([A-Z0-9]{34})", re.I),
     "Explorer API key (Etherscan family)"),
    (re.compile(r"(?:BINANCE|COINBASE|KRAKEN|KUCOIN|BYBIT|OKX)_(?:API_)?(?:KEY|SECRET)\s*[=:]\s*([A-Za-z0-9/+=_\-]{20,})", re.I),
     "Exchange API credential"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "PEM private key block"),
]

MINER_PATTERNS = [
    (re.compile(r"coinhive|coin-hive|coinimp|authedmine|cryptoloot|mineralt|jsecoin|coinnerbula|webminepool|moneroocean", re.I),
     "Known browser-miner kit (CoinHive lineage)"),
    (re.compile(r"stratum\+(?:tcp|ssl)://[^\s\"']+", re.I),
     "Stratum mining endpoint"),
    (re.compile(r"xmrig|CryptoNight|RandomX.*wasm|cn\.js|miner\.js", re.I),
     "Miner binary / WASM miner reference"),
    (re.compile(r"pool\.(?:minexmr|supportxmr|nanopool|2miners)\.[a-z]+", re.I),
     "Mining pool domain"),
]

def extract_seeds(text: str) -> List[Artifact]:
    """Sliding window over the token stream: a seed buried mid-sentence
    in prose is still found (checksum decides, prose words fail it)."""
    tokens = re.findall(r"[a-z]+", text.lower())
    out, seen = [], set()
    for i in range(len(tokens)):
        for n in (24, 21, 18, 15, 12):
            window = tokens[i:i + n]
            if len(window) == n and bip39_checksum_ok(window):
                phrase = " ".join(window)
                if phrase not in seen:
                    seen.add(phrase)
                    out.append(Artifact(
                        "seed_phrase", "", phrase, secret=True,
                        severity="critical",
                        label=f"BIP-39 seed phrase ({n} words, checksum valid)"))
                break
    return out


def extract(text: str) -> List[Artifact]:
    """All artifacts in `text`, deduped by (type, value)."""
    found: dict = {}

    def add(a: Artifact):
        found.setdefault((a.type, a.value), a)

    for pat, typ, chain, secret, sev, validator, label in PATTERNS:
        for m in re.finditer(pat, text):
            val = m.group(0)
            if validator is not None:
                try:
                    if not validator(val):
                        continue
                except Exception:
                    continue
            if typ == "private_key" and chain == "" and val.startswith(("0x", "0X")) is False:
                lo = max(0, m.start() - 120)
                if not _HEXKEY_CTX.search(text[lo:m.end() + 40]):
                    continue
            add(Artifact(typ, chain, val, secret=secret, severity=sev, label=label))

    for rx, label in API_KEY_PATTERNS:
        for m in rx.finditer(text):
            val = m.group(1) if m.groups() else m.group(0)
            add(Artifact("api_key", "", val, secret=True, severity="high", label=label))

    for rx, label in MINER_PATTERNS:
        for m in rx.finditer(text):
            add(Artifact("miner_indicator", "XMR", m.group(0), secret=False,
                         severity="high", label=label))

    for a in extract_seeds(text):
        add(a)

    return list(found.values())


def fingerprint(artifact_type: str, value: str) -> str:
    return hashlib.sha256(f"{artifact_type}:{value}".encode()).hexdigest()
