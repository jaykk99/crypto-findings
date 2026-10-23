"""Address derivation from full secrets, at ingest, IN MEMORY ONLY.

When a complete private key or seed phrase is present in source
material, the wallet address(es) it controls are public data and are
worth more than the secret itself for triage: they let the existing
balance enrichment show what the leaked secret actually controls.

The secret is used transiently to derive and is then discarded by the
caller - it is never persisted or logged here or anywhere else (the
storage rule in db.py is unchanged: masked preview + fingerprint).

Coverage:
- BTC WIF (compressed / uncompressed) -> P2PKH (+ P2WPKH if compressed)
- 64-hex private keys -> BTC P2PKH / P2WPKH (compressed form) + ETH
- BIP-39 seed phrases -> first BIP-44 address for BTC (m/44'/0'/0'/0/0)
  and ETH (m/44'/60'/0'/0/0)

secp256k1 and BIP-32 are implemented in pure Python on stdlib
primitives (hashlib / hmac) plus the Keccak-256 and Base58Check /
Bech32 helpers in validators.py. No new dependencies.
Redacted or masked values (what ReconAnything scan findings carry)
derive nothing and are skipped silently.
"""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
from typing import List, Optional, Tuple

from . import validators as v
from .bip39 import BIP39_WORDSET

# ---------------------------------------------------------------------------
# secp256k1 (pure Python; ingest-time only, a handful of multiplies)
# ---------------------------------------------------------------------------

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p == q:
        m = (3 * x1 * x1) * pow(2 * y1, _P - 2, _P) % _P
    else:
        m = (y2 - y1) * pow((x2 - x1) % _P, _P - 2, _P) % _P
    x3 = (m * m - x1 - x2) % _P
    return x3, (m * (x1 - x3) - y1) % _P


def _point_mul(k: int, point=_G):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _pubkey_bytes(k: int, compressed: bool = True) -> bytes:
    x, y = _point_mul(k)
    if compressed:
        return bytes([0x02 | (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _valid_key(k: int) -> bool:
    return 1 <= k < _N


# ---------------------------------------------------------------------------
# RIPEMD-160: hashlib where OpenSSL offers it, pure-Python fallback
# (OpenSSL 3 builds frequently drop it from the default provider).
# ---------------------------------------------------------------------------

_RMD_R1 = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
_RMD_R2 = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
_RMD_S1 = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
_RMD_S2 = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
_RMD_K1 = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_RMD_K2 = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
_M32 = 0xFFFFFFFF


def _rmd_f(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | ~y) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def _rol32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _M32


def _ripemd160_pure(data: bytes) -> bytes:
    msg = bytearray(data)
    bitlen = (len(msg) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += bitlen.to_bytes(8, "little")
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    for off in range(0, len(msg), 64):
        block = msg[off:off + 64]
        x = [int.from_bytes(block[i * 4:(i + 1) * 4], "little")
             for i in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            g = j // 16
            t = (_rol32((al + _rmd_f(j, bl, cl, dl)
                        + x[_RMD_R1[j]] + _RMD_K1[g]) & _M32,
                       _RMD_S1[j]) + el) & _M32
            al, el, dl, cl, bl = el, dl, _rol32(cl, 10), bl, t
            t = (_rol32((ar + _rmd_f(79 - j, br, cr, dr)
                        + x[_RMD_R2[j]] + _RMD_K2[g]) & _M32,
                       _RMD_S2[j]) + er) & _M32
            ar, er, dr, cr, br = er, dr, _rol32(cr, 10), br, t
        t = (h[1] + cl + dr) & _M32
        h[1] = (h[2] + dl + er) & _M32
        h[2] = (h[3] + el + ar) & _M32
        h[3] = (h[4] + al + br) & _M32
        h[4] = (h[0] + bl + cr) & _M32
        h[0] = t
    return b"".join(word.to_bytes(4, "little") for word in h)


def _ripemd160(data: bytes) -> bytes:
    try:
        return hashlib.new("ripemd160", data).digest()
    except (ValueError, TypeError):
        return _ripemd160_pure(data)


def _hash160(data: bytes) -> bytes:
    return _ripemd160(hashlib.sha256(data).digest())


# ---------------------------------------------------------------------------
# Address encoders
# ---------------------------------------------------------------------------

def btc_p2pkh(k: int, compressed: bool = True) -> str:
    return v.b58check_encode(b"\x00" + _hash160(_pubkey_bytes(k, compressed)))


def _segwit_encode(hrp: str, version: int, program: bytes) -> str:
    data = [version] + v._convertbits(program, 8, 5)
    const = 1 if version == 0 else 0x2BC830A3
    pm = v._bech32_polymod(v._bech32_hrp_expand(hrp) + data + [0] * 6) ^ const
    cksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(v._BECH32_CHARSET[d] for d in data + cksum)


def btc_p2wpkh(k: int) -> str:
    return _segwit_encode("bc", 0, _hash160(_pubkey_bytes(k, True)))


def _eip55(addr20: bytes) -> str:
    lower = addr20.hex()
    digest = v.keccak256(lower.encode()).hex()
    out = "".join(c.upper() if c.isalpha() and int(digest[i], 16) >= 8
                  else c for i, c in enumerate(lower))
    return "0x" + out


def eth_address(k: int) -> str:
    pub = _pubkey_bytes(k, compressed=False)[1:]  # x || y, no 0x04 prefix
    return _eip55(v.keccak256(pub)[-20:])


# ---------------------------------------------------------------------------
# Key / seed decoding
# ---------------------------------------------------------------------------

def wif_decode(s: str) -> Optional[Tuple[int, bool]]:
    """WIF string -> (private key int, compressed?) or None."""
    payload = v.b58check_verify(s.strip())
    if not payload or payload[0] != 0x80:
        return None
    if len(payload) == 33:
        k, compressed = int.from_bytes(payload[1:], "big"), False
    elif len(payload) == 34 and payload[-1] == 0x01:
        k, compressed = int.from_bytes(payload[1:-1], "big"), True
    else:
        return None
    return (k, compressed) if _valid_key(k) else None


def _hex_key(s: str) -> Optional[int]:
    h = s.strip()
    if h.lower().startswith("0x"):
        h = h[2:]
    if len(h) != 64:
        return None
    try:
        k = int(h, 16)
    except ValueError:
        return None
    return k if _valid_key(k) else None


def _mnemonic_seed(mnemonic: str, passphrase: str = "") -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha512", mnemonic.encode("utf-8"),
        ("mnemonic" + passphrase).encode("utf-8"), 2048, dklen=64)


def _ckd(k: int, chain: bytes, index: int) -> Tuple[int, bytes]:
    if index >= 0x80000000:  # hardened
        data = b"\x00" + k.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = _pubkey_bytes(k, True) + index.to_bytes(4, "big")
    digest = hmac_mod.new(chain, data, hashlib.sha512).digest()
    child = (int.from_bytes(digest[:32], "big") + k) % _N
    return child, digest[32:]


def _bip32_path(seed: bytes, path: List[int]) -> int:
    digest = hmac_mod.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, chain = int.from_bytes(digest[:32], "big"), digest[32:]
    for index in path:
        k, chain = _ckd(k, chain, index)
    return k


_H = 0x80000000


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def derivations(artifact_type: str, value: str, chain: str = "") -> List[dict]:
    """Wallets a FULL secret controls: [{chain, address, kind}].

    First entry is the primary link for the finding. Anything that is
    not a complete, valid secret (masked previews, redacted scan
    output, bad checksums, out-of-range keys) returns [].
    """
    out: List[dict] = []

    def add(chain_: str, address: str, kind: str):
        if address and all(d["address"] != address for d in out):
            out.append({"chain": chain_, "address": address, "kind": kind})

    try:
        if artifact_type == "seed_phrase":
            words = value.split()
            if (len(words) not in (12, 15, 18, 21, 24)
                    or not all(w in BIP39_WORDSET for w in words)):
                return []
            from .parser import bip39_checksum_ok
            if not bip39_checksum_ok(words):
                return []
            seed = _mnemonic_seed(" ".join(words))
            k_btc = _bip32_path(seed, [44 | _H, 0 | _H, 0 | _H, 0, 0])
            add("BTC", btc_p2pkh(k_btc, True), "BIP-44 m/44'/0'/0'/0/0")
            k_eth = _bip32_path(seed, [44 | _H, 60 | _H, 0 | _H, 0, 0])
            add("ETH", eth_address(k_eth), "BIP-44 m/44'/60'/0'/0/0")
        elif artifact_type == "private_key":
            wif = wif_decode(value)
            if wif is not None:
                k, compressed = wif
                add("BTC", btc_p2pkh(k, compressed), "P2PKH from WIF")
                if compressed:
                    add("BTC", btc_p2wpkh(k), "P2WPKH from WIF")
            else:
                k = _hex_key(value)
                if k is None:
                    return []
                btc = [("BTC", btc_p2pkh(k, True), "P2PKH"),
                       ("BTC", btc_p2wpkh(k), "P2WPKH")]
                eth = [("ETH", eth_address(k), "Ethereum account")]
                ordered = eth + btc if chain == "ETH" else btc + eth
                for chain_, address, kind in ordered:
                    add(chain_, address, kind)
    except Exception:
        return []
    return out
