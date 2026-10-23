import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import validators as v
from app.parser import extract, bip39_checksum_ok

BTC_LEGACY = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"          # genesis address
BTC_BECH32 = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"  # BIP-173 example
BTC_TAPROOT = ("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9"
               "rusxg3297")                                  # BIP-350 example
ETH_OK = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"       # EIP-55 example
SOL_OK = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"     # SPL token program
SEED_OK = ("abandon " * 11 + "about").strip()               # BIP-39 test vector


def vals(text, type_=None):
    return [a.value for a in extract(text) if type_ is None or a.type == type_]


def test_btc_legacy_valid_and_invalid():
    assert BTC_LEGACY in vals(f"donate {BTC_LEGACY} please", "address")
    bad = BTC_LEGACY[:-1] + "b"
    assert bad not in vals(f"donate {bad} please", "address")


def test_btc_bech32_and_taproot():
    assert BTC_BECH32 in vals(BTC_BECH32, "address")
    assert BTC_TAPROOT in vals(BTC_TAPROOT, "address")
    assert (BTC_BECH32[:-1] + "x") not in vals(BTC_BECH32[:-1] + "x", "address")


def test_eth_eip55():
    assert ETH_OK in vals(ETH_OK, "address")
    bad = "0x5aaEb6053F3E94C9b9A09f33669435E7Ef1BeAed"  # case flipped wrongly
    assert v.eip55_state(bad) == "bad"
    assert bad not in vals(bad, "address")
    lower = ETH_OK.lower()
    assert lower in vals(lower, "address")  # plain lowercase accepted


def test_solana():
    assert SOL_OK in vals(SOL_OK, "address")
    assert "abc123" not in vals("abc123", "address")


def test_xmr_roundtrip_and_mutation():
    xa = v.xmr_encode(bytes([0x12]) + bytes(range(32)) + bytes(range(32, 64)))
    assert len(xa) == 95
    assert xa in vals(xa, "address")
    mut = xa[:20] + "1" + xa[21:]
    assert mut not in vals(mut, "address")


def test_ltc_doge_bch():
    ltc = v.b58check_encode(b"\x30" + bytes(range(20)))
    assert ltc in vals(ltc, "address")
    doge = v.b58check_encode(b"\x1e" + bytes(range(20)))
    assert doge in vals(doge, "address")


def test_seed_checksum_valid_and_invalid():
    words = SEED_OK.split()
    assert bip39_checksum_ok(words)
    arts = extract("leaked mnemonic: " + SEED_OK)
    seeds = [a for a in arts if a.type == "seed_phrase"]
    assert len(seeds) == 1 and seeds[0].secret
    bad = ("abandon " * 12).strip()  # valid words, bad checksum
    assert not bip39_checksum_ok(bad.split())
    assert not [a for a in extract(bad) if a.type == "seed_phrase"]
    assert not bip39_checksum_ok(["notaword"] * 12)


def test_seed_buried_in_prose():
    txt = ("operator note from the ticket: the intern pasted the wallet "
           "backup into slack again, it reads " + SEED_OK +
           " and legal wants it rotated today")
    seeds = [a for a in extract(txt) if a.type == "seed_phrase"]
    assert len(seeds) == 1 and seeds[0].value == SEED_OK


def test_private_key_needs_context():
    key = "a" * 63 + "1"
    assert key in vals(f"private_key = {key}", "private_key")
    assert key not in vals(f"sha256 checksum {key} end", "private_key")


def test_api_keys_and_miner():
    txt = "src https://mainnet.infura.io/v3/0123456789abcdef0123456789abcdef"
    arts = extract(txt + " <script src=coinhive.min.js></script>")
    assert any(a.type == "api_key" and a.secret for a in arts)
    assert any(a.type == "miner_indicator" for a in arts)
    strat = extract("pool stratum+tcp://pool.minexmr.com:4444")
    assert any(a.type == "miner_indicator" for a in strat)
