"""Derivation of controlled wallets from full secrets at ingest.

Test vectors are all widely published, never-funded examples:
- Bitcoin Wiki WIF example key and address
- private key = 1 (textbook addresses on every chain)
- Hardhat's default account #0 (public test key/address pair)
- the canonical BIP-39 'abandon x11 + about' vector and its
  published first BIP-44 addresses
"""
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from app import db, derive, validators as v
from app.parser import Artifact, extract

WIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
WIF_ADDR = "1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S"
KEY1 = "00" * 31 + "01"
KEY1_P2PKH_C = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
KEY1_P2PKH_U = "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"
KEY1_P2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
KEY1_ETH = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
HH_KEY = ("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
HH_ADDR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
SEED = ("abandon " * 11 + "about").strip()
SEED_BTC = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
SEED_ETH = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
TEST_DB = "/tmp/cf-derive-test.db"


@pytest.fixture(scope="module", autouse=True)
def own_db():
    old = db.DB_PATH
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    db.DB_PATH = TEST_DB
    db.init_db()
    yield TEST_DB
    db.DB_PATH = old


# ---------------------------------------------------------------------------
# primitives
# ---------------------------------------------------------------------------

def test_ripemd160_pure_vectors():
    assert derive._ripemd160_pure(b"").hex() == \
        "9c1185a5c5e9fc54612808977ee8f548b2258d31"
    assert derive._ripemd160_pure(b"abc").hex() == \
        "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    assert derive._ripemd160_pure(b"a" * 1000000).hex() == \
        "52783243c1697bdbe16d37f97f68f08325dc1528"


def test_wif_decode_vector():
    k, compressed = derive.wif_decode(WIF)
    assert compressed is False
    assert k == int("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE"
                    "89827E19D72AA1D", 16)
    assert derive.wif_decode(WIF[:-1] + "K") is None  # bad checksum
    assert derive.wif_decode("not-a-key") is None


def test_key1_all_forms():
    assert derive.btc_p2pkh(1, compressed=True) == KEY1_P2PKH_C
    assert derive.btc_p2pkh(1, compressed=False) == KEY1_P2PKH_U
    assert derive.btc_p2wpkh(1) == KEY1_P2WPKH
    assert v.segwit_verify(KEY1_P2WPKH, "bc", 0)
    assert derive.eth_address(1) == KEY1_ETH


def test_eth_derivation_checksum():
    addr = derive.eth_address(int(HH_KEY, 16))
    assert addr == HH_ADDR
    assert v.eip55_state(addr) == "checksummed"


# ---------------------------------------------------------------------------
# derivations() coverage
# ---------------------------------------------------------------------------

def test_derivations_wif():
    d = derive.derivations("private_key", WIF, "BTC")
    assert d[0] == {"chain": "BTC", "address": WIF_ADDR,
                    "kind": "P2PKH from WIF"}


def test_derivations_hex_key_covers_btc_and_eth():
    d = derive.derivations("private_key", HH_KEY, "")
    addrs = {x["address"] for x in d}
    assert HH_ADDR in addrs
    assert any(x["chain"] == "BTC" for x in d)
    d_eth = derive.derivations("private_key", HH_KEY, "ETH")
    assert d_eth[0]["address"] == HH_ADDR  # chain hint makes ETH primary


def test_derivations_seed_bip44():
    d = derive.derivations("seed_phrase", SEED, "")
    assert [x["address"] for x in d] == [SEED_BTC, SEED_ETH]
    assert d[0]["chain"] == "BTC" and d[1]["chain"] == "ETH"
    bad = ("abandon " * 12).strip()  # valid words, bad checksum
    assert derive.derivations("seed_phrase", bad, "") == []


def test_derivations_rejects_non_secrets():
    assert derive.derivations("private_key", "ac0974...ff80", "") == []
    assert derive.derivations("seed_phrase",
                              "abandon ability ... (12 words)", "") == []
    assert derive.derivations("private_key", "00" * 32, "") == []  # k = 0
    assert derive.derivations("api_key", HH_KEY, "") == []
    assert derive.derivations("address", SEED_BTC, "BTC") == []


def test_parser_extracts_wif_as_private_key():
    arts = [a for a in extract(f"leaked wif: {WIF}")
            if a.type == "private_key"]
    assert len(arts) == 1 and arts[0].value == WIF
    assert arts[0].chain == "BTC" and arts[0].secret
    mutated = WIF[:10] + ("1" if WIF[10] != "1" else "2") + WIF[11:]
    assert not [a for a in extract(mutated) if a.value == mutated]


# ---------------------------------------------------------------------------
# DB integration: linkage, derived findings, masking unchanged
# ---------------------------------------------------------------------------

def _row(type_, masked_part):
    rows = [r for r in db.list_findings(limit=10000)
            if r["type"] == type_ and masked_part in r["masked_value"]]
    assert rows, f"no {type_} row containing {masked_part}"
    return rows[0]


def test_seed_upsert_links_and_creates_wallets():
    a = [x for x in extract("mnemonic: " + SEED)
         if x.type == "seed_phrase"][0]
    assert db.upsert(a, source="paste", target="leak.example.com") is True
    row = _row("seed_phrase", "abandon abandon")
    assert row["controls_address"] == SEED_BTC
    assert row["controls_chain"] == "BTC"
    derived = [r for r in db.list_findings(source="derived")
               if r["type"] == "address"]
    daddrs = {r["value"] for r in derived}
    assert SEED_BTC in daddrs and SEED_ETH in daddrs
    assert all(r["source"] == "derived" for r in derived)


def test_wif_upsert_links():
    a = [x for x in extract("wif " + WIF) if x.type == "private_key"][0]
    assert db.upsert(a, source="paste") is True
    row = _row("private_key", WIF[:6])
    assert row["controls_address"] == WIF_ADDR
    assert row["controls_chain"] == "BTC"


def test_hex_key_upsert_links_eth_wallet():
    a = [x for x in extract(f"private_key = {HH_KEY}")
         if x.type == "private_key"][0]
    assert db.upsert(a, source="paste") is True
    row = _row("private_key", HH_KEY[:6])
    assert row["controls_address"]  # primary link set
    eth = [r for r in db.list_findings(source="derived")
           if r["value"] == HH_ADDR]
    assert eth and eth[0]["chain"] == "ETH"


def test_redacted_secret_skips_derivation():
    masked = HH_KEY[:6] + "..." + HH_KEY[-4:]
    a = Artifact("private_key", "", masked, secret=True,
                 severity="critical", label="redacted by scanner")
    assert db.upsert(a, source="recon:redacted") is True
    row = _row("private_key", HH_KEY[:6] + "...")
    assert row["controls_address"] == "" and row["controls_chain"] == ""


def test_secrets_never_in_db_rows_or_file(own_db):
    blob = json.dumps(db.list_findings(limit=10000))
    for secret in (SEED, WIF, HH_KEY):
        assert secret not in blob
    raw = open(own_db, "rb").read()
    for secret in (SEED, WIF, HH_KEY):
        assert secret.encode() not in raw
    assert b"ability" not in raw  # 3rd seed word: only 2-word preview kept


def test_controls_balance_attached():
    rows = db.list_findings(limit=10000)
    addr_row = [r for r in rows if r["type"] == "address"
                and r["value"] == SEED_BTC][0]
    db.set_balance(addr_row["id"], json.dumps(
        {"ok": True, "chain": "BTC", "balance": 0.5, "unit": "BTC",
         "usd": 50000.0}))
    seed_row = _row("seed_phrase", "abandon abandon")
    assert seed_row["controls_balance"]["usd"] == 50000.0
    detail = db.get(seed_row["id"])
    assert detail["controls_balance"]["balance"] == 0.5


def test_migration_adds_controls_columns():
    path = "/tmp/cf-old-schema.db"
    if os.path.exists(path):
        os.remove(path)
    c = sqlite3.connect(path)
    c.execute("""
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL,
            chain TEXT NOT NULL DEFAULT '', value TEXT NOT NULL,
            masked_value TEXT NOT NULL, fingerprint TEXT NOT NULL UNIQUE,
            source TEXT NOT NULL, target TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT 'medium',
            label TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'new', balance_json TEXT,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL)""")
    c.commit()
    c.close()
    old = db.DB_PATH
    db.DB_PATH = path
    try:
        db.init_db()
        cols = {r[1] for r in db.conn().execute("PRAGMA table_info(findings)")}
        assert "controls_address" in cols and "controls_chain" in cols
    finally:
        db.DB_PATH = old
