# Crypto Findings

Standalone collector for crypto scan findings. Every crypto artifact
from your scans in one place, with balances attached.

**Access code:** set your own value as `CRYPTO_FINDINGS_CODE` in the
server env; the app is gated by it, same pattern as Jay's other apps.
(A real code used to be written out here in plaintext — removed; see
the security note in the audit history for this repo. Rotate the
deployed env var if it still matches the old committed value.)

## What it does

**Four ways in, one pipeline (dedupe + masking + auto-balance):**

1. **Paste** - paste scan output / JSON / notes, or upload a file.
   A checksum-verified parser extracts wallet addresses (BTC legacy,
   bech32, taproot, testnet, ETH EIP-55, SOL, XMR, LTC, DOGE, BCH and
   more, ported from ReconAnything's cp_* pack validators), BIP-39
   seed phrases (full checksum validation against the official 2048
   wordlist, sliding-window so seeds buried in prose are found),
   private keys (context-gated), exchange/RPC API keys, and
   cryptojacking/miner indicators.
2. **Pull from ReconAnything** - imports crypto findings (cp_* plugins
   plus wallet/seed/key/miner-tagged findings) from recent runs.
   Idempotent: re-pulling a run imports nothing twice (fingerprint
   dedupe, sha256 of type+value).
3. **URL scan** - paste any URL (webpage, GitHub file, explorer page,
   docs). Fetched read-only, artifacts extracted, and crypto-relevant
   outbound links plus same-host pages followed one level deep
   (max 25 pages). Shows pages scanned / artifacts / new vs dupe.
4. **Blockchain pull** - paste a wallet address, an explorer URL
   (blockstream.info, etherscan.io, solscan.io, blockchain.com...),
   or a tx hash. Pulls balance + tokens, the last ~25 transactions,
   and every counterparty address (depth 1) as findings.
   "1 address in, N findings out."

**Balances are core, not a side feature.** Every address that lands
is auto-enriched in the background from keyless public sources:
BTC (blockstream.info), LTC (litecoinspace.org), DOGE (dogechain.info),
ETH (public RPC + top ERC-20 balances: USDT, USDC, DAI, WBTC, LINK,
UNI, WETH), SOL (public RPC + SPL token accounts). USD values via
CoinGecko, with price + fetched_at stored per address and a manual
refresh. The dashboard headlines **Total exposed value found**, has a
**richest wallets** view, and the table sorts by balance USD.
Monero balances are **not public** without a view key, and lookup
failures show as "lookup failed" - never as a fake zero.

**Security rule (hard):** secret material (seed phrases, private
keys, API secrets) is **never stored in full**. Only a masked preview
(first 6 + last 4 for keys, first 2 words + word count for seeds) and
the sha256 fingerprint are kept. Addresses are public data and are
stored in full.

**Dashboard:** counts by chain/type/severity, filterable table
(search, chain, type, source, status, balance sort), finding detail
drawer with token breakdown and status changer, JSON + CSV export
formatted for bug bounty reports.

## Non-goals (deliberately NOT built)

- No wallet import
- No transaction building or signing
- No sweeping or moving funds
- No key generation

This app catalogues findings only.

## Run it

```bash
pip install -r requirements.txt
CRYPTO_FINDINGS_CODE=<code> RECON_ACCESS_CODE=<reconanything code> \
  uvicorn app.main:app --port 8000
```

Env vars: `CRYPTO_FINDINGS_CODE` (gate), `RECON_ACCESS_CODE`
(ReconAnything pull), `RECON_BASE` (default
https://recon-anything.onrender.com), `CRYPTO_FINDINGS_DB`
(SQLite path, default ./findings.db).

## Deploy

`render.yaml` is included (web service, Python). Create the service
from this repo in Render and set `CRYPTO_FINDINGS_CODE` and
`RECON_ACCESS_CODE` in its env. Note: free-tier ephemeral disk means
the SQLite DB resets on redeploy; attach a persistent disk or point
`CRYPTO_FINDINGS_DB` at one for durable storage.

## Tests

```bash
python3 -m pytest tests/ -q   # 27 tests, all network mocked
```

Parser vectors are checksum-valid AND checksum-invalid cases per
chain (BIP-173/350, EIP-55, Monero and BIP-39 test vectors), plus
dedupe, masking, ReconAnything pull, balance enrichment (success,
failure-not-zero, XMR-not-public, USD math), auto-enrich on ingest,
and URL/blockchain ingest fixtures.
