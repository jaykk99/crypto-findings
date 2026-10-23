"""Pull crypto findings from ReconAnything runs (read-only GETs).

A finding counts as crypto-related when:
- its plugin id starts with cp_ (the crypto pack), or
- its category/key/source mentions wallet/seed/miner/crypto, or
- the parser extracts a crypto artifact from its value/evidence text
  (this also catches secrets the pack plugins redacted in evidence).
Idempotency comes from db.upsert fingerprint dedupe.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Optional

from . import db
from .parser import extract, Artifact

BASE = os.environ.get("RECON_BASE", "https://recon-anything.onrender.com")

_TAG_WORDS = ("wallet", "seed", "miner", "mining", "crypto", "private_key",
              "api_key", "mnemonic", "keystore", "stratum", "cryptojack")


def _get(path: str, code: str, timeout: int = 60):
    req = urllib.request.Request(BASE + path,
                                 headers={"User-Agent": "crypto-findings/1.0"})
    sep = "&" if "?" in path else "?"
    with urllib.request.urlopen(f"{BASE}{path}{sep}code={code}",
                                timeout=timeout) as r:
        return json.loads(r.read().decode())


def fetch_runs(code: str, limit: int = 10) -> list:
    d = _get(f"/api/runs?limit={limit}", code)
    return d.get("runs", [])


def fetch_run(code: str, run_id: str) -> dict:
    return _get(f"/api/runs/{run_id}", code)


def is_crypto_finding(f: dict) -> bool:
    plugin = str(f.get("plugin") or "")
    blob = " ".join(str(f.get(k) or "") for k in
                    ("category", "key", "source")).lower()
    if plugin.startswith("cp_"):
        return True
    return any(w in blob for w in _TAG_WORDS)


def _target_host(run: dict, f: dict) -> str:
    tid = f.get("target_id")
    for t in run.get("targets") or []:
        if t.get("id") == tid:
            return t.get("normalized") or t.get("raw") or ""
    if f.get("source_url"):
        return f["source_url"]
    targets = run.get("targets") or []
    return (targets[0].get("normalized") if targets else "") or ""


def import_run(run: dict, run_id: str) -> dict:
    """Import crypto artifacts from one run payload. Returns counts."""
    new = dup = parsed = 0
    targets = {t.get("id"): t for t in run.get("targets") or []}
    for f in run.get("findings") or []:
        text = " ".join(str(f.get(k) or "") for k in ("value", "source"))
        ev = f.get("evidence")
        if isinstance(ev, dict):
            text += " " + " ".join(str(x) for x in ev.values()
                                    if isinstance(x, str))
        arts = extract(text)
        tagged = is_crypto_finding(f)
        if not arts and not tagged:
            continue
        host = _target_host(run, f)
        if not arts:
            # Tagged crypto finding with no parseable artifact (e.g. a
            # miner-kit signature): store the finding value itself.
            val = str(f.get("value") or "")[:200]
            if not val:
                continue
            arts = [Artifact("miner_indicator" if "miner" in text.lower()
                             or "miner" in str(f.get("key", "")).lower()
                             else "indicator",
                             "", val, secret=False, severity="medium",
                             label=f"ReconAnything {f.get('plugin')} finding")]
        for a in arts:
            parsed += 1
            sev = f.get("evidence", {}).get("severity") if isinstance(
                f.get("evidence"), dict) else None
            if sev in ("low", "medium", "high", "critical"):
                a.severity = sev
            if db.upsert(a, source=f"recon:{run_id}", target=host):
                new += 1
            else:
                dup += 1
    return {"run_id": run_id, "artifacts_seen": parsed,
            "imported_new": new, "duplicates": dup,
            "targets_in_run": len(targets)}


def pull(code: Optional[str] = None, limit: int = 5) -> dict:
    code = code or os.environ.get("RECON_ACCESS_CODE", "")
    if not code:
        return {"ok": False, "error": "RECON_ACCESS_CODE not set on the server"}
    runs = fetch_runs(code, limit=limit)
    out = {"ok": True, "runs": []}
    for r in runs:
        rid = r.get("id")
        if not rid:
            continue
        try:
            full = fetch_run(code, rid)
            out["runs"].append(import_run(full, rid))
        except Exception as e:
            out["runs"].append({"run_id": rid, "error": str(e)})
    out["imported_new"] = sum(x.get("imported_new", 0) for x in out["runs"])
    out["duplicates"] = sum(x.get("duplicates", 0) for x in out["runs"])
    return out
