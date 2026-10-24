"""Crypto Findings - standalone collector for crypto scan findings.

Ingest by paste/upload, pull from ReconAnything, dedupe, mask secrets,
enrich addresses with public balance data, export for bounty reports.
Cataloguing only: no wallet import, no signing, no moving funds.
"""
from __future__ import annotations

import csv
import io
import json
import os
import secrets as pysecrets
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from . import chain_ingest, db, enrich, recon, url_ingest
from .parser import extract, Artifact

CODE = os.environ.get("CRYPTO_FINDINGS_CODE", "")
STATIC = os.path.join(os.path.dirname(__file__), "..", "static")
COOKIE = "cf_code"


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="Crypto Findings", lifespan=_lifespan)


def _authed(request: Request) -> bool:
    if not CODE:
        return True  # local dev without a code set
    return (request.cookies.get(COOKIE) == CODE
            or request.headers.get("x-access-code") == CODE
            or request.query_params.get("code") == CODE)


def _deny():
    return JSONResponse({"error": "access code required"}, status_code=401)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if not _authed(request):
        return HTMLResponse(_login_html(), status_code=401)
    with open(os.path.join(STATIC, "index.html")) as f:
        resp = HTMLResponse(f.read())
    if request.query_params.get("code") == CODE and CODE:
        resp.set_cookie(COOKIE, CODE, httponly=True, max_age=86400 * 30)
    return resp


def _login_html() -> str:
    return """<!doctype html><meta charset=utf-8><title>Crypto Findings</title>
<body style="background:#0b0e14;color:#e6e6e6;font-family:system-ui;padding:40px">
<h2>Crypto Findings</h2><p>Enter the access code:</p>
<input id=c type=password style="padding:8px;background:#161b26;color:#fff;border:1px solid #333">
<button onclick="document.cookie='cf_code='+document.getElementById('c').value+';path=/';location.reload()">Enter</button>
</body>"""


@app.post("/api/login")
async def login(request: Request):
    body = await request.json()
    if CODE and pysecrets.compare_digest(str(body.get("code", "")), CODE):
        resp = JSONResponse({"ok": True})
        resp.set_cookie(COOKIE, CODE, httponly=True, max_age=86400 * 30)
        return resp
    return JSONResponse({"ok": False}, status_code=401)


@app.get("/api/stats")
def api_stats(request: Request):
    if not _authed(request):
        return _deny()
    return db.stats()


def enrich_one(fid: int) -> None:
    """Background auto-enrichment: fetch balance for one address row."""
    f = db.get(fid)
    if not f or f["type"] != "address":
        return
    res = enrich.lookup(f["chain"], f["value"])
    db.set_balance(fid, json.dumps(res))


def enrich_pending() -> None:
    for f in db.unenriched_addresses():
        enrich_one(f["id"])


@app.get("/api/findings")
def api_findings(request: Request, search: str = "", chain: str = "",
                 type: str = "", source: str = "", status: str = "",
                 sort: str = ""):
    if not _authed(request):
        return _deny()
    return {"findings": db.list_findings(search, chain, type, source,
                                         status, sort=sort)}


@app.get("/api/richest")
def api_richest(request: Request):
    if not _authed(request):
        return _deny()
    return {"richest": db.richest(10),
            "total_exposed_usd": db.total_exposed_usd()}


@app.get("/api/findings/{fid}")
def api_finding(request: Request, fid: int):
    if not _authed(request):
        return _deny()
    f = db.get(fid)
    return f or JSONResponse({"error": "not found"}, status_code=404)


@app.post("/api/findings/{fid}/status")
async def api_status(request: Request, fid: int):
    if not _authed(request):
        return _deny()
    body = await request.json()
    ok = db.set_status(fid, str(body.get("status", "")))
    return {"ok": ok}


@app.post("/api/ingest")
async def api_ingest(request: Request, background: BackgroundTasks,
                     text: str = Form(""),
                     file: UploadFile = File(None), target: str = Form("")):
    if not _authed(request):
        return _deny()
    if file is not None and file.filename:
        text = (await file.read()).decode("utf-8", "replace")
    arts = extract(text or "")
    new = sum(1 for a in arts if db.upsert(a, source="paste", target=target))
    background.add_task(enrich_pending)  # auto-enrich new addresses
    return {"parsed": len(arts), "imported_new": new,
            "duplicates": len(arts) - new}


@app.post("/api/manual")
async def api_manual(request: Request, background: BackgroundTasks):
    if not _authed(request):
        return _deny()
    body = await request.json()
    arts = extract(str(body.get("value", "")))
    if arts:
        a = arts[0]
    else:
        a = Artifact(str(body.get("type", "address")),
                     str(body.get("chain", "")), str(body.get("value", "")),
                     secret=body.get("type") in db.SECRET_TYPES,
                     severity=str(body.get("severity", "medium")),
                     label="manual entry")
    new = db.upsert(a, source="manual", target=str(body.get("target", "")),
                    note=str(body.get("note", "")))
    background.add_task(enrich_pending)
    return {"ok": True, "imported_new": 1 if new else 0}


@app.post("/api/pull")
async def api_pull(request: Request, background: BackgroundTasks):
    if not _authed(request):
        return _deny()
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    out = recon.pull(limit=int(body.get("limit", 5)))
    background.add_task(enrich_pending)
    return out


@app.post("/api/ingest-url")
async def api_ingest_url(request: Request, background: BackgroundTasks):
    if not _authed(request):
        return _deny()
    body = await request.json()
    out = url_ingest.ingest_url(str(body.get("url", "")))
    background.add_task(enrich_pending)
    return out


@app.post("/api/ingest-chain")
async def api_ingest_chain(request: Request, background: BackgroundTasks):
    if not _authed(request):
        return _deny()
    body = await request.json()
    out = chain_ingest.ingest_chain(str(body.get("input", "")))
    background.add_task(enrich_pending)
    return out


@app.post("/api/findings/{fid}/balance")
def api_balance(request: Request, fid: int):
    if not _authed(request):
        return _deny()
    f = db.get(fid)
    if not f:
        return JSONResponse({"error": "not found"}, status_code=404)
    if f["type"] != "address":
        return {"ok": False, "error": "balance lookup is for addresses only"}
    res = enrich.lookup(f["chain"], f["value"])
    if res.get("ok"):
        db.set_balance(fid, json.dumps(res))
    return res


def _export_rows():
    return db.list_findings(limit=100000)


@app.get("/api/export.json")
def export_json(request: Request):
    if not _authed(request):
        return _deny()
    rows = [{k: r[k] for k in ("type", "chain", "masked_value", "fingerprint",
                               "source", "target", "severity", "label",
                               "status", "first_seen", "last_seen")}
            for r in _export_rows()]
    return JSONResponse({"findings": rows},
                        headers={"Content-Disposition":
                                 "attachment; filename=crypto-findings.json"})


@app.get("/api/export.csv")
def export_csv(request: Request):
    if not _authed(request):
        return _deny()
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ("type", "chain", "masked_value", "fingerprint", "source",
            "target", "severity", "label", "status", "first_seen", "last_seen")
    w.writerow(cols)
    for r in _export_rows():
        w.writerow([r[c] for c in cols])
    return PlainTextResponse(buf.getvalue(), media_type="text/csv",
                             headers={"Content-Disposition":
                                      "attachment; filename=crypto-findings.csv"})
