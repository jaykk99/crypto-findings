"""URL ingestion: fetch a page read-only, extract crypto artifacts,
follow crypto-relevant links one level deep (max 25 pages total).

Public GETs only. No credentials, no form submissions, no POSTs.
GitHub blob pages, explorer pages, docs pages all work the same way:
whatever artifact the parser can checksum-verify in the text counts.
"""
from __future__ import annotations

import re
import urllib.request
from urllib.parse import urljoin, urlparse

from . import db
from .parser import extract

MAX_PAGES = 25
MAX_CHARS = 500_000
CRYPTO_LINK_HINTS = ("address", "wallet", "token", "contract", "tx/",
                     "account", "crypto", "coin", "swap", "pool")


def fetch_text(url: str, timeout: int = 20) -> str:
    req = urllib.request.Request(
        url, headers={"User-Agent": "crypto-findings/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read(MAX_CHARS * 2)
    return raw.decode("utf-8", "replace")[:MAX_CHARS]


_HREF = re.compile(r'href=["\']([^"\']+)["\']', re.I)


def harvest_links(page_url: str, html: str) -> list:
    host = urlparse(page_url).netloc
    out, seen = [], set()
    for m in _HREF.finditer(html):
        full = urljoin(page_url, m.group(1))
        if not full.startswith(("http://", "https://")):
            continue
        if full in seen:
            continue
        seen.add(full)
        p = urlparse(full)
        same_host = p.netloc == host
        cryptoish = any(h in p.path.lower() for h in CRYPTO_LINK_HINTS)
        if same_host or (cryptoish and ("scan" in p.netloc
                                        or "explorer" in p.netloc
                                        or "blockstream" in p.netloc
                                        or "blockchain" in p.netloc)):
            out.append(full)
    return out


def _import_text(text: str, source_url: str) -> tuple:
    host = urlparse(source_url).netloc or source_url
    arts = extract(text)
    new = sum(1 for a in arts
              if db.upsert(a, source="url", target=host))
    return len(arts), new


def ingest_url(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    scanned, queue, seen_pages = [], [url], set()
    total_found = total_new = 0
    depth_of = {url: 0}
    while queue and len(scanned) < MAX_PAGES:
        page = queue.pop(0)
        if page in seen_pages:
            continue
        seen_pages.add(page)
        try:
            text = fetch_text(page)
        except Exception as e:
            scanned.append({"url": page, "error": str(e)})
            continue
        scanned.append({"url": page})
        # artifacts hidden inside link URLs themselves (explorer links)
        found, new = _import_text(text + " " + " ".join(
            _HREF.findall(text)), page)
        total_found += found
        total_new += new
        if depth_of.get(page, 0) == 0:
            for link in harvest_links(page, text):
                if link not in seen_pages and len(queue) < MAX_PAGES:
                    depth_of[link] = 1
                    queue.append(link)
    return {"ok": True, "mode": "url", "pages_scanned": scanned,
            "pages_count": len([s for s in scanned if "error" not in s]),
            "artifacts_found": total_found, "imported_new": total_new,
            "duplicates": total_found - total_new}
