"""CVE publication volume (the "rain") from cvelistV5 end-of-day deltas.

We never full-clone the ~200k-file repo. cvelistV5 publishes one "End of Day"
GitHub release per date whose single delta zip holds every CVE added or updated
that day. The release tag and asset name are deterministic, so we fetch the zip
directly and bucket records by ``datePublished``. Bucketing across whichever
deltas we fetched makes day-boundary placement self-correcting and naturally
de-duplicates (a CVE counts once, on its publication date).
"""

from __future__ import annotations

import io
import json
import logging
import zipfile
from collections import defaultdict
from collections.abc import Iterable
from datetime import date

from . import sources
from .http import get

log = logging.getLogger("floodline")


def _eod_url(day: date) -> str:
    iso = day.isoformat()
    tag = sources.CVELIST_EOD_TAG.format(date=iso)
    asset = sources.CVELIST_EOD_ASSET.format(date=iso)
    return sources.CVELIST_EOD_DOWNLOAD.format(tag=tag, asset=asset)


def _published_date(record: dict) -> date | None:
    meta = record.get("cveMetadata", {})
    if meta.get("state") != "PUBLISHED":
        return None
    raw = meta.get("datePublished")
    if not raw or len(raw) < 10:
        return None
    try:
        return date.fromisoformat(raw[:10])
    except ValueError:
        return None


# Skip absurdly large zip members (decompression-bomb guard on third-party zips).
_MAX_MEMBER_BYTES = 8 * 1024 * 1024


def _meta_of(record: dict) -> dict:
    """Lightweight naming metadata (vendor/product/title) for one CVE record."""
    cna = record.get("containers", {}).get("cna", {})
    vendor = product = ""
    for aff in cna.get("affected", []) or []:
        v = (aff.get("vendor") or "").strip()
        p = (aff.get("product") or "").strip()
        if v and v.lower() not in ("n/a", "unknown"):
            vendor, product = v, p
            break
        if not product and p:
            product = p
    title = (cna.get("title") or "").strip()
    return {"vendor": vendor, "product": product, "title": title}


def _scan_delta(
    blob: bytes,
    buckets: dict[date, set[str]],
    meta: dict[str, dict],
    wanted: set[date],
) -> None:
    """Add every PUBLISHED record in this delta zip to ``buckets`` keyed on its
    publication date (restricted to ``wanted``), and capture naming metadata."""
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for info in zf.infolist():
            name = info.filename
            if not name.endswith(".json"):
                continue
            if info.file_size > _MAX_MEMBER_BYTES:
                log.warning("skipping oversized zip member %s (%d bytes)", name, info.file_size)
                continue
            try:
                record = json.loads(zf.read(name))
            except (json.JSONDecodeError, KeyError):
                continue
            pub = _published_date(record)
            if pub is None or pub not in wanted:
                continue
            cve_id = record.get("cveMetadata", {}).get("cveId")
            if cve_id:
                buckets[pub].add(cve_id)
                meta[cve_id] = _meta_of(record)


def published_by_day(
    dates: Iterable[date],
) -> tuple[dict[date, set[str]], set[date], dict[str, dict]]:
    """Return ``({date: {cve_ids}}, fetched_dates, {cve_id: meta})``.

    Downloads each date's end-of-day delta (idempotent, deterministic URL). A
    missing release is logged and that day is OMITTED from ``fetched_dates`` so
    the caller can distinguish "no release yet" (must not be finalized) from a
    genuine zero-publication day. ``meta`` carries naming info (vendor/product/
    title) for the published CVEs.
    """
    wanted = set(dates)
    buckets: dict[date, set[str]] = defaultdict(set)
    meta: dict[str, dict] = {}
    fetched: set[date] = set()
    for day in sorted(wanted):
        url = _eod_url(day)
        try:
            resp = get(url, retries=2)
        except Exception as exc:  # noqa: BLE001 -- missing/forbidden release
            log.warning("no end-of-day delta for %s (%s)", day, exc)
            continue
        fetched.add(day)
        _scan_delta(resp.content, buckets, meta, wanted)
        log.info("cvelistV5 %s: %d CVEs published", day, len(buckets.get(day, ())))
    return dict(buckets), fetched, meta
