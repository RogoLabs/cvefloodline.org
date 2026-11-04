"""Shared record-building: turn cohorts into day records with maturation cells.

Both bootstrap and the daily update call this. The window is small (90 days) and
EPSS/CVE horizon files are immutable, so recomputing the whole window from the
persisted cohorts each run is deterministic and idempotent -- and it lets KEV
counts and maturation cells stay current (fixing the "frozen at finalization"
problem) without re-downloading every delta.
"""

from __future__ import annotations

import logging
from datetime import date, timedelta

from . import cves, kev, sources
from .compute import day_record
from .epss import EpssDay, load_epss

log = logging.getLogger("floodline")


def _needed_epss_dates(cohort_days: list[date], today: date) -> set[date]:
    dates: set[date] = set()
    for d in cohort_days:
        # D+0 fill neighbours.
        for off in range(-sources.FILL_DAYS, sources.FILL_DAYS + 1):
            nd = d + timedelta(days=off)
            if nd <= today:
                dates.add(nd)
        # Maturation horizons that are observable yet.
        for h in sources.HORIZONS:
            hd = d + timedelta(days=h)
            if hd <= today:
                dates.add(hd)
    return dates


_NAME_FIELDS = ("vendor", "product", "title")


def fill_missing_names(records: list[dict]) -> None:
    """Look up vendor/product/title for named CVEs that have none, in place.

    The daily run only holds metadata for days whose delta it fetched this run
    plus CVEs already named. A CVE that becomes notable later (its EPSS climbs
    or it joins KEV) would otherwise be named with a bare CVE id.
    """
    blank = [n for r in records for n in r["named"]
             if not any(n.get(f) for f in _NAME_FIELDS)]
    if not blank:
        return
    found = cves.fetch_meta(sorted({n["id"] for n in blank}))
    for n in blank:
        if n["id"] in found:
            n.update({f: found[n["id"]][f] for f in _NAME_FIELDS})
    log.info("named-CVE metadata: %d blank, %d filled from cvelistV5 records",
             len(blank), sum(1 for n in blank if n["id"] in found))


def build(
    cohorts: dict[date, set[str]],
    meta: dict[str, dict],
    today: date,
) -> tuple[list[dict], str, dict]:
    """Return ``(records, kev_snapshot_date, matured_meta)``."""
    cohort_days = sorted(cohorts)
    keep: set[str] = set()
    for ids in cohorts.values():
        keep |= ids

    cache: dict[date, EpssDay] = {}
    for dt in sorted(_needed_epss_dates(cohort_days, today)):
        try:
            cache[dt] = load_epss(dt, keep=keep)
        except Exception as exc:  # noqa: BLE001
            log.warning("EPSS missing for %s (%s)", dt, exc)
    if not cache:
        raise RuntimeError("no EPSS files could be loaded")

    latest = cache[max(cache)]
    kev_added, kev_date = kev.load_kev()

    records = [
        day_record(d, cohorts[d], meta, cache, kev_added, today)
        for d in cohort_days
    ]
    fill_missing_names(records)
    matured_meta = {"date": latest.date.isoformat(), "model_version": latest.model_version}
    log.info("built %d day records; latest EPSS %s (%s)",
             len(records), latest.date, latest.model_version)
    return records, kev_date, matured_meta
