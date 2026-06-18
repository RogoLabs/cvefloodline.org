#!/usr/bin/env python3
"""Daily update of data/cohorts.json + data/floodline.json (V2).

Loads the persisted cohorts, fetches any window days not yet captured (catch-up
after missed runs / late releases), then recomputes the whole 90-day window from
cohorts. Because EPSS/CVE horizon files are immutable, recomputation is
idempotent; recomputing also lets maturation cells fill in as horizons become
observable and keeps KEV current. A day with no cvelistV5 release yet is simply
absent (never finalized as an empty zero). Exits nonzero only on fatal error.
"""

from __future__ import annotations

import logging
import sys
from datetime import date, datetime, timedelta, timezone

from floodline import build, cves, store
from floodline.sources import SETTLE_DAYS, WINDOW_DAYS

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("floodline")


def main() -> int:
    today = datetime.now(timezone.utc).date()
    newest = today - timedelta(days=SETTLE_DAYS)
    oldest = today - timedelta(days=WINDOW_DAYS - 1)

    doc = store.load()
    stored = store.load_cohorts()
    if doc is None or not stored:
        log.error("no existing data; run bootstrap.py first")
        return 1

    cohorts: dict[date, set[str]] = {
        date.fromisoformat(k): set(v)
        for k, v in stored.items()
        if oldest <= date.fromisoformat(k) <= newest
    }

    # Catch up any window day we don't yet have a cohort for.
    missing = [
        oldest + timedelta(days=i)
        for i in range((newest - oldest).days + 1)
        if (oldest + timedelta(days=i)) not in cohorts
    ]
    meta: dict[str, dict] = {}
    if missing:
        log.info("fetching %d missing day(s): %s .. %s", len(missing), missing[0], missing[-1])
        published, fetched, meta = cves.published_by_day(missing)
        for d in fetched:
            cohorts[d] = published.get(d, set())

    # Reuse prior naming metadata (vendor/title) for days whose delta we didn't refetch.
    for day in doc.get("days", []):
        for n in day.get("named", []):
            meta.setdefault(n["id"], {
                "vendor": n.get("vendor", ""),
                "product": n.get("product", ""),
                "title": n.get("title", ""),
            })

    if not cohorts:
        log.error("no cohorts in window; aborting")
        return 1

    records, kev_date, matured_meta = build.build(cohorts, meta, today)

    store.write_cohorts(cohorts)
    store.write(records, kev_date, matured_meta)
    return 0


if __name__ == "__main__":
    sys.exit(main())
