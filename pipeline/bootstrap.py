#!/usr/bin/env python3
"""One-time seed of data/cohorts.json + data/floodline.json (V2).

Stitches cvelistV5 end-of-day deltas to get each day's published CVEs (the
cohorts), persists them, then scores every cohort against EPSS at the maturation
horizons (D+0/+7/+30/+90) and the current KEV catalog, and writes the aggregated
floodline file. Only days whose delta was actually fetched are written.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timedelta, timezone

from floodline import build, cves, store
from floodline.sources import BOOTSTRAP_DAYS, SETTLE_DAYS

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("floodline")


def main() -> int:
    today = datetime.now(timezone.utc).date()
    last_day = today - timedelta(days=SETTLE_DAYS)
    first_day = today - timedelta(days=BOOTSTRAP_DAYS)
    targets = [first_day + timedelta(days=i) for i in range((last_day - first_day).days + 1)]
    log.info("bootstrap: seeding %s .. %s", first_day, last_day)

    published, fetched, meta = cves.published_by_day(targets)
    cohorts = {d: published.get(d, set()) for d in fetched}
    if not cohorts:
        log.error("no cvelistV5 releases fetched; aborting")
        return 1

    records, kev_date, matured_meta = build.build(cohorts, meta, today)

    store.write_cohorts(cohorts)
    store.write(records, kev_date, matured_meta)
    return 0


if __name__ == "__main__":
    sys.exit(main())
