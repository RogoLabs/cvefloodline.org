"""CISA Known Exploited Vulnerabilities catalog (current snapshot).

We keep each entry's ``dateAdded`` so the site can show KEV *cadence* (when CISA
actually flags exploitation) and the disclosure->KEV lag, instead of pretending
the current catalog was knowable on every historical day. KEV has no
point-in-time archive, so ``dateAdded`` is the best available proxy.
"""

from __future__ import annotations

import logging
from datetime import date

from . import sources
from .http import get

log = logging.getLogger("floodline")


def load_kev() -> tuple[dict[str, str], str]:
    """Return ``({cveID: dateAdded(YYYY-MM-DD)}, catalog_release_date)``."""
    resp = get(sources.KEV_URL)
    data = resp.json()
    added: dict[str, str] = {}
    for v in data.get("vulnerabilities", []):
        cve = v.get("cveID")
        if cve:
            added[cve] = (v.get("dateAdded") or "")[:10]
    catalog_date = data.get("dateReleased", "")[:10] or date.today().isoformat()
    log.info("KEV: %d entries, catalog %s", len(added), catalog_date)
    return added, catalog_date
