"""Constants and source URLs for the CVE Floodline pipeline.

Everything tunable lives here so the methodology is auditable at a glance.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Methodology constants
# ---------------------------------------------------------------------------

# EPSS flood-line thresholds, as whole percentages. The frontend slider snaps
# to exactly these 18 values; each day's record stores a count per threshold.
THRESHOLDS: list[int] = [10, 15, 20, 25, 30, 35, 40, 45, 50, 55,
                         60, 65, 70, 75, 80, 85, 90, 95]

# Days of observed data shown in the rolling window.
WINDOW_DAYS = 90

# Days seeded by the one-time bootstrap (a little more than the window so the
# window is full immediately and there is slack for the settle lag).
BOOTSTRAP_DAYS = 95

# A CVE published on day D usually is not yet scored by EPSS on day D (EPSS
# lags publication by 1-3 days). We therefore finalize each day only once it
# is SETTLE_DAYS old, so the carry-forward fill has real data to draw on, and
# we never have to recompute a day. The newest point shown is ~SETTLE_DAYS
# stale -- surfaced honestly in the UI's freshness labels.
SETTLE_DAYS = 3

# When a day-D CVE has no EPSS score in day D's file, fall back to the nearest
# available score within +/- FILL_DAYS, preferring the earliest on-or-after D
# (forward fill) before looking backward.
FILL_DAYS = 3

# Maturation: re-score each day's cohort against the EPSS file this many days
# LATER. The story is that exploitability arrives un-priced and develops over
# weeks; these horizons trace that curve. A horizon cell is null until the
# EPSS file at D+horizon exists.
HORIZONS = [0, 7, 30, 90]

# The "matured" comparison used in the headline / slopegraph: a fixed, fully
# comparable maturation period (apples-to-apples across cohorts), NOT "today's
# EPSS" (which would compare cohorts of wildly different ages). Only cohorts at
# least this old contribute to the matured aggregate.
MATURE_HORIZON = 30

# How many of each day's highest-EPSS / KEV CVEs to name in the output.
NAMED_PER_DAY = 5

# ---------------------------------------------------------------------------
# Source URLs
# ---------------------------------------------------------------------------

# Point-in-time EPSS daily archive (empiricalsec/epss_scores).
# Files are organized by year: 2026/epss_scores-YYYY-MM-DD.csv.gz
EPSS_CONTENTS_API = "https://api.github.com/repos/empiricalsec/epss_scores/contents/{year}"
EPSS_RAW_URL = (
    "https://raw.githubusercontent.com/empiricalsec/epss_scores/main/"
    "{year}/epss_scores-{date}.csv.gz"
)

# CVEProject/cvelistV5 publishes a per-day "End of Day" GitHub release whose
# single delta asset holds every CVE added or updated that day. We read those
# and bucket by datePublished -- never the 537 MB full baseline.
CVELIST_RELEASES_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases"
CVELIST_EOD_TAG = "cve_{date}_at_end_of_day"
CVELIST_EOD_ASSET = "{date}_delta_CVEs_at_end_of_day.zip"
CVELIST_EOD_DOWNLOAD = (
    "https://github.com/CVEProject/cvelistV5/releases/download/"
    "{tag}/{asset}"
)

# CISA Known Exploited Vulnerabilities catalog (current snapshot).
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Output paths, relative to the repo root.
OUTPUT_PATH = "data/floodline.json"      # aggregated layer the frontend reads
COHORTS_PATH = "data/cohorts.json"       # raw per-day CVE-id cohorts (recompute substrate)

# HTTP politeness.
USER_AGENT = "cvefloodline.org-pipeline (+https://github.com/jgamblin/cvefloodline.org)"
HTTP_TIMEOUT = 60  # seconds
