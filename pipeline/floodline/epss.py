"""Point-in-time EPSS access.

Each dated file reflects the EPSS scores *as they were on that day*. We never
reconstruct history from the current snapshot -- that is the whole point.
"""

from __future__ import annotations

import csv
import gzip
import io
import logging
from dataclasses import dataclass
from datetime import date

from . import sources
from .http import get

log = logging.getLogger("floodline")


@dataclass
class EpssDay:
    """One day's point-in-time EPSS scores."""
    date: date
    model_version: str
    scores: dict[str, float]  # cve id -> epss probability (0..1)


def _parse_comment(line: str) -> str:
    """Pull model_version out of '#model_version:v2025.03.14,score_date:...'."""
    line = line.lstrip("#").strip()
    for part in line.split(","):
        key, _, value = part.partition(":")
        if key.strip() == "model_version":
            return value.strip()
    return ""


def load_epss(day: date, keep: set[str] | None = None) -> EpssDay:
    """Download and parse the dated EPSS file for ``day``.

    Format: a leading ``#model_version:...,score_date:...`` comment, a
    ``cve,epss,percentile`` header, then rows. Raises if the file is missing
    (the caller decides whether that day is skippable).

    ``keep`` restricts retained scores to that set of CVE ids. The full file is
    ~327k rows; the window only needs the few thousand CVEs published in it, so
    filtering keeps memory bounded across a 95-day bootstrap.
    """
    url = sources.EPSS_RAW_URL.format(year=day.year, date=day.isoformat())
    resp = get(url)
    raw = gzip.decompress(resp.content)
    text = io.StringIO(raw.decode("utf-8"))

    model_version = ""
    scores: dict[str, float] = {}
    for row in csv.reader(text):
        if not row:
            continue
        first = row[0]
        if first.startswith("#"):
            model_version = _parse_comment(first)
            continue
        if first == "cve":  # header
            continue
        if len(row) < 2:
            continue
        if keep is not None and first not in keep:
            continue
        try:
            scores[first] = float(row[1])
        except ValueError:
            continue
    log.info("EPSS %s: %d scores, model %s", day, len(scores), model_version or "?")
    return EpssDay(date=day, model_version=model_version, scores=scores)
