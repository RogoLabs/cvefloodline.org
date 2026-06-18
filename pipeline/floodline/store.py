"""Read, merge, trim, validate, and write the data layer.

Two files:
- ``data/cohorts.json``, raw per-day CVE-id cohorts (the recompute substrate;
  not read by the frontend). Lets the daily job fill maturation horizons as they
  become observable without re-downloading every delta.
- ``data/floodline.json``, the aggregated layer the frontend reads.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from . import sources

log = logging.getLogger("floodline")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def output_path() -> Path:
    return repo_root() / sources.OUTPUT_PATH


def cohorts_path() -> Path:
    return repo_root() / sources.COHORTS_PATH


def load() -> dict | None:
    path = output_path()
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def load_cohorts() -> dict[str, list[str]]:
    path = cohorts_path()
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def write_cohorts(cohorts: dict) -> None:
    """Persist {date: set_of_cve_ids}. Keys may be date objects or ISO strings."""
    path = cohorts_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    norm = {(d.isoformat() if hasattr(d, "isoformat") else str(d)): sorted(ids)
            for d, ids in cohorts.items()}
    serializable = {d: norm[d] for d in sorted(norm)}
    tmp = path.with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(serializable, fh, separators=(",", ":"))
        fh.write("\n")
    os.replace(tmp, path)
    log.info("wrote %s (%d cohort-days)", path, len(serializable))


def existing_dates(doc: dict | None) -> set[str]:
    if not doc:
        return set()
    return {d["date"] for d in doc.get("days", [])}


class ValidationError(Exception):
    """Raised when a computed document fails sanity checks; aborts the write."""


def validate(doc: dict) -> None:
    days = doc.get("days", [])
    if not days:
        raise ValidationError("no days")
    if len(days) > sources.WINDOW_DAYS:
        raise ValidationError(f"{len(days)} days exceeds window {sources.WINDOW_DAYS}")
    dates = [d["date"] for d in days]
    if dates != sorted(dates):
        raise ValidationError("days not sorted ascending")
    if len(set(dates)) != len(dates):
        raise ValidationError("duplicate dates")
    nonzero = sum(1 for d in days if d["total"] > 0)
    if nonzero < 0.8 * len(days):
        raise ValidationError(f"only {nonzero}/{len(days)} days have CVEs (suspicious)")
    for d in days:
        if d["total"] < 0:
            raise ValidationError(f"negative total on {d['date']}")
        if "maturation" not in d or "0" not in d["maturation"]:
            raise ValidationError(f"missing maturation on {d['date']}")
        counts = [d["thresholds"][str(t)] for t in sources.THRESHOLDS]
        if any(counts[i] < counts[i + 1] for i in range(len(counts) - 1)):
            raise ValidationError(f"threshold counts not non-increasing on {d['date']}")
        if d["thresholds"]["10"] > d["total"]:
            raise ValidationError(f"flood>total on {d['date']}")


def _summary(days: list[dict]) -> dict:
    """Pre-computed headline numbers (also used for the static OG card).

    The matured figures use the fixed MATURE_HORIZON and only count days old
    enough to have observed it -- an apples-to-apples comparison, never "today's
    EPSS against a cohort published yesterday."
    """
    total = sum(d["total"] for d in days)
    backfilled = sum(d["backfilled"] for d in days)
    kev = sum(d["kev"] for d in days)
    cross0 = sum(d["thresholds"]["10"] for d in days)

    mh = str(sources.MATURE_HORIZON)
    eligible = [d for d in days if d["maturation"].get(mh) is not None]
    cross_mat = sum(d["maturation"][mh]["thresholds"]["10"] for d in eligible)
    eligible_total = sum(d["total"] for d in eligible)
    return {
        "total": total,
        "backfilled": backfilled,
        "net_total": total - backfilled,
        "kev": kev,
        "cross10_pit": cross0,
        "mature_horizon": sources.MATURE_HORIZON,
        "cross10_matured": cross_mat,
        "matured_eligible_days": len(eligible),
        "matured_eligible_total": eligible_total,
    }


def write(days: list[dict], kev_snapshot_date: str, matured_meta: dict) -> Path:
    """Merge, sort, trim to WINDOW_DAYS, validate, and write atomically.

    ``matured_meta`` carries provenance for the latest EPSS file used in any
    "today's EPSS" lookups (``{"date": ..., "model_version": ...}``).
    """
    by_date: dict[str, dict] = {}
    for record in days:
        by_date[record["date"]] = record

    ordered = sorted(by_date.values(), key=lambda d: d["date"])
    newest = date.fromisoformat(ordered[-1]["date"])
    cutoff = (newest - timedelta(days=sources.WINDOW_DAYS - 1)).isoformat()
    trimmed = [d for d in ordered if d["date"] >= cutoff][-sources.WINDOW_DAYS:]

    doc = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_days": sources.WINDOW_DAYS,
        "days_present": len(trimmed),
        "horizons": sources.HORIZONS,
        "mature_horizon": sources.MATURE_HORIZON,
        "kev_snapshot_date": kev_snapshot_date,
        "latest_epss_date": matured_meta.get("date"),
        "latest_epss_model_version": matured_meta.get("model_version"),
        "summary": _summary(trimmed),
        "days": trimmed,
    }
    validate(doc)

    path = output_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)
    log.info("wrote %s (%d days, generated %s)", path, len(trimmed), doc["generated"])
    return path
