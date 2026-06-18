"""Per-day flood-line computation (V2).

For the CVEs published on day D we measure exploitability not just on D but as
it *matures*: we re-score the same cohort against the EPSS files at D+0, D+7,
D+30, D+90 (HORIZONS). The story is that newly disclosed CVEs arrive un-priced
and their EPSS develops over weeks; the horizon cells trace that curve. A cell
is null until the EPSS file at D+horizon exists, so recent cohorts are
explicitly provisional rather than silently flat.

Percentile / max ("high-water mark") are over CVEs that actually have a score
(a low value can't be manufactured by imputing zeros); `coverage` reports the
scored fraction. Threshold *counts* are over the whole cohort (an unscored CVE
has not crossed the line). We also name the day's highest-EPSS / KEV CVEs.
"""

from __future__ import annotations

import re
from datetime import date, timedelta

from . import sources
from .epss import EpssDay

_CVE_YEAR = re.compile(r"CVE-(\d{4})-")


def score_for(cve: str, day: date, cache: dict[date, EpssDay]) -> float | None:
    """Point-in-time EPSS for ``cve`` on ``day`` with nearest-available fill
    (forward first) within +/- FILL_DAYS. Used for the D+0 horizon."""
    same = cache.get(day)
    if same and cve in same.scores:
        return same.scores[cve]
    for offset in range(1, sources.FILL_DAYS + 1):
        ahead = cache.get(day + timedelta(days=offset))
        if ahead and cve in ahead.scores:
            return ahead.scores[cve]
        behind = cache.get(day - timedelta(days=offset))
        if behind and cve in behind.scores:
            return behind.scores[cve]
    return None


def _model_version(day: date, cache: dict[date, EpssDay]) -> str:
    same = cache.get(day)
    if same and same.model_version:
        return same.model_version
    for offset in range(1, sources.FILL_DAYS + 1):
        for cand in (cache.get(day + timedelta(days=offset)),
                     cache.get(day - timedelta(days=offset))):
            if cand and cand.model_version:
                return cand.model_version
    return ""


def _percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = k - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def _threshold_counts(scores: list[float]) -> dict[str, int]:
    return {
        str(t): sum(1 for s in scores if s > t / 100.0)
        for t in sources.THRESHOLDS
    }


def _backfilled(cves: set[str], day: date) -> int:
    n = 0
    for cve in cves:
        m = _CVE_YEAR.match(cve)
        if m and int(m.group(1)) < day.year:
            n += 1
    return n


def _horizon_scores(cve_scores: dict[str, float | None], cohort: set[str]) -> list[float]:
    return [cve_scores[c] for c in cohort if cve_scores.get(c) is not None]


def _cell(scored: list[float], cohort_size: int) -> dict:
    """One maturation cell: high-water mark + threshold crossings + coverage."""
    s = sorted(scored)
    return {
        "p90": round(_percentile(s, 0.90), 5) if s else 0.0,
        "max": round(s[-1], 5) if s else 0.0,
        "coverage": round(len(s) / cohort_size, 4) if cohort_size else 0.0,
        "thresholds": _threshold_counts(s),
    }


def day_record(
    day: date,
    cohort: set[str],
    meta: dict[str, dict],
    cache: dict[date, EpssDay],
    kev_added: dict[str, str],
    today: date,
) -> dict:
    """Build one day's record with a maturation cell per horizon and named CVEs.

    ``meta`` maps cve id -> {vendor, product, title}. ``kev_added`` maps cve id
    -> KEV dateAdded. ``today`` bounds which horizons can exist yet.
    """
    # Score the cohort at each horizon. For D+0 we use the fill; for later
    # horizons we use the exact dated file (null if it doesn't exist yet).
    maturation: dict[str, dict | None] = {}
    per_cve_horizon: dict[str, dict[int, float]] = {c: {} for c in cohort}
    for h in sources.HORIZONS:
        hday = day + timedelta(days=h)
        if hday > today:
            maturation[str(h)] = None  # not yet observable
            continue
        if h == 0:
            scores = {c: score_for(c, day, cache) for c in cohort}
        else:
            f = cache.get(hday)
            if f is None:
                maturation[str(h)] = None
                continue
            scores = {c: f.scores.get(c) for c in cohort}
        for c in cohort:
            v = scores.get(c)
            if v is not None:
                per_cve_horizon[c][h] = v
        maturation[str(h)] = _cell(_horizon_scores(scores, cohort), len(cohort))

    # KEV membership + disclosure->KEV lag (days), only for cohort CVEs.
    kev_members = [c for c in cohort if c in kev_added]
    kev_lags = []
    for c in kev_members:
        try:
            kev_lags.append((date.fromisoformat(kev_added[c]) - day).days)
        except ValueError:
            pass

    # Name the day's most notable CVEs: highest peak EPSS across horizons, plus
    # any KEV member. Peak EPSS = max observed across the available horizons.
    def peak(c: str) -> float:
        hs = per_cve_horizon.get(c) or {}
        return max(hs.values()) if hs else 0.0

    ranked = sorted(cohort, key=lambda c: (c in kev_added, peak(c)), reverse=True)
    named = []
    for c in ranked[: sources.NAMED_PER_DAY]:
        hs = per_cve_horizon.get(c) or {}
        pk = peak(c)
        if pk < 0.05 and c not in kev_added:
            continue  # not notable enough to name
        m = meta.get(c, {})
        named.append({
            "id": c,
            "vendor": m.get("vendor", ""),
            "product": m.get("product", ""),
            "title": m.get("title", ""),
            "epss0": round(hs.get(0, 0.0), 5),
            "epss_peak": round(pk, 5),
            "kev": c in kev_added,
        })

    cell0 = maturation["0"] or {"thresholds": {str(t): 0 for t in sources.THRESHOLDS},
                                "p90": 0.0, "max": 0.0, "coverage": 0.0}
    return {
        "date": day.isoformat(),
        "epss_model_version": _model_version(day, cache),
        "total": len(cohort),
        "backfilled": _backfilled(cohort, day),
        "net_total": len(cohort) - _backfilled(cohort, day),
        "kev": len(kev_members),
        "kev_lag_median": round(sorted(kev_lags)[len(kev_lags) // 2]) if kev_lags else None,
        # Convenience top-level mirror of the D+0 cell (frontend default view).
        "epss_p90": cell0["p90"],
        "epss_max": cell0["max"],
        "coverage": cell0["coverage"],
        "thresholds": cell0["thresholds"],
        "maturation": maturation,
        "named": named,
    }
