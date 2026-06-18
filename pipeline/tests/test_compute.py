"""Unit tests for the per-day computation (no network)."""

from datetime import date

from floodline.compute import _backfilled, _percentile, _threshold_counts, day_record
from floodline.epss import EpssDay


def test_percentile_interpolates():
    assert _percentile([0.0, 1.0], 0.5) == 0.5
    assert abs(_percentile([0.0, 0.0, 0.0, 1.0], 0.90) - 0.7) < 1e-9
    assert _percentile([], 0.9) == 0.0


def test_threshold_counts_non_increasing():
    counts = _threshold_counts([0.05, 0.12, 0.40, 0.96])
    assert counts["10"] == 3 and counts["15"] == 2 and counts["50"] == 1 and counts["95"] == 1
    vals = [counts[str(t)] for t in (10, 30, 50, 95)]
    assert all(vals[i] >= vals[i + 1] for i in range(len(vals) - 1))


def test_backfilled_counts_old_ids():
    assert _backfilled({"CVE-2026-1", "CVE-2024-9", "CVE-2016-20066"}, date(2026, 5, 1)) == 2


def test_day_record_maturation_and_naming():
    day = date(2026, 5, 1)
    today = date(2026, 8, 1)  # all horizons observable
    cohort = {"CVE-2026-1", "CVE-2026-2", "CVE-2026-3"}
    meta = {"CVE-2026-3": {"vendor": "Acme", "product": "Gateway", "title": "RCE"}}
    cache = {
        day: EpssDay(day, "v4", {"CVE-2026-1": 0.02, "CVE-2026-2": 0.01}),
        day.replace(day=8): EpssDay(day.replace(day=8), "v4", {"CVE-2026-3": 0.20}),   # D+7
        day.replace(day=31): EpssDay(day.replace(day=31), "v4", {"CVE-2026-3": 0.80}),  # D+30
    }
    # D+90 = 2026-07-30, not in cache -> null cell.
    kev_added = {"CVE-2026-3": "2026-06-10"}
    rec = day_record(day, cohort, meta, cache, kev_added, today)

    assert rec["total"] == 3
    assert rec["kev"] == 1
    # D+0 cell present; D+7 and D+30 present; D+90 null (no file).
    assert rec["maturation"]["0"] is not None
    assert rec["maturation"]["30"]["max"] == 0.8
    assert rec["maturation"]["90"] is None
    # CVE-2026-3 matures to 0.80 and is KEV -> should be named with peak 0.80.
    named = {n["id"]: n for n in rec["named"]}
    assert "CVE-2026-3" in named
    assert named["CVE-2026-3"]["epss_peak"] == 0.8
    assert named["CVE-2026-3"]["kev"] is True
    assert named["CVE-2026-3"]["vendor"] == "Acme"
    # KEV lag = 2026-06-10 - 2026-05-01 = 40 days.
    assert rec["kev_lag_median"] == 40


def test_day_record_provisional_recent_cohort():
    day = date(2026, 5, 1)
    today = date(2026, 5, 3)  # only D+0 observable
    cohort = {"CVE-2026-1"}
    cache = {day: EpssDay(day, "v4", {"CVE-2026-1": 0.01})}
    rec = day_record(day, cohort, {}, cache, {}, today)
    assert rec["maturation"]["0"] is not None
    assert rec["maturation"]["7"] is None
    assert rec["maturation"]["30"] is None
