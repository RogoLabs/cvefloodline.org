"""Unit tests for trim + validation (no network)."""

from datetime import date, timedelta

import pytest

from floodline import sources, store


def _cell():
    return {
        "p90": 0.001, "max": 0.01, "coverage": 1.0,
        "thresholds": {str(t): max(0, 5 - i) for i, t in enumerate(sources.THRESHOLDS)},
    }


def _day(d: date, total=100):
    c = _cell()
    return {
        "date": d.isoformat(),
        "epss_model_version": "v4",
        "total": total,
        "backfilled": 0,
        "net_total": total,
        "kev": 0,
        "kev_lag_median": None,
        "epss_p90": c["p90"],
        "epss_max": c["max"],
        "coverage": c["coverage"],
        "thresholds": c["thresholds"],
        "maturation": {"0": c, "7": None, "30": None, "90": None},
        "named": [],
    }


def test_validate_rejects_increasing_thresholds():
    d = _day(date(2026, 1, 1))
    d["thresholds"]["95"] = 999
    with pytest.raises(store.ValidationError):
        store.validate({"days": [d]})


def test_validate_rejects_missing_maturation():
    d = _day(date(2026, 1, 1))
    del d["maturation"]
    with pytest.raises(store.ValidationError):
        store.validate({"days": [d]})


def test_validate_rejects_mostly_zero():
    days = [_day(date(2026, 1, 1) + timedelta(days=i), total=0) for i in range(10)]
    with pytest.raises(store.ValidationError):
        store.validate({"days": days})


def test_write_trims_to_window_anchored_to_newest(tmp_path, monkeypatch):
    out = tmp_path / "floodline.json"
    monkeypatch.setattr(store, "output_path", lambda: out)

    start = date(2026, 1, 1)
    days = [_day(start + timedelta(days=i)) for i in range(sources.WINDOW_DAYS + 20)]
    store.write(days, "2026-06-15", {"date": "2026-06-15", "model_version": "v4"})

    import json
    doc = json.loads(out.read_text())
    assert doc["days_present"] == sources.WINDOW_DAYS
    assert doc["days"][-1]["date"] == days[-1]["date"]
    span = (date.fromisoformat(doc["days"][-1]["date"])
            - date.fromisoformat(doc["days"][0]["date"])).days
    assert span == sources.WINDOW_DAYS - 1
    assert "summary" in doc and doc["summary"]["total"] > 0
