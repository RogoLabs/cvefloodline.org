"""Unit tests for naming CVEs that became notable after their delta (no network)."""

from floodline import build, cves


def test_record_url_buckets_by_thousand():
    assert cves.record_url("CVE-2026-65400").endswith("/cves/2026/65xxx/CVE-2026-65400.json")
    assert cves.record_url("CVE-2026-109618").endswith("/cves/2026/109xxx/CVE-2026-109618.json")
    assert cves.record_url("CVE-2026-0042").endswith("/cves/2026/0xxx/CVE-2026-0042.json")


def _named(cve_id, vendor="", product="", title=""):
    return {"id": cve_id, "vendor": vendor, "product": product, "title": title,
            "epss0": 0.01, "epss_peak": 0.5, "kev": True}


def test_fill_missing_names_fetches_only_blank(monkeypatch):
    asked = []

    def fake_fetch(ids):
        asked.extend(ids)
        return {"CVE-2026-2": {"vendor": "Apple", "product": "macOS", "title": ""}}

    monkeypatch.setattr(cves, "fetch_meta", fake_fetch)
    records = [
        {"named": [_named("CVE-2026-1", vendor="PHP Group"), _named("CVE-2026-2")]},
        {"named": [_named("CVE-2026-3")]},
    ]
    build.fill_missing_names(records)

    assert asked == ["CVE-2026-2", "CVE-2026-3"]
    assert records[0]["named"][0]["vendor"] == "PHP Group"
    assert records[0]["named"][1]["vendor"] == "Apple"
    assert records[0]["named"][1]["product"] == "macOS"
    # A failed lookup leaves the entry blank rather than failing the run.
    assert records[1]["named"][0]["vendor"] == ""


def test_fill_missing_names_no_lookup_when_all_named(monkeypatch):
    monkeypatch.setattr(cves, "fetch_meta", lambda ids: (_ for _ in ()).throw(AssertionError))
    build.fill_missing_names([{"named": [_named("CVE-2026-1", title="Bug")]}])
