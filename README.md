# CVE Floodline · [cvefloodline.org](https://cvefloodline.org)

A daily-updating static site visualizing CVE volume vs. exploitability over
time, building on FIRST.org's June 2026 vulnerability forecast by Jerry Gamblin
and Eireann Leverett.

**The thesis:** new CVEs arrive with low scores. Of ~18,900 disclosed in a quarter,
only a handful look high-risk the day they land, but the risk **matures in over
the following weeks** (EPSS climbs, CISA KEV listings arrive). Volume is the
rain; the real signal is the tide coming in behind it. The work isn't patching
volume, it's finding the few early.

> Built on the [FIRST.org 2026 vulnerability forecast update](https://www.first.org/blog/20260615-vulnerability-forecast-update).
> Methodology adapted from [FirstForecast](https://github.com/jgamblin/FirstForecast).
> This repo paraphrases and links the blog rather than reproducing its text.

## What the data shows

Across a ~90-day window (~18,900 CVEs): about **6** crossed a 10% EPSS line on
their disclosure day, but **33** of the same cohorts crossed within **30 days**,
and **40** landed in CISA KEV. Re-scored at fixed horizons, crossings per 1,000
CVEs climb roughly **0.3 → 1.3 → 2.7** at day 0 / +7 / +30 (the +90 horizon needs
cohorts older than the window, so it is not shown until enough time passes). So
the near-zero day-one number is *not* the whole story, it's a snapshot taken
before the danger has surfaced. Among CVEs old enough to have a 30-day score,
about **1 in 370** crosses the line. ~9% of raw "volume" is backfilled old CVE
IDs (shown net), and the CVEs that do cross are recognizable (Cisco, Ivanti,
Palo Alto, NetScaler, Apache, cPanel), the site names them.

This is **not** an argument to slow patching: EPSS climbs over time and KEV
listings lag disclosure by months, so recent counts are lower bounds, and this
is a population view, not a substitute for triaging the software you run. The
site states these caveats inline.

## Architecture

Two halves, both free to run, no servers, no runtime backend:

| Part | Stack | Role |
|------|-------|------|
| `pipeline/` | Python 3.12 + `requests` | Computes a small `data/floodline.json`, run by GitHub Actions. |
| `web/` | Vite + TypeScript + D3 + Tailwind | Static site on GitHub Pages; fetches only `data/floodline.json`. |

## Methodology, and why point-in-time matters

EPSS **revises every score daily**, so you can't reconstruct how a cohort looked
on its disclosure day from today's snapshot. We use the **dated daily EPSS
archive** ([empiricalsec/epss_scores](https://github.com/empiricalsec/epss_scores),
an Empirical Security mirror of the FIRST EPSS SIG), where each file is frozen as
it was on that day, and we re-score each cohort at fixed **maturation horizons**.

For each day `D` (cohort = CVEs with `datePublished == D`, state `PUBLISHED`,
from cvelistV5's per-day **"End of Day"** delta, never the 537 MB baseline):

1. **Maturation cells**, the cohort scored against EPSS at **D+0 / +7 / +30 /
   +90** (`HORIZONS`). Each cell records crossings per threshold (10…95%), the
   90th-percentile and max EPSS over *scored* CVEs, and `coverage`. A horizon is
   `null` until its file exists, so recent cohorts are explicitly provisional
   rather than silently flat. D+0 uses a ±3-day nearest-file fill.
2. **The headline / slopegraph** compares D+0 vs the fixed **`MATURE_HORIZON`
   (30 days)**, over only the cohorts old enough to have observed it. This is
   apples-to-apples, never "today's EPSS against a cohort published yesterday."
3. **Named CVEs (`named`)**, each day's most notable crossing/KEV CVEs, with
   vendor/product/title and the day-0 → peak EPSS climb.
4. **`kev` + `kev_lag_median`**, cohort ∩ CISA KEV, using `dateAdded` for the
   disclosure→KEV lag. KEV lags disclosure by months, so recent counts are
   **lower bounds** (stated inline).
5. **Backfill (`backfilled` / `net_total`)**, CVEs whose ID year predates their
   publication year (old IDs re-published); shown net rather than hidden.

**Recompute model.** Cohorts are persisted to `data/cohorts.json`; because EPSS
and CVE horizon files are immutable, the daily job recomputes the whole 90-day
window from cohorts each run. This is idempotent and lets maturation cells fill
and KEV refresh as time passes, no "frozen at finalization" staleness and no
permanent holes (a day with no release yet is simply absent until it appears).
Each record keeps its `epss_model_version` so a window never silently mixes EPSS
regimes (shifts: v2 2022-02-04, v3 2023-03-07, v4 2025-03-17). The newest ~3 days
are held back while scores settle.

### `data/floodline.json` (shape)

```json
{
  "generated": "…Z", "window_days": 90, "days_present": 90,
  "horizons": [0, 7, 30, 90], "mature_horizon": 30,
  "kev_snapshot_date": "…", "latest_epss_date": "…", "latest_epss_model_version": "…",
  "summary": { "total": 19674, "net_total": 17879, "kev": 41,
               "cross10_pit": 6, "cross10_matured": 35, "matured_eligible_days": 62 },
  "days": [{
    "date": "2026-04-01", "total": 235, "backfilled": 9, "net_total": 226,
    "kev": 1, "kev_lag_median": 0,
    "thresholds": { "10": 0, "…": 0 },
    "maturation": { "0": {"p90": 0.0, "max": 0.004, "coverage": 1.0, "thresholds": {…}},
                    "7": {…}, "30": {…}, "90": null },
    "named": [{ "id": "CVE-2026-…", "vendor": "Cisco", "product": "…",
                "epss0": 0.016, "epss_peak": 0.838, "kev": true }]
  }]
}
```

`data/cohorts.json` (`{date: [cve_ids]}`) is the raw recompute substrate; the
frontend never loads it.

## Pipeline: bootstrap vs. daily update

- **`pipeline/bootstrap.py`**, one-time seed / recovery. Stitches ~95 days of
  cvelistV5 end-of-day deltas into cohorts, loads the dated EPSS files across all
  maturation horizons (filtered to the window's CVEs, to bound memory), and
  writes both `data/cohorts.json` and `data/floodline.json`.
- **`pipeline/update.py`**, daily. Loads the persisted cohorts, fetches any
  window day not yet captured (catch-up), then recomputes the whole window from
  cohorts. Idempotent (horizon files are immutable); maturation cells fill and
  KEV refreshes as time passes. A day with no release yet is simply absent.

The output is validated before writing (sorted/unique dates, non-increasing
threshold counts, maturation present, plausible volume); on any download failure
or failed validation either script exits nonzero and leaves committed data
untouched.

## Local development

```bash
# Pipeline (seed the data once)
python3 -m venv .venv && .venv/bin/pip install -r pipeline/requirements.txt
.venv/bin/python pipeline/bootstrap.py        # writes data/floodline.json
# (set GITHUB_TOKEN to raise GitHub API rate limits)

# Pipeline checks
.venv/bin/pip install -r pipeline/requirements-dev.txt
ruff check pipeline
cd pipeline && python -m pytest -q && cd ..

# Frontend
cd web
npm install
npm run dev        # predev copies ../data/floodline.json into public/
```

`npm run build` type-checks and emits `web/dist/`.

## GitHub Actions

| Workflow | Trigger | Does |
|----------|---------|------|
| `.github/workflows/update.yml` | daily cron 12:00 UTC + manual | runs `update.py`, commits `data/floodline.json` if changed |
| `.github/workflows/bootstrap.yml` | manual only | runs `bootstrap.py` for first setup / recovery |
| `.github/workflows/pages.yml` | push to `web/**` or `data/**` + manual | builds `web/` and deploys to Pages |
| `.github/workflows/ci.yml` | push / PR | ruff + pytest for the pipeline, type-check + build for the web app |

The daily data commit automatically triggers a Pages rebuild. Commits use the
built-in `GITHUB_TOKEN` and push with rebase-and-retry to survive races.

## Deploying to GitHub Pages with the custom domain

1. Repo **Settings → Pages → Build and deployment → Source: GitHub Actions**.
2. Run **Bootstrap floodline (manual)** once to seed `data/floodline.json`.
3. Push to `main` (or run **Deploy to GitHub Pages**). `web/public/CNAME`
   (`cvefloodline.org`) ships in the build output, so Pages serves the apex
   domain, set the matching DNS `A`/`ALIAS` records at your registrar per
   [GitHub's custom-domain docs](https://docs.github.com/pages/configuring-a-custom-domain-for-your-github-pages-site).

## Data sources & licenses

- **EPSS** (point-in-time): [empiricalsec/epss_scores](https://github.com/empiricalsec/epss_scores),
  mirroring the FIRST EPSS SIG. EPSS data is published by FIRST for public use;
  see FIRST's EPSS terms.
- **CISA KEV**: [known_exploited_vulnerabilities.json](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), U.S. Government public domain.
- **CVE records**: [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5), distributed under the CVE Program's terms of use.
- **Forecast & metaphor**: [FIRST.org blog](https://www.first.org/blog/20260615-vulnerability-forecast-update); methodology from [FirstForecast](https://github.com/jgamblin/FirstForecast).

This project's own code is licensed under **Apache 2.0** (see `LICENSE`).
Upstream data remains under its respective licenses.
