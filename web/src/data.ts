// Loads and shapes data/floodline.json (V2). No backend, a static fetch.

export interface Cell {
  p90: number;
  max: number;
  coverage: number;
  thresholds: Record<string, number>;
}

export interface NamedCve {
  id: string;
  vendor: string;
  product: string;
  title: string;
  epss0: number;
  epss_peak: number;
  kev: boolean;
}

export interface DayRecord {
  date: string;
  epss_model_version: string;
  total: number;
  backfilled: number;
  net_total: number;
  kev: number;
  kev_lag_median: number | null;
  epss_p90: number;
  epss_max: number;
  coverage: number;
  thresholds: Record<string, number>;
  maturation: Record<string, Cell | null>; // "0","7","30","90"
  named: NamedCve[];
}

export interface Summary {
  total: number;
  backfilled: number;
  net_total: number;
  kev: number;
  cross10_pit: number;
  mature_horizon: number;
  cross10_matured: number;
  matured_eligible_days: number;
  matured_eligible_total: number;
}

export interface Floodline {
  generated: string;
  window_days: number;
  days_present: number;
  horizons: number[];
  mature_horizon: number;
  kev_snapshot_date: string;
  latest_epss_date: string;
  latest_epss_model_version: string;
  summary: Summary;
  days: DayRecord[];
}

export const THRESHOLDS = [10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80, 85, 90, 95];

export async function loadFloodline(): Promise<Floodline> {
  const url = `${import.meta.env.BASE_URL}data/floodline.json`;
  const res = await fetch(url, { cache: "no-cache" });
  if (!res.ok) throw new Error(`Failed to load ${url}: ${res.status}`);
  const doc = (await res.json()) as Floodline;
  doc.days.sort((a, b) => a.date.localeCompare(b.date));
  return doc;
}

export function mean(xs: number[]): number {
  return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0;
}
const sum = (xs: number[]) => xs.reduce((a, b) => a + b, 0);

/** Crossings at a threshold for a horizon, summed only over days where that
 *  horizon is observable (eligible), apples-to-apples. */
export function crossingsAt(days: DayRecord[], threshold: number, horizon: number) {
  const key = String(threshold);
  const hk = String(horizon);
  const eligible = days.filter((d) => d.maturation[hk]);
  const crossed = sum(eligible.map((d) => d.maturation[hk]!.thresholds[key] ?? 0));
  const total = sum(eligible.map((d) => d.total));
  return { crossed, total, eligibleDays: eligible.length };
}

/** The slopegraph comparison: at publication vs at the matured horizon, over the
 *  SAME set of days (those old enough to have observed the matured horizon). */
export function slope(days: DayRecord[], threshold: number, matureHorizon: number) {
  const key = String(threshold);
  const hk = String(matureHorizon);
  const eligible = days.filter((d) => d.maturation[hk] && d.maturation["0"]);
  const pit = sum(eligible.map((d) => d.maturation["0"]!.thresholds[key] ?? 0));
  const matured = sum(eligible.map((d) => d.maturation[hk]!.thresholds[key] ?? 0));
  const total = sum(eligible.map((d) => d.total));
  return { pit, matured, total, eligibleDays: eligible.length };
}

/** Maturation curve: crossings per 1,000 CVEs at each horizon (rate, so
 *  horizons with different eligible day-sets are comparable). */
export function maturationCurve(days: DayRecord[], threshold: number, horizons: number[]) {
  return horizons.map((h) => {
    const { crossed, total, eligibleDays } = crossingsAt(days, threshold, h);
    return { horizon: h, ratePerK: total ? (crossed / total) * 1000 : 0, crossed, eligibleDays };
  });
}

/** Deduped, ranked named CVEs across the window. */
export function topNamed(days: DayRecord[], limit = 24): (NamedCve & { date: string })[] {
  const best = new Map<string, NamedCve & { date: string }>();
  for (const d of days) {
    for (const n of d.named) {
      const prev = best.get(n.id);
      if (!prev || n.epss_peak > prev.epss_peak) best.set(n.id, { ...n, date: d.date });
    }
  }
  return [...best.values()]
    .sort((a, b) => Number(b.kev) - Number(a.kev) || b.epss_peak - a.epss_peak)
    .slice(0, limit);
}
