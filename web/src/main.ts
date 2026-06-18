import "./styles.css";
import { loadFloodline, slope, crossingsAt } from "./data";
import { createHero } from "./hero";
import { renderFunnel } from "./funnel";
import { createSlope } from "./slope";
import { createMaturation } from "./maturation";
import { createVolume } from "./volume";
import { renderFloodList } from "./floodlist";

const $ = <T extends HTMLElement = HTMLElement>(id: string) =>
  document.getElementById(id) as T | null;

const nf = new Intl.NumberFormat();

function fmtDate(iso: string): string {
  return new Date(iso + "T00:00:00Z").toLocaleDateString(undefined, {
    month: "short", day: "numeric", year: "numeric", timeZone: "UTC",
  });
}
function oneIn(total: number, part: number): string {
  return part > 0 ? `1 in ${nf.format(Math.round(total / part))}` : "none";
}
function fail(msg: string) {
  const c = $("caption");
  if (c) c.textContent = msg;
  $("threshold")?.setAttribute("disabled", "true");
}

async function main() {
  let doc;
  try {
    doc = await loadFloodline();
  } catch (e) {
    console.error(e);
    return fail("Floodline data is temporarily unavailable, please check back shortly.");
  }
  if (!doc.days?.length) return fail("Floodline data is temporarily unavailable.");

  const days = doc.days;
  const s = doc.summary;
  const mh = doc.mature_horizon;
  const perDay = Math.round(s.total / days.length);

  // Static framing numbers.
  $("rain-rate") && ($("rain-rate")!.textContent = `~${nf.format(perDay)}/day`);
  $("backfill-pct") && ($("backfill-pct")!.textContent = `${Math.round((s.backfilled / s.total) * 100)}%`);

  const hero = createHero($("hero")!, days);
  renderFunnel($("funnel")!, s);
  const slopeChart = createSlope($("slope")!, days, mh);
  const matChart = createMaturation($("maturation")!, days, doc.horizons, doc.window_days);
  createVolume($("volume")!, days);
  renderFloodList($("floodlist")!, days);

  const slider = $<HTMLInputElement>("threshold")!;
  const thresholdValue = $("threshold-value")!;
  const caption = $("caption")!;
  const srStatus = $("sr-status")!;
  const slopeNote = $("slope-note")!;

  function render() {
    const t = Number(slider.value);
    const sl = slope(days, t, mh);
    const d0 = crossingsAt(days, t, 0);

    thresholdValue.textContent = `${t}%`;
    slider.setAttribute("aria-valuetext", `EPSS greater than or equal to ${t} percent`);

    const mult = sl.pit > 0 ? ` (${(sl.matured / sl.pit).toFixed(1)}× higher)` : "";
    caption.innerHTML =
      `At a flood stage of <span class="text-flood font-semibold">EPSS ${t}%</span>: of ` +
      `<span class="text-rain font-semibold">${nf.format(d0.total)}</span> CVEs in the window, ` +
      `<span class="text-flood font-semibold">${nf.format(d0.crossed)}</span> topped the levee on day one ` +
      `(${oneIn(d0.total, d0.crossed)}). Give the water 30 days to crest and ` +
      `<span class="text-flood font-semibold">${nf.format(sl.matured)}</span> cross${mult}.`;

    slopeNote.textContent = `over ${sl.eligibleDays} cohorts ≥ ${mh} days old · matured = scored ${mh} days after disclosure`;

    hero.update(t);
    slopeChart.update(t);
    matChart.update(t);
    srStatus.textContent = caption.textContent ?? "";
  }

  let timer = 0;
  slider.addEventListener("input", () => {
    render();
    window.clearTimeout(timer);
    timer = window.setTimeout(() => (srStatus.textContent = caption.textContent ?? ""), 350);
  });
  render();

  $("freshness") && ($("freshness")!.textContent =
    `${fmtDate(days[0].date)} → ${fmtDate(days[days.length - 1].date)} · ${days.length} days`);
  $("footer-generated")!.textContent =
    `Last updated ${new Date(doc.generated).toUTCString()} · KEV snapshot ${doc.kev_snapshot_date} · ` +
    `matured against EPSS ${doc.latest_epss_date}.`;
}

main();
