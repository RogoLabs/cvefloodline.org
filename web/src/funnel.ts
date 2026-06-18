// "1 in N", the scarcity made legible. A block of N dots with exactly ONE lit
// shows, literally, how rare a flood is: one in this many CVEs tops the levee
// within 30 days. A full-population grid would be almost entirely empty (the
// real ratio is ~1 in several hundred), so we make the unit the ratio itself.

import { Summary } from "./data";

const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const COLS = 38;
const MAX_DOTS = 760; // keep the waffle a sane size

const nf = new Intl.NumberFormat();
const ratio = (total: number, part: number) => (part > 0 ? Math.round(total / part) : 0);

export function renderFunnel(container: HTMLElement, summary: Summary) {
  // Matured rate uses only CVEs old enough to HAVE a 30-day score (eligible
  // cohorts), not all volume; otherwise un-assessable recent CVEs dilute it.
  const matured = ratio(summary.matured_eligible_total, summary.cross10_matured);
  const dayOne = ratio(summary.total, summary.cross10_pit);
  const kev = ratio(summary.total, summary.kev);

  const N = Math.min(MAX_DOTS, Math.max(matured, 1));
  const hiIndex = Math.floor(N * 0.42); // one clearly-placed lit dot
  const rows = Math.ceil(N / COLS);
  const r = 3, gap = 9, pad = 4;
  const w = pad * 2 + (COLS - 1) * gap;
  const h = pad * 2 + (rows - 1) * gap;

  const dots = Array.from({ length: N }, (_, i) => {
    const cx = pad + (i % COLS) * gap;
    const cy = pad + Math.floor(i / COLS) * gap;
    const hi = i === hiIndex;
    const fill = hi ? "#f59e0b" : "rgba(56,189,248,0.22)";
    const rr = hi ? r + 2.4 : r;
    const style = hi
      ? ` style="filter:drop-shadow(0 0 5px #f59e0b)"`
      : reduced ? "" : ` style="opacity:0;animation:dotIn .4s ${((i / N) * 500).toFixed(0)}ms forwards"`;
    return `<circle cx="${cx}" cy="${cy}" r="${rr}" fill="${fill}"${style}/>`;
  }).join("");

  const stat = (label: string, n: number) =>
    `<div class="rounded-lg border border-edge bg-panel2 px-3 py-2">
       <div class="font-mono text-[10px] uppercase tracking-widest text-mist/70">${label}</div>
       <div class="text-lg font-semibold text-flood">1 in ${nf.format(n)}</div>
     </div>`;

  container.innerHTML = `
    <div class="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <div class="text-4xl font-semibold text-flood sm:text-5xl">1 in ${nf.format(matured)}</div>
        <div class="mt-1 text-sm text-mist">CVEs top the levee within 30 days (EPSS ≥ 10%)</div>
      </div>
    </div>
    <svg viewBox="0 0 ${w} ${h}" role="img"
         aria-label="One lit dot among ${nf.format(N)}: about 1 in ${nf.format(matured)} CVEs reaches high EPSS within 30 days."
         class="mt-4 w-full h-auto">${dots}</svg>
    <div class="mt-4 grid grid-cols-3 gap-2">
      ${stat("on day one", dayOne)}
      ${stat("within 30 days", matured)}
      ${stat("reaches CISA KEV", kev)}
    </div>`;
}
