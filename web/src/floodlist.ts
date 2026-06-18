// Name the flood line: the actual CVEs that crossed, recognition over
// abstraction. Each card shows the ID, vendor/product, the day-0 → peak EPSS
// climb, and a KEV badge. Links to the CVE record.

import { DayRecord, topNamed } from "./data";

function pct(x: number): string {
  return `${(x * 100).toFixed(x >= 0.1 ? 0 : 1)}%`;
}
function esc(s: string): string {
  const d = document.createElement("div");
  d.textContent = (s ?? "").replace(/\s*[, -]\s*/g, ", "); // strip em/en dashes from third-party text
  return d.innerHTML;
}

export function renderFloodList(container: HTMLElement, days: DayRecord[]) {
  const items = topNamed(days, 24);
  if (!items.length) {
    container.innerHTML = `<p class="text-sm text-mist">No high-EPSS or KEV CVEs in the window.</p>`;
    return;
  }
  container.innerHTML = items
    .map((n) => {
      const who = [n.vendor, n.product].filter(Boolean).join(" · ") || n.title || ", ";
      const url = `https://www.cve.org/CVERecord?id=${encodeURIComponent(n.id)}`;
      return `
      <a href="${url}" target="_blank" rel="noopener"
         class="block rounded-xl border border-edge bg-panel2 p-3 transition hover:border-flood/60">
        <div class="flex items-center justify-between gap-2">
          <span class="font-mono text-xs text-rain">${esc(n.id)}</span>
          ${n.kev ? `<span class="rounded bg-kev/20 px-1.5 py-0.5 font-mono text-[10px] text-kev">KEV</span>` : ""}
        </div>
        <div class="mt-1 truncate text-sm text-slate-200" title="${esc(who)}">${esc(who)}</div>
        <div class="mt-2 font-mono text-[11px] text-mist">
          EPSS <span class="text-mist/70">${pct(n.epss0)}</span>
          <span class="text-flood">→ ${pct(n.epss_peak)}</span>
        </div>
      </a>`;
    })
    .join("");
}
