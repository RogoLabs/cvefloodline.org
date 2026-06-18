// Name the flood line: the actual CVEs that crossed, recognition over
// abstraction. Each card leads with the affected product, with the CVE id and
// the day-0 to peak EPSS climb beneath. Links to the CVE record.

import { DayRecord, NamedCve, topNamed } from "./data";

function pct(x: number): string {
  return `${(x * 100).toFixed(x >= 0.1 ? 0 : 1)}%`;
}

function esc(s: string): string {
  const d = document.createElement("div");
  // Strip only em/en dashes (— –) from third-party text; leave hyphens.
  d.textContent = (s ?? "").replace(/\s*[—–]\s*/g, ", ");
  return d.innerHTML;
}

/** A clean product label: vendor + product, de-duplicated. */
function productLabel(n: NamedCve): string {
  const v = (n.vendor || "").trim();
  const p = (n.product || "").trim();
  let label: string;
  if (!v && !p) label = (n.title || "").trim() || n.id;
  else if (!v) label = p;
  else if (!p) label = v;
  else if (p.toLowerCase().includes(v.toLowerCase())) label = p; // product already names the vendor
  else if (v.toLowerCase().includes(p.toLowerCase())) label = v; // vendor already names the product
  else label = `${v} ${p}`;
  return label.replace(/\s+/g, " ");
}

export function renderFloodList(container: HTMLElement, days: DayRecord[]) {
  const items = topNamed(days, 24);
  if (!items.length) {
    container.innerHTML = `<p class="text-sm text-mist">No high-EPSS or KEV CVEs in the window.</p>`;
    return;
  }
  container.innerHTML = items
    .map((n) => {
      const product = productLabel(n);
      const url = `https://www.cve.org/CVERecord?id=${encodeURIComponent(n.id)}`;
      return `
      <a href="${url}" target="_blank" rel="noopener"
         class="block rounded-xl border border-edge bg-panel2 p-3 transition hover:border-flood/60">
        <div class="flex items-start justify-between gap-2">
          <span class="line-clamp-2 text-sm font-medium text-slate-100" title="${esc(product)}">${esc(product)}</span>
          ${n.kev ? `<span class="shrink-0 rounded bg-kev/20 px-1.5 py-0.5 font-mono text-[10px] text-kev">KEV</span>` : ""}
        </div>
        <div class="mt-2 flex items-center justify-between gap-2 font-mono text-[11px]">
          <span class="text-rain">${esc(n.id)}</span>
          <span><span class="text-mist/60">${pct(n.epss0)}</span> <span class="text-flood">→ ${pct(n.epss_peak)}</span></span>
        </div>
      </a>`;
    })
    .join("");
}
