// Daily CVE volume, the one place a time series earns its keep, because volume
// genuinely varies (16→700+/day). Gross bars with a darker net-of-backfill core,
// and amber ticks marking days that produced a CVE which later hit KEV.

import * as d3 from "d3";
import { DayRecord } from "./data";

const parseDate = d3.utcParse("%Y-%m-%d")!;

export function createVolume(container: HTMLElement, days: DayRecord[]) {
  const tooltip = document.createElement("div");
  tooltip.id = "tooltip";
  tooltip.setAttribute("role", "status");
  container.appendChild(tooltip);

  const pts = days.map((d) => ({
    date: parseDate(d.date)!,
    total: d.total,
    net: d.net_total,
    kev: d.kev,
    raw: d,
  }));

  function render() {
    container.querySelectorAll("svg").forEach((n) => n.remove());
    const width = container.clientWidth || 700;
    const height = Math.min(320, Math.max(220, Math.round(width * 0.34)));
    const m = { top: 14, right: 14, bottom: 28, left: 40 };
    const iw = width - m.left - m.right;
    const ih = height - m.top - m.bottom;

    const svg = d3.select(container).append("svg")
      .attr("width", width).attr("height", height).attr("viewBox", `0 0 ${width} ${height}`)
      .attr("role", "img")
      .attr("aria-label", "Daily count of newly published CVEs over the window, with a net-of-backfill core and KEV-day markers.");
    const g = svg.append("g").attr("transform", `translate(${m.left},${m.top})`);

    const x = d3.scaleBand<Date>().domain(pts.map((p) => p.date)).range([0, iw]).padding(0.15);
    const y = d3.scaleLinear().domain([0, (d3.max(pts, (p) => p.total) ?? 1) * 1.08]).nice().range([ih, 0]);
    const bw = x.bandwidth();

    g.append("g").attr("class", "chart-grid").selectAll("line").data(y.ticks(4)).join("line")
      .attr("x1", 0).attr("x2", iw).attr("y1", (d) => y(d)).attr("y2", (d) => y(d));

    g.selectAll("rect.gross").data(pts).join("rect").attr("class", "gross")
      .attr("x", (p) => x(p.date)!).attr("y", (p) => y(p.total))
      .attr("width", bw).attr("height", (p) => ih - y(p.total))
      .attr("fill", "rgba(56,189,248,0.30)");
    g.selectAll("rect.net").data(pts).join("rect").attr("class", "net")
      .attr("x", (p) => x(p.date)!).attr("y", (p) => y(p.net))
      .attr("width", bw).attr("height", (p) => ih - y(p.net))
      .attr("fill", "rgba(56,189,248,0.7)");

    // KEV-day markers along the baseline.
    g.selectAll("rect.kev").data(pts.filter((p) => p.kev > 0)).join("rect").attr("class", "kev")
      .attr("x", (p) => x(p.date)!).attr("y", ih - 4)
      .attr("width", bw).attr("height", 4).attr("fill", "#f43f5e");

    g.append("g").attr("class", "chart-axis").attr("transform", `translate(0,${ih})`)
      .call(d3.axisBottom(x).tickValues(x.domain().filter((_, i) => i % Math.ceil(pts.length / 7) === 0))
        .tickFormat((d) => d3.utcFormat("%b %d")(d as Date)));
    g.append("g").attr("class", "chart-axis").call(d3.axisLeft(y).ticks(4));

    const overlay = g.append("rect").attr("width", iw).attr("height", ih).attr("fill", "transparent").style("touch-action", "none");
    overlay.on("pointermove", (event) => {
      const [mx] = d3.pointer(event);
      const i = Math.max(0, Math.min(pts.length - 1, Math.floor(mx / (iw / pts.length))));
      const p = pts[i];
      tooltip.style.opacity = "1";
      tooltip.style.left = `${m.left + x(p.date)! + bw / 2}px`;
      tooltip.style.top = `${m.top + y(p.total)}px`;
      tooltip.innerHTML = `
        <div style="font-weight:600;color:#fff">${d3.utcFormat("%b %d, %Y")(p.date)}</div>
        <div style="color:#38bdf8">${p.total} CVEs (${p.net} new, ${p.total - p.net} backfilled)</div>
        ${p.kev ? `<div style="color:#f43f5e">${p.kev} later in KEV</div>` : ""}`;
    });
    overlay.on("pointerleave", () => (tooltip.style.opacity = "0"));
  }

  render();
  new ResizeObserver(render).observe(container);
}
