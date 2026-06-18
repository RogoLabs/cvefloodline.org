// The maturation curve: crossings per 1,000 CVEs at each horizon (D+0/+7/+30/+90).
// A rising curve is the cleanest statement of "exploitability arrives later."
// Horizons whose cohorts are still maturing are drawn provisional (hollow).

import * as d3 from "d3";
import { DayRecord, maturationCurve } from "./data";

export interface MaturationHandle {
  update(threshold: number): void;
}

export function createMaturation(
  container: HTMLElement,
  days: DayRecord[],
  horizons: number[],
  windowDays: number,
): MaturationHandle {
  function render(threshold: number) {
    container.querySelectorAll("svg").forEach((n) => n.remove());
    // Only horizons with at least one eligible cohort; a horizon no cohort is
    // old enough for (e.g. +90 in a 90-day window) would otherwise plot a
    // misleading zero.
    const data = maturationCurve(days, threshold, horizons).filter((d) => d.eligibleDays > 0);

    const width = container.clientWidth || 600;
    const height = 240;
    const m = { top: 20, right: 18, bottom: 36, left: 44 };
    const iw = width - m.left - m.right;
    const ih = height - m.top - m.bottom;

    const svg = d3.select(container).append("svg")
      .attr("width", width).attr("height", height).attr("viewBox", `0 0 ${width} ${height}`)
      .attr("role", "img")
      .attr("aria-label",
        `Crossings of EPSS ${threshold}% per 1,000 CVEs rise from ${data[0].ratePerK.toFixed(1)} on day zero to ${data[data.length - 1].ratePerK.toFixed(1)} by ${horizons[horizons.length - 1]} days.`);
    const g = svg.append("g").attr("transform", `translate(${m.left},${m.top})`);

    const x = d3.scalePoint().domain(data.map((d) => String(d.horizon))).range([0, iw]).padding(0.5);
    const yMax = Math.max(d3.max(data, (d) => d.ratePerK) ?? 1, 1) * 1.2;
    const y = d3.scaleLinear().domain([0, yMax]).nice().range([ih, 0]);

    g.append("g").attr("class", "chart-grid").selectAll("line").data(y.ticks(4)).join("line")
      .attr("x1", 0).attr("x2", iw).attr("y1", (d) => y(d)).attr("y2", (d) => y(d));

    // A cohort is fully eligible for horizon h only if windowDays > h.
    const fully = (h: number) => windowDays > h;

    g.append("path").datum(data)
      .attr("fill", "none").attr("stroke", "#f59e0b").attr("stroke-width", 2.5)
      .attr("d", d3.line<{ horizon: number; ratePerK: number }>()
        .x((d) => x(String(d.horizon))!).y((d) => y(d.ratePerK)).curve(d3.curveMonotoneX));

    g.selectAll("circle").data(data).join("circle")
      .attr("cx", (d) => x(String(d.horizon))!).attr("cy", (d) => y(d.ratePerK))
      .attr("r", 5)
      .attr("fill", (d) => (fully(d.horizon) ? "#f59e0b" : "#0e1626"))
      .attr("stroke", "#f59e0b").attr("stroke-width", 2);

    g.selectAll("text.val").data(data).join("text").attr("class", "val")
      .attr("x", (d) => x(String(d.horizon))!).attr("y", (d) => y(d.ratePerK) - 12)
      .attr("text-anchor", "middle").attr("fill", "#fff").attr("font-size", 12).attr("font-weight", 600)
      .text((d) => d.ratePerK.toFixed(1));

    g.append("g").attr("class", "chart-axis").attr("transform", `translate(0,${ih})`)
      .call(d3.axisBottom(x).tickFormat((d) => (d === "0" ? "day 0" : `+${d}d`)));
    g.append("g").attr("class", "chart-axis").call(d3.axisLeft(y).ticks(4));
  }

  let current = 10;
  render(current);
  new ResizeObserver(() => render(current)).observe(container);
  return { update(t) { current = t; render(t); } };
}
