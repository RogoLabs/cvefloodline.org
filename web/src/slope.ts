// The interactive payoff: a slopegraph comparing how many of the SAME cohorts
// crossed an EPSS threshold on publication day vs. after the matured horizon
// (+30d). Drag the threshold, publication-day counts collapse toward zero while
// matured counts stay alive far longer. This is the relationship that moves.

import * as d3 from "d3";
import { DayRecord, slope } from "./data";

export interface SlopeHandle {
  update(threshold: number): void;
}

export function createSlope(
  container: HTMLElement,
  days: DayRecord[],
  matureHorizon: number,
): SlopeHandle {
  const tooltip = container; // labels are inline

  function render(threshold: number) {
    container.querySelectorAll("svg").forEach((n) => n.remove());
    const { pit, matured, eligibleDays } = slope(days, threshold, matureHorizon);

    const width = container.clientWidth || 600;
    const height = 260;
    const m = { top: 28, right: 120, bottom: 28, left: 120 };
    const iw = width - m.left - m.right;
    const ih = height - m.top - m.bottom;

    const svg = d3.select(container).append("svg")
      .attr("width", width).attr("height", height).attr("viewBox", `0 0 ${width} ${height}`)
      .attr("role", "img")
      .attr("aria-label",
        `At EPSS ${threshold}%, ${pit} CVEs crossed on publication day and ${matured} crossed after ${matureHorizon} days, across ${eligibleDays} cohorts.`);
    const g = svg.append("g").attr("transform", `translate(${m.left},${m.top})`);

    const yMax = Math.max(matured, pit, 1) * 1.15;
    const y = d3.scaleLinear().domain([0, yMax]).range([ih, 0]);
    const xPit = 0, xMat = iw;

    // Connecting slope.
    g.append("line")
      .attr("x1", xPit).attr("y1", y(pit)).attr("x2", xMat).attr("y2", y(matured))
      .attr("stroke", "#f59e0b").attr("stroke-width", 2.5).attr("stroke-linecap", "round");

    const point = (x: number, val: number, label: string, sub: string, anchor: string, dx: number) => {
      g.append("circle").attr("cx", x).attr("cy", y(val)).attr("r", 6).attr("fill", "#f59e0b");
      g.append("text").attr("x", x + dx).attr("y", y(val) - 14)
        .attr("text-anchor", anchor).attr("fill", "#fff")
        .attr("font-size", 22).attr("font-weight", 700).text(val.toLocaleString());
      g.append("text").attr("x", x + dx).attr("y", y(val) + 6)
        .attr("text-anchor", anchor).attr("fill", "#8aa0c0")
        .attr("font-size", 11).attr("font-family", "ui-monospace,monospace").text(label);
      g.append("text").attr("x", x + dx).attr("y", y(val) + 22)
        .attr("text-anchor", anchor).attr("fill", "#8aa0c0")
        .attr("font-size", 10).attr("font-family", "ui-monospace,monospace").text(sub);
    };
    point(xPit, pit, "on publication day", "", "end", -14);
    point(xMat, matured, `after ${matureHorizon} days`, "", "start", 14);

    // Multiplier annotation.
    const mult = pit > 0 ? `${(matured / pit).toFixed(1)}×` : matured > 0 ? `0 to ${matured}` : "0";
    g.append("text").attr("x", iw / 2).attr("y", y((pit + matured) / 2) - 12)
      .attr("text-anchor", "middle").attr("fill", "#f59e0b")
      .attr("font-size", 13).attr("font-weight", 600).text(mult);

    return tooltip;
  }

  let current = 10;
  render(current);
  new ResizeObserver(() => render(current)).observe(container);

  return {
    update(threshold: number) {
      current = threshold;
      render(threshold);
    },
  };
}
