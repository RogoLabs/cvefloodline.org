// The waterline hero, the thesis in one glance. Daily CVE volume is the rain
// (a tall cool-blue area); the dangerous subset that crosses the threshold on
// day one is the flood line (amber, pinned near the floor). The vast gap is the
// argument: the river is high, but it isn't over the levee.

import * as d3 from "d3";
import { DayRecord } from "./data";

const parseDate = d3.utcParse("%Y-%m-%d")!;

export interface HeroHandle {
  update(threshold: number): void;
}

export function createHero(container: HTMLElement, days: DayRecord[]): HeroHandle {
  const pts = days.map((d) => ({ date: parseDate(d.date)!, total: d.total, raw: d }));
  let threshold = 10;

  function render() {
    container.querySelectorAll("svg").forEach((n) => n.remove());
    const width = container.clientWidth || 800;
    const height = Math.min(360, Math.max(240, Math.round(width * 0.42)));
    const m = { top: 16, right: 16, bottom: 26, left: 44 };
    const iw = width - m.left - m.right;
    const ih = height - m.top - m.bottom;

    const svg = d3.select(container).append("svg")
      .attr("width", width).attr("height", height).attr("viewBox", `0 0 ${width} ${height}`)
      .attr("role", "img");
    svg.append("title").text("Daily CVE volume (rain) vs. the dangerous subset (flood line)");
    const desc = svg.append("desc");
    const g = svg.append("g").attr("transform", `translate(${m.left},${m.top})`);

    const x = d3.scaleUtc().domain(d3.extent(pts, (p) => p.date) as [Date, Date]).range([0, iw]);
    const y = d3.scaleLinear().domain([0, (d3.max(pts, (p) => p.total) ?? 1) * 1.08]).nice().range([ih, 0]);

    g.append("g").attr("class", "chart-grid").selectAll("line").data(y.ticks(4)).join("line")
      .attr("x1", 0).attr("x2", iw).attr("y1", (d) => y(d)).attr("y2", (d) => y(d));

    const grad = svg.append("defs").append("linearGradient")
      .attr("id", "rainGrad").attr("x1", "0").attr("y1", "0").attr("x2", "0").attr("y2", "1");
    grad.append("stop").attr("offset", "0%").attr("stop-color", "#38bdf8").attr("stop-opacity", 0.5);
    grad.append("stop").attr("offset", "100%").attr("stop-color", "#38bdf8").attr("stop-opacity", 0.04);

    g.append("path").datum(pts).attr("fill", "url(#rainGrad)")
      .attr("d", d3.area<typeof pts[0]>().x((p) => x(p.date)).y0(ih).y1((p) => y(p.total)).curve(d3.curveMonotoneX));
    g.append("path").datum(pts).attr("fill", "none").attr("stroke", "#38bdf8").attr("stroke-width", 1.5).attr("stroke-opacity", 0.85)
      .attr("d", d3.line<typeof pts[0]>().x((p) => x(p.date)).y((p) => y(p.total)).curve(d3.curveMonotoneX));

    g.append("g").attr("class", "chart-axis").attr("transform", `translate(0,${ih})`)
      .call(d3.axisBottom(x).ticks(width < 520 ? 4 : 7).tickFormat((d) => d3.utcFormat("%b %d")(d as Date)));
    g.append("g").attr("class", "chart-axis").call(d3.axisLeft(y).ticks(4));

    const floodArea = g.append("path").attr("fill", "#f59e0b").attr("fill-opacity", 0.3);
    const floodLine = g.append("path").attr("fill", "none").attr("stroke", "#f59e0b").attr("stroke-width", 2.5);

    function drawFlood() {
      const flood = (p: typeof pts[0]) => p.raw.thresholds[String(threshold)] ?? 0;
      floodArea.datum(pts).attr("d",
        d3.area<typeof pts[0]>().x((p) => x(p.date)).y0(ih).y1((p) => y(flood(p))).curve(d3.curveMonotoneX));
      floodLine.datum(pts).attr("d",
        d3.line<typeof pts[0]>().x((p) => x(p.date)).y((p) => y(flood(p))).curve(d3.curveMonotoneX));
      const avgRain = Math.round(d3.mean(pts, (p) => p.total) ?? 0);
      desc.text(`CVE volume averages ${avgRain} a day (the rain). The subset crossing EPSS ${threshold}% on disclosure day (the flood line) stays near zero, far below the river of volume.`);
    }
    drawFlood();
    return drawFlood;
  }

  let redraw = render();
  new ResizeObserver(() => (redraw = render())).observe(container);

  return {
    update(t: number) {
      threshold = t;
      redraw();
    },
  };
}
