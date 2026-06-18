// Generates web/public/og.png (1200x630) from the committed data, so social
// crawlers (which don't run JS) get a card that carries the message standalone.
import { mkdir, writeFile, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import sharp from "sharp";

const here = dirname(fileURLToPath(import.meta.url));
const dataPath = resolve(here, "../../data/floodline.json");
const out = resolve(here, "../public/og.png");

const nf = new Intl.NumberFormat("en-US");

let s;
try {
  s = JSON.parse(await readFile(dataPath, "utf-8")).summary;
} catch {
  console.warn("[make-og] no data/floodline.json; skipping og image");
  process.exit(0);
}

// A small scatter of dots for texture (mostly faint, a couple highlighted).
const dots = [];
for (let i = 0; i < 220; i++) {
  const cx = 760 + (i % 22) * 19;
  const cy = 180 + Math.floor(i / 22) * 19;
  const hi = i === 47 ? "#f59e0b" : i === 138 ? "#f43f5e" : null;
  dots.push(
    `<circle cx="${cx}" cy="${cy}" r="${hi ? 5 : 3}" fill="${hi || "rgba(56,189,248,0.22)"}"/>`,
  );
}

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#0a1322"/><stop offset="100%" stop-color="#070b14"/>
    </linearGradient>
  </defs>
  <rect width="1200" height="630" fill="url(#bg)"/>
  <rect x="0" y="0" width="1200" height="6" fill="#f59e0b"/>
  ${dots.join("")}
  <text x="64" y="92" fill="#38bdf8" font-family="monospace" font-size="22" letter-spacing="6">CVEFLOODLINE.ORG</text>
  <text x="64" y="206" fill="#ffffff" font-family="Helvetica,Arial,sans-serif" font-size="68" font-weight="700">AI is bringing the rain,</text>
  <text x="64" y="286" fill="#f59e0b" font-family="Helvetica,Arial,sans-serif" font-size="68" font-weight="700">not the flood.</text>
  <text x="64" y="378" fill="#cdd8ea" font-family="Helvetica,Arial,sans-serif" font-size="36">A record surge in CVE volume. Of ${nf.format(s.total)} in 90 days,</text>
  <text x="64" y="426" fill="#cdd8ea" font-family="Helvetica,Arial,sans-serif" font-size="36"><tspan fill="#f59e0b" font-weight="700">${nf.format(s.cross10_pit)}</tspan> were dangerous on day one, <tspan fill="#f59e0b" font-weight="700">${nf.format(s.cross10_matured)}</tspan> within a month.</text>
  <text x="64" y="556" fill="#8aa0c0" font-family="Helvetica,Arial,sans-serif" font-size="26">The river is high; it is not over the levee.</text>
  <text x="64" y="596" font-family="monospace" font-size="20" fill="#6b7e9c">Jerry Gamblin &amp; Eireann Leverett · FIRST 2026 forecast</text>
</svg>`;

await mkdir(dirname(out), { recursive: true });
await sharp(Buffer.from(svg)).png().toFile(out);
console.log(`[make-og] wrote ${out}`);
