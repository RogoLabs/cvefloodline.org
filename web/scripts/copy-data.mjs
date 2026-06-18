// Copies the committed data/floodline.json into web/public so Vite serves it as
// a static asset (the site has no backend; it just fetches this file).
import { mkdir, copyFile, access } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const src = resolve(here, "../../data/floodline.json");
const dest = resolve(here, "../public/data/floodline.json");

try {
  await access(src);
} catch {
  console.warn(`[copy-data] ${src} not found, run the pipeline (bootstrap.py) first.`);
  process.exit(0);
}

await mkdir(dirname(dest), { recursive: true });
await copyFile(src, dest);
console.log(`[copy-data] ${src} -> ${dest}`);
