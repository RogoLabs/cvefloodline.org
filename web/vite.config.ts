import { defineConfig } from "vite";

// Apex custom domain (cvefloodline.org) serves from the root.
export default defineConfig({
  base: "/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
