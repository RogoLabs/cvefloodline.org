/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,js}"],
  theme: {
    extend: {
      colors: {
        // Weather-instrument palette.
        ink: "#070b14",        // deep night sky / panel base
        panel: "#0e1626",      // instrument panel
        panel2: "#131f33",     // raised panel
        edge: "#22304a",       // hairline borders
        rain: "#38bdf8",       // cool blue — total volume
        rainDeep: "#0ea5e9",
        flood: "#f59e0b",      // warning amber — EPSS flood line
        floodDeep: "#d97706",
        kev: "#f43f5e",        // KEV line — rose
        mist: "#8aa0c0",       // muted labels
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};
