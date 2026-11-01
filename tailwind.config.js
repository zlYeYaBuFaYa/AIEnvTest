/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        paper: "var(--paper)",
        card: "var(--card)",
        ink: "var(--ink)",
        muted: "var(--muted)",
        line: "var(--line)",
        teal: "var(--teal)",
        "teal-ink": "var(--teal-ink)",
      },
      fontFamily: {
        serif: ["Palatino", "Iowan Old Style", "Songti SC", "Noto Serif CJK SC", "serif"],
        sans: [
          "Segoe UI",
          "Noto Sans CJK SC",
          "Noto Sans CJK JP",
          "Noto Sans CJK KR",
          "WenQuanYi Micro Hei",
          "sans-serif",
        ],
      },
      boxShadow: {
        card: "0 1px 0 rgba(28, 25, 21, 0.04), 0 12px 32px rgba(80, 58, 28, 0.06)",
      },
    },
  },
  plugins: [],
};
