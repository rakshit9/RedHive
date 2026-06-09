import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        hive: {
          bg: "#0b0e14",
          panel: "#11161f",
          border: "#1e2733",
          accent: "#f59e0b",
        },
      },
    },
  },
  plugins: [],
};

export default config;
