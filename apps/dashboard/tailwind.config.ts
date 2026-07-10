import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/lib/**/*.{js,ts,jsx,tsx,mdx}"
  ],
  theme: {
    extend: {
      colors: {
        william: {
          bg: "#07080b",
          panel: "#0b0c0f",
          soft: "#111217",
          orange: "#f97316"
        }
      }
    }
  },
  plugins: []
};

export default config;