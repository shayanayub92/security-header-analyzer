/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Deep cybersecurity color palette
        vuln: {
          good: '#10b981',    // Emerald green
          warning: '#f59e0b', // Amber warning
          danger: '#ef4444',  // Rose red
          info: '#3b82f6',    // Blue
        },
        slate: {
          950: '#0b0f19',     // Rich deep black-blue
        }
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
