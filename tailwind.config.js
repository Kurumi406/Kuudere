/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './templates/**/*.html',
    './static/js/**/*.js',
    // Add other paths as needed
  ],
  theme: {
    extend: {
      colors: {
        'theme-red': '#FF0033',
        'theme-dark': '#121212',
        'theme-home-gray': '#1E1E1E',
        'primary': '#121212',
        'primary-red': '#FF0033',
        zinc: {
          800: '#27272a',
          900: '#18181b',
        },
        theme: {
          black: '#1A1A1A',
          red: '#DC2626',
          gray: '#1E1E1E',
          dark: '#121212',
        },
      },
      height: {
        '[300px]': '300px',
        '[400px]': '400px',
      },
      aspectRatio: {
        '16/9': '16 / 9',
        '4/3': '4 / 3',
      },
    },
  },
};

