module.exports = {
    plugins: [
      require('@tailwindcss/typography'),
      ...(process.env.NODE_ENV === 'production' ? { cssnano: {} } : {})
    ],
}