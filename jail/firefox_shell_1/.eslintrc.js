module.exports = {
  extends: 'plugin:mozilla/recommended',
  plugins: ['mozilla'],
  ignorePatterns: ['temp.js', 'src/nodejs/**/*.js', 'src/nodejs-bundled.js'],
  rules: {
    quotes: ['error', 'single', { avoidEscape: true }],
    'prefer-const': 'error',
    'func-style': ['error', 'expression'],
    // 'nonblock-statement-body-position': ['error', 'below'],
    eqeqeq: 'error',
    'no-var': 'error',
  },
  globals: {
    global: false,
    module: false,
    require: false,
    EXPORTED_SYMBOLS: true,
  },
};
