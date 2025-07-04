const { defineConfig, globalIgnores } = require('eslint/config');

const globals = require('globals');
const js = require('@eslint/js');

const { FlatCompat } = require('@eslint/eslintrc');

const compat = new FlatCompat({
  baseDirectory: __dirname,
  recommendedConfig: js.configs.recommended,
  allConfig: js.configs.all,
});

module.exports = defineConfig([
  {
    languageOptions: {
      globals: {
        ...globals.commonjs,
        ...globals.jest,
        ...globals.node,
        Atomics: 'readonly',
        SharedArrayBuffer: 'readonly',
        _: false,
      },

      ecmaVersion: 9,
      parserOptions: {},
    },

    extends: compat.extends('eslint:recommended'),

    rules: {
      'eol-last': ['error', 'always'],

      indent: [
        'error',
        2,
        {
          SwitchCase: 1,
        },
      ],

      'linebreak-style': ['error', 'unix'],
      'no-console': process.env.NODE_ENV === 'production' ? 'error' : 'warn',
      'no-debugger': process.env.NODE_ENV === 'production' ? 'error' : 'warn',
      quotes: ['error', 'single'],
      semi: ['error', 'always'],
    },
  },
  {
    files: ['**/__tests__/*.{j,t}s?(x)', '**/tests/unit/**/*.spec.{j,t}s?(x)'],

    languageOptions: {
      globals: {
        ...globals.jest,
      },
    },
  },
  globalIgnores(['**/dist', '**/frontend', '**/node_modules', 'public/js']),
]);
