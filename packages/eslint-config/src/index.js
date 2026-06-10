// @ts-check
import js from '@eslint/js';
import pluginN from 'eslint-plugin-n';
import simpleImportSort from 'eslint-plugin-simple-import-sort';
import tseslint from 'typescript-eslint';
import prettier from 'eslint-config-prettier';

/** @type {import('typescript-eslint').ConfigArray} */
export const base = tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    plugins: {
      n: pluginN,
      'simple-import-sort': simpleImportSort,
    },
    rules: {
      // Forbid direct process.env access by default; packages that must read env
      // (e.g. the plugin's provider resolution) opt out in their own eslint config.
      'n/no-process-env': 'error',

      // Import discipline
      'simple-import-sort/imports': 'error',
      'simple-import-sort/exports': 'error',

      // TypeScript strictness extras
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/consistent-type-imports': ['error', { prefer: 'type-imports' }],
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',

      // No warnings — everything is error or off
      'no-console': 'error',
    },
  },
  prettier,
);

export default base;
