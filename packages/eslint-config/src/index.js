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

// OSS/enterprise dependency wall (see CLAUDE.md "Package dependency rules"):
// packages that ship in the public oss/ tree must never import enterprise-only
// modules — @akasecurity/client (the tenant-aware HTTP client), drizzle-orm and
// @akasecurity/schema-enterprise (the Postgres/tenancy layer). Apply this to
// every OSS package except the plugin, which is the documented exception
// allowed to use @akasecurity/client to sync to a backend when attached.
const ENTERPRISE_IMPORT_MESSAGE =
  'OSS packages must never import enterprise-only modules (this keeps tenancy/auth/Postgres code out of the public oss/ tree). See CLAUDE.md "Package dependency rules".';

/** @type {import('typescript-eslint').ConfigArray} */
export const noEnterpriseImports = tseslint.config({
  rules: {
    'no-restricted-imports': [
      'error',
      {
        paths: [
          { name: '@akasecurity/client', message: ENTERPRISE_IMPORT_MESSAGE },
          { name: 'drizzle-orm', message: ENTERPRISE_IMPORT_MESSAGE },
          { name: '@akasecurity/schema-enterprise', message: ENTERPRISE_IMPORT_MESSAGE },
        ],
        patterns: [
          { group: ['drizzle-orm/*'], message: ENTERPRISE_IMPORT_MESSAGE },
          { group: ['@akasecurity/schema-enterprise/*'], message: ENTERPRISE_IMPORT_MESSAGE },
        ],
      },
    ],
  },
});

export default base;
