// @ts-check
import { noEnterpriseImports } from '@akasecurity/eslint-config';
import { react } from '@akasecurity/eslint-config/react';
import tseslint from 'typescript-eslint';

export default [
  ...react,
  ...noEnterpriseImports,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    // Config files live outside the app-only tsconfig, so skip type-aware linting.
    files: ['**/*.config.{ts,mts,cts,mjs,cjs,js}'],
    ...tseslint.configs.disableTypeChecked,
  },
];
