// @ts-check
import { base, noEnterpriseImports } from '@akasecurity/eslint-config';

export default [
  ...base,
  ...noEnterpriseImports,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
];
