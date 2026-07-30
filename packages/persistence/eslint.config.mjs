// @ts-check
import { base, noEnterpriseImports, rootConfigFiles } from '@akasecurity/eslint-config';

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
  ...rootConfigFiles,
];
