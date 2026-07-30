// @ts-check
import { noEnterpriseImports, rootConfigFiles } from '@akasecurity/eslint-config';
import { react } from '@akasecurity/eslint-config/react';

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
  ...rootConfigFiles,
];
