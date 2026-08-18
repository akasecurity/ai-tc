// @ts-check
import { rootConfigFiles } from '@akasecurity/eslint-config';
import { reactUiPackage } from '@akasecurity/eslint-config/react';

export default [
  ...reactUiPackage,
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
