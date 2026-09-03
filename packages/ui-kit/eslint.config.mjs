// @ts-check
import { rootConfigFiles } from '@akasecurity/eslint-config';
import { presentationalUiPackage } from '@akasecurity/eslint-config/react';

export default [
  ...presentationalUiPackage,
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
