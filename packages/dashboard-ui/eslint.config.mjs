// @ts-check
import { rootConfigFiles } from '@akasecurity/eslint-config';
import { react } from '@akasecurity/eslint-config/react';

export default [
  ...react,
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
