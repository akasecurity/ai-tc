// @ts-check
import { noDrizzleImports, rootConfigFiles, tonalInkTokens } from '@akasecurity/eslint-config';
import { react } from '@akasecurity/eslint-config/react';

export default [
  ...react,
  ...noDrizzleImports,
  ...tonalInkTokens,
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
