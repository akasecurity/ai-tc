// @ts-check
import { noEnterpriseImports, rootConfigFiles, tonalInkTokens } from '@akasecurity/eslint-config';
import { react } from '@akasecurity/eslint-config/react';

export default [
  ...react,
  ...noEnterpriseImports,
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
