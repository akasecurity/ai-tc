// @ts-check
import { base, noDrizzleImports, rootConfigFiles } from '@akasecurity/eslint-config';

export default [
  ...base,
  ...noDrizzleImports,
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
