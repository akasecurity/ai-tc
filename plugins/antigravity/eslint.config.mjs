// @ts-check
import { base, rootConfigFiles } from '@akasecurity/eslint-config';

export default [
  ...base,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    // The ephemeral judge subprocess inherits the host environment untouched:
    // `antigravity` must resolve on PATH and its auth (GEMINI_HOME / ~/.gemini
    // credentials) must survive the spawn.
    files: ['src/triage/judge.ts'],
    rules: {
      'n/no-process-env': 'off',
    },
  },
  ...rootConfigFiles,
];
