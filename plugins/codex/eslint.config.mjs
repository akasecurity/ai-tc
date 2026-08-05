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
    // `codex` must resolve on PATH and its auth (CODEX_HOME / ~/.codex
    // credentials) must survive the spawn.
    files: ['src/triage/judge.ts'],
    rules: {
      'n/no-process-env': 'off',
    },
  },
  ...rootConfigFiles,
];
