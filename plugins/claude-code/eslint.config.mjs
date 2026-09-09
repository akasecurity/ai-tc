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
  {
    // SessionStart reads the interface the HOST stamps on its own subprocess
    // environment (terminal, the VS Code panel, the desktop app). Nothing else
    // in a hook's payload distinguishes them, and the transcript cannot: the
    // record carrying `entrypoint` does not exist yet when a fresh session
    // starts.
    files: ['src/hooks/session-start.ts'],
    rules: {
      'n/no-process-env': 'off',
    },
  },
  ...rootConfigFiles,
];
