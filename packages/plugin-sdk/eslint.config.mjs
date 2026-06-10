// @ts-check
import { base } from '@akasecurity/eslint-config';

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
    // provider.ts resolves the LLM provider from the host process env at
    // SessionStart (Bedrock/Vertex flags + ANTHROPIC_BASE_URL). The opt-out is
    // scoped to that one file so every other module in this package still fails
    // lint on a process.env read.
    files: ['src/provider.ts'],
    rules: {
      'n/no-process-env': 'off',
    },
  },
];
