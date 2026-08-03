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
  ...rootConfigFiles,
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
  {
    // provider-codex.ts is the Codex CLI counterpart: resolves the LLM
    // provider from the host process env at SessionStart (OPENAI_BASE_URL).
    // Same file-scoped opt-out as provider.ts above.
    files: ['src/provider-codex.ts'],
    rules: {
      'n/no-process-env': 'off',
    },
  },
  {
    // provider-antigravity.ts is the Antigravity counterpart: resolves the LLM
    // provider from the host process env at the conversation's first
    // invocation (GOOGLE_GENAI_USE_VERTEXAI / GOOGLE_GEMINI_BASE_URL). Same
    // file-scoped opt-out as the two above.
    files: ['src/provider-antigravity.ts'],
    rules: {
      'n/no-process-env': 'off',
    },
  },
];
