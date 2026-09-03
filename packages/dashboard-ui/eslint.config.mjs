// @ts-check
import { reactSyntaxBans, rootConfigFiles } from '@akasecurity/eslint-config';
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
  {
    // The one sanctioned reader of the ambient clock in this package. Every other
    // client module takes the instant as a prop; this hook is what produces the
    // live one they are given, after hydration has committed. Written through
    // `reactSyntaxBans` rather than by hand so lifting THIS ban cannot lift the
    // network, drizzle or tonal ones with it — a bare `no-restricted-syntax`
    // entry here would replace all four.
    files: ['src/lib/useRenderClock.ts'],
    rules: { 'no-restricted-syntax': reactSyntaxBans({ allowAmbientClock: true }) },
  },
  ...rootConfigFiles,
];
