// @ts-check
import { presentationalSyntaxBans, rootConfigFiles } from '@akasecurity/eslint-config';
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
    // `presentationalSyntaxBans` rather than by hand so lifting THIS ban cannot
    // lift the network, drizzle, tonal or ambient-locale ones with it, nor narrow
    // the locale ban's src-wide widening for this file — a bare
    // `no-restricted-syntax` entry here would replace all five.
    files: ['src/lib/useRenderClock.ts'],
    rules: { 'no-restricted-syntax': presentationalSyntaxBans({ allowAmbientClock: true }) },
  },
  ...rootConfigFiles,
];
