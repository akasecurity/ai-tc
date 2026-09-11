// @ts-check
import { drizzleWallRules, reactSyntaxBans, rootConfigFiles } from '@akasecurity/eslint-config';
import { reactUiPackage } from '@akasecurity/eslint-config/react';

export default [
  ...reactUiPackage,
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
    // The suite for the Scan page's Data Shares forward stands a real server on
    // loopback and reads the request off the wire: a stubbed transport can show
    // what the action decided, never what it sent, and the claims that forward
    // makes — no source text in the body, a digested project key, the credential
    // in a header and nowhere else — are all about the bytes that left the
    // process. Scoped to the one helper that binds it; every other network
    // import stays banned here.
    //
    // Both halves are set, and each has to be built through its own helper
    // because a flat-config `rules` entry REPLACES a rule's options rather than
    // merging them. `drizzleWallRules` carries the imports ban plus the Drizzle
    // wall; `reactSyntaxBans` is what this package's syntax ban actually is —
    // network, Drizzle, tonal tokens and the ambient clock — so stating only the
    // network side would silently drop the other three for this file.
    files: ['test/helpers/loopback.ts'],
    rules: {
      ...drizzleWallRules({ allow: ['node:http'] }),
      'no-restricted-syntax': reactSyntaxBans({ allowNetwork: ['node:http'] }),
    },
  },
];
