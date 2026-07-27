// @ts-check
import { base, noNetworkImports, noNetworkSyntax } from '@akasecurity/eslint-config';

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
    // dashboard.ts's isPortFree() binds a probe server on 127.0.0.1 to detect an
    // in-use port before launching the dashboard — a local bind, not a network
    // call. Allow node:net in this one file; every other network import (and the
    // bare `net` specifier) stays banned here. The static and dynamic bans opt
    // out together so the exception holds whichever import form the file uses.
    files: ['src/commands/dashboard.ts'],
    rules: {
      'no-restricted-imports': noNetworkImports({ allow: ['node:net'] }),
      'no-restricted-syntax': noNetworkSyntax({ allow: ['node:net'] }),
    },
  },
];
