// @ts-check
import {
  base,
  drizzleWallRules,
  noDrizzleImports,
  rootConfigFiles,
} from '@akasecurity/eslint-config';

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
  {
    // dashboard.ts's isPortFree() binds a probe server on 127.0.0.1 to detect an
    // in-use port before launching the dashboard — a local bind, not a network
    // call. Allow node:net in this one file; every other network import (and the
    // bare `net` specifier) stays banned here. The static and dynamic bans opt
    // out together so the exception holds whichever import form the file uses.
    //
    // Built through `drizzleWallRules` rather than `noNetworkImports` directly:
    // this entry SETS both rules, and flat config replaces rather than merges,
    // so stating only the network side would silently drop the Drizzle wall for
    // this one file while lint stayed green.
    files: ['src/commands/dashboard.ts'],
    rules: drizzleWallRules({ allow: ['node:net'] }),
  },
  {
    // The suite for `aka scan`'s Data Shares forward stands a real server on
    // 127.0.0.1 and reads the request off the wire: a stubbed transport can show
    // what the command decided, never what it sent, and the claims that forward
    // makes — no source text in the body, a digested project key, the credential
    // in a header and nowhere else — are all about the bytes that left the
    // process. Scoped to the one helper that binds it; every other network
    // import stays banned here, and both halves of the ban drop together so the
    // exception holds whichever import form the file uses.
    files: ['test/helpers/loopback.ts'],
    rules: drizzleWallRules({ allow: ['node:http'] }),
  },
];
