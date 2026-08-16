// @ts-check
import {
  base,
  noNetworkImports,
  noNetworkSyntax,
  rootConfigFiles,
} from '@akasecurity/eslint-config';

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
    // serve-release.ts stands a throwaway HTTP server on 127.0.0.1 so the real
    // install scripts can be driven against a local base — a loopback bind, not
    // egress, and the only way to drive BOTH scripts the same way (PowerShell's
    // Invoke-WebRequest rejects a file:// URI, so a file base cannot serve the
    // .ps1 half). Allow node:http in this one file; every other network module
    // stays banned here. The static and dynamic bans opt out together so the
    // exception holds whichever import form the file uses (mirrors the CLI's
    // smoke-dashboard.mjs opt-out).
    files: ['test/helpers/serve-release.ts'],
    rules: {
      'no-restricted-imports': noNetworkImports({ allow: ['node:http'] }),
      'no-restricted-syntax': noNetworkSyntax({ allow: ['node:http'] }),
    },
  },
];
