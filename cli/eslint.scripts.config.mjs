// @ts-check
// Network-only guard for the CLI's dev/CI scripts (scripts/), which the main
// `eslint src test` pass never reaches. It enforces just the no-network bans —
// not the source-only conventions — so build/smoke tooling is not dragged into
// the full ruleset. Run with `--no-config-lookup` so `eslint.config.mjs` (which
// pulls in `base`) does not also apply here.
import { networkGuard, noNetworkImports, noNetworkSyntax } from '@akasecurity/eslint-config';

export default [
  ...networkGuard,
  {
    // smoke-dashboard.mjs polls the launched dashboard over loopback HTTP in a
    // CI smoke test — a local health check, not egress. Allow node:http here
    // only; the guard still bans every other network module. The static and
    // dynamic bans opt out together so the exception holds whichever import form
    // the file uses (mirrors cli's dashboard.ts opt-out).
    files: ['**/smoke-dashboard.mjs'],
    rules: {
      'no-restricted-imports': noNetworkImports({ allow: ['node:http'] }),
      'no-restricted-syntax': noNetworkSyntax({ allow: ['node:http'] }),
    },
  },
];
