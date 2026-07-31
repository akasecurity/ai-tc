// @ts-check
// Network-only guard for the no-network enforcement suites under
// `packages/eslint-config/test`, which reach no other ESLint pass: the
// eslint-config package's own `lint` is a deliberate no-op, and `pnpm lint`
// (turbo) never sees the repo root. It enforces just the no-network bans — not
// the source-only conventions or the type-aware rules — so these plain-JS suites,
// full of untyped fixtures and banned-primitive strings, are not dragged into the
// full ruleset (the same split the per-package `eslint.scripts.config.mjs` makes
// for non-compiled JS). Driven by `pnpm lint:root`'s second pass; run with
// `--no-config-lookup` so `eslint.root.config.mjs` (base) does not also apply.
import { networkGuard, noNetworkImports, noNetworkSyntax } from '@akasecurity/eslint-config';

export default [
  ...networkGuard,
  {
    // no-network-runtime.test.js is the runtime half of the guarantee: it imports
    // node:net/node:dgram/node:dns to drive real connect/send/resolve calls at the
    // patched guard. Allow those three here only; every other network module stays
    // banned, and the static and dynamic bans opt out together so the exception
    // holds whichever import form the file uses. Its one real `fetch()` carries an
    // inline disable — a stray network global anywhere in the suites still fails.
    files: ['**/no-network-runtime.test.js'],
    rules: {
      'no-restricted-imports': noNetworkImports({ allow: ['node:net', 'node:dgram', 'node:dns'] }),
      'no-restricted-syntax': noNetworkSyntax({ allow: ['node:net', 'node:dgram', 'node:dns'] }),
    },
  },
];
