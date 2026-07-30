// @ts-check
//
// Lints the repo-root sources no workspace package owns: the vitest no-network
// guard and the CI egress probe. `pnpm lint` is `turbo run lint`, which drives
// per-package scripts, and the repo root is not a workspace package — so these
// two files were reachable by no ESLint pass at all. Driven by `pnpm lint:root`,
// which CI runs as its own step, in the same spirit as the per-package
// `eslint.scripts.config.mjs` second pass.
//
// Both files import banned network modules on purpose: opening a socket is what
// they are for. The opt-outs below are what let the full ruleset — type-aware
// rules, import sorting, no-console, n/no-process-env — cover them at all,
// rather than the files sitting outside every pass. Widening an opt-out here
// does NOT quietly widen what is allowed: no-network-runtime.test.js lints both
// files with the raw `networkGuard` (no `allow`) and fails if either trips one
// more ban than it does today, so the exception stays measured.
import { base, noNetworkImports, noNetworkSyntax } from '@akasecurity/eslint-config';

/** The three the vitest guard patches. Anything else is still banned there. */
const GUARD_MODULES = ['node:net', 'node:dgram', 'node:dns'];
/** The probe only opens TCP sockets. */
const PROBE_MODULES = ['node:net'];

export default [
  ...base,
  {
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.root.json'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    files: ['test/setup/no-network.ts'],
    rules: {
      'no-restricted-imports': noNetworkImports({ allow: GUARD_MODULES }),
      'no-restricted-syntax': noNetworkSyntax({ allow: GUARD_MODULES }),
    },
  },
  {
    files: ['tools/ci/*.mjs'],
    // Plain JS, so `no-undef` is live here (typescript-eslint switches it off for
    // .ts, where the compiler covers it). Declare what the probe actually uses
    // rather than pulling in a globals package for one identifier.
    languageOptions: { globals: { process: 'readonly' } },
  },
  {
    files: ['tools/ci/egress-probe.mjs'],
    rules: {
      'no-restricted-imports': noNetworkImports({ allow: PROBE_MODULES }),
      'no-restricted-syntax': noNetworkSyntax({ allow: PROBE_MODULES }),
    },
  },
];
