// @ts-check
//
// The full-ruleset half of `pnpm lint:root`, which lints the sources no
// per-package `lint` pass reaches. `pnpm lint` is `turbo run lint`, which drives
// per-package scripts and never sees the repo root, so lint:root runs as its own
// CI step. This config covers the repo-root files no workspace package owns that
// ARE written for the full ruleset: the vitest no-network guard, the CI egress
// probe, and the repo-root `*.config.*` (this file and commitlint's). The plain-JS
// enforcement suites under `packages/eslint-config/test` — which the eslint-config
// package's deliberate no-op `lint` leaves behind every pass — get network-only
// coverage from the sibling `eslint.root.guard.config.mjs`, the same split the
// per-package `eslint.scripts.config.mjs` second pass makes for non-compiled JS.
//
// The guard and probe import banned network modules on purpose: opening a socket
// is what they are for. The file-scoped opt-outs below are what let the full
// ruleset cover them at all rather than leave them outside every pass. Widening an
// opt-out here does NOT quietly widen what is allowed: no-network-runtime.test.js
// re-lints each opted-out file with the raw `networkGuard` (no `allow`) and fails
// if any trips one more ban than it does today, so every exception stays measured.
import {
  base,
  noNetworkImports,
  noNetworkSyntax,
  rootConfigFiles,
} from '@akasecurity/eslint-config';

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
  // This config and commitlint's are themselves repo-root sources no package owns
  // (lint:root names `*.config.*` as a target). Linted with the type-aware rules
  // off, exactly as package config files are — the network ban is syntactic and
  // still fires. tsconfig.root.json type-checks this file separately (it carries
  // `// @ts-check`). Last-wins: this must follow the block that turns the project
  // on, so the type-aware rules are off for these paths.
  ...rootConfigFiles,
];
