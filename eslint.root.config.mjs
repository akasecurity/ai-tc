// @ts-check
//
// `pnpm lint:root` lints the sources no per-package `lint` pass reaches.
// `turbo run lint` drives per-package scripts and never sees the repo root, so
// lint:root is a pass of its own — chained off `pnpm lint` (which is what the
// pre-push hook and the release workflows run) and named as its own CI step. This
// config covers every repo-root file no workspace package owns: the vitest
// no-network guard, the CI egress probe, and the repo-root `*.config.*` (this file
// and commitlint's).
//
// The plain-JS enforcement suites under `packages/eslint-config/test` are NOT
// here. They sit inside a package, and that package now lints itself: its `lint`
// script runs the full ruleset over `src` and its root configs, then a second
// network-only pass over `test` against its own `eslint.guard.config.mjs` — the
// same split the per-package `eslint.scripts.config.mjs` second pass makes for
// non-compiled JS. A root pass over them used to exist only because that
// package's `lint` was a deliberate no-op.
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
  // The two root ESLint configs and commitlint's are themselves repo-root sources
  // no package owns; lint:root names `*.config.*` as a target and it matches all
  // three. rootConfigFiles lints them with the type-aware rules off — the network
  // ban is syntactic and still fires. The two ESLint configs are also type-checked
  // by tsconfig.root.json (they carry `// @ts-check`), so rootConfigFiles' "sits
  // outside the tsconfig include" rationale now holds only for commitlint's, which
  // is linted here and type-checked nowhere. Last-wins: this must follow the block
  // that turns the project on.
  ...rootConfigFiles,
];
