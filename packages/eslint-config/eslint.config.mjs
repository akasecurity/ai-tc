// @ts-check
//
// The full-ruleset pass for this package's own source. It is the package that
// DEFINES the no-network ban, which is exactly why it must sit behind it: a
// `fetch()` here would ship the ban's own implementation with a network call in
// it, and until this config existed `pnpm lint` was green with one planted.
//
// `src/` is plain JS with `// @ts-check` and sits inside the package tsconfig
// (`allowJs`), so the type-aware rules resolve here the same way they do in
// every other package. `test/` is deliberately NOT covered by this config —
// those suites are plain JS full of untyped fixtures and banned-primitive
// strings, so they take the network-only ruleset from the second pass
// (`eslint.guard.config.mjs`), the same split cli and the plugin make for their
// non-compiled `scripts/`. Both passes are chained with `&&` in the `lint`
// script, so neither can be skipped by a green run.
import { base, rootConfigFiles } from '@akasecurity/eslint-config';

// Bound to an annotated const rather than exported inline. This file is in the
// package's tsconfig `include` — unlike every sibling package's config, which
// nothing runs tsc over — and without the annotation the inferred type of the
// default export names a path inside node_modules, which tsc rejects as
// non-portable.
/** @type {import('typescript-eslint').ConfigArray} */
const config = [
  ...base,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  // Last-wins: this must follow the block that turns the project on, so the
  // root `*.config.*` files (this one, the guard config, vitest's) drop the
  // type-aware rules they have no project for. Every network rule is syntactic
  // and still fires there.
  ...rootConfigFiles,
];

export default config;
