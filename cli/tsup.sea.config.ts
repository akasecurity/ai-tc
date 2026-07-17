import { fileURLToPath } from 'node:url';

import { defineConfig } from 'tsup';

import { normalizeSqliteSpecifier } from './scripts/normalize-sqlite.mjs';

// ink statically imports react-devtools-core (via a DEV-only, dynamically-imported
// module that the single-file bundle inlines and hoists). The CLI never enables
// devtools and the package isn't installed, so alias it to a no-op stub that resolves
// at build time and never runs at runtime.
const devtoolsStub = fileURLToPath(new URL('./scripts/devtools-stub.mjs', import.meta.url));

// Single-file bundle for the Single Executable Application (SEA) build. Unlike the
// published ESM CLI — which keeps ink/react as installed deps — a SEA has no
// node_modules, so everything the in-process CLI needs is inlined: the @akasecurity
// libs, zod, and the TUI stack (ink + react + yoga-layout, whose wasm is base64-inlined
// and so bundles as plain JS).
//
// This bundle is ESM, not CJS: yoga-layout's entry uses top-level await, which esbuild
// cannot emit to a CommonJS output. The SEA's CommonJS entry point dynamic-imports this
// file (dynamic import supports ESM + top-level await) — wired up in the packaging PR.
//
// Only the separately-spawned Next dashboard stack stays external — it ships as the
// sidecar standalone build (`aka dashboard` boots it in-process via dynamic import), and
// its dev-only fallback (`next` bin) is never reached from a packaged binary. node:sqlite
// is restored on the emitted bundle (esbuild may strip the node: prefix).
export default defineConfig({
  entry: { cli: 'src/cli.ts' },
  format: ['esm'],
  outExtension: () => ({ js: '.mjs' }),
  platform: 'node',
  target: 'node24',
  outDir: 'dist-sea',
  splitting: false,
  clean: true,
  noExternal: [/^@akasecurity\//, 'zod', 'ink', 'react'],
  // @akasecurity/web-ui + next: the separately-spawned dashboard stack (sidecar / dev-only).
  external: ['@akasecurity/web-ui', 'next'],
  esbuildOptions(options) {
    options.alias = { ...options.alias, 'react-devtools-core': devtoolsStub };
    // Bundled CJS deps (e.g. signal-exit) call require() for Node builtins. An ESM
    // output has no ambient require, so esbuild's shim throws "Dynamic require of X".
    // Provide a real require so those calls resolve.
    options.banner = {
      ...options.banner,
      js: "import { createRequire as __akaCreateRequire } from 'node:module'; const require = __akaCreateRequire(import.meta.url);",
    };
  },
  onSuccess: async () => {
    normalizeSqliteSpecifier('dist-sea');
  },
});
