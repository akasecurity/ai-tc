import { defineConfig } from 'tsup';

// The dashboard's ReDoS-bounding scan worker, built as one self-contained file.
//
// It is the SAME worker the plugin ships (packages/plugin-sdk/src/scan-worker.ts)
// — one implementation, one wire protocol — packaged a second time because it
// has to reach a second place. The plugin's copy lands beside its hooks in a
// flat `scripts/` directory; this one lands in the Next app directory, which is
// what `app/lib/scan-worker.ts` resolves against and what
// `outputFileTracingIncludes` copies into the standalone build.
//
// `noExternal` is the whole point: nothing that runs this file has a
// node_modules to resolve from. Next bundles the workspace packages into its
// own server chunks and the published CLI ships the standalone tree with
// node_modules stripped, so a surviving specifier would not fail the build — it
// would fail at `new Worker(…)`, on a user's machine, by silently costing the
// scan its bound. tsup externalizes whatever is in THIS package's own
// dependencies, so the `@akasecurity/*` entry is what is doing the work today;
// `zod` is not in web-ui's dependencies and is bundled regardless, and is named
// anyway so that adding it there later cannot quietly break this artifact.
// test/e2e/scan-worker-bundle.e2e.test.ts fails on any specifier that escapes.
export default defineConfig({
  entry: { 'scan-worker': '../packages/plugin-sdk/src/scan-worker.ts' },
  format: ['esm'],
  platform: 'node',
  target: 'node24',
  outDir: 'dist',
  splitting: false,
  clean: true,
  noExternal: [/^@akasecurity\//, 'zod'],
});
