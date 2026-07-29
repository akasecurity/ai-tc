#!/usr/bin/env node
// The bin entry (tsup bundles this to dist/cli.js). It stays a shim so `main`
// lives in a module a test can import without running the CLI as a side effect.
import { main } from './main.ts';

main().catch((err: unknown) => {
  process.stderr.write(`aka: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
