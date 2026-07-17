'use strict';
// Sidecar bootstrap, loaded by the SEA's embedded entry via require(). The embedded main
// cannot import() files, but a normally-loaded CJS module like this one can — so it
// dynamic-imports the ESM CLI bundle (which uses top-level await for ink/yoga and so
// cannot be require()d). The bundle sits next to the executable.
const { pathToFileURL } = require('node:url');
const { dirname, join } = require('node:path');

const bundle = join(dirname(process.execPath), 'cli.mjs');
import(pathToFileURL(bundle).href).catch((err) => {
  process.stderr.write(`aka: failed to start — ${err && err.stack ? err.stack : String(err)}\n`);
  process.exit(1);
});
