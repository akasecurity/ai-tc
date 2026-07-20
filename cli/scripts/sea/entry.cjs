'use strict';
// Embedded main of the Single Executable Application. A SEA main cannot import() files
// (the embedder resolves dynamic import to built-in modules only) and its bare require()
// sees only builtins — so anchor a real require at the executable and load the on-disk
// bootstrap sidecar, which performs the dynamic import of the ESM CLI bundle.
const { createRequire } = require('node:module');
const { pathToFileURL } = require('node:url');
const { dirname, join } = require('node:path');

const requireFromExe = createRequire(pathToFileURL(process.execPath));
requireFromExe(join(dirname(process.execPath), 'boot.cjs'));
