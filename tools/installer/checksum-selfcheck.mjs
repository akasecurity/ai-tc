#!/usr/bin/env node
// CI gate for the installer trust chain: the EXPECTED_MJS_SHA256 pins baked into
// install.sh and install.ps1 must equal the SHA-256 of the install.mjs committed
// alongside them, or the curl|sh download path rejects every legitimate install.
// Run with:  node tools/installer/checksum-selfcheck.mjs
// On drift, regenerate with:  shasum -a 256 tools/installer/install.mjs
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

const actual = createHash('sha256')
  .update(readFileSync(join(here, 'install.mjs')))
  .digest('hex');

const PINS = [
  { file: 'install.sh', re: /^EXPECTED_MJS_SHA256="([0-9a-f]{64})"$/m },
  { file: 'install.ps1', re: /^\$ExpectedMjsSha256 = '([0-9a-f]{64})'$/m },
];

let failed = false;
for (const { file, re } of PINS) {
  const source = readFileSync(join(here, file), 'utf8');
  const match = source.match(re);
  if (!match) {
    console.error(`✗ ${file}: no EXPECTED_MJS_SHA256 pin found (pattern ${re})`);
    failed = true;
    continue;
  }
  if (match[1] !== actual) {
    console.error(`✗ ${file}: pinned checksum ${match[1]} does not match install.mjs (${actual})`);
    console.error(`  Regenerate the pin:  shasum -a 256 tools/installer/install.mjs`);
    failed = true;
    continue;
  }
  console.log(`✓ ${file}: pin matches install.mjs (${actual})`);
}

process.exit(failed ? 1 : 0);
