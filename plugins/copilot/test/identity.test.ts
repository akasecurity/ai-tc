import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { PLUGIN_PACKAGE } from '../src/identity.ts';

// Pinned against the file that actually defines it, so a rename of the npm
// package fails here rather than shipping under a stale identity.
describe('skeleton', () => {
  it('names the npm package this plugin publishes as', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      name: string;
    };
    expect(PLUGIN_PACKAGE).toBe(pkg.name);
  });
});
