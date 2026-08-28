import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { PLUGIN_PACKAGE, pluginBuild } from '../src/build-info.ts';

// The identity every attached posture report from this plugin carries. Both
// halves are pinned against the files that actually define them, so a rename
// of the npm package or a manifest layout change fails here rather than
// shipping reports under a stale identity.
describe('pluginBuild', () => {
  it('names the npm package this plugin publishes as', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      name: string;
    };
    expect(PLUGIN_PACKAGE).toBe(pkg.name);
  });

  it('reads the version from the manifest beside the running code', () => {
    const manifest = JSON.parse(
      readFileSync(new URL('../plugin.json', import.meta.url), 'utf8'),
    ) as { version: string };
    expect(manifest.version).toBeTypeOf('string');
    expect(pluginBuild()).toEqual({ package: PLUGIN_PACKAGE, version: manifest.version });
  });
});
